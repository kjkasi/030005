/*
 * Support for Redirection of IPv6 TCP streams for Linux/iptables
 *
 * Copyright (c) 2011 NETGEAR
 * Author: Robert Leech
 *
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/jiffies.h>
#include <net/checksum.h>
#include <net/udp.h>
#include <net/inet_sock.h>
#include <linux/inetdevice.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>

#include <net/if_inet6.h>
#include <net/addrconf.h>
#include <linux/netfilter_ipv6/ip6_tables.h>

#include <linux/netfilter_ipv6/ip6t_REDIR6.h>

/*Netgear Commented
enum nf_inet_hooks {
        NF_INET_PRE_ROUTING,
        NF_INET_LOCAL_IN,
        NF_INET_FORWARD,
        NF_INET_LOCAL_OUT,
        NF_INET_POST_ROUTING,
        NF_INET_NUMHOOKS
};


enum {
        NFPROTO_UNSPEC =  0,
        NFPROTO_IPV4   =  2,
        NFPROTO_ARP    =  3,
        NFPROTO_BRIDGE =  7,
        NFPROTO_IPV6   = 10,
        NFPROTO_DECNET = 12,
        NFPROTO_NUMPROTO,
};
*/
typedef struct saved_sessions_s {
    struct in6_addr daddr;
    struct in6_addr saddr;
    __be16 dport;
    __be16 sport;
    unsigned long sys_time;
} ss_t;

#define MAX_REDIR6_SESSIONS 10

ss_t redir6_saved_sessions[MAX_REDIR6_SESSIONS];

/*
 * Save Session
 * Stores address/port information in an array element for retrieval later
 * saves the source IP and Port, Dest IP and Port (IPv6).  The find routine will search on Source IP/Port
 * and then can return Dest IP/Port to restore the packet as if it were never modified
*/
static void redir6_save_session(ss_t *ss)
{
    ss_t *redir6_best_match = NULL, *redir6_current;
    int i;
    unsigned long cur_sys_time = jiffies;

    for (i=0; i < MAX_REDIR6_SESSIONS; i++)
    {
        redir6_current = &redir6_saved_sessions[i];
        if ((redir6_current->daddr.in6_u.u6_addr32[0] == ss->daddr.in6_u.u6_addr32[0]) &&
            (redir6_current->daddr.in6_u.u6_addr32[1] == ss->daddr.in6_u.u6_addr32[1]) &&
            (redir6_current->daddr.in6_u.u6_addr32[2] == ss->daddr.in6_u.u6_addr32[2]) &&
            (redir6_current->daddr.in6_u.u6_addr32[3] == ss->daddr.in6_u.u6_addr32[3]) &&
            (redir6_current->saddr.in6_u.u6_addr32[0] == ss->saddr.in6_u.u6_addr32[0]) &&
            (redir6_current->saddr.in6_u.u6_addr32[1] == ss->saddr.in6_u.u6_addr32[1]) &&
            (redir6_current->saddr.in6_u.u6_addr32[2] == ss->saddr.in6_u.u6_addr32[2]) &&
            (redir6_current->saddr.in6_u.u6_addr32[3] == ss->saddr.in6_u.u6_addr32[3]) &&
            (redir6_current->dport == ss->dport) && (redir6_current->sport == ss->sport))
        {
            /* Found a current active session that matches.  Keep using it. */
            redir6_current->sys_time = cur_sys_time;
            return;
        }

        /*
         * Look for best match in case we do not find a current active session.
         * Best match is where the time is 0.  Otherwise, the oldest one will get reused.
         * time_after(a,b) returns true if the time a is after time b.
        */
        if ((redir6_best_match == NULL) || (time_after(redir6_best_match->sys_time, redir6_current->sys_time)))
        {
            redir6_best_match = redir6_current;
        }
    }

    /* At this point, we found no exact match.  Must use best_match. */
    redir6_best_match->daddr = ss->daddr;
    redir6_best_match->saddr = ss->saddr;
    redir6_best_match->dport = ss->dport;
    redir6_best_match->sport = ss->sport;
    redir6_best_match->sys_time = cur_sys_time;
}

/*
 * redir6_find_session.  Find a previously saved session, or return error.
*/
static int
redir6_find_session(ss_t *ss)
{
    int i;
    ss_t *redir6_current;
    unsigned long cur_sys_time = jiffies;

    for (i=0; i < MAX_REDIR6_SESSIONS; i++)
    {
        redir6_current = &redir6_saved_sessions[i];
        if ((redir6_current->saddr.in6_u.u6_addr32[0] == ss->saddr.in6_u.u6_addr32[0]) &&
            (redir6_current->saddr.in6_u.u6_addr32[1] == ss->saddr.in6_u.u6_addr32[1]) &&
            (redir6_current->saddr.in6_u.u6_addr32[2] == ss->saddr.in6_u.u6_addr32[2]) &&
            (redir6_current->saddr.in6_u.u6_addr32[3] == ss->saddr.in6_u.u6_addr32[3]) &&
            (redir6_current->sport == ss->sport))
        {
            /* Found a current active session that matches.  Return it. */
            redir6_current->sys_time = cur_sys_time;
            ss->daddr = redir6_current->daddr;
            ss->dport = redir6_current->dport;
            return (1);
        }
    }
    return (0);
}

static inline const struct in6_addr *
redir6_laddr6(struct sk_buff *skb, const struct in6_addr *user_laddr,
              const struct in6_addr *daddr)
{
        struct inet6_dev *indev;
        struct inet6_ifaddr *ifa;
        struct in6_addr *laddr;

        if (!ipv6_addr_any(user_laddr))
                return user_laddr;
        laddr = NULL;

        rcu_read_lock();
        indev = __in6_dev_get(skb->dev);
        if (indev)

                for (ifa = indev->addr_list; ifa; ifa = ifa->if_next) { 
                        if (ifa->flags & (IFA_F_TENTATIVE | IFA_F_DEPRECATED))
                              continue;

                        laddr = &ifa->addr;
                        break;
                }
        rcu_read_unlock();

        return laddr ? laddr : daddr;
}

static unsigned int
redir6_v1(struct sk_buff *pskb,
          const struct xt_target_param *par)
{
        struct sk_buff *skb = pskb;
        struct ipv6hdr *iph = ipv6_hdr(skb);
        const struct xt_redir6_target_info_v1 *tgi = par->targinfo;
        struct tcphdr _hdr, *hp;
        const struct in6_addr *laddr;
        unsigned int thoff;
        int tproto;
        ss_t ss;

        //printk("redir6_v1 lport=%d\n",tgi->lport);
        tproto = ipv6_find_hdr(skb, &thoff, NEXTHDR_ROUTING, NULL);
        if (tproto < 0) {
                pr_debug("unable to find transport header in IPv6 packet, dropping\n");
                return NF_DROP;
        }

        hp = skb_header_pointer(skb, thoff, sizeof(_hdr), &_hdr);
        if (hp == NULL) {
                pr_debug("unable to grab transport header contents in IPv6 packet, dropping\n");
                return NF_DROP;
        }
        laddr = redir6_laddr6(skb, &tgi->laddr.in6, &iph->daddr);

        if (par->hooknum == NF_INET_PRE_ROUTING)
        {
            ss.daddr = iph->daddr;
            iph->daddr = *laddr;
            ss.dport = hp->dest;
            if (tgi->lport > 0)
            {
                hp->dest = tgi->lport;
            }
            ss.saddr = iph->saddr;
            ss.sport = hp->source;
            redir6_save_session(&ss);
            /*printk("redir6:  Modified TCP packet Inbound from ADDR(0x%x.0x%x.0x%x.0x%x) Port(%d)\n",
                  saved_daddr.in6_u.u6_addr32[0],saved_daddr.in6_u.u6_addr32[1],saved_daddr.in6_u.u6_addr32[2],
                  saved_daddr.in6_u.u6_addr32[3],saved_dport);*/
        }
        else if (par->hooknum == NF_INET_POST_ROUTING)
        {
            __u16 len1;
            /*printk("redir6:  TCP packet Outbound to ADDR(0x%x.0x%x.0x%x.0x%x) DestPort(%d)\n",
                  iph->daddr.in6_u.u6_addr32[0],iph->daddr.in6_u.u6_addr32[1],iph->daddr.in6_u.u6_addr32[2],
                  iph->daddr.in6_u.u6_addr32[3],hp->dest);
            printk("redir6:  TCP packet Outbound from ADDR(0x%x.0x%x.0x%x.0x%x) SourcePort(%d)\n",
                  iph->saddr.in6_u.u6_addr32[0],iph->saddr.in6_u.u6_addr32[1],iph->saddr.in6_u.u6_addr32[2],
                  iph->saddr.in6_u.u6_addr32[3],hp->source);
            printk("redir6:  TCP packet Outbound Saved Info ADDR(0x%x.0x%x.0x%x.0x%x) SourcePort(%d)\n",
                  saved_saddr.in6_u.u6_addr32[0],saved_saddr.in6_u.u6_addr32[1],saved_saddr.in6_u.u6_addr32[2],
                  saved_saddr.in6_u.u6_addr32[3],saved_sport);*/
            ss.saddr = iph->daddr;
            ss.sport = hp->dest;

            if (redir6_find_session(&ss))
            {
                iph->saddr = ss.daddr;
                hp->source = ss.dport;
                len1 = skb->len - thoff;

                hp->check = 0;
                hp->check = csum_ipv6_magic(&(iph->saddr),
                                  &(iph->daddr),
                                  len1, IPPROTO_TCP,
                                  csum_partial((char *)hp,
                                       len1, 0));
                /*printk("redir6: Check After (0x%x)\n",hp->check);*/
            }
        }
        else
        {
            printk("redir6 Module called with incorrect hook 0x%x\n", par->hooknum);
        }
        return NF_ACCEPT;
}

static bool redir6_check(const struct xt_tgchk_param *par)
{
	const struct ip6t_ip6 *i = par->entryinfo;

	if ((i->proto == IPPROTO_TCP)
			&& !(i->invflags & IP6T_INV_PROTO))
		return true;

	pr_info("Can be used only in combination with "
			"either -p tcp\n");
	return false;
}

static struct xt_target redir6_tg_reg[] __read_mostly = {
        {
                .name           = "REDIR6",
                .family         = NFPROTO_IPV6,
                .table          = "mangle",
                .target         = redir6_v1,
                .revision       = 0,
                .targetsize     = sizeof(struct xt_redir6_target_info_v1),
                .checkentry     = redir6_check,
                .hooks          = (1 << NF_INET_PRE_ROUTING)|(1 << NF_INET_POST_ROUTING),
                .me             = THIS_MODULE,
        },

};

static int __init redir6_tg_init(void)
{
    int ret1;

    memset(redir6_saved_sessions, 0, sizeof(ss_t) * MAX_REDIR6_SESSIONS);
    ret1 = xt_register_targets(redir6_tg_reg, ARRAY_SIZE(redir6_tg_reg));
    return (ret1);
}

static void __exit redir6_tg_exit(void)
{
        xt_unregister_targets(redir6_tg_reg, ARRAY_SIZE(redir6_tg_reg));
}

module_init(redir6_tg_init);
module_exit(redir6_tg_exit);
MODULE_LICENSE("NETGEAR");
MODULE_AUTHOR("Robert Leech");
MODULE_DESCRIPTION("Netfilter TCP Stream Redirect for IPv6 (REDIR6) target module.");
MODULE_ALIAS("ip6t_REDIR6");

