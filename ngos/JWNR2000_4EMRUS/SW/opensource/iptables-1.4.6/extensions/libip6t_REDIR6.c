/*
 * Shared library add-on to iptables to add REDIR6 target support.
 *
 * Copyright (C) 2011 NETGEAR
 */
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>

#include <ip6tables.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <linux/netfilter_ipv6/ip6t_REDIR6.h>
//Netgear Add Start
#if defined(BRCM_4_12_XX) || defined(BUILD_INTEL_PUMA_PLATFORM) || defined(BUILD_RTL8196C)
#define LANTIQ_UGW_5_1 1
#endif
#ifdef LANTIQ_UGW_5_1
#include <linux/netfilter.h> 
#endif
//Netgear Add End
static const struct option redir6_tg_opts[] = {
	{"on-port",     true, NULL, '1'},
	{"on-ip",       true, NULL, '2'},
	{ .name = NULL },
};

#define PARAM_ONPORT	1
#define PARAM_ONIP	2

static void redir6_tg_help(void)
{
	printf(
"REDIR6 target v%s options:\n"
"  --on-port port                   Redirect connection to port, or the original port if 0\n"
"  --on-ip ip                       Optionally redirect to the given IP\n"
IPTABLES_VERSION);
}

/* Initialize the target. */
static void
init(struct ip6t_entry_target *t, unsigned int *nfcache)
{
}

static void parse_redir6_lport(const char *s, struct xt_redir6_target_info_v1 *info)
{
	unsigned int lport;

	if (xtables_strtoui(s, NULL, &lport, 0, 65535))
		info->lport = htons(lport);
	else
		xtables_error(PARAMETER_PROBLEM, "bad --on-port \"%s\", lport value: %d", s, lport);
}

static void parse_redir6_laddr(const char *s, struct xt_redir6_target_info_v1 *info)
{
	//struct in_addr *laddr;

	//if ((laddr = dotted_to_addr(s)) == NULL)
		//xtables_error(PARAMETER_PROBLEM, "bad --on-ip \"%s\"", s);
	info->laddr.ip6[0] = /*laddr->s_addr*/0;
	info->laddr.ip6[1] = 0;
	info->laddr.ip6[2] = 0;
	info->laddr.ip6[3] = 0;
}

static int redir6_tg_parse(int c, char **argv, int invert, unsigned int *flags,
                        const struct ip6t_entry *entry, struct ip6t_entry_target **target)
{
	struct xt_redir6_target_info_v1 *redir6info = (void *)(*target)->data;

	switch (c) {
	case '1':
		if (*flags & PARAM_ONPORT)
			xtables_error(PARAMETER_PROBLEM,
				"REDIR6 target: Can't specify --on-port twice");
		parse_redir6_lport(optarg, redir6info);
		*flags |= PARAM_ONPORT;
		return 1;
	case '2':
		if (*flags & PARAM_ONIP)
			xtables_error(PARAMETER_PROBLEM,
				"REDIR6 target: Can't specify --on-ip twice");
		parse_redir6_laddr(optarg, redir6info);
		*flags |= PARAM_ONIP;
		return 1;
	}

	return 0;
}

static void redir6_tg_check(unsigned int flags)
{
	if (!(flags & PARAM_ONPORT))
		xtables_error(PARAMETER_PROBLEM,
		           "REDIR6 target: Parameter --on-port is required");
}

static void redir6_tg_print(const void *ip, const struct ip6t_entry_target *target,
                         int numeric)
{
	const struct xt_redir6_target_info_v1 *info = (const void *)target->data;
	printf("REDIR6 redirect %s:%u",
	       /*addr_to_dotted((const struct in_addr *)&info->laddr)*/"::0",
	       ntohs(info->lport));
}

static void redir6_tg_save(const void *ip, const struct ip6t_entry_target *target)
{
	const struct xt_redir6_target_info_v1 *info = (const void *)target->data;

	printf("--on-port %u ", ntohs(info->lport));
	printf("--on-ip %s ",
	       /*addr_to_dotted((const struct in_addr *)&info->laddr)*/"::0");
}

static struct xtables_target redir6_tg_reg = {
	.next		   = NULL,
	.name          = "REDIR6",
//	.family        = AF_INET,
	.version       = XTABLES_VERSION,
	.size          = IP6T_ALIGN(sizeof(struct xt_redir6_target_info_v1)),
	.userspacesize = IP6T_ALIGN(sizeof(struct xt_redir6_target_info_v1)),
	.help          = &redir6_tg_help,
	.init	       = &init,
	.parse         = &redir6_tg_parse,
	.final_check   = &redir6_tg_check,
	.print         = &redir6_tg_print,
	.save          = &redir6_tg_save,
	.extra_opts    = redir6_tg_opts,
};

void _init(void)
{
	xtables_register_target(&redir6_tg_reg);
}
