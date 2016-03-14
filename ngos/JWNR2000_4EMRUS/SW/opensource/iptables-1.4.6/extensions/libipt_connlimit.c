/* Shared library add-on to iptables to add connection limit support. */
#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <getopt.h>
#include <iptables.h>
/* Netgear Add Start */
#if defined(BRCM_4_12_XX) || defined(BUILD_INTEL_PUMA_PLATFORM) || defined(BUILD_RTL8196C)
#define LANTIQ_UGW_5_1 1
#endif
#ifdef LANTIQ_UGW_5_1
#include <linux/netfilter/xt_connlimit.h>
#else
#include <linux/netfilter_ipv4/ipt_connlimit.h>
#endif
/* Netgear Add end */
/* Function which prints out usage message. */
static void
help(void)
{
	printf(
"connlimit v%s options:\n"
"[!] --connlimit-above n		match if the number of existing tcp connections is (not) above n\n"
" --connlimit-mask n		group hosts using mask\n"
"\n", IPTABLES_VERSION);
}

static struct option opts[] = {
	{ "connlimit-above", 1, 0, '1' },
	{ "connlimit-mask",  1, 0, '2' },
	{0}
};

/* Initialize the match. */
static void
init(struct ipt_entry_match *m, unsigned int *nfcache)
{
	/* Can't cache this */
	*nfcache |= NFC_UNKNOWN;
}

/* Function which parses command options; returns true if it
   ate an option */
static int
parse(int c, char **argv, int invert, unsigned int *flags,
      const struct ipt_entry *entry,
      unsigned int *nfcache,
      struct ipt_entry_match **match)
{
#ifndef LANTIQ_UGW_5_1
	struct ipt_connlimit_info *info = (struct ipt_connlimit_info*)(*match)->data;
#else
	struct xt_connlimit_info *info = (struct xt_connlimit_info*)(*match)->data;
#endif
	int i;

	if (0 == (*flags & 2)) {
		/* set default mask unless we've already seen a mask option */
#ifndef LANTIQ_UGW_5_1
		info->mask = htonl(0xFFFFFFFF);
#else
		info->v4_mask = htonl(0xFFFFFFFF);
#endif
	}

	switch (c) {
	case '1':
		xtables_check_inverse(optarg, &invert, &optind, 0, argv);
		info->limit = atoi(argv[optind-1]);
		info->inverse = invert;
		*flags |= 1;
		break;

	case '2':
		i = atoi(argv[optind-1]);
		if ((i < 0) || (i > 32))
			xtables_error(PARAMETER_PROBLEM,
				"--connlimit-mask must be between 0 and 32");

#ifndef LANTIQ_UGW_5_1
		if (i == 0)
			info->mask = 0;
		else
			info->mask = htonl(0xFFFFFFFF << (32 - i));
#else 
	if (i == 0)
			info->v4_mask = 0;
		else
			info->v4_mask= htonl(0xFFFFFFFF << (32 - i));
#endif
		*flags |= 2;
		break;

	default:
		return 0;
	}

	return 1;
}

/* Final check */
static void final_check(unsigned int flags)
{
	if (!flags & 1)
		xtables_error(PARAMETER_PROBLEM, "You must specify `--connlimit-above'");
}

#ifndef LANTIQ_UGW_5_1
static int
count_bits(u_int32_t mask)
{
	int i, bits;

	for (bits = 0, i = 31; i >= 0; i--) {
		if (mask & htonl((u_int32_t)1 << i)) {
			bits++;
			continue;
		}
		break;
	}
	return bits;
}
#else
static unsigned int 
count_bits4(u_int32_t mask)
{
	unsigned int bits = 0;

	for (mask = ~ntohl(mask); mask != 0; mask >>= 1)
		++bits;

	return 32 - bits;
}
#endif

/* Prints out the matchinfo. */
static void
print(const struct ipt_ip *ip,
      const struct ipt_entry_match *match,
      int numeric)
{
#ifndef LANTIQ_UGW_5_1
	struct ipt_connlimit_info *info = (struct ipt_connlimit_info*)match->data;
	printf("#conn/%d %s %d ", count_bits(info->mask),
	       info->inverse ? "<" : ">", info->limit);
#else
	struct xt_connlimit_info *info = (struct xt_connlimit_info*)match->data;
	printf("#conn/%u %s %u ", count_bits4(info->v4_mask),
	       info->inverse ? "<" : ">", info->limit);
#endif
}

/* Saves the matchinfo in parsable form to stdout. */
static void save(const struct ipt_ip *ip, const struct ipt_entry_match *match)
{
#ifndef LANTIQ_UGW_5_1
	struct ipt_connlimit_info *info = (struct ipt_connlimit_info*)match->data;
	printf("%s--connlimit-above %d ",info->inverse ? "! " : "",info->limit);
	printf("--connlimit-mask %d ",count_bits(info->mask));

#else
    struct xt_connlimit_info *info = (struct xt_connlimit_info*)match->data;
	printf("%s--connlimit-above %d ",info->inverse ? "! " : "",info->limit);
	printf("--connlimit-mask %d ",count_bits4(info->v4_mask));
#endif
}

static struct xtables_match connlimit = {
	.name	=		"connlimit",
	.version	=	XTABLES_VERSION,
#ifndef LANTIQ_UGW_5_1
	.size	=		IPT_ALIGN(sizeof(struct ipt_connlimit_info)),
	.userspacesize	=	offsetof(struct ipt_connlimit_info,data),
#else
	.size	=		IPT_ALIGN(sizeof(struct xt_connlimit_info)),
	.userspacesize	=	offsetof(struct xt_connlimit_info, data),
#endif
	.help	=		help,
	.init	=		init,
	.parse	=		parse,
	.final_check	=	final_check,
	.print	=		print,
	.save	= 		save,
	.extra_opts	=	opts
};

void _init(void)
{
	xtables_register_match(&connlimit);
}

