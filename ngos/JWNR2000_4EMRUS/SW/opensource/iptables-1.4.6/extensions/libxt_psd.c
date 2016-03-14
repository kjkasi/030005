/* 
  Shared library add-on to iptables to add PSD support 
   
  Copyright (C) 2000,2001 astaro AG

  This file is distributed under the terms of the GNU General Public
  License (GPL). Copies of the GPL can be obtained from:
     ftp://prep.ai.mit.edu/pub/gnu/GPL

  2000-05-04 Markus Hennig <hennig@astaro.de> : initial
  2000-08-18 Dennis Koslowski <koslowski@astaro.de> : first release
  2000-12-01 Dennis Koslowski <koslowski@astaro.de> : UDP scans detection added
  2001-02-04 Jan Rekorajski <baggins@pld.org.pl> : converted from target to match
  2003-03-02 Harald Welte <laforge@netfilter.org>: fix 'storage' bug
*/
#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include <getopt.h>
#include <xtables.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>

/* Netgear Changes Start */
struct ipt_psd_info {  
	unsigned int weight_threshold;
	unsigned int delay_threshold;
	unsigned short lo_ports_weight;
	unsigned short hi_ports_weight;
};

/*
 ** High port numbers have a lower weight to reduce the frequency of false
 ** positives, such as from passive mode FTP transfers.
 **/

#define PORT_WEIGHT_PRIV                3
#define PORT_WEIGHT_HIGH                1

/*
 ** Port scan detection thresholds: at least COUNT ports need to be scanned
 ** from the same source, with no longer than DELAY ticks between ports.
 **/

#define SCAN_MIN_COUNT                  7
#define SCAN_MAX_COUNT                  (SCAN_MIN_COUNT * PORT_WEIGHT_PRIV)
#define SCAN_WEIGHT_THRESHOLD           SCAN_MAX_COUNT
#define SCAN_DELAY_THRESHOLD            (300) /* old usage of HZ here was erroneously and broke under uml */
/* Netgear Changes End */

/* Function which prints out usage message. */
static void
help(void)
{
	printf(
"psd v%s options:\n"
" --psd-weight-threshold threshhold  Portscan detection weight threshold\n\n"
" --psd-delay-threshold  delay       Portscan detection delay threshold\n\n"
" --psd-lo-ports-weight  lo          Privileged ports weight\n\n"
" --psd-hi-ports-weight  hi          High ports weight\n\n",
XTABLES_VERSION);
}

static struct option opts[] = {
	{ "psd-weight-threshold", 1, 0, '1' },
	{ "psd-delay-threshold", 1, 0, '2' },
	{ "psd-lo-ports-weight", 1, 0, '3' },
	{ "psd-hi-ports-weight", 1, 0, '4' },
	{ 0 }
};

/* Initialize the target. */
static void
init(struct xt_entry_match *m)
{
	struct ipt_psd_info *psdinfo = (struct ipt_psd_info *)m->data;

	psdinfo->weight_threshold = SCAN_WEIGHT_THRESHOLD;
	psdinfo->delay_threshold = SCAN_DELAY_THRESHOLD;
	psdinfo->lo_ports_weight = PORT_WEIGHT_PRIV;
	psdinfo->hi_ports_weight = PORT_WEIGHT_HIGH;
}

#define IPT_PSD_OPT_CTRESH 0x01
#define IPT_PSD_OPT_DTRESH 0x02
#define IPT_PSD_OPT_LPWEIGHT 0x04
#define IPT_PSD_OPT_HPWEIGHT 0x08

/* Function which parses command options; returns true if it
   ate an option */
static int
parse(int c, char **argv, int invert, unsigned int *flags,
                     const void *entry,
                     struct xt_entry_match **match)
{
	struct ipt_psd_info *psdinfo = (struct ipt_psd_info *)(*match)->data;
	unsigned int num;
	
	switch (c) {
	/* PSD-weight-threshold */
	case '1':
		if (*flags & IPT_PSD_OPT_CTRESH)
			xtables_error(PARAMETER_PROBLEM,
				   "Can't specify --psd-weight-threshold "
				   "twice");
                if (!xtables_strtoui(optarg, NULL, &num, 0, 10000))
                        xtables_error(PARAMETER_PROBLEM,
                                   "bad --psd-weight-threshold `%s'", optarg);
		psdinfo->weight_threshold = num;
		*flags |= IPT_PSD_OPT_CTRESH;
		break;

	/* PSD-delay-threshold */
	case '2':
		if (*flags & IPT_PSD_OPT_DTRESH)
			xtables_error(PARAMETER_PROBLEM,
				   "Can't specify --psd-delay-threshold twice");
                if (!xtables_strtoui(optarg, NULL, &num, 0, 10000))
                        xtables_error(PARAMETER_PROBLEM,
                                   "bad --psd-delay-threshold `%s'", optarg);
		psdinfo->delay_threshold = num;
		*flags |= IPT_PSD_OPT_DTRESH;
		break;

	/* PSD-lo-ports-weight */
	case '3':
		if (*flags & IPT_PSD_OPT_LPWEIGHT)
			xtables_error(PARAMETER_PROBLEM,
				   "Can't specify --psd-lo-ports-weight twice");
                if (!xtables_strtoui(optarg, NULL, &num, 0, 10000))
                        xtables_error(PARAMETER_PROBLEM,
                                   "bad --psd-lo-ports-weight `%s'", optarg);
		psdinfo->lo_ports_weight = num;
		*flags |= IPT_PSD_OPT_LPWEIGHT;
		break;

	/* PSD-hi-ports-weight */
	case '4':
		if (*flags & IPT_PSD_OPT_HPWEIGHT)
			xtables_error(PARAMETER_PROBLEM,
				   "Can't specify --psd-hi-ports-weight twice");
                if (!xtables_strtoui(optarg, NULL, &num, 0, 10000))
                        xtables_error(PARAMETER_PROBLEM,
                                   "bad --psd-hi-ports-weight `%s'", optarg);
		psdinfo->hi_ports_weight = num;
		*flags |= IPT_PSD_OPT_HPWEIGHT;
		break;

	default:
		return false;
	}
	return true;
}

/* Final check; nothing. */
static void final_check(unsigned int flags)
{
}

/* Prints out the targinfo. */
static void
print(const void *ip,
      const struct xt_entry_match *match,
      int numeric)
{
	const struct ipt_psd_info *psdinfo
		= (const struct ipt_psd_info *)match->data;

	printf("psd ");
	printf("weight-threshold: %u ", psdinfo->weight_threshold);
	printf("delay-threshold: %u ", psdinfo->delay_threshold);
	printf("lo-ports-weight: %u ", psdinfo->lo_ports_weight);
	printf("hi-ports-weight: %u ", psdinfo->hi_ports_weight);
}

/* Saves the union ipt_targinfo in parsable form to stdout. */
static void
save(const void *ip, const struct xt_entry_match *match)
{
	const struct ipt_psd_info *psdinfo
		= (const struct ipt_psd_info *)match->data;

	printf("--psd-weight-threshold %u ", psdinfo->weight_threshold);
	printf("--psd-delay-threshold %u ", psdinfo->delay_threshold);
	printf("--psd-lo-ports-weight %u ", psdinfo->lo_ports_weight);
	printf("--psd-hi-ports-weight %u ", psdinfo->hi_ports_weight);
}

static
struct xtables_match psd = {
	.next		= NULL,
	.name		= "psd",
	.version	= XTABLES_VERSION,
	.size		= XT_ALIGN(sizeof(struct ipt_psd_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct ipt_psd_info)),
	.help		= help,
	.init		= init,
	.parse		= parse,
	.final_check 	= final_check,
	.print		= print,
	.save		= save,
	.extra_opts	= opts
};

void _init(void)
{
	xtables_register_match(&psd);
}
