/*
 * Perform PPPoE discovery
 *
 * Copyright (C) 2000-2001 by Roaring Penguin Software Inc.
 * Copyright (C) 2004 Marco d'Itri <md@linux.it>
 *
 * This program may be distributed according to the terms of the GNU
 * General Public License, version 2 or (at your option) any later version.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "pppoe.h"

char *xstrdup(const char *s);
void usage(void);

void die(int status)
{
	exit(status);
}

int main(int argc, char *argv[])
{
	int result;
    int opt;
    int number_of_retries = 0;
    PPPoEConnection *conn;

    conn = malloc(sizeof(PPPoEConnection));
    if (!conn)
	fatalSys("malloc");

    memset(conn, 0, sizeof(PPPoEConnection));

    while ((opt = getopt(argc, argv, "I:N:D:VUAS:C:h")) > 0) {
	switch(opt) {
	case 'S':
	    conn->serviceName = xstrdup(optarg);
	    break;
	case 'C':
	    conn->acName = xstrdup(optarg);
	    break;
	case 'U':
	    conn->useHostUniq = 1;
	    break;
	case 'D':
	    conn->debugFile = fopen(optarg, "w");
	    if (!conn->debugFile) {
		fprintf(stderr, "Could not open %s: %s\n",
			optarg, strerror(errno));
		exit(1);
	    }
	    fprintf(conn->debugFile, "pppoe-discovery %s\n", VERSION);
	    break;
    case 'I':
	    conn->ifName = xstrdup(optarg);
	    break;
    case 'N':
        number_of_retries = atoi(optarg);
	    break;
	case 'A':
	    /* this is the default */
	    break;
	case 'V':
	case 'h':
	    usage();
	    exit(0);
	default:
	    usage();
	    exit(1);
	}
    }

    /* default interface name */
    if (!conn->ifName)
	conn->ifName = strdup("eth0");

    conn->discoverySocket = -1;
    conn->sessionSocket = -1;
    conn->printACNames = 1;

	/* Westell start - added error propogation */
    result = discovery(conn, number_of_retries);
	return (result != PPPOE_OK);
	/* Westell end */
}

void rp_fatal(char const *str)
{
    char buf[1024];

    sprintf(buf, "pppoe-discovery: %.256s", str);
    printErr(str);
    exit(1);
}

/* Westell Start */
void warn(char const *str)
{
    char buf[1024];

    sprintf(buf, "pppoe-discovery: %.256s", str);
	printErr(str);
}
/* Westell End */

void fatalSys(char const *str)
{
    char buf[1024];
    int i = errno;

    sprintf(buf, "%.256s: %.256s", str, strerror(i));
    printErr(buf);
    sprintf(buf, "pppoe-discovery: %.256s: %.256s", str, strerror(i));
    exit(1);
}

void sysErr(char const *str)
{
    rp_fatal(str);
}

char *xstrdup(const char *s)
{
    register char *ret = strdup(s);
    if (!ret)
	sysErr("strdup");
    return ret;
}

void usage(void)
{
    fprintf(stderr, "Usage: pppoe-discovery [options]\n");
    fprintf(stderr, "\nVersion " VERSION "\n");
}
