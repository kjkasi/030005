/***********************************************************************
 *
 * plugin.c
 *
 * pppd plugin for kernel-mode PPPoE on Linux
 *
 * Copyright (C) 2001 by Roaring Penguin Software Inc., Michal Ostrowski
 * and Jamal Hadi Salim.
 *
 * Much code and many ideas derived from pppoe plugin by Michal
 * Ostrowski and Jamal Hadi Salim, which carries this copyright:
 *
 * Copyright 2000 Michal Ostrowski <mostrows@styx.uwaterloo.ca>,
 *                Jamal Hadi Salim <hadi@cyberus.ca>
 * Borrows heavily from the PPPoATM plugin by Mitchell Blank Jr.,
 * which is based in part on work from Jens Axboe and Paul Mackerras.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 ***********************************************************************/

static char const RCSID[] =
"$Id: plugin.c,v 1.12 2004/11/04 10:07:37 paulus Exp $";

#define _GNU_SOURCE 1
#include "pppoe.h"

#include "pppd/pppd.h"
#include "pppd/fsm.h"
#include "pppd/lcp.h"
#include "pppd/ipcp.h"
#include "pppd/ccp.h"
#include "pppd/pathnames.h"

#include <linux/types.h>
#include <syslog.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include "ppp_defs.h"
#include "if_ppp.h"
#include "if_pppox.h"

#define _PATH_ETHOPT         _ROOT_PATH "/etc/ppp/options."

char pppd_version[] = VERSION;

/* From sys-linux.c in pppd -- MUST FIX THIS! */
extern int new_style_driver;

char *pppd_pppoe_service = NULL;
static char *acName = NULL;
static char *existingSession = NULL;
static int printACNames = 0;

static int PPPoEDevnameHook(char *cmd, char **argv, int doit);
static option_t Options[] = {
    { "device name", o_wild, (void *) &PPPoEDevnameHook,
      "PPPoE device name",
      OPT_DEVNAM | OPT_PRIVFIX | OPT_NOARG  | OPT_A2STRVAL | OPT_STATIC,
      devnam},
    { "rp_pppoe_service", o_string, &pppd_pppoe_service,
      "Desired PPPoE service name" },
    { "rp_pppoe_ac",      o_string, &acName,
      "Desired PPPoE access concentrator name" },
    { "rp_pppoe_sess",    o_string, &existingSession,
      "Attach to existing session (sessid:macaddr)" },
    { "rp_pppoe_verbose", o_int, &printACNames,
      "Be verbose about discovered access concentrators"},
    { NULL }
};
static PPPoEConnection *conn = NULL;


/* Begin Westell */
#include <sys/sysinfo.h>

/* Set WSTL_VERBOSE_DEBUG to track pppoe session file transitions. */
#define WSTL_VERBOSE_DEBUG 0

#include "pppoestate.h"

static void terminate_pppoe(void *opaque, int arg);

static void do_create_pppoesessionfile(int connected)
{
    int theunit;
    struct sysinfo info;

    sysinfo(&info);
        
    if (!demand && !connected) {
        /* We don't actually own a ppp interface yet. */
    } else {
        create_pppoesessionfile(ppp_session_number, 
                                &conn->cookie,
                                conn->myEth,
                                conn->peerEth,
                                info.uptime,
                                linkname,
                                devnam,
								&conn->discoveredServiceName, 
								&conn->discoveredACName);
    }
}
/* End Westell */

/**********************************************************************
 * %FUNCTION: PPPOEInitDevice
 * %ARGUMENTS:
 * None
 * %RETURNS:
 *
 * %DESCRIPTION:
 * Initializes PPPoE device.
 ***********************************************************************/
static int
PPPOEInitDevice(void)
{
/* Westell Start */
    if (!conn) {
/* Westell End */
    	conn = malloc(sizeof(PPPoEConnection));
/* Westell Start */
    }
/* Westell End */
    if (!conn) {
	fatal("Could not allocate memory for PPPoE session");
    }
    memset(conn, 0, sizeof(PPPoEConnection));
    if (acName) {
	SET_STRING(conn->acName, acName);
    }
    if (pppd_pppoe_service) {
	SET_STRING(conn->serviceName, pppd_pppoe_service);
    }
    SET_STRING(conn->ifName, devnam);
    conn->discoverySocket = -1;
    conn->sessionSocket = -1;
    conn->useHostUniq = 1;
    conn->printACNames = printACNames;

/* Begin Westell */
#if WSTL_VERBOSE_DEBUG
    error("PPPOEInitDevice resetting session file");
#endif
    do_create_pppoesessionfile(0);
/* End Westell */

    return 1;
}

/**********************************************************************
 * %FUNCTION: PPPOEConnectDevice
 * %ARGUMENTS:
 * None
 * %RETURNS:
 * Non-negative if all goes well; -1 otherwise
 * %DESCRIPTION:
 * Connects PPPoE device.
 ***********************************************************************/
static int
PPPOEConnectDevice(void)
{
    /* Westell Start */
    int dres;
    /* Westell End */
    struct sockaddr_pppox sp;

    strlcpy(ppp_devnam, devnam, sizeof(ppp_devnam));

    /* Begin Westell */
#if WSTL_VERBOSE_DEBUG
    error("PPPOEConnectDevice resetting session file");
#endif
    do_create_pppoesessionfile(0);
    conn->discoveryState = 0; /* NETGEAR - clear discovery state as discovery() may not set it */
    /* End Westell */

    if (existingSession) {
	unsigned int mac[ETH_ALEN];
	int i, ses;
	if (sscanf(existingSession, "%d:%x:%x:%x:%x:%x:%x",
		   &ses, &mac[0], &mac[1], &mac[2],
		   &mac[3], &mac[4], &mac[5]) != 7) {
	    fatal("Illegal value for rp_pppoe_sess option");
	}
	conn->session = htons(ses);
	for (i=0; i<ETH_ALEN; i++) {
	    conn->peerEth[i] = (unsigned char) mac[i];
	}
    } else {
/* Westell Start added number of retries */
        signal_during_discovery = 0; /* Clear indication of signal received in discovery() */
	dres = discovery(conn, 0);
/* Westell End */
	if (conn->discoveryState != STATE_SESSION) {
	    error("Unable to complete PPPoE Discovery");
            /* Westell Start */
            switch(dres) {
		default:
                    break;
        case PPPOE_USER_REQUEST:
                    signal_during_discovery = 1; /* Set indication of signal received in discovery() based on return code */
                    break;
		case PPPOE_TIMEOUT_PADO:
                    status = EXIT_PPPOE_TIMEOUT_PADO;
                    break;
		case PPPOE_TIMEOUT_PADS:
                    status = EXIT_PPPOE_TIMEOUT_PADS;
                    break;
#ifdef BUILD_ERT_SPECIFIC
		case PPPOE_INVALID_ACNAME:
                    status = EXIT_PPPOE_INVALID_ACNAME;
                    break;
#endif
            }
            /* Westell End */
	    return -1;
	}
    }

    /* Set PPPoE session-number for further consumption */
    ppp_session_number = ntohs(conn->session);

    /* Make the session socket */
    conn->sessionSocket = socket(AF_PPPOX, SOCK_STREAM, PX_PROTO_OE);
    if (conn->sessionSocket < 0) {
        fatal("Failed to create PPPoE socket: %m");
/* Westell Start */
        status = EXIT_PPPOE_BAD_ETH_SOCKET;
/* Westell End */
/* Westell start 8/12/2004 */
        return -1;
/* Westell end 8/12/2004 */
    }
    sp.sa_family = AF_PPPOX;
    sp.sa_protocol = PX_PROTO_OE;
    sp.sa_addr.pppoe.sid = conn->session;
    memcpy(sp.sa_addr.pppoe.dev, conn->ifName, IFNAMSIZ);
    memcpy(sp.sa_addr.pppoe.remote, conn->peerEth, ETH_ALEN);

    /* Set remote_number for ServPoET */
    sprintf(remote_number, "%02X:%02X:%02X:%02X:%02X:%02X",
	    (unsigned) conn->peerEth[0],
	    (unsigned) conn->peerEth[1],
	    (unsigned) conn->peerEth[2],
	    (unsigned) conn->peerEth[3],
	    (unsigned) conn->peerEth[4],
	    (unsigned) conn->peerEth[5]);

    if (connect(conn->sessionSocket, (struct sockaddr *) &sp,
		sizeof(struct sockaddr_pppox)) < 0) {
	fatal("Failed to connect PPPoE socket: %m");
	return -1;
    }

    /* Begin Westell */
#if WSTL_VERBOSE_DEBUG
    error("PPPOEConnectDevice filling session file");
#endif
    do_create_pppoesessionfile(1);
    /* End Westell */
    return conn->sessionSocket;
}

/* Begin Westell */
void
PPPOECleanup(void)
{
#if WSTL_VERBOSE_DEBUG
    error("PPPOECleanup destroying session file");
#endif
    //destroy_pppoesessionfile(linkname);
}
/* End Westell */

static void
PPPOESendConfig(int mtu,
		u_int32_t asyncmap,
		int pcomp,
		int accomp)
{
    int sock;
    struct ifreq ifr;

    if (mtu > MAX_PPPOE_MTU) {
        warn("Couldn't increase MTU to %d", mtu);
	mtu = MAX_PPPOE_MTU;
    }

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
	error("Couldn't create IP socket: %m");
	return;
    }
    strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
    ifr.ifr_mtu = mtu;
    if (ioctl(sock, SIOCSIFMTU, &ifr) < 0) {
	error("Couldn't set interface MTU to %d: %m", mtu);
        (void) close (sock); /* Westell added 8/12/2004 */
	return;
    }
    (void) close (sock);
}


static void
PPPOERecvConfig(int mru,
		u_int32_t asyncmap,
		int pcomp,
		int accomp)
{
    if (mru > MAX_PPPOE_MTU) {
        warn("Couldn't increase MRU to %d", mru);
    }
}

/**********************************************************************
 * %FUNCTION: PPPOEDisconnectDevice
 * %ARGUMENTS:
 * None
 * %RETURNS:
 * Nothing
 * %DESCRIPTION:
 * Disconnects PPPoE device
 ***********************************************************************/
static void
PPPOEDisconnectDevice(void)
{
    struct sockaddr_pppox sp;

    sp.sa_family = AF_PPPOX;
    sp.sa_protocol = PX_PROTO_OE;
    sp.sa_addr.pppoe.sid = 0;
    memcpy(sp.sa_addr.pppoe.dev, conn->ifName, IFNAMSIZ);
    memcpy(sp.sa_addr.pppoe.remote, conn->peerEth, ETH_ALEN);
    if (connect(conn->sessionSocket, (struct sockaddr *) &sp,
		sizeof(struct sockaddr_pppox)) < 0) {
	fatal("Failed to disconnect PPPoE socket: %d %m", errno);
#if 0 /* Westell Start - cleanup open sockets anyway! */
	return;
#endif /* Westell End */
    }
    /* Westell Start */
    if (conn->sessionSocket != -1) {
	/* Westell End */
    	close(conn->sessionSocket);
	/* Westell Start */
    	conn->sessionSocket = -1;
    }
    /* Westell End */
    /* don't send PADT?? */
    /* Westell Start */
    if (conn->discoverySocket != -1) {
	/* Westell End */
        close(conn->discoverySocket);
	/* Westell Start */
        conn->discoverySocket = -1;
    }
    /* Westell End */
}

static void
PPPOEDeviceOptions(void)
{
    char buf[256];
    snprintf(buf, 256, _PATH_ETHOPT "%s",devnam);
    if(!options_from_file(buf, 0, 0, 1))
	exit(EXIT_OPTION_ERROR);

}

struct channel pppoe_channel;

/**********************************************************************
 * %FUNCTION: PPPoEDevnameHook
 * %ARGUMENTS:
 * cmd -- the command (actually, the device name
 * argv -- argument vector
 * doit -- if non-zero, set device name.  Otherwise, just check if possible
 * %RETURNS:
 * 1 if we will handle this device; 0 otherwise.
 * %DESCRIPTION:
 * Checks if name is a valid interface name; if so, returns 1.  Also
 * sets up devnam (string representation of device).
 ***********************************************************************/
static int
PPPoEDevnameHook(char *cmd, char **argv, int doit)
{
    int r = 1;
    int fd;
    struct ifreq ifr;

    /* Only do it if name is "ethXXX", "nasXXX", "tapXXX" or "nic-XXXX.
       In latter case strip off the "nic-" */
    /* Thanks to Russ Couturier for this fix */
    if (strlen(cmd) > 4 && !strncmp(cmd, "nic-", 4)) {
	/* Strip off "nic-" */
	cmd += 4;
    } else if (strlen(cmd) < 4
/*NetGear change start*/
               || (strncmp(cmd, "eth", 3) && strncmp(cmd, "nas", 3) && strncmp(cmd, "ptm", 3)
/*NetGear change end*/
                   && strncmp(cmd, "tap", 3) &&  strncmp(cmd, "br", 2))) {
	return 0;
    }

    /* Open a socket */
    if ((fd = socket(PF_PACKET, SOCK_RAW, 0)) < 0) {
	r = 0;
    }

    /* Try getting interface index */
    if (r) {
	strncpy(ifr.ifr_name, cmd, sizeof(ifr.ifr_name));
	if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
	    r = 0;
	} else {
	    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
		r = 0;
	    } else {
		if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
		    error("Interface %s not Ethernet", cmd);
		    r=0;
		}
	    }
	}
    }

    /* Close socket */
    close(fd);
    if (r) {
	strncpy(devnam, cmd, sizeof(devnam));
	if (the_channel != &pppoe_channel) {

	    the_channel = &pppoe_channel;
	    modem = 0;

	    lcp_allowoptions[0].neg_accompression = 0;
	    lcp_wantoptions[0].neg_accompression = 0;

	    lcp_allowoptions[0].neg_asyncmap = 0;
	    lcp_wantoptions[0].neg_asyncmap = 0;

	    lcp_allowoptions[0].neg_pcompression = 0;
	    lcp_wantoptions[0].neg_pcompression = 0;

#if HAVE_CCP /* Westell */
	    ccp_allowoptions[0].deflate = 0 ;
	    ccp_wantoptions[0].deflate = 0 ;
#endif

	    ipcp_allowoptions[0].neg_vj=0;
	    ipcp_wantoptions[0].neg_vj=0;

#if HAVE_CCP /* Westell */
	    ccp_allowoptions[0].bsd_compress = 0;
	    ccp_wantoptions[0].bsd_compress = 0;
#endif

	    PPPOEInitDevice();
    }
	return 1;
    }

    return r;
}

/*Westell added -- start*/
/**********************************************************************
 * %FUNCTION: terminate_pppoe
 * %ARGUMENTS:
 * opaque - Not Used, arg - Not Used
 * %RETURNS:
 * Nothing
 * %DESCRIPTION:
 * Send PADT
 ***********************************************************************/
static void terminate_pppoe(void *opaque, int arg)
{
    char msg[512];
    sprintf (msg, "RP-PPPoE: %.256s", "Termination from client requested");
    msg[511] = 0;
    sendPADT(conn, msg);
}
/*Westell added -- end*/

/**********************************************************************
 * %FUNCTION: plugin_init
 * %ARGUMENTS:
 * None
 * %RETURNS:
 * Nothing
 * %DESCRIPTION:
 * Initializes hooks for pppd plugin
 ***********************************************************************/
void
plugin_init(void)
{
    if (!ppp_available() && !new_style_driver) {
	fatal("Linux kernel does not support PPPoE -- are you running 2.4.x?");
    }

    add_options(Options);
/*Westell added -- start*/
    add_notifier(&lcp_close_notifier, terminate_pppoe, 0);
/*Westell added -- end*/

    info("RP-PPPoE plugin version %s compiled against pppd %s",
	 RP_VERSION, VERSION);
}

/**********************************************************************
 *%FUNCTION: fatalSys
 *%ARGUMENTS:
 * str -- error message
 *%RETURNS:
 * Nothing
 *%DESCRIPTION:
 * Prints a message plus the errno value to stderr and syslog and exits.
 ***********************************************************************/
void
fatalSys(char const *str)
{
    char buf[1024];
    int i = errno;
    sprintf(buf, "%.256s: %.256s", str, strerror(i));
    printErr(buf);
    sprintf(buf, "RP-PPPoE: %.256s: %.256s", str, strerror(i));
    sendPADT(conn, buf);
    exit(1);
}

/**********************************************************************
 *%FUNCTION: rp_fatal
 *%ARGUMENTS:
 * str -- error message
 *%RETURNS:
 * Nothing
 *%DESCRIPTION:
 * Prints a message to stderr and syslog and exits.
 ***********************************************************************/
void
rp_fatal(char const *str)
{
    char buf[1024];
    printErr(str);
    sprintf(buf, "RP-PPPoE: %.256s", str);
    sendPADT(conn, buf);
    exit(1);
}
/**********************************************************************
 *%FUNCTION: sysErr
 *%ARGUMENTS:
 * str -- error message
 *%RETURNS:
 * Nothing
 *%DESCRIPTION:
 * Prints a message plus the errno value to syslog.
 ***********************************************************************/
void
sysErr(char const *str)
{
    rp_fatal(str);
}


struct channel pppoe_channel = {
    options: Options,
    process_extra_options: &PPPOEDeviceOptions,
    check_options: NULL,
    connect: &PPPOEConnectDevice,
    disconnect: &PPPOEDisconnectDevice,
    establish_ppp: &generic_establish_ppp,
    disestablish_ppp: &generic_disestablish_ppp,
    send_config: &PPPOESendConfig,
    recv_config: &PPPOERecvConfig,
    close: NULL,
/* Westell Start */
    cleanup: &PPPOECleanup
/* Westell End */
};
