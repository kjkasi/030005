/* Done for Westell 9/8/2004 */
#include "pppoe.h"
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <syslog.h>

#define PPPOE_STATE_DEBUG 1

#if !defined(PPP_DRV_NAME)
#define PPP_DRV_NAME       "ppp"
#endif /* !defined(PPP_DRV_NAME) */

#include "pppoestate.h"

static volatile int do_destroy = 0;

static int destructors_installed = 0;

static void
atexit_destroy_pppoesessionfile(void)
{
	extern char *linkname;
	extern int kill_link;

	if (kill_link && linkname && linkname[0]) {
		destroy_pppoesessionfile(linkname);
	}
}

/*
 * Create a file named with the unit containing the session id 
 * and a timestamp (timenow)
 */
/* Westell added and removed the old create_pppoesessionfile file request*/
/***************************   Westell Start *********************************************/
void create_pppoesessionfile(unsigned short sessionid, 
		struct PPPoETagStruct *cookie,
		unsigned char myEth[ETH_ALEN], 
		unsigned char peerEth[ETH_ALEN],
		long timenow, 
		const char *linkname, 
		const char *dev,
		struct PPPoETagStruct *discoveredServiceName,
		struct PPPoETagStruct *discoveredACName)
{
	FILE *fp;
	char sfname[MAXSESSIONFILESIZE];
	char buffer[MAXSESSIONLINESIZE];//MaxLine size in net_mgr is 1024
	PPPoETag fake;
	fake.length = 0;
	fake.type = 0;
	
	if (linkname == NULL || linkname[0] == 0) {
		warn("Cannot create PPPoE session file for empty linkname.");
		return;
	}

    slprintf(sfname, sizeof(sfname), "%s%s-%s",
			PPPOE_SESSION_DIR, PPP_DRV_NAME, linkname);

#if PPPOE_STATE_DEBUG
	/* Westell added - make ppp session %u */
	warn("Creating PPPoE session file: %s:"
			" %ld %u %s"
			" %02x:%02x:%02x:%02x:%02x:%02x",
			sfname, 
			timenow, sessionid, dev,
			peerEth[0], peerEth[1], peerEth[2],
			peerEth[3], peerEth[4], peerEth[5]);
#endif
	if ((fp = fopen(sfname, "w")) != NULL) {
		do_destroy = 1;
		if (!destructors_installed) {
			atexit(atexit_destroy_pppoesessionfile);
			destructors_installed = 1;
		}
		/* Westell added - make ppp session %u */
		fprintf(fp,"VER=[1]\n");
		sprintf(buffer,"timenow=%ld\n",timenow);
		fprintf(fp,"%s",buffer);
		sprintf(buffer,"sessionid=%u\n",sessionid);
		fprintf(fp,"%s",buffer);
		sprintf(buffer,"dev=%s\n",dev);
		fprintf(fp,"%s",buffer);

		sprintf(buffer,"myEth=%02x%02x%02x%02x%02x%02x\n", myEth[0],myEth[1],myEth[2],myEth[3],myEth[4],myEth[5]);
		fprintf(fp,"%s",buffer);
		sprintf(buffer,"peerEth=%02x%02x%02x%02x%02x%02x\n", peerEth[0],peerEth[1],peerEth[2],peerEth[3],peerEth[4],peerEth[5]);
		fprintf(fp,"%s",buffer);

		if (cookie == NULL || cookie->type == 0) {
			cookie = &fake;
		}
		sprintf(buffer, "discoveredServiceName=%s\n", discoveredServiceName->payload);
		fprintf(fp,"%s",buffer);

		sprintf(buffer, "discoveredACName=%s\n", discoveredACName->payload);
		fprintf(fp,"%s",buffer);

		sprintf(buffer,"Cookie=");
		int i=0,len=0;
		len=strlen(buffer);
		for(i=0;i<strlen(cookie->payload);i++){
			sprintf(buffer+len+(i*2),"%02x",cookie->payload[i]);
		}
		fprintf(fp,"%s\n",buffer);
		(void) fclose(fp);
	} else {
		error("Failed to create session file %s: %m", sfname, errno);
	}
}
/***************************   Westell End  *********************************************/
#if 0

/*
 * Create a file named with the unit containing the session id 
 * and a timestamp (timenow)
 */
/* Westell added - make ppp session ushort */
void
create_pppoesessionfile(unsigned short sessionid, 
                        struct PPPoETagStruct *cookie,
                        unsigned char myEth[ETH_ALEN], 
                        unsigned char peerEth[ETH_ALEN],
                        long timenow, 
                        const char *linkname, 
                        const char *dev)
{
    FILE *fp;
    char sfname[MAXSESSIONFILESIZE];
	PPPoETag fake;
	fake.length = 0;
	fake.type = 0;

	if (linkname == NULL || linkname[0] == 0) {
		warn("Cannot create PPPoE session file for empty linkname.");
		return;
	}

    slprintf(sfname, sizeof(sfname), "%s%s-%s",
             PPPOE_SESSION_DIR, PPP_DRV_NAME, linkname);

#if PPPOE_STATE_DEBUG
/* Westell added - make ppp session %u */
	warn("Creating PPPoE session file: %s:"
                        " %ld %u %s"
						" %02x:%02x:%02x:%02x:%02x:%02x",
						sfname, 
                        timenow, sessionid, dev,
						peerEth[0], peerEth[1], peerEth[2],
						peerEth[3], peerEth[4], peerEth[5]);
#endif
    if ((fp = fopen(sfname, "w")) != NULL) {
		do_destroy = 1;
		if (!destructors_installed) {
			atexit(atexit_destroy_pppoesessionfile);
			destructors_installed = 1;
		}
/* Westell added - make ppp session %u */
        fprintf(fp, "%ld %u %s\n",
                timenow, sessionid, dev);
        fwrite(myEth, ETH_ALEN, 1, fp);
        fwrite(peerEth, ETH_ALEN, 1, fp);
        if (cookie == NULL || cookie->type == 0) {
            cookie = &fake;
        }
        fwrite(cookie, ntohs(cookie->length) + TAG_HDR_SIZE, 1, fp);
        (void) fclose(fp);
    } else {
        error("Failed to create session file %s: %m", sfname, errno);
    }
}

#endif
/*
 * Destroy the file named with unit
 */
void
destroy_pppoesessionfile(const char *linkname)
{
    char sfname[MAXSESSIONFILESIZE];

#if PPPOE_STATE_DEBUG
	warn("Enter destroy_pppoesessionfile");
#endif
    slprintf(sfname, sizeof(sfname), "%s%s-%s",
             PPPOE_SESSION_DIR, PPP_DRV_NAME, linkname);

#if PPPOE_STATE_DEBUG
	syslog(LOG_ERR, "Unlinking PPPoE session file: %s", sfname);
#endif
    unlink(sfname);

#if PPPOE_STATE_DEBUG
	warn("Leaving destroy_pppoesessionfile");
#endif
}

