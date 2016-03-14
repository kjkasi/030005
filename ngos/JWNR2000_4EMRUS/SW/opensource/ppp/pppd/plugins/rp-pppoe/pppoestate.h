/* Done for Westell 9/8/2004 */

#ifndef _PPPOESTATE_H
#define _PPPOESTATE_H

#define PPPOE_SESSION_DIR	 "/WFIO/"
#define PPPOE_SESSION_PREFIX "ppp-"
#define PPPOE_SESSION_PREFIX_LEN 4
#define MAXSESSIONFILESIZE	256
/*Westell Add*/
#define MAXSESSIONLINESIZE	1024
/*Westell End*/

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

struct PPPoETagStruct;
/* Westell added - make ppp session ushort */
void create_pppoesessionfile(
            unsigned short sessionid, struct PPPoETagStruct *cookie,
            unsigned char myEth[ETH_ALEN], unsigned char peerEth[ETH_ALEN],
            long timenow, const char *link, const char *dev,
            struct PPPoETagStruct  *discoveredServiceName,
            struct PPPoETagStruct  *discoveredACName
);
void destroy_pppoesessionfile(const char *linkname);

#endif /* _PPPOESTATE_H */
