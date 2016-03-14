/* vi: set sw=4 ts=4: */
/*
 * Mini nslookup implementation for busybox
 *
 * Copyright (C) 1999,2000 by Lineo, inc. and John Beppu
 * Copyright (C) 1999,2000,2001 by John Beppu <beppu@codepoet.org>
 *
 * Correct default name server display and explicit name server option
 * added by Ben Zeckel <bzeckel@hmc.edu> June 2001
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 */

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/signal.h>
#include <unistd.h>

#include <stdint.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include <arpa/inet.h>
#include "busybox.h"

/*
 * Signal handler for SIGALRM
 */

static void noresp(int ign)
{
	printf("nslookup timed out\n");
	exit(EXIT_FAILURE);
}

/*
 |  I'm only implementing non-interactive mode;
 |  I totally forgot nslookup even had an interactive mode.
 */

/* only works for IPv4 */
static int addr_fprint(char *addr)
{
	uint8_t split[4];
	uint32_t ip;
	uint32_t *x = (uint32_t *) addr;

	ip = ntohl(*x);
	split[0] = (ip & 0xff000000) >> 24;
	split[1] = (ip & 0x00ff0000) >> 16;
	split[2] = (ip & 0x0000ff00) >> 8;
	split[3] = (ip & 0x000000ff);
	printf("%d.%d.%d.%d", split[0], split[1], split[2], split[3]);
	return 0;
}

/* only works for IPv4 */
static int addr_fsprint(char *addr, char *servIp)
{
	uint8_t split[4];
	uint32_t ip;
	uint32_t *x = (uint32_t *) addr;

	ip = ntohl(*x);
	split[0] = (ip & 0xff000000) >> 24;
	split[1] = (ip & 0x00ff0000) >> 16;
	split[2] = (ip & 0x0000ff00) >> 8;
	split[3] = (ip & 0x000000ff);
	sprintf(servIp, "%d.%d.%d.%d", split[0], split[1], split[2], split[3]);
	return 0;
}

/* takes the NULL-terminated array h_addr_list, and
 * prints its contents appropriately
 */
static int addr_list_fprint(char **h_addr_list)
{
	int i, j;
	char *addr_string = (h_addr_list[1])
		? "Addresses: " : "Address:   ";

	printf("%s ", addr_string);
	for (i = 0, j = 0; h_addr_list[i]; i++, j++) {
		addr_fprint(h_addr_list[i]);

		/* real nslookup does this */
		if (j == 4) {
			if (h_addr_list[i + 1]) {
				printf("\n          ");
			}
			j = 0;
		} else {
			if (h_addr_list[i + 1]) {
				printf(", ");
			}
		}

	}
	printf("\n");
	return 0;
}

/* print the results as nslookup would */
static struct hostent *hostent_fprint(struct hostent *host, const char *server_host)
{
	if (host) {
		printf("%s     %s\n", server_host, host->h_name);
		addr_list_fprint(host->h_addr_list);
	} else {
		printf("*** Unknown host\n");
	}
	return host;
}

/* changes a c-string matching the perl regex \d+\.\d+\.\d+\.\d+
 * into a uint32_t
 */
static uint32_t str_to_addr(const char *addr)
{
	uint32_t split[4];
	uint32_t ip;

	sscanf(addr, "%d.%d.%d.%d",
		   &split[0], &split[1], &split[2], &split[3]);

	/* assuming sscanf worked */
	ip = (split[0] << 24) |
		(split[1] << 16) | (split[2] << 8) | (split[3]);

	return htonl(ip);
}

/* gethostbyaddr wrapper */
static struct hostent *gethostbyaddr_wrapper(const char *address)
{
	struct in_addr addr;

	addr.s_addr = str_to_addr(address);
	return gethostbyaddr((char *) &addr, 4, AF_INET);	/* IPv4 only for now */
}

/* lookup the default nameserver and display it */
static inline void server_print(void)
{
	struct sockaddr_in def = _res.nsaddr_list[0];
	char *ip = inet_ntoa(def.sin_addr);

	hostent_fprint(gethostbyaddr_wrapper(ip), "Server:");
	printf("\n");
}

/* alter the global _res nameserver structure to use
   an explicit dns server instead of what is in /etc/resolv.h */
static inline void set_default_dns(char *server)
{
	struct in_addr server_in_addr;

	if(inet_aton(server,&server_in_addr))
	{
		_res.nscount = 1;
		_res.nsaddr_list[0].sin_addr = server_in_addr;
	}
}

/* If we get the name of the server then we have to resolve it using the default name server
  then call set_default_dns() so that we can use this server as the server for resolution  
*/
static inline void set_default_dns_name( struct hostent *host, const char *serv_name ){
      char servIp[20];
      host = xgethostbyname(serv_name);
	  if(host != NULL){
	       addr_fsprint(host->h_addr_list[0], servIp);
	       set_default_dns(servIp);
	  }
}

/* naive function to check whether char *s is an ip address */
static int is_ip_address(const char *s)
{
	/* Westell add start */
	unsigned int n1,n2,n3,n4;

	if(sscanf(s,"%u.%u.%u.%u", &n1, &n2, &n3, &n4) != 4) 
		return 0;

	if((n1 <= 255) && (n2 <= 255) && (n3 <= 255) && (n4 <= 255)) 
		return 1;
	
	return 0;
    /* Westell add end */

	/* commented by Westell */
	/*
	while (*s) {
		if ((isdigit(*s)) || (*s == '.')) {
			s++;
			continue;
		}
		return 0;
	}
	return 1;
	*/
}

/* Added by Westell for nslookup timeout */

/* Function to check whether char *s is a number 
 * We will never get negative values */

static int is_num(const char *s)
{
    while(*s)  
    {
         if(isdigit(*s))
         {
            s++;
            continue; 
         }
         return 0;            
    }
    return 1;
}

/* ________________________________________________________________________ */
int nslookup_main(int argc, char **argv)
{
	struct hostent *host;
    unsigned int timeout = 0;

	/* Set up Signal handler for SIGALRM */
	
	signal (SIGALRM, noresp);

	/*
	* initialize DNS structure _res used in printing the default
	* name server and in the explicit name server option feature.
	*/

	res_init();

	/*
	* We allow 1, 2 or 3 arguments.

	* The first is the name to be looked up. 
	* This can optionally be followed by a DNS Server with which 
	* to do the lookup and a Timeout value for the lookup OR only 
	* a Timeout value.

	* More than 4 arguments is an error to follow the pattern of 
	* the standard nslookup
	*/

	if (argc < 2 || *argv[1]=='-' || argc > 4)
		bb_show_usage();
	else if(argc == 3) {
		
	         if(is_num(argv[2])) /* can be timeout in seconds*/
             {
                   timeout = atoi(argv[2]);
				   /* Schedule an alarm after 'timeout' seconds as soon as we get the timeout */
                   alarm (timeout);
             } 	
             else if (is_ip_address(argv[2])) /* can be IP address of DNS server*/
			 {
		          set_default_dns(argv[2]);
		     } 
             else /* must be name of DNS server*/
			 {
                  set_default_dns_name(host, argv[2]);
 		     }
		
	}
    else if(argc == 4)
	{
        
        timeout = atoi(argv[3]);  /* must be timeout in seconds */
		/* Schedule an alarm after 'timeout' seconds as soon as we get the timeout */
        alarm (timeout);

		if (is_ip_address(argv[2])) 
		{
		     set_default_dns(argv[2]);
		} 
		else 
		{
             set_default_dns_name(host, argv[2]);
		}
		
	}
        
	server_print();
	if (is_ip_address(argv[1])) {
		host = gethostbyaddr_wrapper(argv[1]);
	} else {
		host = xgethostbyname(argv[1]);
	}
	hostent_fprint(host, "Name:  ");
	
	printf("Timeout:     %d\n", (_res.retrans)*(_res.retry));
	printf("Authoritative: %s\n", "Yes");
	
    if (host) {
		return EXIT_SUCCESS;
	}
	return EXIT_FAILURE;
}

/* $Id: nslookup.c,v 1.33 2004/10/13 07:25:01 andersen Exp $ */
