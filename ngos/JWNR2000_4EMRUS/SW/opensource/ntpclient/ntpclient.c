/*
 * ntpclient.c - NTP client
 *
 * Copyright 1997, 1999, 2000, 2003  Larry Doolittle  <larry@doolittle.boa.org>
 * Last hack: July 5, 2003
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License (Version 2,
 *  June 1991) as published by the Free Software Foundation.  At the
 *  time of writing, that license was published by the FSF with the URL
 *  http://www.gnu.org/copyleft/gpl.html, and is incorporated herein by
 *  reference.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  Possible future improvements:
 *      - Double check that the originate timestamp in the received packet
 *        corresponds to what we sent.
 *      - Verify that the return packet came from the host we think
 *        we're talking to.  Not necessarily useful since UDP packets
 *        are so easy to forge.
 *      - Write more documentation  :-(
 *
 *  Compile with -D_PRECISION_SIOCGSTAMP if your machine really has it.
 *  There are patches floating around to add this to Linux, but
 *  usually you only get an answer to the nearest jiffy.
 *  Hint for Linux hacker wannabes: look at the usage of get_fast_time()
 *  in net/core/dev.c, and its definition in kernel/time.c .
 *
 *  If the compile gives you any flak, check below in the section
 *  labelled "XXXX fixme - non-automatic build configuration".
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>     /* gethostbyname */
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#ifdef _PRECISION_SIOCGSTAMP
#include <sys/ioctl.h>
#endif

#define ENABLE_DEBUG

extern char *optarg;

/* XXXX fixme - non-automatic build configuration */
#ifdef linux
#include <sys/utsname.h>
#include <sys/time.h>
typedef u_int32_t __u32;
#include <sys/timex.h>
#else
extern struct hostent *gethostbyname(const char *name);
extern int h_errno;
#define herror(hostname) \
	fprintf(stderr,"Error %d looking up hostname %s\n", h_errno,hostname)
typedef uint32_t __u32;
#endif

#define JAN_1970        0x83aa7e80      /* 2208988800 1970 - 1900 in seconds */
#define NTP_PORT (123)

/* How to multiply by 4294.967296 quickly (and not quite exactly)
 * without using floating point or greater than 32-bit integers.
 * If you want to fix the last 12 microseconds of error, add in
 * (2911*(x))>>28)
 */
#define NTPFRAC(x) ( 4294*(x) + ( (1981*(x))>>11 ) )

/* The reverse of the above, needed if we want to set our microsecond
 * clock (via settimeofday) based on the incoming time in NTP format.
 * Basically exact.
 */
#define USEC(x) ( ( (x) >> 12 ) - 759 * ( ( ( (x) >> 10 ) + 32768 ) >> 16 ) )

/* Converts NTP delay and dispersion, apparently in seconds scaled
 * by 65536, to microseconds.  RFC1305 states this time is in seconds,
 * doesn't mention the scaling.
 * Should somehow be the same as 1000000 * x / 65536
 */
#define sec2u(x) ( (x) * 15.2587890625 )

struct ntptime {
	unsigned int coarse;
	unsigned int fine;
};

/* prototype for function defined in phaselock.c */
int contemplate_data(unsigned int absolute, double skew, double errorbar, int freq);

/* prototypes for some local routines */
void send_packet(int usd);
int rfc1305print(uint32_t *data, struct ntptime *arrival);
void udp_handle(int usd, char *data, int data_len, struct sockaddr *sa_source, int sa_len);

/* variables with file scope
 * (I know, bad form, but this is a short program) */
static uint32_t incoming_word[325];
#define incoming ((char *) incoming_word)
#define sizeof_incoming (sizeof(incoming_word)*sizeof(uint32_t))
static struct timeval time_of_send;
static int live=0;
static int set_clock=0;   /* non-zero presumably needs root privs */
/*Westell added */
#define EXPON_FACTOR 2    /*exponential factor for the backoff function after loop fails to get NTP servers*/
#define NTP_SERV_LOOPS 1       /*Number of times we need to check  NTP servers before backing off*/
/*If we have no values supplied then use default values in secs.*/
#define DEF_BACKOFFMIN_VAL 5
#define DEF_BACKOFFMAX_VAL 60

static int counter;
static int min_val = DEF_BACKOFFMIN_VAL;    
static int max_val = DEF_BACKOFFMAX_VAL;

/*File to communicate the  status of NTP Server Status to cwmpd*/
#define NTPCLIENT_FILE "/var/etc/ntpclient"
/*enum of NTP State to be written to the File. Better to write integer instead of whole string.*/
typedef enum {Unsynchronized = 1, Synchronized, Error_FailedToSynchronize} NTPState;  
static void update_ntpstate( NTPState );   
/*Westell added */

/* Netgeart Changes Starts Here */
#define EXEC_SCRIPT_SIZE 256
static char executeScript[EXEC_SCRIPT_SIZE] = {0};
/* Netgeart Changes Ends Here */

/* when present, debug is a true global, shared with phaselock.c */
#ifdef ENABLE_DEBUG
int debug=0;
#define DEBUG_OPTION "d"
#else
#define debug 0
#define DEBUG_OPTION
#endif

int get_current_freq(void)
{
	/* OS dependent routine to get the current value of clock frequency.
	 */
#ifdef linux
	struct timex txc;
	txc.modes=0;
        //__adjtimex changed to adjtimex
	if (adjtimex(&txc) < 0) {
		perror("adjtimex");
		syslog(LOG_ERR, "__adjtimex Failure, Bailing");
                /*
                 when exiting update the status as failed to Synchronize,
                 as we do not know how long the client has been down, we would have to assume at this point                           that we do not have the every X minute sync up to date, so therefore our time is not accura                          te
                */
              
                update_ntpstate(Error_FailedToSynchronize);   
		exit(1);
	}
	return txc.freq;
#else
	return 0;
#endif
}

int set_freq(int new_freq)
{
	/* OS dependent routine to set a new value of clock frequency.
	 */
#ifdef linux
	struct timex txc;
	txc.modes = ADJ_FREQUENCY;
	txc.freq = new_freq;
        //__adjtimex changed to adjtimex
	if (adjtimex(&txc) < 0) {
		perror("adjtimex");
		syslog(LOG_ERR, "__adjtimex Failure, Bailing");
                /*
                 when exiting update the status as failed to Synchronize,
                 as we do not know how long the client has been down, we would have to assume at this point                           that we do not have the every X minute sync up to date, so therefore our time is not accura                          te*/
                update_ntpstate(Error_FailedToSynchronize);   
		exit(1);
	}
	return txc.freq;
#else
	return 0;
#endif
}

void send_packet(int usd)
{
	__u32 data[12];
	struct timeval now;
#define LI 0
#define VN 3
#define MODE 3
#define STRATUM 0
#define POLL 4 
#define PREC -6

	if (debug) fprintf(stderr,"Sending ...\n");
	if (sizeof(data) != 48) {
		fprintf(stderr,"size error\n");
		return;
	}
	bzero((char *) data,sizeof(data));
	data[0] = htonl (
		( LI << 30 ) | ( VN << 27 ) | ( MODE << 24 ) |
		( STRATUM << 16) | ( POLL << 8 ) | ( PREC & 0xff ) );
	data[1] = htonl(1<<16);  /* Root Delay (seconds) */
	data[2] = htonl(1<<16);  /* Root Dispersion (seconds) */
	gettimeofday(&now,NULL);
	data[10] = htonl(now.tv_sec + JAN_1970); /* Transmit Timestamp coarse */
	data[11] = htonl(NTPFRAC(now.tv_usec));  /* Transmit Timestamp fine   */
	send(usd,data,48,0);
	time_of_send=now;
}

void get_packet_timestamp(int usd, struct ntptime *udp_arrival_ntp)
{
	struct timeval udp_arrival;
#ifdef _PRECISION_SIOCGSTAMP
	if ( ioctl(usd, SIOCGSTAMP, &udp_arrival) < 0 ) {
		perror("ioctl-SIOCGSTAMP");
		gettimeofday(&udp_arrival,NULL);
	}
#else
	gettimeofday(&udp_arrival,NULL);
#endif
	udp_arrival_ntp->coarse = udp_arrival.tv_sec + JAN_1970;
	udp_arrival_ntp->fine   = NTPFRAC(udp_arrival.tv_usec);
}

void check_source(int data_len, struct sockaddr *sa_source, int sa_len)
{
	/* This is where one could check that the source is the server we expect */
	if (debug) {
		struct sockaddr_in *sa_in=(struct sockaddr_in *)sa_source;
		printf("packet of length %d received\n",data_len);
		if (sa_source->sa_family==AF_INET) {
			printf("Source: INET Port %d host %s\n",
				ntohs(sa_in->sin_port),inet_ntoa(sa_in->sin_addr));
		} else {
			printf("Source: Address family %d\n",sa_source->sa_family);
		}
	}
}

double ntpdiff( struct ntptime *start, struct ntptime *stop)
{
	int a;
	unsigned int b;
	a = stop->coarse - start->coarse;
	if (stop->fine >= start->fine) {
		b = stop->fine - start->fine;
	} else {
		b = start->fine - stop->fine;
		b = ~b;
		a -= 1;
	}
	
	return a*1.e6 + b * (1.e6/4294967296.0);
}

/* Does more than print, so this name is bogus.
 * It also makes time adjustments, both sudden (-s)
 * and phase-locking (-l).  */
/* return value is number of microseconds uncertainty in answer */
int rfc1305print(uint32_t *data, struct ntptime *arrival)
{
/* straight out of RFC-1305 Appendix A */
	int li, vn, mode, stratum, poll, prec;
	int delay, disp, refid;
	struct ntptime reftime, orgtime, rectime, xmttime;
	double el_time,st_time,skew1,skew2;
	int freq;

#define Data(i) ntohl(((uint32_t *)data)[i])
	li      = Data(0) >> 30 & 0x03;
	vn      = Data(0) >> 27 & 0x07;
	mode    = Data(0) >> 24 & 0x07;
	stratum = Data(0) >> 16 & 0xff;
	poll    = Data(0) >>  8 & 0xff;
	prec    = Data(0)       & 0xff;
	if (prec & 0x80) prec|=0xffffff00;
	delay   = Data(1);
	disp    = Data(2);
	refid   = Data(3);
	reftime.coarse = Data(4);
	reftime.fine   = Data(5);
	orgtime.coarse = Data(6);
	orgtime.fine   = Data(7);
	rectime.coarse = Data(8);
	rectime.fine   = Data(9);
	xmttime.coarse = Data(10);
	xmttime.fine   = Data(11);
#undef Data

	if (set_clock) {   /* you'd better be root, or ntpclient will crash! */
		struct timeval tv_set;
		/* it would be even better to subtract half the slop */
		tv_set.tv_sec  = xmttime.coarse - JAN_1970;
		/* divide xmttime.fine by 4294.967296 */
		tv_set.tv_usec = USEC(xmttime.fine);
		if (settimeofday(&tv_set,NULL)<0) {
			perror("settimeofday");
			syslog(LOG_ERR, "settimeofday Failure, Bailing");
                        /*we couldnot set the System Time Though we contacted the TimeServer set
                         failed to synchronize*/
                        update_ntpstate(Error_FailedToSynchronize);   
			exit(1);
 		}
                /*We have successfully set the time now so update the status as synchronized*/                       
                update_ntpstate(Synchronized);  

		if (debug) {
			printf("set time to %lu.%.6lu\n", tv_set.tv_sec, tv_set.tv_usec);
		}
	}

	if (debug) {
	printf("LI=%d  VN=%d  Mode=%d  Stratum=%d  Poll=%d  Precision=%d\n",
		li, vn, mode, stratum, poll, prec);
	printf("Delay=%.1f  Dispersion=%.1f  Refid=%u.%u.%u.%u\n",
		sec2u(delay),sec2u(disp),
		refid>>24&0xff, refid>>16&0xff, refid>>8&0xff, refid&0xff);
	printf("Reference %u.%.10u\n", reftime.coarse, reftime.fine);
	printf("Originate %u.%.10u\n", orgtime.coarse, orgtime.fine);
	printf("Receive   %u.%.10u\n", rectime.coarse, rectime.fine);
	printf("Transmit  %u.%.10u\n", xmttime.coarse, xmttime.fine);
	printf("Our recv  %u.%.10u\n", arrival->coarse, arrival->fine);
	}
	el_time=ntpdiff(&orgtime,arrival);   /* elapsed */
	st_time=ntpdiff(&rectime,&xmttime);  /* stall */
	skew1=ntpdiff(&orgtime,&rectime);
	skew2=ntpdiff(&xmttime,arrival);
	freq=get_current_freq();
	if (debug) {
	printf("Total elapsed: %9.2f\n"
	       "Server stall:  %9.2f\n"
	       "Slop:          %9.2f\n",
		el_time, st_time, el_time-st_time);
	printf("Skew:          %9.2f\n"
	       "Frequency:     %9d\n"
	       " day   second     elapsed    stall     skew  dispersion  freq\n",
		(skew1-skew2)/2, freq);
	}
	/* Not the ideal order for printing, but we want to be sure
	 * to do all the time-sensitive thinking (and time setting)
	 * before we start the output, especially fflush() (which
	 * could be slow).  Of course, if debug is turned on, speed
	 * has gone down the drain anyway. */
	if (live) {
		int new_freq;
		new_freq = contemplate_data(arrival->coarse, (skew1-skew2)/2,
			el_time+sec2u(disp), freq);
		if (!debug && new_freq != freq) set_freq(new_freq);
	}
	printf("%d %.5d.%.3d  %8.1f %8.1f  %8.1f %8.1f %9d\n",
		arrival->coarse/86400, arrival->coarse%86400,
		arrival->fine/4294967, el_time, st_time,
		(skew1-skew2)/2, sec2u(disp), freq);
	fflush(stdout);
	return(el_time-st_time);
}

/*Update the NTP State in the file*/
/*This function opens the file and writes the status.
  Variables to be updated are global so no parameters are passed */ 
static void update_ntpstate( NTPState ntp_state)   
{
        FILE *fp_ntp = NULL;
        fp_ntp = fopen(NTPCLIENT_FILE,"w");
        if(!fp_ntp)
        {
          /*if we fail then ntpclient can't do anything except logging*/ 
          if(debug)
              printf("failed to open file %s", NTPCLIENT_FILE); 
          syslog(LOG_ERR,"%s:failed to open file %s", __FUNCTION__, NTPCLIENT_FILE);  
        }
        else
        {    
             if(fwrite(&ntp_state,sizeof(ntp_state),1,fp_ntp) == 0)
             {
                 if(debug)
                     printf("fwrite failed on file %s", NTPCLIENT_FILE); 
                  syslog(LOG_ERR,"%s:failed to write to file %s", __FUNCTION__, NTPCLIENT_FILE);  
             }
               
             fclose(fp_ntp);
        }

/*Netgear Changes Starts Here */
	if(executeScript[0] != '\0')
	{
		if(ntp_state == Unsynchronized)
			ntp_state = Error_FailedToSynchronize;

		char cmd[EXEC_SCRIPT_SIZE + 64];
 		sprintf(cmd,"sh %s %d",executeScript,ntp_state);
		system(cmd);
	}
/*Netgear Changes Ends Here */	
}

int stuff_net_addr(struct in_addr *p, char *hostname)
{
	struct hostent *ntpserver;
	ntpserver=gethostbyname(hostname);
	if (ntpserver == NULL) 
	{
		if (debug) herror(hostname);
		return 0;
	}
	if (ntpserver->h_length != 4) 
	{
		if (debug) fprintf(stderr,"oops %d\n",ntpserver->h_length);
		return 0;
	}
	memcpy(&(p->s_addr),ntpserver->h_addr_list[0],4);
	return 1;
}

void setup_receive(int usd, unsigned int interface, short port)
{
	struct sockaddr_in sa_rcvr;
	bzero((char *) &sa_rcvr, sizeof(sa_rcvr));
	sa_rcvr.sin_family=AF_INET;
	sa_rcvr.sin_addr.s_addr=htonl(interface);
	sa_rcvr.sin_port=htons(port);
	if(bind(usd,(struct sockaddr *) &sa_rcvr,sizeof(sa_rcvr)) == -1) {
		if (debug) fprintf(stderr,"could not bind to udp port %d\n",port);
		perror("bind");
		syslog(LOG_ERR, "Bind Error, Bailing");
                /*We are exiting before updating the Time s update the status*/ 
                update_ntpstate(Error_FailedToSynchronize);   
		exit(1);
	}
	listen(usd,3);
}

int setup_transmit(int usd, char *host, short port)
{
	struct sockaddr_in sa_dest;
	bzero((char *) &sa_dest, sizeof(sa_dest));
	sa_dest.sin_family=AF_INET;
	if(stuff_net_addr(&(sa_dest.sin_addr),host) == 0)
	{
		if (debug) fprintf(stderr,"Failed to get address for host(%s)\n", host);
		return 0;
	}

	sa_dest.sin_port=htons(port);
	if (connect(usd,(struct sockaddr *)&sa_dest,sizeof(sa_dest)) == -1)
	{
		perror("connect");
		if (debug) fprintf(stderr,"Failed to connect to host(%s) errno(%d)\n", host, errno);
		return 0;
	}
	if (debug) fprintf(stderr,"Connected to host(%s)\n", host);
	syslog(LOG_NOTICE, "Connected to host(%s)", host);
	return 1;
}

void primary_loop(int num_probes, int interval, int goodness, char *hname, short udp_local_port, int *psetup_transmit  )
{
	fd_set fds;
	struct sockaddr sa_xmit;
	int i, pack_len, sa_xmit_len, probes_sent, error, initial_recv_count;
 	int irecvfrom = 1; /*whether we have received the packet or not;initialize it with 1 so that we can open the                            socket for the firstime we enter the loop*/ 
        int usd = -1;  /* socket */

	struct timeval to;
	struct ntptime udp_arrival_ntp;

	if (debug) printf("Listening...\n");
	
	/* This will setup the NTP client to retry the server once every
	   30 seconds for 1 try before falling back to whatever the
	   interval is set to. This allows for time for a DSL connection
	   to become active and tht NTPClient to be successful in contact
	   without having to wait the full interval again */
	initial_recv_count = 1;
	probes_sent=0;
	sa_xmit_len=sizeof(sa_xmit);
	to.tv_sec=30;
	to.tv_usec=0;
	/* 
	 * The CPE will switch to the secondary NTP server in the following 2 scenarios:
	 *	1)  The response is not received from the primary server
	 *	2) Wrong respone is received from the  primary  server
	 */
	
	for (;;) 
	{

                /*
                  If we have received the packet successfully only then close the socket and open a new one.
                  recvfrom() would be expecting the packet from the same socket that was used for sending the probe  
                  in the TIMEOUT phase of this Cycle so close only when we have already received it.
   
                  Once we receive a reply we would go to the TIMEOUT phase and send the probe packet. For this 
                  we would be required to close the old socket open a new one and make fresh gethostbyname()
                  This would cause the ntpclient to make a fresh query to dnsmasq which would inturn make a fresh que                  ry if the TTL of DNS Entry has expired 
                */
                if(irecvfrom)
                { 
                   
                    irecvfrom = 0;/*Reset the State of the variable*/

                    if(usd != -1)
                        close(usd);/*close an already opened socket before openning a new one*/
 
                    /*This part of code was earlier in main() but moved here so that a fresh DNS query is made 
                     before every NTP packet sent*/
 
      	            if ((usd = socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP)) == -1)
                    {
	                perror ("socket");
	                syslog(LOG_ERR, "Socket Error, Bailing");
                        /*We failed to open socket so we can't contact the Time Server* and Synch our time*/
                        update_ntpstate(Error_FailedToSynchronize);   
	                exit(1);
	            }

                    setup_receive(usd, INADDR_ANY, udp_local_port);

                    /*need to communicate the status of setup_transmit so that backoff counter can be updated*/
                    if (setup_transmit(usd, hname, NTP_PORT))
                    {
                        *psetup_transmit = 1;
                    }
                    else
                    {   /*setup_transmit() failed return*/
                        *psetup_transmit = 0; 
                        close(usd); /*close the opened socket*/ 
                        return;
                    }
                }


		FD_ZERO(&fds);
		FD_SET(usd,&fds);
		i=select(usd+1,&fds,NULL,NULL,&to);  /* Wait on read or error */
		
		if ((i!=1)||(!FD_ISSET(usd,&fds))) 
		{
			if (i<0) 
			{
				if (errno == EINTR)
					continue;

				if (debug) fprintf(stderr, "%s: Select returned an error(%d)\n", __FUNCTION__, errno);
				perror("select");
                                close(usd); /*close the opened socket*/ 
				return;
			}
			if (to.tv_sec == 0) 
			{
				if ((probes_sent >= num_probes) && (num_probes != 0)) 
				{	
                                        close(usd); /*close the opened socket*/ 
					return;
				}
				send_packet(usd);
				++probes_sent;
				if (initial_recv_count == 0)
				{
					to.tv_sec=interval;
				}
				else
				{
					/* No initial recv from server, retry in 30 seconds
					   since this would indicate net connection
					   may not be up */
					to.tv_sec=30;
				}
				to.tv_usec=0;
			}
			continue;
		}
		pack_len = recvfrom(usd,incoming,sizeof_incoming,0, &sa_xmit,&sa_xmit_len);
		
		/* 
		 * In case response is received from the NTP server probes_sent will be decremented to 
		 * ensure that the CPE will switch to the secondary server only in case of no response 
		 * from the primary server.
		 */
		
		--probes_sent; 
		error = goodness+1;
		if (pack_len < 0) 
		{
			perror("recvfrom");
                        close(usd); /*close the opened socket*/ 
			return; /* try again, perhaps with another server */
		} 
		else if ((pack_len > 0) && ((unsigned)pack_len < sizeof_incoming))
		{
			get_packet_timestamp(usd, &udp_arrival_ntp);
			check_source(pack_len, &sa_xmit, sa_xmit_len);
			error = rfc1305print(incoming_word, &udp_arrival_ntp);
			initial_recv_count = 0;
                        irecvfrom = 1;/*we have received the packet now, we can open a new socket*/
			/* udp_handle(usd,incoming,pack_len,&sa_xmit,sa_xmit_len); */
		} 
		else 
		{
			if (debug) fprintf(stderr, "%s: Ooops.  pack_len=%d\n", __FUNCTION__, pack_len);
                        close(usd); /*close the opened socket*/ 
			return; /* try again, perhaps with another server */
		}
		
		if ((error < goodness) && (goodness != 0)) 
		{
                        close(usd); /*close the opened socket*/ 
			return; /* try again, perhaps with another server */
		}	

		if ((probes_sent >= num_probes) && (num_probes != 0)) 
		{	
                        close(usd);/*close the opened socket*/ 
			return; /* try again, perhaps with another server */
		} 
	}
}

void do_replay(void)
{
	char line[100];
	int n, day, freq, absolute;
	float sec, el_time, st_time, disp;
	double skew, errorbar;
	int simulated_freq = 0;
	unsigned int last_fake_time = 0;
	double fake_delta_time = 0.0;

	while (fgets(line,sizeof(line),stdin)) {
		n=sscanf(line,"%d %f %f %f %lf %f %d",
			&day, &sec, &el_time, &st_time, &skew, &disp, &freq);
		if (n==7) {
			fputs(line,stdout);
			absolute=day*86400+(int)sec;
			errorbar=el_time+disp;
			if (debug) printf("contemplate %u %.1f %.1f %d\n",
				absolute,skew,errorbar,freq);
			if (last_fake_time==0) simulated_freq=freq;
			fake_delta_time += (absolute-last_fake_time)*((double)(freq-simulated_freq))/65536;
			if (debug) printf("fake %f %d \n", fake_delta_time, simulated_freq);
			skew += fake_delta_time;
			freq = simulated_freq;
			last_fake_time=absolute;
			simulated_freq = contemplate_data(absolute, skew, errorbar, freq);
		} else {
			if (debug) fprintf(stderr,"Replay input error\n");
			syslog(LOG_ERR, "Replay input error, Bailing");
                        /*
                          when exiting update the status as failed to Synchronize,
                          as we do not know how long the client has been down, we would have to assume at this point                           that we do not have the every X minute sync up to date, so therefore our time is not accura                          te
                        */
                        update_ntpstate(Error_FailedToSynchronize);   
			exit(2);
		}
	}
}

void usage(char *argv0)
{
	fprintf(stderr,
	"Usage: %s [-c count] [-d] [-g goodness] -h priHostname [-i interval]\n"
	"\t[-l] [-m minBackoffval ][-p port] [-r] [-s] [-n secHostname] [-x maxBackoffval] [-e execScript]\n", argv0);
	/* Netgear Changes Here -- Added -e option */
}

void back_off(void)
{
    if(counter > max_val)/*exceeded the peak val now use the peak val*/
    {
        counter = max_val;
    }

    sleep(counter);

    if(counter < max_val)/*if we are below peak val then increase backoff period */
    {
        counter *= EXPON_FACTOR;
    } 
} 

int main(int argc, char *argv[])
{
	short int udp_local_port = 0;  /* default of 0 means kernel chooses */
	int c;
	/* These parameters are settable from the command line
	   the initializations here provide default behavior */
	int cycle_time=600;           /* seconds */
	int probe_count=0;            /* default of 0 means loop forever */
	/* int debug=0; is a global above */
	int goodness=0;
	int replay=0;                 /* replay mode overrides everything */
        /*Westell added */
        int  loop =0;
        /*Westell added */
	char *priHostname = NULL;
	char *secHostname = NULL;
	char *hname;
        int isetup_transmit = 0; /*set if setup_transmit function succeeded in the primary loop*/

	openlog(argv[0], LOG_PERROR | LOG_PID, LOG_DAEMON);
	setlogmask(LOG_UPTO(LOG_ERR));

        /*Entered the NTP Client update the State to Unsynchronized*/ 
        update_ntpstate(Unsynchronized);

	for (;;) 
	{
		c = getopt( argc, argv, "c:" DEBUG_OPTION "g:h:n:i:lm:x:rs:e:");
		/* Netgear Changes Here -- Added -e option */
		if (c == EOF) break;
		switch (c) {
			case 'c':
				probe_count = atoi(optarg);
				break;
#ifdef ENABLE_DEBUG
			case 'd':
				++debug;
				setlogmask(LOG_UPTO(LOG_DEBUG));
				break;
#endif
			case 'g':
				goodness = atoi(optarg);
				break;
			case 'h':
				priHostname = optarg;
				break;
			case 'n':
				secHostname = optarg;
				break;		
			case 'i':
				cycle_time = atoi(optarg);
				break;
			case 'l':
				live++;
				break;
			case 'm':/*Westell added min backoff value in secs.*/
				min_val = atoi(optarg);
				break;
			case 'p':
				udp_local_port = atoi(optarg);
				break;
			case 'r':
				replay++;
				break;
			case 's':
				set_clock++;
				probe_count = 1;
				break;
			case 'x':/*Westell added max backoff value in secs.*/
			        max_val = atoi(optarg);
				break;	
		/* Netgear Changes Starts Here */				
			case 'e':
					strcpy(executeScript,optarg);
				break;
		/* Netgear Changes Ends Here */
			default:
				usage(argv[0]);
				syslog(LOG_ERR, "Input Error, Bailing");
                                /*just in case if the wrong options are supplied; should never happen
                                when exiting update the status as failed to Synchronize,as we do not know 
                                how long the client has been down, we would have to assume at this point                                             that we do not have the every X minute sync up to date, so therefore our time is not                                 accurate*/
                                update_ntpstate(Error_FailedToSynchronize);   
				exit(1);
		}
	}
	if (replay) {
		do_replay();
		syslog(LOG_NOTICE, "Replay Complete");
		exit(0);
	}
	if (priHostname == NULL) {
		usage(argv[0]);
		syslog(LOG_ERR, "No Primary Host, Bailing");
               /*just in case if the wrong options are supplied; should never happen
                 when exiting update the status as failed to Synchronize,
                 as we do not know how long the client has been down, we would have to assume at this point                           that we do not have the every X minute sync up to date, so therefore our time is not accura                          te*/
                update_ntpstate(Error_FailedToSynchronize);   
		exit(1);
	}
	if (debug) {
		printf("Configuration:\n"
		"  -c probe_count %d\n"
		"  -d (debug)     %d\n"
		"  -g goodness    %d\n"
		"  -h priHostname %s\n"
		"  -n secHostname %s\n"		
		"  -i interval    %d\n"
		"  -l live        %d\n"
		"  -m min_val     %d\n"/*Westell added */
		"  -p local_port  %d\n"
		"  -x max_val     %d\n"/*Westell added */
		"  -e execScript  %s\n"/*Netgear added */
		"  -s set_clock   %d\n",
		probe_count, debug, goodness, priHostname, secHostname,  cycle_time,
		live, min_val, udp_local_port,max_val,executeScript,set_clock );
	}
        
        /* Westell added */
        /*If we have invalid values for min_val and max_val 
          then take default values */
        if(min_val < 1 || min_val > max_val)
        {
            min_val = DEF_BACKOFFMIN_VAL;
        }

        if(max_val < 1 || min_val > max_val)
        {
            max_val = DEF_BACKOFFMAX_VAL;
        }
 
        counter = min_val;
        /* Westell added */ 

	/* Main outer loop */

	syslog(LOG_NOTICE, "Started");
	hname = priHostname;
	for (;;)
	{
	       /* Main inner loop */
 
                /*parameters added hname, udp_local_port and isetup_transmit*/
		primary_loop(probe_count, cycle_time, goodness, hname, udp_local_port, &isetup_transmit);

                /*In case we receive any type of error we will comeout of the primary loop*/
                update_ntpstate(Error_FailedToSynchronize);   

                if( isetup_transmit ) 
                     counter = min_val;/*if we disconnect from a connected server again reset the backoffcounter*/


		syslog(LOG_NOTICE, "%s: Problems with host(%s)", argv[0], hname);

		/* 
		 * If the connection is not established with the Primary NTP Server or the 
		 * Primary server's name is not resolved then the CPE switches to the 
		 * secondary NTP server
		 */
		if (strcmp(hname, priHostname) == 0)
		{
			if (secHostname)
			{
				hname = secHostname;
			}
                        /*Westell added */
                        else
                                loop++;   
                        /*Westell added */ 
		}
		else
		{
			hname = priHostname;
                        loop++; /*Westell added */
		}

		syslog(LOG_NOTICE, "Trying again with host(%s)", hname);

                /*Westell added */
                if(debug)
                    printf("loop %d min_val %d max_val %d counter %d", loop, min_val, max_val, counter);

                if(loop == NTP_SERV_LOOPS)/*backoff after we have looped through the NTP servers NTP_SERV_LOOPS times*/
                {
                    back_off();      
                    loop=0;
                }
                /*Westell added */
	}
	syslog(LOG_NOTICE, "Halted");
	return 0;
}
