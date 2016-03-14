/* 
 * $Id$
 * A simple tftpd server for busybox
 *
 * Copyright (C) 2001 Steven Carr <Steven_Carr@yahoo.com>
 *
 * Tries to follow RFC1350 and RFC2347.
 * Only "octet" mode supported.
 * tsize option is supported on sending files only (pxelinux support).
 * chroot jail for security.
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-137 USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/tftp.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <asm/ioctls.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <errno.h>
#include "busybox.h"



#ifndef OACK
#define OACK 6
#endif
#ifndef EOPTNEG
#define EOPTNEG 8
#endif

#define ENOPUT -2
#define ENOGET -3

#if !defined(__UCLIBC__) || defined(__UCLIBC_HAS_MMU__)
#define FORK() fork()
#else
#define FORK() vfork()
#endif

#define TFTP_BLOCKSIZE_DEFAULT 512	/* according to RFC 1350, don't change */
#define TFTP_TIMEOUT 5		/* seconds */

#define CONFIG_FEATURE_TFTPD_GET
#define CONFIG_FEATURE_TFTPD_PUT


/*
 * Handle initial connection protocol.
 *     +-------+---~~---+---+---~~---+---+---~~---+---+---~~---+---+-->  >-------+---+---~~---+---+
 *     |  opc  |filename| 0 |  mode  | 0 |  opt1  | 0 | value1 | 0 | <  <  optN  | 0 | valueN | 0 |
 *     +-------+---~~---+---+---~~---+---+---~~---+---+---~~---+---+-->  >-------+---+---~~---+---+
 *             ^--->
 */

/* The options are zero terminated, retrieve a list of pointers to the first character of each option */
int tftpd_options (char *options, int opt_len, char **argv, int max_arg)
{
  int x;
  int y;
  argv[0] = options;
  for (y = 1, x = 0; (y < max_arg) && (x < (opt_len - 1)); x++)
    {
      if (options[x] == 0)
	{
	  if (options[x + 1] == 0)
	    return y;
	  argv[y] = &options[x + 1];
	  y++;
	}
    }
  return y;
}


/*
 * Send a nak packet (error message).
 * Error code passed in is one of the
 * standard TFTP codes, or a UNIX errno
 * offset by 100.
 */
void tftpd_nak (int peer, int error)
{
  char buf[TFTP_BLOCKSIZE_DEFAULT + 4];
  struct tftphdr *pkt;

  pkt = (struct tftphdr *) buf;
  pkt->th_opcode = htons ((u_short) ERROR);
  pkt->th_code = htons ((u_short) error);

  switch (error)
    {
    case ENOPUT:
      strcpy (pkt->th_msg, "Put not supported");
      pkt->th_code = htons (EUNDEF);
      break;
    case ENOGET:
      strcpy (pkt->th_msg, "Get not supported");
      pkt->th_code = htons (EUNDEF);
      break;
    case EUNDEF:
      strcpy (pkt->th_msg, "Undefined error code");
      break;
    case ENOTFOUND:
      strcpy (pkt->th_msg, "File not found");
      break;
    case EACCESS:
      strcpy (pkt->th_msg, "Access violation");
      break;
    case ENOSPACE:
      strcpy (pkt->th_msg, "Disk full or allocation exceeded");
      break;
    case EBADOP:
      strcpy (pkt->th_msg, "Illegal TFTP operation");
      break;
    case EBADID:
      strcpy (pkt->th_msg, "Unknown transfer ID");
      break;
    case EEXISTS:
      strcpy (pkt->th_msg, "File already exists");
      break;
    case ENOUSER:
      strcpy (pkt->th_msg, "No such user");
      break;
    case EOPTNEG:
      strcpy (pkt->th_msg, "Failure to negotiate RFC2347 options");
      break;
    default:
      strcpy (pkt->th_msg, strerror (error - 100));
      pkt->th_code = htons (EUNDEF);
      break;
    }

  send (peer, buf, strlen (pkt->th_msg) + 5, 0);
}

/*
 * Send a ack packet 
 */
void tftpd_ack (int peer, int block)
{
  struct tftphdr pkt;

  pkt.th_opcode = htons (ACK);
  pkt.th_block = htons (block);

  if (send (peer, &pkt, sizeof(pkt), 0)!=sizeof(pkt))
  	bb_perror_msg_and_die("tftpd_ack send");
}


/*
 * send an oack
 */
void tftpd_oack (int peer, int count, char **list)
{
  char buf[TFTP_BLOCKSIZE_DEFAULT + 4];
  struct tftphdr *pkt;
  int x;
  char *ptr;

  pkt=(struct tftphdr *)buf;
  pkt->th_opcode = htons (OACK);
  ptr=pkt->th_stuff;
  
  for (x=0;x<count;x++)
	 ptr=strrchr (strcpy (ptr, list[x]), '\0') + 1;

 if ( send (peer, buf, (ptr-buf), 0)!=(ptr-buf))
  	bb_perror_msg_and_die("tftpd_oack send");
}


/*
 * send data
 */
void tftpd_data (int peer, int block, char *data, int size)
{
  struct tftphdr *pkt;
  char buf[TFTP_BLOCKSIZE_DEFAULT + 4];

  pkt=(struct tftphdr *)buf;
  pkt->th_opcode = htons (DATA);
  pkt->th_block  = htons(block);
  
  memcpy(pkt->th_data,data,size);

  if (send (peer, &buf, size+4, 0)!=(size+4))
  	bb_perror_msg_and_die("tftpd_data send");
}


int tftpd_getdata(int peer, int block, char *data, int size)
{
  struct tftphdr *pkt;
  struct timeval tv;
  fd_set rfds;
  int len=-1;
  int timeout_counter = 4;
  
  pkt=(struct tftphdr *)data;
  
  do {	
      tv.tv_sec = TFTP_TIMEOUT;
      tv.tv_usec = 0;
      FD_ZERO (&rfds);
      FD_SET (peer, &rfds);
      switch (select (FD_SETSIZE, &rfds, NULL, NULL, &tv))
	{
	case 1:		/* data ready */
	  len = recv (peer, data, size, 0);
	  if (len < 0)
	    bb_perror_msg_and_die ("failed to read (data)");

	  pkt->th_opcode = ntohs (pkt->th_opcode);
	  pkt->th_block = ntohs (pkt->th_block);
	  if (pkt->th_opcode == ERROR)
	    {
	      bb_error_msg (pkt->th_data);
	      exit (0);
	    }
	  if ((pkt->th_opcode == DATA) && (pkt->th_block != block))
	    {
	      //synchronize (peer);
	    }
	  break;
	case 0:		/* timeout */
	  timeout_counter--;
	  if (timeout_counter == 0)
	    {
	      bb_error_msg ("last timeout");
	      exit (0);
	    }
	  break;
	default:		/* error */
	  bb_perror_msg_and_die ("select failed");
	  break;
	}
   }while (!(pkt->th_opcode == DATA) && (pkt->th_block == block));
   return len;
}



int tftpd_getack(int peer, int block)
{
  char data[TFTP_BLOCKSIZE_DEFAULT + 4];
  struct tftphdr *pkt;
  struct timeval tv;
  fd_set rfds;
  int timeout_counter = 4;
  int len;
  
  pkt=(struct tftphdr *)data;

  do {	
      tv.tv_sec = TFTP_TIMEOUT;
      tv.tv_usec = 0;
      FD_ZERO (&rfds);
      FD_SET (peer, &rfds);
      switch (select (FD_SETSIZE, &rfds, NULL, NULL, &tv))
	{
	case 1:		/* data ready */

	  len = recv (peer, data, TFTP_BLOCKSIZE_DEFAULT + 4, 0);
	  if (len < 0)
	    bb_perror_msg_and_die ("failed to read (data)");

	  pkt->th_opcode = ntohs (pkt->th_opcode);
	  pkt->th_block = ntohs (pkt->th_block);

	  if (pkt->th_opcode == ERROR)
	    {
	      bb_error_msg (pkt->th_data);
	      exit (0);
	    }

	  if ((pkt->th_opcode == ACK) && (pkt->th_block != block))
	    {
	      //synchronize (peer);
	    }
	  break;
	case 0:		/* timeout */
	  timeout_counter--;
	  if (timeout_counter == 0)
	    {
	      bb_error_msg ("last timeout");
	      exit (0);
	    }
	  break;
	default:		/* error */
	  bb_perror_msg_and_die ("select failed");
	  break;
	}
   }while (! ((pkt->th_opcode == ACK) && (pkt->th_block == block)) );

  return (1==1);
}





#ifndef CONFIG_FEATURE_TFTPD_GET
void
tftpd_send (int peer, struct tftphdr *tp, int n, int buffersize)
{
	/* we aren't configured for sending files */
	tftpd_nak (peer, ENOGET);
	close (peer);
	exit(0);
}

#else
void
tftpd_send (int peer, struct tftphdr *first_pkt, int pkt_len, int buffersize)
{
	FILE *file=NULL;
	char buffer[TFTP_BLOCKSIZE_DEFAULT+4];
	char *list[64]; /* list of pointers to options and values */
	int listcount;
	char *reply_list[64];
	int reply_listcount=0;
	char tsize_ret[32];
	int block, inbytes, x;
	
	listcount = tftpd_options (first_pkt->th_stuff, pkt_len, list ,64);

	/* get the size of the file (remember, chroot() supposed to point us in the right directory) */

	if (strcasecmp(list[1],"octet")!=0)
	{
		tftpd_nak(peer,EBADOP);
		close(peer);
		exit(0);
	}


	file = fopen (list[0], "r");
	if (file == NULL)
	{
	  tftpd_nak (peer, ENOTFOUND);
	  close(peer);
	  exit(0);
	}
	fseek (file, 0, SEEK_END);
	sprintf(tsize_ret,"%lu", ftell (file));
	fseek (file, 0, SEEK_SET);


	/* 0=filename, 1=mode, 2=option, 3=option_value ... */
	block = 1;
	reply_listcount=0;

	/* look through the options for the ones we support */
	for (x=2;x<listcount;x++)
	{
		if (strcasecmp(list[x],"tsize")==0) /* only one option supported so far */
		{
			reply_list[reply_listcount]=list[x];		
			reply_listcount++;
			reply_list[reply_listcount]=tsize_ret; /* point to the real value */
			reply_listcount++;
		}
	}

	/* if there are any options, send an OACK instead of an ACK */
	if (reply_listcount>0)
	{
		do
		{
			tftpd_oack(peer,reply_listcount,reply_list);
		}
		while (!tftpd_getack(peer,0));
	}	


	/* Send the file! */
	while ((inbytes = fread(buffer,1,TFTP_BLOCKSIZE_DEFAULT,file))>0)
	{
		do
		{
			tftpd_data(peer,block,buffer,inbytes);
		}
		while (!tftpd_getack(peer,block));
		block++;
	}
	fclose(file);
	close(peer);
	exit (0);
}

#endif






#ifndef CONFIG_FEATURE_TFTPD_PUT
void
tftpd_receive (int peer, struct tftphdr *tp, int n, int buffersize)
{
	/* we aren't configured for receiving files */
	tftpd_nak (peer, ENOPUT);
	close (peer);
	exit(0);
}

#else
void
tftpd_receive (int peer, struct tftphdr *first_pkt, int pkt_len, int buffersize)
{
	FILE *file=NULL;
	char buffer[TFTP_BLOCKSIZE_DEFAULT+4];
	struct tftphdr *pkt;
	int block, inbytes;
	char *list[64];
	int listcount;

	pkt=(struct tftphdr *)buffer;
	listcount = tftpd_options (first_pkt->th_stuff, pkt_len, list ,64);

	/* get the size of the file (remember, chroot() supposed to point us in the right directory) */

	if (strcasecmp(list[1],"octet")!=0)
	{
		tftpd_nak(peer,EBADOP);
		close(peer);
		exit(0);
	}


	file = fopen (list[0], "w");
	if (file == NULL)
	{
	  tftpd_nak (peer, EACCESS);
	  close(peer);
	  exit(0);
	}

	block=0;
	do
	{
		tftpd_ack(peer,block);
		block++;
		inbytes=tftpd_getdata(peer,block,buffer,TFTP_BLOCKSIZE_DEFAULT+4);
		fwrite(pkt->th_msg,1,inbytes-4,file);
	}
	while (inbytes==(TFTP_BLOCKSIZE_DEFAULT+4));

	tftpd_ack(peer,block); /* final acknowledge */

	fclose(file);
	close(peer);
	exit (0);
}

#endif

int from_inetd = 0;

static int
tftpd_daemon (char *directory, char *address, int port)
{
  char *buf;
  struct tftphdr *tp;
  struct sockaddr_in from;
  struct sockaddr_in myaddr;
  struct sockaddr_in bindaddr;
  int fd = -1;
  int peer;
  int rv;
  int fromlen, n;
  pid_t pid;
  buf = xmalloc (TFTP_BLOCKSIZE_DEFAULT + 4);
  if (!from_inetd)
  {
  if ((fd = socket (PF_INET, SOCK_DGRAM, 0)) < 0)
    bb_perror_msg_and_die ("socket");
  memset (&bindaddr, 0, sizeof (bindaddr));
  bindaddr.sin_family = AF_INET;
  bindaddr.sin_addr.s_addr = INADDR_ANY;
  bindaddr.sin_port = htons (port);
  if (address != NULL)
    {
      struct hostent *hostent;
      hostent = xgethostbyname (address);
      if (!hostent || hostent->h_addrtype != AF_INET)
	bb_perror_msg_and_die ("cannot resolve local bind address");
      memcpy (&bindaddr.sin_addr, hostent->h_addr, hostent->h_length);
    }

  if (bind (fd, (struct sockaddr *) &bindaddr, sizeof (bindaddr)) < 0)
    bb_perror_msg_and_die ("daemon bind failed");
  }
  /* This means we don't want to wait() for children */
  signal (SIGCHLD, SIG_IGN);
  do
    {
      fd_set readset;
      memset(buf,0,TFTP_BLOCKSIZE_DEFAULT + 4);
      memset (&myaddr, 0, sizeof (myaddr));
      if (!from_inetd)
      {
      FD_ZERO (&readset);
      FD_SET (fd, &readset);
      /* Never time out, we're in standalone mode */
      rv = select (fd + 1, &readset, NULL, NULL, NULL);
      if (rv == -1 && errno == EINTR)
	continue;		/* Signal caught, reloop */
      if (rv == -1)
	bb_perror_msg_and_die ("select loop");
      if (rv == 0)
	{
	  bb_error_msg ("We shouldn't be timeing out!");
	  exit (0);		/* Timeout, return to inetd */
	}
      }
      else
      	fd = 0;

      fromlen = sizeof (from);
      n =
	recvfrom (fd, buf, TFTP_BLOCKSIZE_DEFAULT + 4, 0,
		  (struct sockaddr *) &from, &fromlen);
      if (!from_inetd)
      {
      if (myaddr.sin_addr.s_addr == INADDR_ANY)
	memcpy (&myaddr.sin_addr, &bindaddr.sin_addr,
		sizeof bindaddr.sin_addr);
      /* Now that we have read the request packet from the UDP
         socket, we fork and go back to listening to the socket. */
      pid = FORK ();
      if (pid < 0)
	bb_perror_msg_and_die ("cannot fork");
      if (pid == 0)
	break;			/* Child exits the while(1), parent continues to loop */
      }
    }while (!from_inetd);

  /* Close file descriptors we don't need */
  close (fd);

  /* Get a socket.  This has to be done before the chroot() (/dev goes away) */
  peer = socket (AF_INET, SOCK_DGRAM, 0);
  if (peer < 0)
    bb_perror_msg_and_die ("socket");
  if (chroot ("."))
    bb_perror_msg_and_die ("chroot");
  from.sin_family = AF_INET;

  /* Process the request */
  myaddr.sin_family = AF_INET;
  myaddr.sin_port = htons (0);	/* we want a new local port */
  if (bind (peer, (struct sockaddr *) &myaddr, sizeof myaddr) < 0)
    bb_perror_msg_and_die ("daemon-child bind");
  if (connect (peer, (struct sockaddr *) &from, sizeof from) < 0)
    bb_perror_msg_and_die ("daemon-child connect");
  tp = (struct tftphdr *) buf;


  tp->th_opcode = ntohs (tp->th_opcode);

  switch(tp->th_opcode)
  {
  	case RRQ:
	    tftpd_send (peer, tp, n, TFTP_BLOCKSIZE_DEFAULT);
	    break;
	case WRQ:
	    tftpd_receive (peer, tp, n, TFTP_BLOCKSIZE_DEFAULT);
	    break;
  }
  exit (0);
}







int tftpd_main (int argc, char **argv)
{
  int result;
  int opt;
  int on = 1;
  int fd = 0;
  char *address = NULL;		/* address to listen to */
  char directory[256];		/* default directory "/tftpboot/" */
  int port = 69;
  int daemonize = (1 == 0);
  memset (directory, 0, sizeof (directory));
  strcpy (directory, "/tftpboot/");
  while ((opt = getopt (argc, argv, "sp:a:d:h:I")) != -1)
    {
      switch (opt)
	{
	case 'p':
	  port = atoi (optarg);
	  break;
	case 'a':
	  address = optarg;
	  break;
	case 's':
	  daemonize = (1 == 1);
	  break;
	case 'd':
	  safe_strncpy (directory, optarg, sizeof (directory));
	  break;
	case 'I':
	  from_inetd = 1;
	  break;
	case 'h':
	  //show_usage ();
	  break;
	}
    }

  if (chdir (directory))
    bb_perror_msg_and_die ("Invalid Directory");

  if (ioctl (fd, FIONBIO, &on) < 0)
    bb_perror_msg_and_die ("ioctl(FIONBIO)");
  /* daemonize this process */
  if (daemonize)
    {
      pid_t f = FORK ();
      if (f > 0)
	exit (0);
      if (f < 0)
	bb_perror_msg_and_die ("cannot fork");
      close (0);
      close (1);
      close (2);
    }
  result = tftpd_daemon (directory, address, port);
  return (result);
}

