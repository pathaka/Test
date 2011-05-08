/****************************************************************************
 *  Pathneck: locating network path bottlenecks
 *  Copyright (C) 2004
 *  Ningning Hu and the Carnegie Mellon University
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License (in the COPYING file) for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 ****************************************************************************/

#ifndef pathneck_h
#define pathneck_h
#define USE_PCAP

#include "ip_icmp.h"

#include <stdio.h>
#include <stdlib.h>
#ifdef _BSD
#include <sys/param.h>
#endif
#ifdef __APPLE__
#include <stdint.h>
#endif 
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <netinet/in.h>
#include <resolv.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <unistd.h>

#if !defined SUN && !defined _BSD && !defined __APPLE__
#define LINUX
#endif

#define MAX_ECHO		1500 	/* max probing packet size */
#define PKT_SIZE		500	/* max probing packet size */
#define PORT_NONEXISTENT	7000

/* NOTE: because we always start TTL from 1, the 0 index array is not
 * used, so the real usage max ttl should be (MAX_TTL-1) */
#define MAX_TTL			51
/* the number of probing packet for each node */
#define TRAIN_LEN		2
#define UDP_TRAIN_LEN		60
#define MAX_UDP_NUM		1024 	/* max number of udp pkts */
#define MAX_REC			(MAX_TTL * TRAIN_LEN)

/* used for dst replied ICMP packets */
#define MAX_RTT_NUM		5

/* used for the configuration processing */
#define CONF_COMPLETE		1
#define CONF_NO_SRC		2
#define CONF_DST_EXPIRE		3
#define CONF_NO_FILE		4
#define ONE_DAY			(24 * 3600)
#define ONE_HOUR		(3600)
#define MAX_CONFIG_NUM		1024 		/* store at most 1024 items */

//long MAGIC_NUM = 0xabcdef78; 	/* used for matching pkts */

#if defined SUN || defined _BSD || defined __APPLE__ || defined __CYGWIN__
struct iphdr
{
#if defined BYTE_ORDER == LITTLE_ENDIAN || defined _BSD 
    unsigned int ihl:4;
    unsigned int version:4;
#else
    unsigned int version:4;
    unsigned int ihl:4;
#endif
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
    /*The options start here. */
};
#endif  /* SUN */

struct outdata {
	u_char seq;		/* sequence number of this packet */
	u_char ttl;		/* ttl packet left with */
	struct timeval tv;	/* time packet left */
};

/*
 * Overlay for ip header used by other protocols (tcp, udp).
 */
struct ip_overlay {
	caddr_t ih_next, ih_prev;       /* for protocol sequence q's */
	u_char  ih_x1;                  /* (unused) */
	u_char  ih_pr;                  /* protocol */
	u_short ih_len;                 /* protocol length */
	struct  in_addr ih_src;         /* source internet address */
	struct  in_addr ih_dst;         /* destination internet address */
};

/*
 * UDP kernel structures and variables.
 */
struct  udpip_header {
	struct  ip_overlay ui_i;                /* overlaid ip structure */
	struct  udphdr ui_u;                /* udp header */
};

#define ui_next         ui_i.ih_next
#define ui_prev         ui_i.ih_prev
#define ui_x1           ui_i.ih_x1
#define ui_pr           ui_i.ih_pr
#define ui_len          ui_i.ih_len
#define ui_src          ui_i.ih_src
#define ui_dst          ui_i.ih_dst
#define ui_sport        ui_u.source
#define ui_dport        ui_u.dest
#define ui_ulen         ui_u.len
#define ui_sum          ui_u.check

/* path node time sequence */
struct ip_icmp_hdr {
   	struct iphdr iph; 
   	struct icmp  icmph; 
	double 	     stime;
	double	     rtime;
};

/* ip_path */
struct time_arr {
    	int 	index[TRAIN_LEN]; 	/* index to time_path */
	int   	cnt; 			/* number of indexes each phase */ 

	double 	avg_gap;
	int 	cong_order;

	uint32_t ip;
	int	as;
};

/* used for sort the gap array */
struct value_pair {
    	int 	index; 		/* index to the position in ip_path */
	double 	gap;		/* average gap value */
};

extern struct ip_icmp_hdr time_path[MAX_REC];	
extern int path_i;
extern struct time_arr ip_path[MAX_TTL];
extern int ip_path_len;

#define USAGE_TXT "\
Pathenck V1.2 Usage: \n\
\n\
    	./pathneck [-e end_pkt_num] [-l udp_pkt_num] [-s pkt_size] 	\n\
		   [-i self_ip] [-y delay_num] [-coptx] [-dvh]		\n\
		   <dst_ip | dst_hostname>				\n\
\n\
[probing configuration]\n\
	-e end_pkt_num	number of measurement packets [30]		\n\
	-l udp_pkt_num	number of load packets [60]			\n\
	-s pkt_size	the load packet size in byte [500]		\n\
	-c		use ICMP probing packets, [UDP]			\n\
    	-p 		use the planetlab raw socket interface [0]	\n\
	-y delay_num	specify the src gap within the packet train [0]	\n\
	-i self_ip	sproof the probing pkt source ip [not set]	\n\
\n\
[output setting] \n\
	-x		enable the DNS lookup [0]			\n\
	-o 		enable on-line detection processing [0]		\n\
	-t		dump the packet sending times [0]		\n\
	-d 		debug mode [0]					\n\
	-v 		verbose mode [0]				\n\
	-h 		print this message [0]				\n\
"

#endif /* pathneck_h */
