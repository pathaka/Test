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
 *
 *  The GetCannonicalInfo() function used by this file is copied from 
 *  sting's code, which is under BSD license.
 ****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
long MAGIC_NUM = 0xabcdef78; 	/* used for matching pkts */
#if defined(_BSD) || defined(__APPLE__) || defined __CYGWIN__
#include <sys/param.h>
#else
#include <values.h>
#endif

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>   /* _BSD: should be before resolv.h */
#include <resolv.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>

#include "pathneck.h"
#include "planetlab.h"
#include "get-line.h"
#include "util.h"
#include "choke.h"

#if defined USE_PCAP
#include <pcap.h>
void pcap_init();
pcap_t *adhandle;
struct pcap_pkthdr *header;
const u_char *pkt_data;
int res;
bpf_u_int32 NetMask;


void  print_IP (struct iphdr * ip)
{

    struct in_addr src;
    struct in_addr dst;

    src.s_addr = ip->saddr;
    dst.s_addr = ip->daddr;

    printf("IP: ");
    printf("%s ",
           inet_ntoa(src));
    printf("%s %d %d\n",
           inet_ntoa(dst),
           ip->tot_len,
           ip->ihl);
}


#endif

struct ip *outip;		/* last output (udp) packet */
struct udphdr *outudp;		/* last output (udp) packet */
struct icmp *outicmp;
struct outdata *outdata;	/* last output (udp) packet */
u_short ident;
u_short port = 42768 + 666;	/* start udp dest port # for probe packets */

int debug = 0;
int verbose = 0;
int delay_num = 0;
int udp_probing_size = PKT_SIZE;
int udp_pkt_num = UDP_TRAIN_LEN;
int end_pkt_num = 30;
int win_size = 0;
int planetlab = 0;
int on_line_processing = 0;
int icmp_probing = 0; 	/* set it with 1 means using ICMP packets to probe */
int dns_lookup = 0;	/* x: enable the hostname conversion */
int dump_send_time = 0; /* dump the send_time2 array */

/* config filename: $HOME/.patheneck.$hostname */
char conf_file[256];
FILE * conf_fp = NULL;

char info_line1[256];
char info_line2[1024];

int udp_sock;
int icmp_sock;
int udpicmp_sock;
int udp_port = 31415;
uint32_t self_ip = 0;
uint32_t ip;
char dst_hostname[MAXHOSTNAMELEN];
char dst_ip_str[16];
char self_hostname[MAXHOSTNAMELEN];
char self_ip_str[16];

/* the received path info, ordered by receiving time */
struct ip_icmp_hdr time_path[MAX_REC];
int path_i = 0;

/* the received path info, ordered by ttl */
struct time_arr ip_path[MAX_TTL];
int ip_path_len = 0;

/* record the sending time for all the packets, including the load pkts */
double send_time[MAX_REC + MAX_UDP_NUM];
double send_time2[MAX_REC + MAX_UDP_NUM];
int send_i2 = 0;

/* used to record one time of receiving operations */
char path_rec[MAX_REC][256];
double arr_time[MAX_REC];
int rec_i = 0;

/* used for recording the responses from the destinations */
char rtt_rec[MAX_RTT_NUM][256];
double rtt_arr_time[MAX_RTT_NUM];
double avg_rtt = 0;
uint32_t rtt_dst;
int rtt_i = 0;

void usage()
{
	printf("%s\n", USAGE_TXT);
	exit(0);
}

/* borrowed from sting's code */
int GetCannonicalInfo(char *string, char name[MAXHOSTNAMELEN], 
		      uint32_t *address, char ip_str[16])
{
	struct hostent *hp;
	struct in_addr in_a;

	/* Is string in dotted decimal format? */
#ifdef SUN
	if ((*address = inet_addr(string)) == INADDR_BROADCAST) {
#else
	if ((*address = inet_addr(string)) == INADDR_NONE) {
#endif
	    /* No, then lookup IP address */
	    if ((hp = gethostbyname(string)) == NULL) {
	      	/* Can't find IP address */
	      	printf("ERROR: couldn't obtain address for %s\n", string);
	      	return -1;
	    } else {
	      	strncpy(name, hp->h_name, MAXHOSTNAMELEN-1);
	      	memcpy((void *)address, (void *)hp->h_addr, hp->h_length);
	      	in_a.s_addr = *address;
	      	strcpy(ip_str, inet_ntoa(in_a)); 
	    }
	} else {
	    strcpy(ip_str, string);
	    if ((hp = gethostbyaddr((char *)address, 
	          	sizeof(*address), AF_INET)) == NULL) {
	      	/* Can't get cannonical hostname, so just use input string */
	      	strncpy(name, string, MAXHOSTNAMELEN - 1);
	    } else {
	      	strncpy(name, hp->h_name, MAXHOSTNAMELEN - 1);
	    }
	}
	return 0;
}

int create_raw_socket(int port, int proto)
{
	int sock, yes=1;
	struct sockaddr_in address;

	sock = socket(AF_INET, SOCK_RAW, proto);
	if (sock < 0) {
	    perror("socket");
	    exit(1);
	}
	if(setsockopt(sock, 0, IP_HDRINCL, &yes, sizeof(yes)) < 0) {
	    perror("IP_HDRINCL");
	    exit(1);
	}

	if (port <= 0)
	    return sock;
	memset(&address, 0, sizeof(address));
	address.sin_family = AF_INET;
	address.sin_port   = htons(port);
	address.sin_addr.s_addr   = INADDR_ANY;
	if (bind(sock, (struct sockaddr *) &address, sizeof(address)) < 0) {
	    perror("bind");
	    exit(1);
	}
	return sock;
}

/* send out one raw udp/icmp packet */
void send_echo_udp(int seq, int size, int ttl, uint32_t dst_ip)
{
	struct timeval t1;
	struct timezone tz;
	struct sockaddr_in addr;
	register struct udpip_header *ui, *oui;
	struct ip tip;

	outip->ip_ttl = ttl;
#ifdef _BSD
	outip->ip_id = ident + seq;
	outip->ip_len = size;
	outip->ip_off = 0;
#else
	outip->ip_id = htons(ident + seq);
	outip->ip_len = htons(size);
	outip->ip_off = htons(0);
#endif
	/* In most cases, the kernel will recalculate the ip checksum.
	 * But we must do it anyway so that the udp checksum comes out
	 * right.  
	 */
	outip->ip_sum =
	    in_cksum((u_short *)outip, sizeof(*outip));
	if (outip->ip_sum == 0)
		outip->ip_sum = 0xffff;

	/* Payload */
	outdata->seq = seq;
	outdata->ttl = ttl;
	(void)gettimeofday(&t1, &tz);
	outdata->tv = t1;

	send_time[seq] = (double)t1.tv_sec + (double)t1.tv_usec / 1000000;
	send_time2[send_i2] = (double)t1.tv_sec + (double)t1.tv_usec / 1000000;
	send_i2 ++;

	if (!icmp_probing) {
	    /* Checksum (we must save and restore ip header) */
	    tip = *outip;
	    ui = (struct udpip_header *)outip;
	    oui = (struct udpip_header *)&tip;
	    /* Easier to zero and put back things that are ok */
	    memset((char *)ui, 0, sizeof(ui->ui_i));
	    ui->ui_src = oui->ui_src;
	    ui->ui_dst = oui->ui_dst;
	    ui->ui_pr = oui->ui_pr;

#if defined SUN || defined _BSD || defined __APPLE__ || defined __CYGWIN__
	    outudp->uh_dport = htons(port + seq);
	    outudp->uh_ulen = htons((u_short)(size - (sizeof(*outip))));
	    ui->ui_len = outudp->uh_ulen;
	    outudp->uh_sum = 0;
	    /* TODO: set the checksum to 0 will trigger last hop's reply,
	     * but we filter them anyway */
	    outudp->uh_sum = in_cksum((u_short *)ui, size);
	    if (outudp->uh_sum == 0)
		    outudp->uh_sum = 0xffff;

#else /* Linux UDP packets */

   	    outudp->dest = htons(port + seq);
	    outudp->len = htons((u_short)(size - (sizeof(*outip))));
	    ui->ui_len = outudp->len;
	    outudp->check = 0;
	    /* TODO: set the checksum to 0 will trigger last hop's reply,
	     * but we filter them anyway */
	    outudp->check = in_cksum((u_short *)ui, size);
	    if (outudp->check == 0)
		    outudp->check = 0xffff;
#endif
	    *outip = tip;

	} else  { /* send ICMP probing packets */
	    outicmp->icmp_seq = htons(port+seq);

	    /* the magic number here for packet matching */
	    outicmp->icmp_mask = htonl(MAGIC_NUM);

	    outicmp->icmp_cksum = 0;
	    outicmp->icmp_cksum = in_cksum((u_short *)outicmp, 
		    size - sizeof(*outip));
	    if (outicmp->icmp_cksum == 0)
		outicmp->icmp_cksum = 0xffff;

	}

	outip->ip_dst.s_addr = dst_ip;

	/* we must change port number each time, this will be used for
	 * identification */
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = dst_ip;

	if (planetlab && icmp_probing) {
	    /* Planetlab nodes doesn't allows udp_sock to send ICMP raw 
	     * packets */
	    if (sendto(icmp_sock, outip, size, 0, (struct sockaddr*)&addr, sizeof(addr)) < 0)
	    	perror(ip2str(ip));
	} else {
	    if (sendto(udp_sock, outip, size, 0, (struct sockaddr*)&addr, sizeof(addr)) < 0)
	    	perror(ip2str(ip));
	}
}

/* zero all the global variables */
void clean_path()
{
    	int i, k;

	rec_i = 0;
	path_i = 0;
	ip_path_len = 0;
	memset(time_path, 0, sizeof(struct ip_icmp_hdr) * MAX_REC);
	memset(path_rec, 0, MAX_REC);

	info_line1[0] = 0;
	info_line2[0] = 0;

	for (i=0; i<MAX_TTL; i++) {
		for (k=0; k<TRAIN_LEN; k++) {
		    ip_path[i].index[k] = -1;
		    ip_path[i].cnt = 0;
		    ip_path[i].ip = 0;
		    ip_path[i].avg_gap = 0;
		    ip_path[i].cong_order = 0;
		}
	}
	for (i=0; i<MAX_REC; i++) {
		send_time[i] = 0;
		arr_time[i] = 0;
	}

	memset(rtt_rec, 0, MAX_RTT_NUM * 256);
	memset(rtt_arr_time, 0, MAX_RTT_NUM * sizeof(double));
	avg_rtt = 0;
	rtt_dst = 0;
	rtt_i = 0;
}

void set_udp_header() 
{
	register u_char *outp = (u_char *)(outip + 1);

	outip->ip_p = IPPROTO_UDP;
	outudp = (struct udphdr *)outp;
	// outudp->source = htons(ident);
#if defined SUN || defined _BSD || defined __APPLE__ || defined __CYGWIN__
	outudp->uh_sport = htons(udp_port);
#else
	outudp->source = htons(udp_port);
#endif
	outdata = (struct outdata *)(outudp + 1);
}

void set_icmp_header() 
{
	register u_char *outp = (u_char *)(outip + 1);

	outip->ip_p = IPPROTO_ICMP;
			
	outicmp = (struct icmp *)outp;
	outicmp->icmp_type = ICMP_ECHO;
	// outicmp->icmp_code = 0;
	/* this field is important for Planetlab nodes, must be the same port
	 * with the corresponding packets */
	outicmp->icmp_id = htons(udp_port);
									
	outdata = (struct outdata *)(outp + 8); /* XXX magic number */
}

void init()
{
	register u_char *outp = (u_char *)(outip + 1);

	if (!icmp_probing) {
	    udp_sock = create_raw_socket(udp_port, IPPROTO_UDP);
    	    icmp_sock = create_raw_socket(udp_port, IPPROTO_ICMP);
	} else {
	    udp_sock = create_raw_socket(udp_port, IPPROTO_ICMP);
	    icmp_sock = udp_sock;
	}

	if (planetlab) 
    	    udpicmp_sock = create_raw_socket(udp_port, IPPROTO_ICMP_UDP);
	else
    	    udpicmp_sock = create_raw_socket(udp_port, IPPROTO_ICMP); 

	/* init the shared pkt header structures */
	outip = (struct ip *)malloc(MAX_ECHO);
	if (outip == NULL) {
		perror("malloc");
		exit(1);
	}
	memset((char *)outip, 0, MAX_ECHO);

	outip->ip_v = IPVERSION;
	outip->ip_tos = 0;
	outp = (u_char *)(outip + 1);

	outip->ip_dst.s_addr = ip;
	outip->ip_src.s_addr = self_ip;

	outip->ip_hl = (outp - (u_char *)outip) >> 2;
	ident = (getpid() & 0xffff) | 0x8000;

	if (!icmp_probing)
	    set_udp_header();
	else 
	    set_icmp_header();

#ifdef USE_PCAP
    pcap_init();
#endif
}

/* output the probing results */
void dump_route()
{
    	int i, j, k1, k2;
	double rtt1, rtt2, rtt;
	double bw;
	char hostname[MAXHOSTNAMELEN], ipstr[16], my_ipstr[16];
	uint32_t cur_ip;
    //printf ("Dumping Routes\n");
	if (on_line_processing)
	    get_choke();

	printf("%s %d\n", info_line1, delay_num);
	printf("%s", info_line2);

	/* no valid reponse */
	if (ip_path_len == 0 && !ip_path[0].ip) {
	    printf("# no hop reponses\n\n");
	    return;
	}

	printf("\n");
	j = 0;
	for (i=0; i<=ip_path_len; i++) {
	    if (!dns_lookup) {
		strcpy(hostname, ip2str(ip_path[i].ip));
	    } else {
		strcpy(my_ipstr, ip2str(ip_path[i].ip));
		GetCannonicalInfo(my_ipstr, hostname, &cur_ip, ipstr);
	    }

	    k1 = ip_path[i].index[0];
	    rtt1 = time_path[k1].rtime - time_path[k1].stime;
	    k2 = ip_path[i].index[1];
	    rtt2 = (time_path[k2].rtime - time_path[k2].stime);
	    rtt = (rtt1 + rtt2) / 2;

	    /* the basic output */
	    printf("%02d %7.3f %15s %6d", 
		    i, rtt1 * 1000, ip2str(ip_path[i].ip),
		    (int)(ip_path[i].avg_gap * 1000000));
	    /* if require on line detection*/
	    if (on_line_processing) {
		if (i == node[j].index) {
		    printf(" %6d", node[j].gap1);
		    if (selected[j]) 
			printf(" %c", selected[j][1]);
		    else
			printf(" %c", '.');

		    bw = ((double)udp_probing_size * udp_pkt_num * 8) / (1000000 * (double)ip_path[i].avg_gap);
		    if (node[j].bw_flag > 0)
			printf(" %7.3f ub", bw);
		    else if (node[j].bw_flag < 0)
			printf(" %7.3f lb", bw);
		    else 
			printf(" %7.3f uk", 0.0);

		    j ++;

		} else {
		    printf(" %6d . %7.3f uk", 0, 0.0);
		}
	    }
	    /* IP -> DNS name lookup */
	    if (dns_lookup)
		printf(" %s", hostname);
	    printf("\n");
	}

	/* confidence information */
	if (on_line_processing) {
	    printf("conf =");
	    for (i=0; i<num_choke; i++) 
		printf(" %.3f", conf[i]);
	    printf("\n");
	}
	printf("\n");

	/* dump rtt */
	if (avg_rtt) {
	    printf("rtt = %.3f ( %s )\n", 
		    avg_rtt * 1000, ip2str(rtt_dst));
	    printf("\n");
	}

	if (dump_send_time) {
	    for (i = 0; i<send_i2; i++) {
	    	printf("%03d %.6f\n", i, send_time2[i]);
	    }
	    printf("\n");
	}
}

#if defined USE_PCAP
//Pcap addition
void pcap_init(){
  pcap_if_t *alldevs;
  pcap_if_t *d;
  char *dev;
  int inum;
  int i=0;
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_dumper_t *dumpfile;
  
  /* Retrieve the device list*/
  if(pcap_findalldevs(&alldevs, errbuf) == -1){
    fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
    exit(1);
  }
  
  /* Print the list */
  for(d=alldevs; d; d=d->next)
    {
      ++i;
      //printf("%d. %s", ++i, d->name);
      //if (d->description)
      //	printf(" (%s)\n", d->description);
      //else
      //	printf(" (No description available)\n");
    }
  
  if(i==0)
    {
      printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
      return ;
    }

#if 0
  printf("Enter the interface number (1-%d):",i);
  scanf("%d", &inum);
  
  if(inum < 1 || inum > i)
    {
      printf("\nInterface number out of range.\n");
      /* Free the device list */
      pcap_freealldevs(alldevs);
      return ;
    }
#endif
  inum = 1;
  /* Jump to the selected adapter */
  for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
  //dev=pcap_lookupdev(errbuf);
  //printf("DEV %s\n", dev);
  /* Open the device */
  /* Open the adapter */
  if ((adhandle= pcap_open_live(d->name,	// name of the device
				65536,			// portion of the packet to capture. 
				// 65536 grants that the whole packet will be captured on all the MACs.
				0,				// promiscuous mode (nonzero means promiscuous)
				1,			// read timeout
				errbuf			// error buffer
				)) == NULL)
    {
      fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* Free the device list */
      pcap_freealldevs(alldevs);
      return ;
    }
  
  pcap_setnonblock(adhandle, 1, errbuf);
  //  printf("\nlistening on %s...\n", d->name);
  
  
  NetMask=0xffffff;
  struct bpf_program fcode;
  char *filter = "proto ICMP";
  
    //compile the filter
  if(pcap_compile(adhandle, &fcode, filter, 1, NetMask) < 0){
    fprintf(stderr,"\nError compiling filter: wrong syntax.\n");
    pcap_close(adhandle);
    return;
  }
  
    //set the filter
  if(pcap_setfilter(adhandle, &fcode)<0){
    fprintf(stderr,"\nError setting the filter\n");
    pcap_close(adhandle);
    return;
  }
  
	
  /* At this point, we don't need any more the device list. Free it */
  pcap_freealldevs(alldevs);

  srand(time(NULL)+getpid());
  MAGIC_NUM = (rand() * rand())%MAGIC_NUM;
  printf("MAGIC_NUM 0x%x\n", MAGIC_NUM);
  
}


#endif

/* only receive and store, avoid on-line processing as much as possible */
void recv_pkts(int last)
{
    	char buffer[1024];
	int len, addrlen;
	struct sockaddr_in addr;

#ifdef _BSD
	fd_set rfds;
	struct timeval tv;
	int retval;
#endif

	struct iphdr * iphdr;
	struct icmp * icmp;

	int cnt = 0;
	double pre_time, cur_time;

	/* receive */
	pre_time = get_time();
	cur_time = pre_time;

	cnt = 0;
	while (cnt < 2*end_pkt_num) {

#ifdef _BSD 
            FD_ZERO(&rfds);
	    FD_SET(udpicmp_sock, &rfds);
	    tv.tv_sec = 0;
	    tv.tv_usec = 0;
	    retval = select(udpicmp_sock + 1, &rfds, NULL, NULL, &tv);

	    if (!(retval && FD_ISSET(udpicmp_sock, &rfds))) {
		if (!last) return;
		cur_time = get_time();
		if (cur_time - pre_time > 3)
		    break;
		continue;
	    }
#endif

	    addrlen = sizeof(addr);
	    memset(buffer, 0, sizeof(buffer));

#ifdef USE_PCAP
	    //printf("Calling pcap\n");
        len = pcap_next_ex( adhandle, &header, &pkt_data);
        //printf("pcap returned %d\n", len);
        if(len>0){
            memcpy(buffer, pkt_data + 14, header->len - 14);
            len = header->len-14;
        }
        //buffer = (char*)((unsigned int)buffer + 14); //remove ether header
#else
	    len=recvfrom(udpicmp_sock, buffer, sizeof(buffer), MSG_DONTWAIT, 
			    (struct sockaddr*)&addr, &addrlen);
#endif

	    if (len > 0) {
	       	iphdr = (struct iphdr *)buffer;
	       	icmp  = (struct icmp *)(buffer + ((iphdr->ihl * 4)>20 ? (iphdr->ihl*4) : 20));

#ifdef USE_PCAP
		//print_IP(iphdr);
		//printf("ICMP %d %d %d %x %x\n", icmp->icmp_type, ICMP_ECHOREPLY,  (iphdr->ihl<<2), MAGIC_NUM, htonl(icmp->icmp_mask));
#endif

		/* icmp echoreply is supposed to be from the last hop */
		if (icmp->icmp_type == ICMP_ECHOREPLY) {
		    /* make sure the data part is match the magic number,
		     * o.w., it is not our packets */
#ifdef USE_PCAP || 0
		    if (htonl(icmp->icmp_mask) != MAGIC_NUM)
#else
		    if (ntohl(icmp->icmp_mask) != MAGIC_NUM)
#endif
			continue;

		    //printf("Matched packet\n");
		    /* if "-c" is specified, rtt_i could exceed MAX_RTT_NUM */
		    if (rtt_i < MAX_RTT_NUM) {
                memcpy(rtt_rec[rtt_i], buffer, len);
                rtt_arr_time[rtt_i] = get_time();
                pre_time = rtt_arr_time[rtt_i];
                rtt_i ++;
		    }
		    continue;
		}

		if (icmp->icmp_type != ICMP_TIMXCEED)
		    continue;
		//printf("ICMP_TIMXCEED\n");
		/* need to check the Internet head to make sure it is
		 * our packets */
#ifdef USE_PCAP
        //iphdr = (struct iphdr *)((void *)icmp + 4);
        iphdr = (struct iphdr*)(& icmp->icmp_dun.id_ip);
#else
        iphdr = (struct iphdr *)(buffer + (iphdr->ihl<<2) + 8);
#endif
        //printf("Our packet? %s - ", ip2str(iphdr->daddr));
        //printf("Our packet? %s - ", ip2str(iphdr->saddr));
        //printf("Our packet? %s %d\n", ip2str(ip), iphdr->ihl);
		if (iphdr->daddr != ip)
		    continue;
		//printf("Yes our packet\n");

		memcpy(path_rec[rec_i], buffer, len);	
		arr_time[rec_i] = get_time();
		pre_time = arr_time[rec_i];
		rec_i ++;
		if (rec_i >= MAX_REC) break;

		if (debug)
		    printf("rec_i = %d\n", rec_i);

		cnt ++;
	    }	
	    else {
		if (!last) return;

		cur_time = get_time();
		if (cur_time - pre_time > 3) 
		    break;

		continue;
	    }
	}
}

/* send out a train with ttl */
void send_pkts(uint32_t ip, int delay_num)
{	
	int j, k, di;
	double tmp = 133333.000333;
	double stime, etime;

	struct timeval tv;

	/* allow recv_pkts() to resume */
	tv.tv_sec = 0;
	tv.tv_usec = 300000;
	select(0, NULL, NULL, NULL, &tv);

	stime = get_time();

	/* for udp probing, send max_num_rtt icmp echo packets to 
	 * measure rtt */
	if (!icmp_probing && !planetlab) {
	    icmp_probing = 1;
	    set_icmp_header();
	    for (j=1; j<=MAX_RTT_NUM; j++) {
	    	k = end_pkt_num * TRAIN_LEN + 2 + udp_pkt_num + j;
		send_echo_udp(k, 60, 100, ip);
	    }

	    /* reset for udp probing */
	    icmp_probing = 0;
	    set_udp_header();
	}

	/* the head measurement packets */
	for (j=1; j<=end_pkt_num; j++) {
	    k = j * TRAIN_LEN;
	    send_echo_udp(k, 60, j, ip);
	}

	/* the load packets */
	for (j=0; j<udp_pkt_num; j++) {
	    if (debug) {
	    	printf("%d\n", j);
	    }

	    recv_pkts(0);

	    /* load packet, k doesn't change to avoid using too much 
	     * destination ports, and avoid triggering the alarm */
	    k = 0;
	    send_echo_udp(k, udp_probing_size, 100, ip);

	    if (j == udp_pkt_num - 1)
		break;

	    /* src gap generation */
	    for (di=0; di<delay_num; di++) {
		tmp = tmp * 7;
		tmp = tmp / 13;
		if (di % 20 == 0)
		    recv_pkts(0);
	    }
	}

	/* the end measurement packets */
	for (j=1; j<=end_pkt_num; j++) {
	    k = (end_pkt_num-j+1) * TRAIN_LEN + 1;
	    send_echo_udp(k, 60, end_pkt_num-j+1, ip);
	}

	etime = get_time();

	recv_pkts(1);

	sprintf(info_line1, "%f %s %d %d", stime,
		ip2str(ip), udp_probing_size, udp_pkt_num);
}

/* store the rtt measurment (echo reply) packets, used by store() */
void store_rtt()
{
	int i, j;
	struct iphdr *iphdr;
	struct icmp *icmp;
	double cur_rtt;
	double sum_rtt = 0;
	int rtt_cnt = 0;

	/* store the rtt packets  */
	for (i=0; i<rtt_i; i++) {

	    iphdr = (struct iphdr *)&(rtt_rec[i]);
        icmp  = (struct icmp *)((char *)(rtt_rec[i]) + ((iphdr->ihl * 4)>20 ? (iphdr->ihl*4) : 20));
	    //icmp  = (struct icmp *)((char *)(rtt_rec[i])+(iphdr->ihl<<2));

	    /* echoreply packet can only be generated by
	     * icmp probing packets */
	    j = ntohs(icmp->icmp_seq) - port;
        //printf("J %d %d\n",  ntohs(icmp->icmp_seq), port);
	    if (j >= 0)  {
            cur_rtt = rtt_arr_time[i] - send_time[j];
            rtt_dst = iphdr->saddr;
            sum_rtt += cur_rtt; 
            
		/* we only compute the first 5 rtt echo reply packets,
		 * later reply tends to have larger error due to icmp packet
		 * generation delay */
            if (++rtt_cnt > MAX_RTT_NUM) break;
            
            if (debug) 
                printf("%2d rtt: %.3f, %s\n", j, cur_rtt * 1000, ip2str(rtt_dst));
	    }
	    else if (debug) 
            printf("wrong seq number in the echo reply pkt: j = %d\n", j);
	}

	if (rtt_cnt) 
	    avg_rtt = sum_rtt / rtt_cnt; 
}

/* check if this IP already appears for an ealier hop */
int exist_ip_before(uint32_t in_ip) 
{
    	int i;

    	for (i=0; i<=ip_path_len; i++)
	    if (ip_path[i].ip == in_ip) 
		return 1;

	return 0;
}

/* store the time exceeds icmp pkts */
void store()
{
	int i, j, k, k1, k2;

	struct iphdr *iphdr;
	struct icmp *icmp;
	struct udphdr *udphdr;
	struct icmp *icmphdr;

	/* store the headers */
	for (i=0; i<rec_i; i++) {
	       	iphdr = (struct iphdr *)&(path_rec[i]);
            icmp  = (struct icmp *)((char *)(path_rec[i]) + ((iphdr->ihl * 4)>20 ? (iphdr->ihl*4) : 20));
	       	//icmp  = (struct icmp *)((char *)(path_rec[i])+(iphdr->ihl<<2));

	    	memcpy(&(time_path[path_i].iph), iphdr, sizeof(struct iphdr));
	    	memcpy(&(time_path[path_i].icmph), icmp, sizeof(struct icmp));
		time_path[path_i].rtime = arr_time[i];

		if (!icmp_probing) {
		    udphdr = (struct udphdr *)((char *)icmp + 8 + sizeof(struct ip));
#if defined SUN || defined _BSD || defined __APPLE__ || defined __CYGWIN__
		    j = ntohs(udphdr->uh_dport) - port;
#else
		    j = ntohs(udphdr->dest) - port;
#endif
		} else {
		    icmphdr = (struct icmp *)((char *)icmp + 8 + sizeof(struct ip));
		    j = ntohs(icmphdr->icmp_seq) - port;
            //printf("J %d %d\n", ntohs(icmphdr->icmp_seq), port);
		}

		/* @@ when there is route loop, j could be < 0 */
		if (j < 0 || j >= MAX_REC + MAX_UDP_NUM) 
		    continue;

		time_path[path_i].stime = send_time[j];

		k = j % TRAIN_LEN;
		j = (int) j / TRAIN_LEN - 1;

		/* @@ this is also used to deal with route loop */
		if (j > ip_path_len && exist_ip_before(iphdr->saddr)) {
		    sprintf(info_line2 + strlen(info_line2), "%d %s loop\n", 
			    j, ip2str(iphdr->saddr));
		    continue;
		}

		if (debug)
		    printf("%d %d %f %s\n", j, k, arr_time[i],
		    		ip2str(iphdr->saddr));

		ip_path[j].index[k] = path_i;
		ip_path[j].cnt ++;

		if (!ip_path[j].ip) {
		    ip_path[j].ip = iphdr->saddr;
		} else if (iphdr->saddr != ip_path[j].ip) {
		    ip_path[j].as = -1;
		    sprintf(info_line2 + strlen(info_line2), "%d %s ", j, ip2str(iphdr->saddr));
		    sprintf(info_line2 + strlen(info_line2), "%s\n", ip2str(ip_path[j].ip));
		}

		if (j > ip_path_len)
	    	    ip_path_len = j;

		path_i ++;
	}
	rec_i = 0;

	for (i=0; i<=ip_path_len; i++) {
	    k1 = ip_path[i].index[0];
	    k2 = ip_path[i].index[1];
	    if (k1>=0 && k2>=k1) 
	    	ip_path[i].avg_gap = time_path[k2].rtime - time_path[k1].rtime;
	}

	store_rtt();
}

void probe_once()
{
    	if (verbose) 
	    printf("probe_once() with [%d %d]\n", udp_pkt_num, delay_num);

    	clean_path();
	send_pkts(ip, delay_num);
	if (rec_i > 0) store();
}

int main(int argc, char * argv[])
{
	int opt;
    	int sock;
	struct sockaddr_in src_addr;
#ifndef SUN
	struct in_addr in_s;
#endif
	int src_size;

	/* we have too many options here, but SUN generally doesn't
	 * support getopt_long, so have to live with these short options */

        while ((opt = getopt(argc, argv, "e:i:l:s:y:coptxdvh")) != EOF) {
            switch ((char)opt) {
            case 'e':
		end_pkt_num = atoi(optarg);
                break;
            case 'i':
		self_ip = inet_addr(optarg);
                break;
            case 'l':
		udp_pkt_num = atoi(optarg);
                break;
            case 's':
		udp_probing_size = atoi(optarg);
                break;
            case 'y':
		delay_num = atoi(optarg);
                break;

            case 'c':
		icmp_probing = 1;
                break;
	    case 'o':
		on_line_processing = 1;
		break;
            case 'p':
		planetlab = 1;
                break;
	    case 't':
		dump_send_time = 1;
		break;
            case 'x':
		dns_lookup = 1;
                break;

            case 'd':
		debug = 1;
                break;
            case 'v':
		verbose = 1;
                break;
	
            case 'h':
	    default:
		usage();
	    }
	}
	switch (argc - optind) {
        case 1:
#ifdef SUN
	    /* if it is IP, break immeadiately */
	    if (inet_aton(argv[optind], &in_s) != 0) {
		strcpy(dst_ip_str, argv[optind]);
		ip = in_s.s_addr;	
		break;
	    }
#else
	    ip = inet_addr(argv[optind]);
	    if (ip == -1) 
		ip = 0;
	    else
		break;
#endif

	    /* otherwise, convert from hostname to IP */
	    if (GetCannonicalInfo(argv[optind], dst_hostname, 
			&ip, dst_ip_str) < 0)
		exit(0);
	    break;
	default:
	    usage();
	}

	if (!self_ip) {
	    if (gethostname(self_hostname, sizeof(self_hostname)) < 0) {
		perror("gethostname() failed");	
		exit(1);
	    } 

	    /* this method gives us the ip 0.0.0.0, but works so far */
	    sock = socket(AF_INET, SOCK_STREAM, 0);
	    src_size = sizeof(struct sockaddr);
	    getsockname(sock, (struct sockaddr *)&src_addr, &src_size);
	    self_ip = src_addr.sin_addr.s_addr;
	    close(sock);
	}

	init();
	
	probe_once();
	dump_route();

	close(udp_sock);
	close(udpicmp_sock);

	/* keep "make" happy */
	return 0;
}
