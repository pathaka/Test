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
 *  The in_cksum() used in this file is copied from traceroute source code, 
 *  which is under BSD license.
 ****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <arpa/inet.h>

double get_time()
{
        struct timeval tv;
        struct timezone tz;
        double cur_time;

        if (gettimeofday(&tv, &tz) < 0) {
            perror("get_time() fails, exit\n");
	    exit(1);
        }

        cur_time = (double)tv.tv_sec + ((double)tv.tv_usec/(double)1000000.0);
	//printf("Time: %f\n", cur_time);
        return cur_time;
}

/* find the delay number which can set the src_gap exactly as "gap" */
int get_delay_num(double gap) 
{
#define Scale 		(10)
	int lower, upper, mid;
	double s_time, e_time, tmp;
	int k;

	lower = 0;
	upper = 16;
	tmp = 133333.000333;

	/* search for upper bound */
	s_time = e_time = 0;
	while (e_time - s_time < gap * Scale) {
	    s_time = get_time();
	    for (k=0; k<upper * Scale; k++) {
		tmp = tmp * 7;
		tmp = tmp / 13;
	    }
	    e_time = get_time();

	    upper *= 2;
	}

	/* binary search for delay_num */
	mid = (int)(upper + lower) / 2;
	while (upper - lower > 20) {
	    s_time = get_time();
	    for (k=0; k<mid * Scale; k++) {
		tmp = tmp * 7;
		tmp = tmp / 13;
	    }
	    e_time = get_time();

	    if (e_time - s_time > gap * Scale) 
		upper = mid;
	    else 
		lower = mid;

	    mid = (int)(upper + lower) / 2;
	}

	return mid;
}

char * ip2str(unsigned long ip)
{
	struct in_addr s;

	s.s_addr = ip;
	return inet_ntoa(s);
}

u_short in_cksum(register u_short *addr, register int len)
{
	register int nleft = len;
	register u_short *w = addr;
	register u_short answer;
	register int sum = 0;

	/*  Our algorithm is simple, using a 32 bit accumulator (sum),
	 *  we add sequential 16 bit words to it, and at the end, fold
	 *  back all the carry bits from the top 16 bits into the lower
	 *  16 bits.
	 */
	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1)
		sum += *(u_char *)w;

	/*
	 * add back carry outs from top 16 bits to low 16 bits
	 */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return (answer);
}
