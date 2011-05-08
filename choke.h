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

#ifndef choke_h
#define choke_h

#define MAX_PATH	30	/* max number of nodes in a path */
#define MAX_SEG_NUM	6	/* max # of segments splitted */
#define GAP_THRESHOLD	100	/* minimum gap difference */
#define PATH_MAP_LEN    7       /* bit map for the whole path's nodes */

#define DEBUG		0
#define DEBUG2		0

#define abs(a) 		(((a)>0) ? (a) :(-(a)))

struct node_t {
    	double rtt;
	int    gap;	/* original value */
	int    gap1; 	/* after sanity check */
	int    bw_flag; /* -1->lower bound; 1->upper bound; 0->unknown*/
	char   ip_str[16];
	char   as[128];
	char   hostname[256];

	int    index;  	/* only used in processing, used to map back to 
			   in_node */
};

struct rec_t {
    	double opt;
	double ls; 
	double fs; 
	char   sp[PATH_MAP_LEN];
};

extern struct node_t in_node[MAX_PATH]; 	/* the original reading */
extern struct node_t node[MAX_PATH]; 		/* used for processing */
extern int in_path_len;
extern int path_len;

extern char * selected[MAX_PATH];
extern double conf[MAX_SEG_NUM];
extern double conf_gap[MAX_SEG_NUM];
extern int choke_gap[MAX_SEG_NUM];
extern int num_choke;

void get_choke();

#endif /* choke_h */
