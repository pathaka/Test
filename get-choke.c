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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef SUN
#include <strings.h>
#endif
#include <unistd.h>

#define BUF_SIZE        (1024 * 1024)
#define LINE_SIZE       1024
#define EOLN            10

#define MAX_ITEM_NUM    5	/* number of items in each line */
#define MAX_PATH	50	/* max number of nodes in a path */
#define PATH_MAP_LEN	7	/* bit map for the whole path's nodes */
#define MAX_SEG_NUM	6	/* max # of segments splitted */
#define GAP_THRESHOLD	100	/* minimum gap difference */

#define DEBUG		0
#define DEBUG2		0

#define abs(a) 		(((a)>0) ? (a) :(-(a)))

struct node_t {
    	double rtt;
	int    gap;	/* original value */
	int    gap1; 	/* after sanity check */
	int    bw_flag;
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

FILE * fp = NULL;
char * cur_pos = (char *)0;
char * end_pos = (char *)-1; /* this initializatio is a must */
char file_read_buf[BUF_SIZE];

struct node_t in_node[MAX_PATH]; 	/* the original reading */
struct node_t node[MAX_PATH]; 		/* used for processing */
int in_path_len = 0;
int path_len = 0;

/* default values are set here, will be from commmand line */
int pkt_size = 500; 
int pkt_num = 60;

char * selected[MAX_PATH];

int get_line(char items[MAX_ITEM_NUM][LINE_SIZE]) 
{
	int item_cnt = 0;
	char * s_pos;
	int len;

	/* have we finished the reading? */
	if (cur_pos > end_pos) 
	    return 0; 

	/* we assume one line is never longer than 128 Bytes */
	len = end_pos - cur_pos + 1;

	/* fill the buffer */
	if (len < LINE_SIZE) {
	    int ret;

	    /* move the remaining to the beging of the buffer*/
	    if (len > 0)
	    	memcpy(file_read_buf, cur_pos, len);
	
	    /* read from file */
	    ret = fread(file_read_buf + len, 1, BUF_SIZE - len, fp);
	    if (ret < 0) {
		perror("file read");
		exit(1);
	    }
	    cur_pos = file_read_buf;
	    end_pos = file_read_buf + len + ret - 1;
	}

	s_pos = cur_pos;
	/* read until end of line */
	while (cur_pos <= end_pos) {
	    if ((item_cnt<MAX_ITEM_NUM) && (((*cur_pos) == ' ') || ((*cur_pos) == EOLN))) {
		/* get the string */
		len = cur_pos - s_pos;
		memcpy(items[item_cnt], s_pos, len);
		items[item_cnt][len] = 0;	
		item_cnt ++;
		s_pos = cur_pos+1;
	    }

	    if ((*cur_pos) == EOLN) break;
	    cur_pos ++;
	}
	cur_pos ++;

	return item_cnt;
}

void read_in()
{
        char item[MAX_ITEM_NUM][LINE_SIZE];
	int num;
	int i = 0;

    	while (1) {
	    num = get_line(item); 
	    if (!num) break;

	    in_node[i].rtt = strtod(item[0], NULL); 
	    in_node[i].gap = atoi(item[1]); 
	    strcpy(in_node[i].ip_str, item[2]);
	    strcpy(in_node[i].as, item[3]);
	    strcpy(in_node[i].hostname, item[4]);
	    in_node[i].gap1 = 0;

	    i++;
	    /* we will deal with a path that is longer than MAX_PATH */
	    if (i >= MAX_PATH) break;
	}
	in_path_len = i;
}

/* out is a sorted index for the values in "in" */
void sort(double *in, int *out, int len)
{
    	int i, j;
	int tmp[MAX_PATH];
	double max;
	int maxi;

	for (i=0; i<len; i++) 
	    tmp[i] = in[i];

	for (i=0; i<len; i++) {
	    max = -1;
	    for (j=0; j<len; j++) {
		if (tmp[j] >= 0 && tmp[j] > max) {
		    maxi = j;
		    max = tmp[j];
		}
	    }
	    out[i] = maxi;
	    tmp[maxi] = -1;
	}
}

int sanity_check()
{
    	int sg[MAX_PATH];
	double gap[MAX_PATH];
	int i, j, k;
	int mean_gap;

    	if (in_path_len < 4)
	    return 0;

	path_len = in_path_len;
	for (i=0; i<path_len; i++) {
	    node[i].gap = in_node[i].gap;
	    node[i].rtt = in_node[i].rtt;
	    strcpy(node[i].as, in_node[i].as);
	    strcpy(node[i].hostname, in_node[i].hostname);
	    strcpy(node[i].ip_str, in_node[i].ip_str);
	    node[i].index = i;
	    node[i].gap1 = 0;
	}

	/* detect routing loops */
	i = 1;
	while (i < path_len) {
	    j = 0;
	    while (j < i) {
		if (strcmp(node[i].hostname, node[j].hostname) == 0) {
		    /* remove this one */ 
		    for (k=i+1; k<path_len; k++)
	    		memcpy((void *)&node[k-1], (void *)&node[k], 
				sizeof(struct node_t));
		    path_len --;
		    i --;
		    break;
		}
		j ++;
	    }
	    i ++;
	}

	/* remove 0 gaps  */
	k = 0;
	for (i=0; i<path_len; i++) {
	    if (node[i].gap < 1) {
		k ++;
		continue;
	    }
	    if (k) 
	    	memcpy((void *)&node[i-k], (void *)&node[i], 
				sizeof(struct node_t));
	}
	path_len -= k;

	if (path_len < 4) 
	    return 0;

	for (i=0; i<path_len; i++)
	    gap[i] = (double)node[i].gap;
	sort(gap, sg, path_len);
	i = sg[(int) path_len/2];
	mean_gap = node[i].gap;

	/* deal with the first few small gaps */
	node[0].gap1 = node[0].gap;
	i = 0;
	while (i<path_len && node[i].gap < mean_gap/5) 
    	    i ++;
	if (i >= path_len) return 0;

	for (j=0; j<i; j++) 
	    node[j].gap1 = node[i].gap;

	/* deal with the middle gaps */
	for (k=1; k<path_len-1; k++) {
	    if (node[k].gap < mean_gap/5) {
		node[k].gap1 = node[k-1].gap1;
	    } else if (node[k].gap > node[k-1].gap1 && 
		       node[k].gap > node[k+1].gap) {
		node[k].gap1 = (node[k-1].gap1 > node[k+1].gap) ? 
		    		node[k-1].gap1 : node[k+1].gap;
		if (node[k].gap1 == 0)
		    node[k].gap1 = node[k].gap;
	    } else if (node[k].gap < node[k-1].gap1 && 
		       node[k].gap < node[k+1].gap) {
		node[k].gap1 = (node[k-1].gap1 < node[k+1].gap) ? 
		    		node[k-1].gap1 : node[k+1].gap;
		if (node[k].gap1 == 0) 
		    node[k].gap1 = node[k].gap;
	    } else {
		node[k].gap1 = node[k].gap;
	    }
	}

	k = path_len - 1;
	if (node[k].gap < mean_gap / 5) {
	    node[k].gap1 = node[k-1].gap1;
	} else {
	    node[k].gap1 = node[k].gap;
	}

#if DEBUG
	for (k=0; k<path_len; k++)
	    printf("%6.3f %5d %5d %s\n", 
		    node[k].rtt, 
		    node[k].gap, 
		    node[k].gap1, 
		    node[k].hostname);
#endif

	return 1;
}

/* calculate the segment distance for [si, ei], return the average and
 * distance sum for this segment */
void init_segment(int si, int ei, struct rec_t * rec)
{	
    	int j;
	double sum, cur_avg;
    	
	cur_avg = 0;
	for (j=si; j<=ei; j++) 
	    cur_avg += node[j].gap1;
	cur_avg /= (ei-si+1);

	sum = 0;
	for (j=si; j<=ei; j++) 
	    sum += abs(node[j].gap1 - cur_avg);

	rec->opt = sum;
	rec->ls = cur_avg;
	rec->fs = cur_avg;
}

void bit_merge(char * in1, int k, char * in2, char * dst)
{
    	int i;

	for (i=0; i<MAX_PATH; i++) {
	    dst[i] = in1[i] | in2[i];
	    if (k >= 0 && k < 8) 
		dst[i] |= (0x1 << k);
	    k -= 8; 
	}
}

void segment_all()
{
    	struct rec_t rec[MAX_PATH][MAX_PATH][MAX_PATH];	
	int i, j, l, k, m, i1, i2;
	char * map, mask;
	double diff[MAX_PATH]; 
	int sd[MAX_PATH];
	int diff_len, index, pos[MAX_PATH];
	
	/* initialization */
	bzero((void *)&rec, 
	      sizeof(struct rec_t) * MAX_PATH * MAX_PATH * MAX_PATH);
	for (i=0; i<path_len; i++)
	for (j=i; j<path_len; j++)
	    init_segment(i, j, &rec[i][j][0]);

	/* the dynamic algorithm */
	for (l=1; l<path_len; l++) {
	    for (i=0; i<path_len; i++) {
	    for (j=i; j<path_len; j++) {

		rec[i][j][l] = rec[i][j][l-1];

		for (m=0; m<l; m++) {
		for (k=i; k<j; k++) {
#if DEBUG
		     printf("%d %d %d %d | %.2f %.2f | %.3f %.3f %.3f\n", 
			 i, j, k, l,
			 rec[i][k][m].ls, rec[k+1][j][l-m-1].fs,
			 rec[i][k][m].opt, rec[k+1][j][l-m-1].opt, 
			 rec[i][j][l].opt);
#endif

		     if (abs(rec[i][k][m].ls - rec[k+1][j][l-m-1].fs) > GAP_THRESHOLD 
			 && rec[i][k][m].opt + rec[k+1][j][l-m-1].opt < rec[i][j][l].opt) {
			/* add in one more split point for "k" */
		        rec[i][j][l].opt = rec[i][k][m].opt + rec[k+1][j][l-m-1].opt;
		        bit_merge(rec[i][k][m].sp, k, rec[k+1][j][l-m-1].sp, rec[i][j][l].sp);
		        rec[i][j][l].ls = rec[k+1][j][l-m-1].ls;
		        rec[i][j][l].fs = rec[i][k][m].fs;
		    }
		}}
	    }}
	}

	/* now all the splitting points are in SP[0][path_len-1][path_len-1] */

	/* calculate the gap differences at the splitting points */
	diff_len = 0;
	index = 0;
	map = rec[0][path_len-1][path_len-1].sp;
	for (i=0; i<PATH_MAP_LEN; i++) {
	    mask = 0x1;
	    for (j=0; j<8; j++) {
		if (map[i] & mask) {
		    diff[diff_len] =
			abs(rec[index+1][path_len-1][path_len-1].fs - 
			rec[0][index][path_len-1].ls);
		    pos[diff_len] = index+1;
		    diff_len ++;
		}
		index ++;
		mask = mask << 1;
	    }
	}

	/* if there is no splitting point */
	if (!diff_len) {
	    selected[0] = (char *)malloc(10);
	    sprintf(selected[0], "[1]");
	    return;
	}

	/* here it is */
	sort(diff, sd, diff_len);

	/* the last 3 diff are: * diff[sd[0]], diff[sd[1]], diff[sd[2]] */
	l = (diff_len < 3) ? diff_len : 3;
	for (k=0; k<l; k++) {
	    i1 = pos[sd[k]];
	    i2 = sd[k] + 1;

	    if ((i1 == path_len-1) || 
		((sd[k]+1 < diff_len && 
		  pos[sd[k]+1] - i1 == 1 && 
		  (sd[k]+1 == sd[0] ||
		   sd[k]+1 == sd[1] ||
		   sd[k]+1 == sd[2])))) {
		selected[i1] = (char *)malloc(10);
		sprintf(selected[i1], "(%d)", k+1);
	    } else {
		selected[i1] = (char *)malloc(10);
		sprintf(selected[i1], "[%d]", k+1);
	    }
	}
}

void dump()
{
    	int i, j, conf_i;
	double conf[MAX_SEG_NUM];
	char num_str[2];
	int num_choke = 0;

	double bw;
	char bw_str[3];

	j = 0;
	for (i=0; i<in_path_len; i++) {
	    if (i == node[j].index) {
		printf("%-5d %-5d ", in_node[i].gap, node[j].gap1);

		if (j==0)
		    /* first hop is always considered as an upper bound */
		    node[j].bw_flag = 1; 
		else
		    /* assume this is not a choke point yet, most of hops are
		     * lower bounds */
	    	    node[j].bw_flag = -1;

		/* the choke nodes */
		if (selected[j] != NULL) {
		    printf("%s ", selected[j]);
		    num_choke ++;

		    num_str[0] = selected[j][1]; 
		    num_str[1] = 0;
		    conf_i = atoi(num_str) - 1; 
		    if (j==0) 
		    	conf[conf_i] = 1;
		    else {
		    	conf[conf_i] = abs(1/(double)node[j-1].gap1 - 1/(double)node[j].gap1) / (1/(double)node[j-1].gap1);

			if (node[j].gap1 < node[j-1].gap1)
			    node[j].bw_flag = 0;
			else
			    node[j].bw_flag = 1; /* upper bound */
		    }
		} else 
		    printf("    ");

		/* this need to be further processed by script/get-summary.pl, 
		 * since we don't know pkt_num & pkt_size */
		bw = ((double) pkt_size * pkt_num * 8) / ((double) node[j].gap1); 
		if (node[j].bw_flag > 0)
		    sprintf(bw_str, "ub");
		else if (node[j].bw_flag < 0)
		    sprintf(bw_str, "lb");
		else
		    sprintf(bw_str, "uk");
	    } else {
		printf("%-5d %-5d     ", in_node[i].gap, in_node[i].gap1);
		bw = 0; 
		sprintf(bw_str, "uk");
	    }

	    printf("%7.3f %-15s %6s %7.3f %s %s\n",
		    in_node[i].rtt, in_node[i].ip_str, in_node[i].as, 
		    bw, bw_str, in_node[i].hostname);

	    if (i == node[j].index && j < path_len-1) 
		j++;
	}

	/* out the confidence line */
	printf("conf = ");
	for (i=0; i<num_choke; i++) {
	    printf("%.3f ", conf[i]);
	}
	printf("\n\n");
}

int main(int argc, char * argv[]) 
{
    	if (argc != 4) {
	    printf("wrong command line\n");
	    exit(0);
	}

	if ((fp = fopen(argv[1], "r")) == NULL) {
	    perror("file open error");
	    exit(1);
	}

	pkt_size = atoi(argv[2]);
	pkt_num = atoi(argv[3]);

    	read_in();

	if (sanity_check()) 
	    segment_all();

	dump();

	return 1;
}
