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

/*  Copied from get-choke.c, used by pathneck.c for on-line processing
 *  to get the choke points */

#include <stdio.h>
#include <stdlib.h>
#ifdef SUN
#include <strings.h>
#else
#include <string.h>
#endif

#include "choke.h"
#include "pathneck.h"
#include "util.h"

struct node_t in_node[MAX_PATH]; 	/* the original reading */
struct node_t node[MAX_PATH]; 		/* used for processing, by discarding
					 the unuseless elements from in_node */
int in_path_len = 0;
int path_len = 0;

char * selected[MAX_PATH];
double conf[MAX_SEG_NUM];
double conf_gap[MAX_SEG_NUM];
int choke_gap[MAX_SEG_NUM];
int num_choke = 0;

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
    //printf("Snit0\n");

    if (in_path_len < 4)
	    return 0;
    //printf("Snit1\n");
    
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

    //printf("Snit2\n");
    
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

    //printf("Snit3\n");
    
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
	    } else if (node[k].gap < node[k-1].gap1 && 
                   node[k].gap < node[k+1].gap) {
            node[k].gap1 = (node[k-1].gap1 < node[k+1].gap) ? 
                node[k-1].gap1 : node[k+1].gap;
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

    sleep(1);

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
                    }
                }
            }
            // sleep(1);
	    }
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

void dump(int real_dump)
{
    	int i, j, conf_i;
	char num_str[2];

	j = 0;
	for (i=0; i<in_path_len; i++) {
	    if (i == node[j].index) {
		if (real_dump)
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
		    if (real_dump)
		    	printf("%s ", selected[j]);

		    choke_gap[num_choke] = node[j].gap1;
		    num_choke ++;

		    num_str[0] = selected[j][1]; 
		    num_str[1] = 0;
		    conf_i = atoi(num_str) - 1; 

		    if (j==0) {
		    	conf[conf_i] = 1;
		    	conf_gap[conf_i] = 1;

		    } else {
		    	conf[conf_i] = abs(1/(double)node[j-1].gap1 - 1/(double)node[j].gap1) / (1/(double)node[j-1].gap1);
		    	conf_gap[conf_i] = abs((double)node[j-1].gap1 - (double)node[j].gap1) / (double)node[j-1].gap1;

			if (node[j].gap1 < node[j-1].gap1)
			    node[j].bw_flag = 0;
			else
			    node[j].bw_flag = 1; /* upper bound */
		    }
		}
		else 
		    if (real_dump)
		    	printf("    ");
	    } else {
		if (real_dump)
		    printf("%-5d %-5d     ", in_node[i].gap, in_node[i].gap1);
	    }

	    if (real_dump)
	    	printf("%7.3f %-15s %6s %s\n", 
		    in_node[i].rtt, in_node[i].ip_str, 
		    in_node[i].as, in_node[i].hostname);

	    if (i == node[j].index && j < path_len-1) 
		j++;
	}

	/* out the confidence line */
	if (real_dump) {
	    printf("conf = ");
	    for (i=0; i<num_choke; i++) {
		printf("%.3f ", conf[i]);
	    }
	    printf("\n\n");
	}
}

void clean_choke_data()
{
    memset(in_node, 0, sizeof(struct node_t) * MAX_PATH);
    memset(node, 0, sizeof(struct node_t) * MAX_PATH);
	in_path_len = 0;
	path_len = 0;
    memset(selected, 0, sizeof(char *) * MAX_PATH);
    memset(conf, 0, sizeof(double) * MAX_SEG_NUM);
    memset(conf_gap, 0, sizeof(double) * MAX_SEG_NUM);
    memset(choke_gap, 0, sizeof(int) * MAX_SEG_NUM);
	num_choke = 0;
}

void get_choke() 
{
    	int i;
        //printf("Get Choke\n");        
        clean_choke_data();

        for (i=0; i<=ip_path_len; i++) {
            in_node[i].rtt = 0;
            in_node[i].gap = (int)(ip_path[i].avg_gap * 1000000);
            in_node[i].ip_str[0] = 0;
            in_node[i].as[0] = 0;
            strcpy(in_node[i].hostname, ip2str(ip_path[i].ip));
            in_node[i].gap1 = 0;
        }
        in_path_len = ip_path_len + 1;
        //printf("Pre sanit\n");
        
        if (sanity_check()) 
            segment_all();
        
	dump(0);
}
