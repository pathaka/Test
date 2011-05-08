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
#include <unistd.h>
#include <string.h>

#include "get-line.h"

char * cur_pos = (char *)0;
char * end_pos = (char *)-1; 	/* this initializatio is a must */
char file_read_buf[BUF_SIZE];

int get_line(char items[MAX_ITEM_NUM][LINE_SIZE], FILE * fp) 
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
	    if ((item_cnt<MAX_ITEM_NUM) && (((*cur_pos) == ' ') || 
		((*cur_pos) == EOLN))) {
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

#if 0 /* this is an example on how to use get_line() */
void read_in_map(char * filename)
{
	char item[2][128];
	char *pos;
	char tmp_str[16];
	int mask_num;

	struct map_item * p;

    	if ((fp = fopen(filename, "r")) == NULL) {
	    perror("file open");
	    exit(1);
	}

	/* read into an link list first, for the convenience of sorting */
	while (get_line(item) == 2) {
	    p = (struct map_item *)malloc(sizeof(struct map_item));
	    pos = index(item[0], '/');
	    *pos = 0;

	    strncpy(tmp_str, item[0], pos-item[0]+1);
	    p->ip = inet_addr(tmp_str);
	    // printf("%x\n", p->ip);

	    strcpy(tmp_str, pos+1);
	    mask_num = atoi(tmp_str);
	    p->mask = (0xffffffff >> (32-mask_num));

	    p->as = atoi(item[1]);
	    p->next = NULL;

	    as_map[map_size] = p;
	    map_size ++;
	}
}
#endif
