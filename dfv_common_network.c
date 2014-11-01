/*
 * Device File-based I/O Virtualization (DFV)
 * File: dfv_common_network.c
 *
 * Copyright (c) 2014 Rice University, Houston, TX, USA
 * All rights reserved.
 *
 * Authors: Ardalan Amiri Sani <arrdalan@gmail.com>
 *
 * Originally based on the Device Virtualization project
 *
 * Copyright (c) 2010 Nokia Research Center, Palo Alto, USA
 * All rights reserved.
 *
 * Authors: Sreekumar Nair
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer,
 *    without modification.
 * 2. Redistributions in binary form must reproduce at minimum a disclaimer
 *    substantially similar to the "NO WARRANTY" disclaimer below
 *    ("Disclaimer") and any redistribution must be conditioned upon
 *    including a substantially similar Disclaimer requirement for further
 *    binary redistribution.
 * 3. Neither the names of the above-listed copyright holders nor the names
 *    of any contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") version 2 as published by the Free
 * Software Foundation.
 *
 * NO WARRANTY
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDERS OR CONTRIBUTORS BE LIABLE FOR SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGES.
 */

#include <linux/module.h>
#include <net/sock.h>
#include "ksocket.h"
#include "dfv_common.h"
#include "dfv_common_network.h"

int dfvn_send(ksocket_t sockfd, char *data, int size)
{
	char *p = data;
	int n = 0;
	int current_size = size;
	int m, restart = 0;

	while (n != size) {

		m = ksend(sockfd, p, current_size, 0);
		if (m == -ERESTARTSYS) {
			restart++;
		} else if (m < 0) {
			DFVPRINTK_ERR("Error: m = %d\n", m);
			break;
		} else {
			n += m;
			current_size -= m;
			p += m;
		}
	}

	if (n != size) {
		DFVPRINTK_ERR("Error: failed to send frame completely. "
			"sent(n) = %d, size = %d\n", n, size);
	}

	return 0;
}

int dfvn_receive(ksocket_t sockfd, char *data, int size)
{
	char *p = data;
	int n = 0;
	int current_size = size;
	int m, restart = 0;

	while (n != size) {

		m = krecvall(sockfd, p, current_size, MSG_WAITALL);
		if (m == -ERESTARTSYS) {
			restart++;
		} else if (m < 0) {
			DFVPRINTK_ERR("Error: m = %d\n", m);
			break;
		} else {
			n += m;
			current_size -= m;
			p += m;
		}
	}

	if (n != size) {
		DFVPRINTK_ERR("Error: failed to receive frame completely. "
			"received(n) = %d, size = %d\n", n, size);
	}

	return 0;
}

void prepare_error_response_packet(struct dfvn_packet *dfvnpacket)
{
	dfvnpacket->arg_1 = -1;
	dfvnpacket->arg_2 = -1;
	dfvnpacket->arg_3 = -1;
	dfvnpacket->arg_4 = -1;
	dfvnpacket->arg_5 = -1;
	dfvnpacket->arg_6 = -1;
	dfvnpacket->prefetch_size = 0;
}

int resize_data_buffer(int reqsize, char **databuffer, int *databuffersize)
{
	if (*databuffersize == 0)
	{
		*databuffersize = DFVN_BUFFER_SIZE;
		*databuffer = kmalloc(*databuffersize, GFP_KERNEL);
		if (!(*databuffer)) {
			DFVPRINTK_ERR("Error1: ran out of memory\n");
			return -ENOMEM;
		}
	}
	else if (reqsize > *databuffersize)
	{

		int size = *databuffersize;

		while (reqsize > size)
			size *= 2;

		*databuffersize = size;
		kfree(*databuffer);
		*databuffer = kmalloc(*databuffersize, GFP_KERNEL);
		if (!*databuffer) {
			DFVPRINTK_ERR("Error2: ran out of memory\n");
			return -ENOMEM;
		}
	}

	return 0;
}
