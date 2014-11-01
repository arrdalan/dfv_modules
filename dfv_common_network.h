/*
 * Device File-based I/O Virtualization (DFV)
 * File: dfv_common_network.h
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

#ifdef CONFIG_ARM

#define THROUGHPUT_NUM_PAGES		1000

#define DFV_IOREMAP_TYPE MT_DEVICE_WC
#endif /* CONFIG_ARM */

#define DFVN_BUFFER_SIZE		65536

#define DFVN_DATA_MAX_ENTRIES 	2
#define DFVN_IP_LENGTH         	32

enum dfvn_operation_type {
	DFVN_OPTYPE_REQUEST = 0,
	DFVN_OPTYPE_RESULT = 1,
	DFVN_OPTYPE_COPY_FROM_CLIENT = 2,
	DFVN_OPTYPE_COPY_TO_CLIENT = 3,
	DFVN_OPTYPE_DSM = 4
};

struct dfvn_packet {
	unsigned long arg_1;
	unsigned long arg_2;
	unsigned long arg_3;
	unsigned long arg_4;
	unsigned long arg_5;
	unsigned long arg_6;
	enum dfvn_operation_type type;
	unsigned long prefetch_size;
};

enum dfvn_acknowledgement {
	DFVN_ACK_FOP_REQUEST_RECEIVED = 1,
	DFVN_ACK_FOP_RESULT_RECEIVED = 2,
	DFVN_ACK_RESPONSE_RECEIVED = 3,
	DFVN_ACK_COPY_FROM_CLIENT_COMPLETE = 4,
	DFVN_ACK_COPY_TO_CLIENT_COMPLETE = 5,
	DFVN_ACK_CONTINUE = 6
};

#define DFVN_ARGS_GUEST_ID				dfvnpacket->arg_1
#define DFVN_ARGS_GUEST_THREAD_ID			dfvnpacket->arg_2

#define DFVN_ARGS_COPY_FROM_CLIENT_FROM			dfvnpacket->arg_3
#define DFVN_ARGS_COPY_FROM_CLIENT_COUNT			dfvnpacket->arg_4

#define DFVN_ARGS_COPY_TO_CLIENT_TO			dfvnpacket->arg_3
#define DFVN_ARGS_COPY_TO_CLIENT_COUNT			dfvnpacket->arg_4

enum dfvn_custom_ops {
	DFVN_CUSTOM_OP_ION_ALLOC = 0,
	DFVN_CUSTOM_OP_ION_TILER_ALLOC = 1,
	DFVN_CUSTOM_OP_ION_MAP = 2,
	DFVN_CUSTOM_OP_ION_FREE = 3
};

#define DFVN_CUSTOM_OP			CUSTOM_REQ_ARG1

#define DFVN_ION_ALLOC_LEN 		CUSTOM_REQ_ARG2
#define DFVN_ION_ALLOC_FLAGS_ALIGN	CUSTOM_REQ_ARG3
#define DFVN_ION_ALLOC_HANDLE		CUSTOM_REQ_ARG4
#define DFVN_ION_ALLOC_RESULT		CUSTOM_RES_ARG1

#define DFVN_ION_TILER_ALLOC_W_H 	CUSTOM_REQ_ARG2
#define DFVN_ION_TILER_ALLOC_FMT		CUSTOM_REQ_ARG3
#define	DFVN_ION_TILER_ALLOC_HANDLE	CUSTOM_REQ_ARG4
#define DFVN_ION_TILER_ALLOC_RESULT	CUSTOM_RES_ARG1
#define DFVN_ION_TILER_ALLOC_STRIDE	CUSTOM_RES_ARG2
#define DFVN_ION_TILER_ALLOC_OFFSET	CUSTOM_RES_ARG3

#define DFVN_ION_MAP_HANDLE 		CUSTOM_REQ_ARG2
#define DFVN_ION_MAP_ADDR		CUSTOM_REQ_ARG3
#define DFVN_ION_MAP_RESULT		CUSTOM_RES_ARG1

#define DFVN_ION_FREE_HANDLE 		CUSTOM_REQ_ARG2
#define DFVN_ION_FREE_RESULT		CUSTOM_RES_ARG1

int dfvn_send(ksocket_t sockfd, char * data, int size);
int dfvn_receive(ksocket_t sockfd, char *data, int size);
void prepare_error_response_packet(struct dfvn_packet *dfvnpacket);
int resize_data_buffer(int reqsize, char **databuffer, int *databuffersize);
