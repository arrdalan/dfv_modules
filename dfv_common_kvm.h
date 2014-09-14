/*
 * Device File-based I/O Virtualization (DFV)
 * File: dfv_common_kvm.h
 *
 * Copyright (c) 2014 Rice University, Houston, TX, USA
 * All rights reserved.
 *
 * Authors: Ardalan Amiri Sani <arrdalan@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#define DFVK_SH_PAGE_RES_OFF		3

enum dfvk_custom_ops {
	DFVK_CUSTOM_OP_SHARE_PAGE = 0,
	DFVK_CUSTOM_OP_IRQ_PAGE = 1,
	DFVK_CUSTOM_OP_FINISH_VM = 2
};

#define DFVK_CUSTOM_OP				CUSTOM_REQ_ARG1

#define DFVK_CUSTOM_SHARE_PAGE_GFN 		CUSTOM_REQ_ARG2
#define DFVK_CUSTOM_SHARE_PAGE_RESULT		CUSTOM_RES_ARG1

#define DFVK_CUSTOM_IRQ_PAGE_GFN 		CUSTOM_REQ_ARG2
#define DFVK_CUSTOM_IRQ_PAGE_RESULT		CUSTOM_RES_ARG1

/* FIXME: do not hard-code */
#define DFVK_IRQ_NUM	 		13

#define DFVK_IRQ_TYPE_OFF		3
#define DFVK_IRQ_NUM_ARGS		9
