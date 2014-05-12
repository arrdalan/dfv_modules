/*
 * Device File-based I/O Virtualization (DFV)
 * File: dfv_drm.c
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

#include <linux/module.h>
#include <linux/slab.h>
#include "dfv_common.h"
#include "dfv_server.h"
#include "dfv_drm.h"

static struct guest_struct *fg_guest = NULL;

struct guest_struct *get_fg_guest(void)
{
	return fg_guest;
}
EXPORT_SYMBOL(get_fg_guest);

bool __dfv_is_fg(void)
{
	if (fg_guest)
		return true;

	return false;
}

int __dfv_drm_setcrtc(bool is_dfv)
{
	if (is_dfv)
		fg_guest = (struct guest_struct *) current->dfvguest;
	else
		fg_guest = NULL;

	return 0;
}

int __dfv_drm_rmfb(void)
{
	return 0;
}

static int __init dfv_drm_init(void)
{
	dfv_drm_setcrtc = __dfv_drm_setcrtc;
	dfv_drm_rmfb = __dfv_drm_rmfb;
	dfv_is_fg = __dfv_is_fg;

	return 0;
}

static void __exit dfv_drm_exit(void)
{
}

module_init(dfv_drm_init);
module_exit(dfv_drm_exit);

MODULE_AUTHOR("Ardalan Amiri Sani <arrdalan@gmail.com>");
MODULE_DESCRIPTION("Module for keeping track of foreground/background VMs "
		   "graphics for Device File-based I/O Virtualization");
MODULE_LICENSE("GPL");
