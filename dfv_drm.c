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

struct list_head drm_info_list;

static struct guest_struct *fg_guest = NULL;

struct guest_struct *(*get_fg_guest)(void);
EXPORT_SYMBOL(get_fg_guest);

static struct guest_struct *get_fg_guest_simple(void)
{
	return fg_guest;
}

static struct guest_struct *get_fg_guest_full(void)
{
	struct drm_info_struct *drm_entry = NULL;

	list_for_each_entry(drm_entry, &drm_info_list, list) {
		if (drm_entry->fg == true) {
			return drm_entry->guest;
		}
	}

	return NULL;
}

static bool dfv_is_fg_simple(void)
{
	if (fg_guest)
		return true;

	return false;
}

static bool dfv_is_fg_full(void)
{
	struct guest_struct *fg_guest = NULL;

	fg_guest = get_fg_guest();
	if (fg_guest) {
		return true;
	}
	return false;
}

static struct drm_info_struct *get_drm_entry_by_fb_id(uint32_t fb_id)
{
	struct drm_info_struct *drm_entry = NULL;

	list_for_each_entry(drm_entry, &drm_info_list, list)
	{
		if (drm_entry->fb_id == fb_id) {
			return drm_entry;
		}
	}

	return NULL;
}

static struct drm_info_struct *get_drm_entry_by_prev_fb_id(uint32_t prev_fb_id)
{
	struct drm_info_struct *drm_entry = NULL;

	list_for_each_entry(drm_entry, &drm_info_list, list)
	{
		if (drm_entry->prev_fb_id == prev_fb_id) {
			return drm_entry;
		}
	}

	return NULL;
}

static void push_others_to_bg(uint32_t fg_fb_id)
{
	struct drm_info_struct *drm_entry = NULL;
	struct guest_vm_struct *guest_vm;

	list_for_each_entry(drm_entry, &drm_info_list, list) {
		if (drm_entry->fb_id != fg_fb_id) {
			drm_entry->fg = false;
			guest_vm = drm_entry->guest->guest_vm;

			if (guest_vm->send_drm_notification)
				guest_vm->send_drm_notification(drm_entry->guest,
							DFV_IRQ_DRM_BACKGRND);
			else
				DFVPRINTK_ERR("Error: send_drm_notification is "
					     "not set\n");

		}
	}

	return;
}

int __dfv_drm_setcrtc(uint32_t new_fb_id, uint32_t prev_fb_id, bool is_dfv)
{
	struct drm_info_struct *drm_entry;

	/* fg_guest is updated for *_simple() routines */
	if (is_dfv)
		fg_guest = (struct guest_struct *) current->dfvguest;
	else
		fg_guest = NULL;

	if (new_fb_id == 0)
		return 0;

	if (is_dfv) {
		struct guest_struct *guest = NULL;

		/* FIXME: might only work with KVM */
		guest = (struct guest_struct *) current->dfvguest;
		if (guest == NULL)
			DFVPRINTK_ERR("Error: current->dfvguest is NULL\n");

		drm_entry = get_drm_entry_by_fb_id(new_fb_id);
		if (drm_entry == NULL) {
			drm_entry = kmalloc(sizeof(*drm_entry), GFP_KERNEL);

			drm_entry->fb_id = new_fb_id;
			drm_entry->prev_fb_id = prev_fb_id;
			drm_entry->fg = true;

			drm_entry->guest = guest;
			INIT_LIST_HEAD(&drm_entry->list);
			list_add(&drm_entry->list, &drm_info_list);
		} else {
			drm_entry->prev_fb_id = prev_fb_id;
			drm_entry->fg = true;

			drm_entry->guest = guest;

		}
		push_others_to_bg(new_fb_id);
	} else {
		struct guest_vm_struct *guest_vm;
		drm_entry = get_drm_entry_by_prev_fb_id(new_fb_id);

		if (drm_entry != NULL) {
			guest_vm = drm_entry->guest->guest_vm;
			if (guest_vm->send_drm_notification)
				guest_vm->send_drm_notification(drm_entry->guest,
							DFV_IRQ_DRM_FOREGRND);
			else
				DFVPRINTK_ERR("Error: send_drm_notification is "
					     "not set\n");

			push_others_to_bg(drm_entry->fb_id);
		} else {
			/* push all VM's to bg */
			push_others_to_bg(0);
		}
	}

	return 0;
}

int __dfv_drm_rmfb(uint32_t fb_id)
{
	struct drm_info_struct *drm_entry, *d_tmp;

	list_for_each_entry_safe(drm_entry, d_tmp, &drm_info_list, list) {

		if (drm_entry && drm_entry->fb_id == fb_id) {
			list_del(&drm_entry->list);
			kfree(drm_entry);
		}
	}

	return 0;
}

void dfv_drm_use_full(void)
{
	dfv_is_fg = dfv_is_fg_full;
	get_fg_guest = get_fg_guest_full;
}
EXPORT_SYMBOL(dfv_drm_use_full);

static int __init dfv_drm_init(void)
{
	INIT_LIST_HEAD(&drm_info_list);
	dfv_drm_setcrtc = __dfv_drm_setcrtc;
	dfv_drm_rmfb = __dfv_drm_rmfb;
	dfv_is_fg = dfv_is_fg_simple;
	get_fg_guest = get_fg_guest_simple;

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
