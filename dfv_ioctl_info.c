/*
 * Device File-based I/O Virtualization (DFV)
 * File: dfv_ioctl_info.c
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
#include <asm/uaccess.h>
#include <linux/slab.h>
#include "dfv_common.h"
#include "dfv_client.h"
#include "dfv_linux_code.h"
#include "dfv_ioctl_info.h"

static int __get_mem_ops_generic(unsigned long cmd, struct ioctl_mem_op *entries)
{
	int ioc_dir, num_ops, i, _entries[2];
	unsigned long size;

	ioc_dir = _IOC_DIR(cmd);

	if (ioc_dir == 0) /* _IO */
		return 0;

	switch(ioc_dir) {
	case 0x1: /* _IOW */
		num_ops = 1;
		_entries[0] = 0; /* copy_from_user */
		break;
	case 0x2: /* _IOR */
		num_ops = 1;
		_entries[0] = 0; /* copy_to_user */
		break;
	case 0x3: /* _IOWR */
		num_ops = 2;
		_entries[0] = 0;
		_entries[1] = 1;
		break;
	default:
		/* Should not happen, but let's check to be sure. */
		DFVPRINTK_ERR("Error: Invalid _IOC_DIR %#x (%d)\n", ioc_dir, ioc_dir);
		return 0;
	}

	size = _IOC_SIZE(cmd);

	for (i = 0; i < num_ops; i++) {
		entries[i].type = _entries[i];
		entries[i].size = size;
		entries[i].arg_off = 0;
	}

	return num_ops;
}

static int get_mem_ops_generic(unsigned long cmd, unsigned long arg,
						struct ioctl_mem_op **entries)
{
	struct ioctl_mem_op *_entries;
	int num_ops;

	_entries = kmalloc(2 * sizeof(*_entries), GFP_KERNEL);
	if (!entries) {
		DFVPRINTK_ERR("Error: memory allocation failed.\n");
		return 0;
	}

	num_ops = __get_mem_ops_generic(cmd, _entries);

	*entries = _entries;

	return num_ops;
}

/*
 * sound ioctls.
 */
static int get_mem_ops_sound(unsigned long cmd, unsigned long arg,
						struct ioctl_mem_op **entries)
{
	struct ioctl_mem_op *_entries;
	int num_ops;

	_entries = kmalloc(3 * sizeof(*_entries), GFP_KERNEL);
	if (!entries) {
		DFVPRINTK_ERR("Error: memory allocation failed.\n");
		return 0;
	}

	num_ops = __get_mem_ops_generic(cmd, _entries);

	if (num_ops > 2) {
		DFVPRINTK_ERR("Error: Invalid num_ops\n");
		goto err_free_out;
	}

	switch (cmd) {
	case SNDRV_PCM_IOCTL_WRITEI_FRAMES:
	{
		struct snd_xferi xferi;
		struct snd_xferi __user *_xferi = (void *) arg;

		if (copy_from_user(&xferi, _xferi, sizeof(xferi))) {
			DFVPRINTK_ERR("Error: copy_from_user failed\n");
			break;
		}
		_entries[num_ops].type = DFV_COPY_FROM_USER;
		_entries[num_ops].size = xferi.frames * 4;
		_entries[num_ops].arg_off = (unsigned long) (xferi.buf - arg);

		num_ops++;

		break;
	}

	default:
		break;
	}

	*entries = _entries;

	return num_ops;

err_free_out:
	kfree(_entries);
	return 0;
}

/*
 * Note: In case of success (return value > 0) when calling any of the
 * get functions, the caller should call the put_ioctl_mem_ops().
 */
int get_ioctl_mem_ops(struct file *file, unsigned long cmd, unsigned long arg,
						struct ioctl_mem_op **entries)
{
	struct dfv_private_data *priv = file->private_data;
	int num_ops = 0;

	switch (priv->ioctl_info_type) {
	case DFV_IOCTL_INFO_GENERIC:
		num_ops = get_mem_ops_generic(cmd, arg, entries);
		break;

	case DFV_IOCTL_INFO_SOUND:
		num_ops = get_mem_ops_sound(cmd, arg, entries);
		break;

	default:
		DFVPRINTK_ERR("Error: invalid ioctl_info_type.\n");
		num_ops = -EINVAL;
		break;
	}

	return num_ops;
}

void put_ioctl_mem_ops(struct ioctl_mem_op *entries)
{
	kfree(entries);
}
