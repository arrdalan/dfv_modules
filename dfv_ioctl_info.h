/*
 * Device File-based I/O Virtualization (DFV)
 * File: dfv_ioctl_info.h
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

enum ioctl_mem_op_types {
	DFV_COPY_FROM_USER = 0,
	DFV_COPY_TO_USER = 1,
	DFV_MMAP = 2
};

struct ioctl_mem_op {
	int type;
	unsigned long arg_off;
	unsigned long size;
};

int get_ioctl_mem_ops(struct file *file, unsigned long cmd, unsigned long arg,
						struct ioctl_mem_op **entries);
void put_ioctl_mem_ops(struct ioctl_mem_op *entries);
