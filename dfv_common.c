/*
 * Device File-based I/O Virtualization (DFV)
 * File: dfv_common.c
 *
 * Copyright (c) 2014 Rice University, Houston, TX, USA
 * All rights reserved.
 *
 * Authors: Ardalan Amiri Sani <arrdalan@gmail.com>
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
#include <linux/slab.h>
#include "dfv_common.h"

static char device_file_pathname[DFV_PATH_LENGTH];
module_param_string(device_file_pathname, device_file_pathname,
					sizeof(device_file_pathname), 0660);
static int device_type;
module_param(device_type, int, 0660);

static int ioctl_info_type = DFV_IOCTL_INFO_GENERIC;
module_param(ioctl_info_type, int, 0660);

static int major_number = -1;
module_param(major_number, int, 0660);

/*
 * This bitmap is used to communicate from the server to the client which
 * operations are supported for a specific file that is opened. The order
 * MUST be exactly similar to dfv_op. Moreover, we cannot have values above
 * 31 since we are using a 32 bit register for the bitmap in 32
 * bit architectures.
 */
struct dfvbitmap dfvbitmap[] = {
	{0}, /* DFV_VMOP_open, */
	{1}, /* DFV_VMOP_close, */
	{2}, /* DFV_VMOP_fault, */
	{3}, /* DFV_VMOP_page_mkwrite, */
	{4}, /* DFV_VMOP_access, */
	{5}, /* DFV_VMOP_set_policy, */
	{6}, /* DFV_VMOP_get_policy, */
	{7}, /* DFV_VMOP_migrate, */

	{0}, /* DFV_EOP_fault1, */
	{1}, /* DFV_EOP_fault2, */

	{0}, /* DFV_FOP_llseek, */
	{1}, /* DFV_FOP_read, */
	{2}, /* DFV_FOP_write, */
	{3}, /* DFV_FOP_aio_read, */
	{4}, /* DFV_FOP_aio_write, */
	{5}, /* DFV_FOP_readdir, */
	{6}, /* DFV_FOP_poll, */
	{7}, /* DFV_FOP_ioctl, */
	{8}, /* DFV_FOP_unlocked_ioctl, */
	{9}, /* DFV_FOP_compat_ioctl, */
	{11}, /* DFV_FOP_mmap, */
	{12}, /* DFV_FOP_open, */
	{13}, /* DFV_FOP_flush, */
	{14}, /* DFV_FOP_release, */
	{15}, /* DFV_FOP_fsync, */
	{16}, /* DFV_FOP_aio_fsync, */
	{17}, /* DFV_FOP_fasync, */
	{18}, /* DFV_FOP_lock, */
	{19}, /* DFV_FOP_sendpage, */
	{20}, /* DFV_FOP_get_unmapped_area, */
	{21}, /* DFV_FOP_check_flags, */
	{22}, /* DFV_FOP_flock, */
	{23}, /* DFV_FOP_splice_write, */
	{24}, /* DFV_FOP_splice_read, */
	{25}, /* DFV_FOP_setlease, */
	{26}, /* DFV_FOP_fallocate, */
};

struct list_head dfv_file_list;
struct file_operations *register_fops;

static int dfv_register_char_device(char *name, int major_num)
{
	int retval;

	if (!register_fops)
		return -EINVAL;

	retval = register_chrdev(major_num, name, register_fops);
	if (retval < 0) {
		DFVPRINTK_ERR("Error: cannot obtain major number %d\n", major_num);
		return retval;
	}

	return 0;
}

static int add_file_to_dfv_file_list(char *filename, int type,
							int ioctl_info_type)
{
	struct dfv_file_struct *dfv_file;

	dfv_file = kmalloc(sizeof(*dfv_file), GFP_KERNEL);
	if (!dfv_file)
		return -ENOMEM;

	dfv_file->filename = kmalloc(strlen(filename) + 1, GFP_KERNEL);
	if (!dfv_file->filename)
		return -ENOMEM;

	strcpy(dfv_file->filename, filename);
	dfv_file->abs_name = type;
	dfv_file->ioctl_info_type = ioctl_info_type;
	INIT_LIST_HEAD(&dfv_file->list);
	list_add(&dfv_file->list, &dfv_file_list);

	return 0;
}

static int remove_file_from_dfv_file_list(const char *pathname)
{
	struct dfv_file_struct *dfv_file, *tmp;

	list_for_each_entry_safe(dfv_file, tmp, &dfv_file_list, list) {

		if (strlen(dfv_file->filename) != strlen(pathname))
			continue;

		if (!strncmp(dfv_file->filename, pathname,
						strlen(dfv_file->filename))) {

			list_del(&dfv_file->list);
			kfree(dfv_file->filename);
			kfree(dfv_file);
			return 0;
		}
	}

	return -EINVAL;
}

void empty_dfv_file_list(void)
{
	struct dfv_file_struct *dfv_file = NULL, *tmp;

	list_for_each_entry_safe(dfv_file, tmp, &dfv_file_list, list) {

		list_del(&dfv_file->list);
		kfree(dfv_file->filename);
		kfree(dfv_file);
	}
}

int get_abs_name_from_pathname(const char *pathname)
{
	struct dfv_file_struct *dfv_file;
	int abs_name;

	list_for_each_entry(dfv_file, &dfv_file_list, list) {

		if (strlen(dfv_file->filename) != strlen(pathname))
			continue;

		if (!strncmp(dfv_file->filename, pathname,
						strlen(dfv_file->filename))) {
			abs_name = dfv_file->abs_name;
			return abs_name;
		}
	}

	return -EINVAL;
}

int get_ioctl_info_from_abs_name(int abs_name)
{
	struct dfv_file_struct *dfv_file;
	int ioctl_info_type;

	list_for_each_entry(dfv_file, &dfv_file_list, list) {
		if (dfv_file->abs_name == abs_name) {
			ioctl_info_type = dfv_file->ioctl_info_type;
			return ioctl_info_type;
		}
	}

	return -EINVAL;
}

char *get_pathname_from_abs_name(int abs_name)
{
	struct dfv_file_struct *dfv_file;
	char *pathname;

	list_for_each_entry(dfv_file, &dfv_file_list, list) {
		if (dfv_file->abs_name == abs_name) {
			pathname = dfv_file->filename;
			return pathname;
		}
	}

	return NULL;
}

static ssize_t add_device_file_show(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf)
{
	int ret, major_num;

	if (device_type < 0)
		return sprintf(buf, "Error: device_type must be >= 0\n");

	if (get_pathname_from_abs_name(device_type))
		return sprintf(buf, "Error: device_type already exists\n");

	if (get_abs_name_from_pathname(device_file_pathname) >= 0)
		return sprintf(buf, "Error: device_file_pathname "
							"already exists\n");

	if (major_number != -1) {
		major_num = major_number;
		major_number = -1;
		ret = dfv_register_char_device(device_file_pathname, major_num);
		if (ret)
			return sprintf(buf, "Error: could not register char "
						"device file %d\n", major_num);
	}

	ret = add_file_to_dfv_file_list(device_file_pathname, device_type,
							ioctl_info_type);
	ioctl_info_type = DFV_IOCTL_INFO_GENERIC; /* default */
	if (ret)
		return sprintf(buf, "Error: could not add device file "
							"(error = %d)\n", ret);

	return sprintf(buf, "device file successfully added\n");
}

static ssize_t add_device_file_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	return 0;
}

static ssize_t remove_device_file_show(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf)
{
	int ret, major_num;

	ret = remove_file_from_dfv_file_list(device_file_pathname);
	if (ret)
		return sprintf(buf, "Error: could not remove device file "
							"(error = %d)\n", ret);

	if (major_number != -1) {
		major_num = major_number;
		major_number = -1;
		unregister_chrdev(major_num, device_file_pathname);
	}

	return sprintf(buf, "device file successfully removed\n");
}

static ssize_t remove_device_file_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	return 0;
}

static struct kobj_attribute add_device_file_attribute =
	__ATTR(add_device_file, 0666, add_device_file_show,
						add_device_file_store);
static struct kobj_attribute remove_device_file_attribute =
	__ATTR(remove_device_file, 0666, remove_device_file_show,
						remove_device_file_store);

static struct attribute *dfv_attrs[] = {
	&add_device_file_attribute.attr,
	&remove_device_file_attribute.attr,
	NULL,	/* need to NULL terminate the list of attributes */
};

struct attribute_group dfv_attr_group = {
	.attrs = dfv_attrs,
};
