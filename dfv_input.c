/*
 * Device File-based I/O Virtualization (DFV)
 * File: dfv_input.c
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
#include <linux/pci.h>
#include <linux/input.h>
#include "dfv_common.h"
#include "dfv_client.h"
#include "dfv_pci.h"

static char name[200];
module_param_string(name, name, sizeof(name), 0660);
static int bustype;
module_param(bustype, int, 0660);
static int vendor;
module_param(vendor, int, 0660);
static int product;
module_param(product, int, 0660);
static int version;
module_param(version, int, 0660);
static unsigned long evbit[BITS_TO_LONGS(EV_CNT)];
module_param_array(evbit, ulong, NULL, 0660);
static unsigned long keybit[BITS_TO_LONGS(KEY_CNT)];
module_param_array(keybit, ulong, NULL, 0660);
static unsigned long relbit[BITS_TO_LONGS(REL_CNT)];
module_param_array(relbit, ulong, NULL, 0660);
static unsigned long absbit[BITS_TO_LONGS(ABS_CNT)];
module_param_array(absbit, ulong, NULL, 0660);
static unsigned long mscbit[BITS_TO_LONGS(MSC_CNT)];
module_param_array(mscbit, ulong, NULL, 0660);
static unsigned long ledbit[BITS_TO_LONGS(LED_CNT)];
module_param_array(ledbit, ulong, NULL, 0660);
static unsigned long sndbit[BITS_TO_LONGS(SND_CNT)];
module_param_array(sndbit, ulong, NULL, 0660);
static unsigned long ffbit[BITS_TO_LONGS(FF_CNT)];
module_param_array(ffbit, ulong, NULL, 0660);
static unsigned long swbit[BITS_TO_LONGS(SW_CNT)];
module_param_array(swbit, ulong, NULL, 0660);
static int major_number;
module_param(major_number, int, 0660);

struct input_dev_struct {
	struct input_dev *in_dev;
	int major_number;
	struct list_head list;
};

struct list_head all_devices;

int register_input_dev(void)
{
	int err, result;
	struct input_dev_struct *idev;
	struct input_dev *in_dev = input_allocate_device();

	in_dev->dev.parent = &dfv_pbus->dev;
	in_dev->name = name;
	in_dev->id.bustype = bustype;
	in_dev->id.vendor = vendor;
	in_dev->id.product = product;
	in_dev->id.version = version;
	memcpy(in_dev->absbit, absbit, sizeof(absbit));
	memcpy(in_dev->evbit, evbit, sizeof(evbit));
	memcpy(in_dev->ffbit, ffbit, sizeof(ffbit));
	memcpy(in_dev->keybit, keybit, sizeof(keybit));
	memcpy(in_dev->ledbit, ledbit, sizeof(ledbit));
	memcpy(in_dev->mscbit, mscbit, sizeof(mscbit));
	memcpy(in_dev->relbit, relbit, sizeof(relbit));
	memcpy(in_dev->sndbit, sndbit, sizeof(sndbit));
	memcpy(in_dev->swbit, swbit, sizeof(swbit));
	err = input_register_device(in_dev);

	if (!err) {

		for (major_number = 255; major_number >= 0; major_number--) {
			result = register_chrdev(major_number, "dfv_input",
								&dfvfops);
			if (!result)
				break;
		}
		if (result) {
			/* We could not register a chrdev */
			DFVPRINTK_ERR("Error: could not register chrdev\n");
			err = -EFAULT;
			input_free_device(in_dev);
			goto out_err;
		}

		idev = kmalloc(sizeof(*idev), GFP_KERNEL);
		if (idev) {
			INIT_LIST_HEAD(&idev->list);
			idev->in_dev = in_dev;
			idev->major_number = major_number;
			list_add(&idev->list, &all_devices);
		} else {
			DFVPRINTK_ERR("Error: Could not allocate memory.\n");
			err = -ENOMEM;
			input_free_device(in_dev);;
		}
	} else {
		input_free_device(in_dev);
	}

out_err:
	return err;
}

static ssize_t register_device_show(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf)
{
	int err;

	err = register_input_dev();

	memset(evbit, 0, sizeof(evbit));
	memset(keybit, 0, sizeof(keybit));
	memset(relbit, 0, sizeof(relbit));
	memset(absbit, 0, sizeof(absbit));
	memset(mscbit, 0, sizeof(mscbit));
	memset(ledbit, 0, sizeof(ledbit));
	memset(sndbit, 0, sizeof(sndbit));
	memset(ffbit, 0, sizeof(ffbit));
	memset(swbit, 0, sizeof(swbit));

	if (err)
		return sprintf(buf, "Registring input device failed "
							"(err = %d)\n", err);
	else
		return sprintf(buf, "Input device successfully registered\n");
}

static ssize_t register_device_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	register_input_dev();
	return 0;
}

static struct kobj_attribute register_device_attribute =
	__ATTR(register_device, 0666, register_device_show,
						register_device_store);

static struct attribute *dfv_input_attrs[] = {
	&register_device_attribute.attr,
	NULL,
};

struct attribute_group dfv_input_attr_group = {
	.attrs = dfv_input_attrs,
};

static struct kobject *dfv_input_kobj;

static int __init dfv_input_init(void)
{
	int retval;

	INIT_LIST_HEAD(&all_devices);

	dfv_input_kobj = kobject_create_and_add("control",
						&(THIS_MODULE->mkobj.kobj));
	if (!dfv_input_kobj)
		return -EFAULT;

	retval = sysfs_create_group(dfv_input_kobj, &dfv_input_attr_group);
	if (retval) {
		kobject_put(dfv_input_kobj);
		return  -EFAULT;
	}

	return 0;
}

static void __exit dfv_input_exit(void)
{
	struct input_dev_struct *idev, *tmp;

	kobject_put(dfv_input_kobj);

	list_for_each_entry_safe(idev, tmp, &all_devices, list) {
		if (!idev)
			continue;

		input_unregister_device(idev->in_dev);

		unregister_chrdev(idev->major_number, "dfv_input");
		kfree(idev);
	}

}

module_init(dfv_input_init);
module_exit(dfv_input_exit);

MODULE_AUTHOR("Ardalan Amiri Sani <arrdalan@gmail.com>");
MODULE_DESCRIPTION("Input device info module for Device File-based I/O "
		   "Virtualization");
MODULE_LICENSE("GPL");
