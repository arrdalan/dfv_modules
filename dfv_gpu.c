/*
 * Device File-based I/O Virtualization (DFV)
 * File: dfv_gpu.c
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
#include <drm/drmP.h>
#include "dfv_pci.h"
#include "dfv_common.h"
#include "dfv_client.h"

static char device_file_name[32];
module_param_string(device_file_name, device_file_name,
						sizeof(device_file_name), 0660);
static char ctl_dev_file_name[32];
module_param_string(ctl_dev_file_name, ctl_dev_file_name,
						sizeof(ctl_dev_file_name), 0660);
static unsigned int funcnr;
module_param(funcnr, uint, 0660);
static unsigned int devnr;
module_param(devnr, uint, 0660);
static unsigned int busnr;
module_param(busnr, uint, 0660);
static unsigned int domainnr;
module_param(domainnr, uint, 0660);
static unsigned short vendor;
module_param(vendor, ushort, 0660);
static unsigned short device;
module_param(device, ushort, 0660);
static unsigned short subsystem_vendor;
module_param(subsystem_vendor, ushort, 0660);
static unsigned short subsystem_device;
module_param(subsystem_device, ushort, 0660);
static unsigned int class;
module_param(class, uint, 0660);
static char driver_name[32];
module_param_string(driver_name, driver_name, sizeof(driver_name), 0660);

#define CFG_SIZE		256
#define RESOURCE_SIZE	39
static unsigned int config[CFG_SIZE];
module_param_array(config, uint, NULL, 0660);
u8 input_config[CFG_SIZE];
static unsigned long resource[RESOURCE_SIZE];
module_param_array(resource, ulong, NULL, 0660);

static struct dfv_pci_info *pci_info;
static struct cdev cdev;
static dev_t devt;
static dev_t devt2;
int major_number, major_number2;

static int create_device_files(struct pci_dev *pdev)
{
	int result, err;

	devt = MKDEV(0, 0);
	devt2 = MKDEV(0, 0);

	result = alloc_chrdev_region(&devt, 0, 1, device_file_name);
	major_number = MAJOR(devt);
	if (result)
		return result;

	result = alloc_chrdev_region(&devt2, 0, 1, ctl_dev_file_name);
	major_number2 = MAJOR(devt2);
	if (result)
		return result;

	cdev_init(&cdev, &dfvfops);
	cdev.owner = THIS_MODULE;
	cdev.ops = &dfvfops;
	err = cdev_add(&cdev, devt, 1);
	err = cdev_add(&cdev, devt2, 1);
	if (err) {
		DFVPRINTK_ERR("Error: Failed adding device (err = %d)", err);
	}
	else {
		device_create(drm_class, &pdev->dev, devt, NULL,
							device_file_name);
		device_create(drm_class, &pdev->dev, devt2, NULL,
							ctl_dev_file_name);
	}

	return 0;
}

static int __init dfv_gpu_init(void)
{
	static struct pci_dev *pdev;
	int i;

	pci_info = kmalloc(sizeof(*pci_info), GFP_KERNEL);
	sprintf(pci_info->dev_name, "%s", device_file_name);
	pci_info->funcnr = funcnr;
	pci_info->devnr = devnr;
	pci_info->busnr = busnr;
	pci_info->domainnr = domainnr;
	pci_info->vendor = vendor;
	pci_info->device = device;
	pci_info->subsystem_vendor = subsystem_vendor;
	pci_info->subsystem_device = subsystem_device;
	pci_info->class = class;
	sprintf(pci_info->driver_name, "%s", driver_name);
	for (i = 0; i < CFG_SIZE; i++) {
		input_config[i] = (u8) config[i];
	}
	pci_info->config = input_config;
	pci_info->cfg_size = CFG_SIZE;
	pci_info->resource = resource;

	pdev = register_to_dfv_pci(pci_info);

	create_device_files(pdev);

	return 0;
}

static void __exit dfv_gpu_exit(void)
{
	device_destroy(drm_class, devt);
	device_destroy(drm_class, devt2);

	unregister_from_dfv_pci(pci_info);
	kfree(pci_info);

	cdev_del(&cdev);
	unregister_chrdev_region(MKDEV(major_number, 0), 1);
	unregister_chrdev_region(MKDEV(major_number2, 0), 1);
}

module_init(dfv_gpu_init);
module_exit(dfv_gpu_exit);

MODULE_AUTHOR("Ardalan Amiri Sani <arrdalan@gmail.com>");
MODULE_DESCRIPTION("GPU info module for Device File-based I/O Virtualization");
MODULE_LICENSE("GPL");
