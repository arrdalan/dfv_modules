/*
 * Device File-based I/O Virtualization (DFV)
 * File: dfv_pci.c
 *
 * Copyright (c) 2014 Rice University, Houston, TX, USA
 * All rights reserved.
 *
 * Authors: Ardalan Amiri Sani <arrdalan@gmail.com>
 *
 * Used help from two files in developing this file:
 *
 * 1) drivers/pci/iov.c
 *
 * Copyright (C) 2009 Intel Corporation, Yu Zhao <yu.zhao@intel.com>
 *
 * PCI Express I/O Virtualization (IOV) support.
 *   Single Root IOV 1.0
 *   Address Translation Service 1.0
 *
 * 2) drivers/pci/bus.c
 *
 * From setup-res.c, by:
 *	Dave Rusling (david.rusling@reo.mts.dec.com)
 *	David Mosberger (davidm@cs.arizona.edu)
 *	David Miller (davem@redhat.com)
 *	Ivan Kokshaysky (ink@jurassic.park.msu.ru)
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
#include "dfv_pci.h"
#include "dfv_common.h"

struct pci_bus *dfv_pbus;
EXPORT_SYMBOL(dfv_pbus);

static struct pci_dev *pdev;
static struct pci_driver *pci_drv;
u8 *pci_config;
char pci_device_name[32];

int pci_bus_read(struct pci_bus *bus, unsigned int devfn, int where,
						int size, u32 *val)
{
	return 0;
}

int pci_bus_write(struct pci_bus *bus, unsigned int devfn, int where,
							int size, u32 val)
{
	return 1;
}

static struct pci_ops pci_ops = {
	.write = pci_bus_write,
	.read = pci_bus_read,
};

char *generate_pci_device_name(struct dfv_pci_info *pci_info)
{
	sprintf(pci_device_name, "%04d:%02d:%02d.%d", pci_info->domainnr,
					pci_info->busnr, pci_info->devnr,
					pci_info->funcnr);
	return pci_device_name;
}

int register_pci_device(struct dfv_pci_info *pci_info)
{
	int rc, i;

	pdev = alloc_pci_dev();
	if (!pdev)
		return -ENOMEM;

	pdev->dev.init_name = generate_pci_device_name(pci_info);
	pdev->dev.bus = &pci_bus_type;
	pdev->dev.parent = &dfv_pbus->dev;

	pdev->bus = dfv_pbus;
	if (!pdev->bus) {
		kfree(pdev);
		return -ENOMEM;
	}
	/* FIXME: are we ignoring the funcnr here? */
	pdev->devfn = pci_info->devnr;
	pdev->vendor = pci_info->vendor;
	pdev->device = pci_info->device;
	pdev->subsystem_vendor = pci_info->subsystem_vendor;
	pdev->subsystem_device = pci_info->subsystem_device;
	pdev->class = pci_info->class;
	pdev->driver = pci_drv;
	pdev->is_virtual_dev = 1;
	pdev->cfg_size = pci_info->cfg_size;
	pci_config = pci_info->config;
	pdev->virtual_config = pci_info->config;
	/* FIXME */
	pdev->resource[PCI_ROM_RESOURCE].flags = IORESOURCE_ROM_SHADOW;
	for(i = 0; i < DEVICE_COUNT_RESOURCE; i++) {
		pdev->resource[i].start = (resource_size_t) pci_info->resource[3*i];
		pdev->resource[i].end = (resource_size_t) pci_info->resource[3*i+1];
		pdev->resource[i].flags = (unsigned long) pci_info->resource[3*i+2];
	}

	pci_device_add(pdev, pdev->bus);

	rc = pci_bus_add_device(pdev);
	if (rc)
		goto failed1;

	kobject_uevent(&pdev->dev.kobj, KOBJ_CHANGE);

	return 0;

failed1:
	DFVPRINTK_ERR("Error: registration failed (rc = %d)\n", rc);

	return rc;
}

void unregister_pci_device(struct dfv_pci_info *pci_info)
{
	struct pci_bus *bus;

	bus = dfv_pbus;
	if (!bus)
		return;

	if (!pdev)
		return;

	pci_remove_bus_device(pdev);

}

int register_pci_driver(struct dfv_pci_info *pci_info)
{
	int ret;
	struct pci_device_id *ids = kmalloc(sizeof(*ids), GFP_KERNEL);

	ids->vendor = pci_info->vendor;
	ids->device = pci_info->device;
	ids->subvendor = pci_info->subsystem_vendor;
	ids->subdevice = pci_info->subsystem_device;
	ids->class = pci_info->class;
	ids->class_mask = 0;
	ids->driver_data = 0;

	pci_drv = kzalloc(sizeof(*pci_drv), GFP_KERNEL);
	pci_drv->name = (const char *) &pci_info->driver_name;
	pci_drv->id_table = ids;
	pci_drv->is_virtual_driver = 1;

	ret = pci_register_driver(pci_drv);

	return 0;
}

int pci_bus_add_child(struct pci_bus *bus)
{
	int retval;

	if (bus->bridge)
		bus->dev.parent = bus->bridge;

	retval = device_register(&bus->dev);
	if (retval)
		return retval;

	bus->is_added = 1;

	return retval;
}

struct pci_bus * get_pci_root(void)
{
	struct pci_bus *pci_root;

	list_for_each_entry(pci_root, &pci_root_buses, node) {
		if (pci_is_root_bus(pci_root)) {
			return pci_root;
		}
	}
	return NULL;

}

struct pci_bus *create_virtual_pci_bus(struct dfv_pci_info *pci_info)
{
	int rc;
	struct pci_bus *pci_root;
	unsigned int busnr = pci_info->busnr;
	unsigned int domainnr = pci_info->domainnr;

	pci_root = get_pci_root();
	if (!pci_root) {
		DFVPRINTK_ERR("Error: could not get the pci root\n");
		return NULL;
	}

	dfv_pbus = pci_find_bus(domainnr, busnr);

	if (dfv_pbus)
		return dfv_pbus;

	DFVPRINTK("Could not find a virtual pci bus with "
		     "busnr = %d. Will now create a virtual one\n", busnr);

	/*
	 * FIXME: We've ignored the domainnr here. Therefore, we might
	 * end up having a different domainnr than the one passed to us
	 * in pci_info.
	 */
	dfv_pbus = pci_add_new_bus(pci_root, NULL, busnr);

	if (!dfv_pbus) {
		DFVPRINTK_ERR("Error: could not create a virtual pci bus "
						"with busnr = %d\n", busnr);
		return NULL;
	}

	dfv_pbus->ops = &pci_ops;

	dfv_pbus->subordinate = busnr;
	dfv_pbus->dev.parent = pci_root->bridge;
	rc = pci_bus_add_child(dfv_pbus);
	if (rc) {
		pci_remove_bus(dfv_pbus);
		return NULL;
	}

	return dfv_pbus;
}

static void remove_virtual_pci_bus(void)
{
	if (!dfv_pbus)
		return;

	if (list_empty(&dfv_pbus->devices))
		pci_remove_bus(dfv_pbus);
}

struct pci_dev *register_to_dfv_pci(struct dfv_pci_info *pci_info)
{
	create_virtual_pci_bus(pci_info);
	register_pci_driver(pci_info);
	register_pci_device(pci_info);

	return pdev;
}

void unregister_pci_driver(void)
{
	pci_unregister_driver(pci_drv);
	kfree(pci_drv->id_table);
	kfree(pci_drv);
}

void unregister_from_dfv_pci(struct dfv_pci_info *pci_info)
{
	unregister_pci_device(pci_info);
	unregister_pci_driver();
	remove_virtual_pci_bus();
}
EXPORT_SYMBOL(register_to_dfv_pci);
EXPORT_SYMBOL(unregister_from_dfv_pci);

static int __init dfv_pci_init(void)
{
	return 0;
}

static void __exit dfv_pci_exit(void)
{
}

module_init(dfv_pci_init);
module_exit(dfv_pci_exit);

MODULE_AUTHOR("Ardalan Amiri Sani <arrdalan@gmail.com>");
MODULE_DESCRIPTION("Virtual PCI bus support for Device File-based I/O "
		   "Virtualization");
MODULE_LICENSE("GPL");
