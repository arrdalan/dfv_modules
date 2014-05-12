/*
 * Device File-based I/O Virtualization (DFV)
 * File: dfv_pci.h
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

struct dfv_pci_info {
	char dev_name[32];
	unsigned int funcnr;
	unsigned int devnr;
	unsigned int busnr;
	unsigned int domainnr;
	unsigned short vendor;
	unsigned short device;
	unsigned short subsystem_vendor;
	unsigned short subsystem_device;
	unsigned int class;
	int cfg_size;
	char driver_name[32];
	u8 *config;
	unsigned long *resource;
};

struct pci_dev *register_to_dfv_pci(struct dfv_pci_info *pci_info);
void unregister_from_dfv_pci(struct dfv_pci_info *pci_info);

extern struct pci_bus *dfv_pbus;
