/*
 * Device File-based I/O Virtualization (DFV)
 * File: dfv_common_xen.c
 *
 * Copyright (c) 2014 Rice University, Houston, TX, USA
 * All rights reserved.
 *
 * Authors: Ardalan Amiri Sani <arrdalan@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation; or, when distributed
 * separately from the Linux kernel or incorporated into other
 * software packages, subject to the following license:
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this source file (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include "dfv_common_xen.h"

void copy_dfv_req(struct dfv_xen_req *dst, struct dfv_xen_req *src)
{
	dst->arg1 = src->arg1;
	dst->arg2 = src->arg2;
	dst->arg3 = src->arg3;
	dst->arg4 = src->arg4;
	dst->arg5 = src->arg5;
	dst->arg6 = src->arg6;
	dst->grant = src->grant;
}

void copy_dfv_rsp(struct dfv_xen_rsp *dst, struct dfv_xen_rsp *src)
{
	dst->arg1 = src->arg1;
	dst->arg2 = src->arg2;
	dst->arg3 = src->arg3;
	dst->arg4 = src->arg4;
	dst->arg5 = src->arg5;
	dst->arg6 = src->arg6;
}
