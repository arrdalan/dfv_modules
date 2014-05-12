/*
 * Device File-based I/O Virtualization (DFV)
 * File: dfv_linux_code.h
 *
 * This file contains code copied from Linux.
 * For licensing, please refer to the original Linux files.
 */

/* The next three are from fs/select.c */
#define POLLIN_SET (POLLRDNORM | POLLRDBAND | POLLIN | POLLHUP | POLLERR)
#define POLLOUT_SET (POLLWRBAND | POLLWRNORM | POLLOUT | POLLERR)
#define POLLEX_SET (POLLPRI)
