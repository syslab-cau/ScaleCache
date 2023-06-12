// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2008 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#ifndef __SCXFS_IOCTL_H__
#define __SCXFS_IOCTL_H__

extern int
scxfs_ioc_space(
	struct file		*filp,
	unsigned int		cmd,
	scxfs_flock64_t		*bf);

int
scxfs_ioc_swapext(
	scxfs_swapext_t	*sxp);

extern int
scxfs_find_handle(
	unsigned int		cmd,
	scxfs_fsop_handlereq_t	*hreq);

extern int
scxfs_open_by_handle(
	struct file		*parfilp,
	scxfs_fsop_handlereq_t	*hreq);

extern int
scxfs_readlink_by_handle(
	struct file		*parfilp,
	scxfs_fsop_handlereq_t	*hreq);

extern int
scxfs_attrmulti_attr_get(
	struct inode		*inode,
	unsigned char		*name,
	unsigned char		__user *ubuf,
	uint32_t		*len,
	uint32_t		flags);

extern int
scxfs_attrmulti_attr_set(
	struct inode		*inode,
	unsigned char		*name,
	const unsigned char	__user *ubuf,
	uint32_t		len,
	uint32_t		flags);

extern int
scxfs_attrmulti_attr_remove(
	struct inode		*inode,
	unsigned char		*name,
	uint32_t		flags);

extern struct dentry *
scxfs_handle_to_dentry(
	struct file		*parfilp,
	void __user		*uhandle,
	u32			hlen);

extern long
scxfs_file_ioctl(
	struct file		*filp,
	unsigned int		cmd,
	unsigned long		p);

extern long
scxfs_file_compat_ioctl(
	struct file		*file,
	unsigned int		cmd,
	unsigned long		arg);

extern int
scxfs_set_dmattrs(
	struct scxfs_inode	*ip,
	uint			evmask,
	uint16_t		state);

struct scxfs_ibulk;
struct scxfs_bstat;
struct scxfs_inogrp;

int scxfs_fsbulkstat_one_fmt(struct scxfs_ibulk *breq,
			   const struct scxfs_bulkstat *bstat);
int scxfs_fsinumbers_fmt(struct scxfs_ibulk *breq, const struct scxfs_inumbers *igrp);

#endif
