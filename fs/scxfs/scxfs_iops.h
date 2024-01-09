// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2003,2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#ifndef __SCXFS_IOPS_H__
#define __SCXFS_IOPS_H__

struct scxfs_inode;

extern const struct file_operations scxfs_file_operations;
extern const struct file_operations scxfs_dir_file_operations;

extern ssize_t scxfs_vn_listxattr(struct dentry *, char *data, size_t size);

/*
 * Internal setattr interfaces.
 */
#define SCXFS_ATTR_NOACL		0x01	/* Don't call posix_acl_chmod */

extern void scxfs_setattr_time(struct scxfs_inode *ip, struct iattr *iattr);
extern int scxfs_setattr_nonsize(struct scxfs_inode *ip, struct iattr *vap,
			       int flags);
extern int scxfs_vn_setattr_nonsize(struct dentry *dentry, struct iattr *vap);
extern int scxfs_vn_setattr_size(struct dentry *dentry, struct iattr *vap);

#endif /* __SCXFS_IOPS_H__ */
