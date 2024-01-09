// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2001-2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#ifndef __SCXFS_ACL_H__
#define __SCXFS_ACL_H__

struct inode;
struct posix_acl;

#ifdef CONFIG_XFS_POSIX_ACL
extern struct posix_acl *scxfs_get_acl(struct inode *inode, int type);
extern int scxfs_set_acl(struct inode *inode, struct posix_acl *acl, int type);
extern int __scxfs_set_acl(struct inode *inode, struct posix_acl *acl, int type);
#else
static inline struct posix_acl *scxfs_get_acl(struct inode *inode, int type)
{
	return NULL;
}
# define scxfs_set_acl					NULL
#endif /* CONFIG_XFS_POSIX_ACL */

extern void scxfs_forget_acl(struct inode *inode, const char *name, int xflags);

#endif	/* __SCXFS_ACL_H__ */
