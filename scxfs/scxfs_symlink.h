// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2012 Red Hat, Inc. All rights reserved.
 */
#ifndef __SCXFS_SYMLINK_H
#define __SCXFS_SYMLINK_H 1

/* Kernel only symlink defintions */

int scxfs_symlink(struct scxfs_inode *dp, struct scxfs_name *link_name,
		const char *target_path, umode_t mode, struct scxfs_inode **ipp);
int scxfs_readlink_bmap_ilocked(struct scxfs_inode *ip, char *link);
int scxfs_readlink(struct scxfs_inode *ip, char *link);
int scxfs_inactive_symlink(struct scxfs_inode *ip);

#endif /* __SCXFS_SYMLINK_H */
