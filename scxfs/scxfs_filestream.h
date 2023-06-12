// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2006-2007 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#ifndef __SCXFS_FILESTREAM_H__
#define __SCXFS_FILESTREAM_H__

struct scxfs_mount;
struct scxfs_inode;
struct scxfs_bmalloca;

int scxfs_filestream_mount(struct scxfs_mount *mp);
void scxfs_filestream_unmount(struct scxfs_mount *mp);
void scxfs_filestream_deassociate(struct scxfs_inode *ip);
scxfs_agnumber_t scxfs_filestream_lookup_ag(struct scxfs_inode *ip);
int scxfs_filestream_new_ag(struct scxfs_bmalloca *ap, scxfs_agnumber_t *agp);
int scxfs_filestream_peek_ag(struct scxfs_mount *mp, scxfs_agnumber_t agno);

static inline int
scxfs_inode_is_filestream(
	struct scxfs_inode	*ip)
{
	return (ip->i_mount->m_flags & SCXFS_MOUNT_FILESTREAMS) ||
		(ip->i_d.di_flags & SCXFS_DIFLAG_FILESTREAM);
}

#endif /* __SCXFS_FILESTREAM_H__ */
