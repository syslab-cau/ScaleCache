// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2004-2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#include "scxfs.h"
#include "scxfs_shared.h"
#include "scxfs_format.h"
#include "scxfs_log_format.h"
#include "scxfs_trans_resv.h"
#include "scxfs_mount.h"
#include "scxfs_dir2.h"
#include "scxfs_export.h"
#include "scxfs_inode.h"
#include "scxfs_trans.h"
#include "scxfs_inode_item.h"
#include "scxfs_icache.h"
#include "scxfs_log.h"
#include "scxfs_pnfs.h"

/*
 * Note that we only accept fileids which are long enough rather than allow
 * the parent generation number to default to zero.  SCXFS considers zero a
 * valid generation number not an invalid/wildcard value.
 */
static int scxfs_fileid_length(int fileid_type)
{
	switch (fileid_type) {
	case FILEID_INO32_GEN:
		return 2;
	case FILEID_INO32_GEN_PARENT:
		return 4;
	case FILEID_INO32_GEN | SCXFS_FILEID_TYPE_64FLAG:
		return 3;
	case FILEID_INO32_GEN_PARENT | SCXFS_FILEID_TYPE_64FLAG:
		return 6;
	}
	return FILEID_INVALID;
}

STATIC int
scxfs_fs_encode_fh(
	struct inode	*inode,
	__u32		*fh,
	int		*max_len,
	struct inode	*parent)
{
	struct fid		*fid = (struct fid *)fh;
	struct scxfs_fid64	*fid64 = (struct scxfs_fid64 *)fh;
	int			fileid_type;
	int			len;

	/* Directories don't need their parent encoded, they have ".." */
	if (!parent)
		fileid_type = FILEID_INO32_GEN;
	else
		fileid_type = FILEID_INO32_GEN_PARENT;

	/*
	 * If the the filesystem may contain 64bit inode numbers, we need
	 * to use larger file handles that can represent them.
	 *
	 * While we only allocate inodes that do not fit into 32 bits any
	 * large enough filesystem may contain them, thus the slightly
	 * confusing looking conditional below.
	 */
	if (!(SCXFS_M(inode->i_sb)->m_flags & SCXFS_MOUNT_SMALL_INUMS) ||
	    (SCXFS_M(inode->i_sb)->m_flags & SCXFS_MOUNT_32BITINODES))
		fileid_type |= SCXFS_FILEID_TYPE_64FLAG;

	/*
	 * Only encode if there is enough space given.  In practice
	 * this means we can't export a filesystem with 64bit inodes
	 * over NFSv2 with the subtree_check export option; the other
	 * seven combinations work.  The real answer is "don't use v2".
	 */
	len = scxfs_fileid_length(fileid_type);
	if (*max_len < len) {
		*max_len = len;
		return FILEID_INVALID;
	}
	*max_len = len;

	switch (fileid_type) {
	case FILEID_INO32_GEN_PARENT:
		fid->i32.parent_ino = SCXFS_I(parent)->i_ino;
		fid->i32.parent_gen = parent->i_generation;
		/*FALLTHRU*/
	case FILEID_INO32_GEN:
		fid->i32.ino = SCXFS_I(inode)->i_ino;
		fid->i32.gen = inode->i_generation;
		break;
	case FILEID_INO32_GEN_PARENT | SCXFS_FILEID_TYPE_64FLAG:
		fid64->parent_ino = SCXFS_I(parent)->i_ino;
		fid64->parent_gen = parent->i_generation;
		/*FALLTHRU*/
	case FILEID_INO32_GEN | SCXFS_FILEID_TYPE_64FLAG:
		fid64->ino = SCXFS_I(inode)->i_ino;
		fid64->gen = inode->i_generation;
		break;
	}

	return fileid_type;
}

STATIC struct inode *
scxfs_nfs_get_inode(
	struct super_block	*sb,
	u64			ino,
	u32			generation)
{
 	scxfs_mount_t		*mp = SCXFS_M(sb);
	scxfs_inode_t		*ip;
	int			error;

	/*
	 * NFS can sometimes send requests for ino 0.  Fail them gracefully.
	 */
	if (ino == 0)
		return ERR_PTR(-ESTALE);

	/*
	 * The SCXFS_IGET_UNTRUSTED means that an invalid inode number is just
	 * fine and not an indication of a corrupted filesystem as clients can
	 * send invalid file handles and we have to handle it gracefully..
	 */
	error = scxfs_iget(mp, NULL, ino, SCXFS_IGET_UNTRUSTED, 0, &ip);
	if (error) {

		/*
		 * EINVAL means the inode cluster doesn't exist anymore.
		 * EFSCORRUPTED means the metadata pointing to the inode cluster
		 * or the inode cluster itself is corrupt.  This implies the
		 * filehandle is stale, so we should translate it here.
		 * We don't use ESTALE directly down the chain to not
		 * confuse applications using bulkstat that expect EINVAL.
		 */
		switch (error) {
		case -EINVAL:
		case -ENOENT:
		case -EFSCORRUPTED:
			error = -ESTALE;
			break;
		default:
			break;
		}
		return ERR_PTR(error);
	}

	if (VFS_I(ip)->i_generation != generation) {
		scxfs_irele(ip);
		return ERR_PTR(-ESTALE);
	}

	return VFS_I(ip);
}

STATIC struct dentry *
scxfs_fs_fh_to_dentry(struct super_block *sb, struct fid *fid,
		 int fh_len, int fileid_type)
{
	struct scxfs_fid64	*fid64 = (struct scxfs_fid64 *)fid;
	struct inode		*inode = NULL;

	if (fh_len < scxfs_fileid_length(fileid_type))
		return NULL;

	switch (fileid_type) {
	case FILEID_INO32_GEN_PARENT:
	case FILEID_INO32_GEN:
		inode = scxfs_nfs_get_inode(sb, fid->i32.ino, fid->i32.gen);
		break;
	case FILEID_INO32_GEN_PARENT | SCXFS_FILEID_TYPE_64FLAG:
	case FILEID_INO32_GEN | SCXFS_FILEID_TYPE_64FLAG:
		inode = scxfs_nfs_get_inode(sb, fid64->ino, fid64->gen);
		break;
	}

	return d_obtain_alias(inode);
}

STATIC struct dentry *
scxfs_fs_fh_to_parent(struct super_block *sb, struct fid *fid,
		 int fh_len, int fileid_type)
{
	struct scxfs_fid64	*fid64 = (struct scxfs_fid64 *)fid;
	struct inode		*inode = NULL;

	if (fh_len < scxfs_fileid_length(fileid_type))
		return NULL;

	switch (fileid_type) {
	case FILEID_INO32_GEN_PARENT:
		inode = scxfs_nfs_get_inode(sb, fid->i32.parent_ino,
					      fid->i32.parent_gen);
		break;
	case FILEID_INO32_GEN_PARENT | SCXFS_FILEID_TYPE_64FLAG:
		inode = scxfs_nfs_get_inode(sb, fid64->parent_ino,
					      fid64->parent_gen);
		break;
	}

	return d_obtain_alias(inode);
}

STATIC struct dentry *
scxfs_fs_get_parent(
	struct dentry		*child)
{
	int			error;
	struct scxfs_inode	*cip;

	error = scxfs_lookup(SCXFS_I(d_inode(child)), &scxfs_name_dotdot, &cip, NULL);
	if (unlikely(error))
		return ERR_PTR(error);

	return d_obtain_alias(VFS_I(cip));
}

STATIC int
scxfs_fs_nfs_commit_metadata(
	struct inode		*inode)
{
	struct scxfs_inode	*ip = SCXFS_I(inode);
	struct scxfs_mount	*mp = ip->i_mount;
	scxfs_lsn_t		lsn = 0;

	scxfs_ilock(ip, SCXFS_ILOCK_SHARED);
	if (scxfs_ipincount(ip))
		lsn = ip->i_itemp->ili_last_lsn;
	scxfs_iunlock(ip, SCXFS_ILOCK_SHARED);

	if (!lsn)
		return 0;
	return scxfs_log_force_lsn(mp, lsn, SCXFS_LOG_SYNC, NULL);
}

const struct export_operations scxfs_export_operations = {
	.encode_fh		= scxfs_fs_encode_fh,
	.fh_to_dentry		= scxfs_fs_fh_to_dentry,
	.fh_to_parent		= scxfs_fs_fh_to_parent,
	.get_parent		= scxfs_fs_get_parent,
	.commit_metadata	= scxfs_fs_nfs_commit_metadata,
#ifdef CONFIG_EXPORTFS_BLOCK_OPS
	.get_uuid		= scxfs_fs_get_uuid,
	.map_blocks		= scxfs_fs_map_blocks,
	.commit_blocks		= scxfs_fs_commit_blocks,
#endif
};
