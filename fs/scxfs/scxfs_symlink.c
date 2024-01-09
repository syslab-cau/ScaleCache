// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2006 Silicon Graphics, Inc.
 * Copyright (c) 2012-2013 Red Hat, Inc.
 * All rights reserved.
 */
#include "scxfs.h"
#include "scxfs_shared.h"
#include "scxfs_fs.h"
#include "scxfs_format.h"
#include "scxfs_log_format.h"
#include "scxfs_trans_resv.h"
#include "scxfs_bit.h"
#include "scxfs_mount.h"
#include "scxfs_dir2.h"
#include "scxfs_inode.h"
#include "scxfs_bmap.h"
#include "scxfs_bmap_btree.h"
#include "scxfs_quota.h"
#include "scxfs_trans_space.h"
#include "scxfs_trace.h"
#include "scxfs_trans.h"

/* ----- Kernel only functions below ----- */
int
scxfs_readlink_bmap_ilocked(
	struct scxfs_inode	*ip,
	char			*link)
{
	struct scxfs_mount	*mp = ip->i_mount;
	struct scxfs_bmbt_irec	mval[SCXFS_SYMLINK_MAPS];
	struct scxfs_buf		*bp;
	scxfs_daddr_t		d;
	char			*cur_chunk;
	int			pathlen = ip->i_d.di_size;
	int			nmaps = SCXFS_SYMLINK_MAPS;
	int			byte_cnt;
	int			n;
	int			error = 0;
	int			fsblocks = 0;
	int			offset;

	ASSERT(scxfs_isilocked(ip, SCXFS_ILOCK_SHARED | SCXFS_ILOCK_EXCL));

	fsblocks = scxfs_symlink_blocks(mp, pathlen);
	error = scxfs_bmapi_read(ip, 0, fsblocks, mval, &nmaps, 0);
	if (error)
		goto out;

	offset = 0;
	for (n = 0; n < nmaps; n++) {
		d = SCXFS_FSB_TO_DADDR(mp, mval[n].br_startblock);
		byte_cnt = SCXFS_FSB_TO_B(mp, mval[n].br_blockcount);

		bp = scxfs_buf_read(mp->m_ddev_targp, d, BTOBB(byte_cnt), 0,
				  &scxfs_symlink_buf_ops);
		if (!bp)
			return -ENOMEM;
		error = bp->b_error;
		if (error) {
			scxfs_buf_ioerror_alert(bp, __func__);
			scxfs_buf_relse(bp);

			/* bad CRC means corrupted metadata */
			if (error == -EFSBADCRC)
				error = -EFSCORRUPTED;
			goto out;
		}
		byte_cnt = SCXFS_SYMLINK_BUF_SPACE(mp, byte_cnt);
		if (pathlen < byte_cnt)
			byte_cnt = pathlen;

		cur_chunk = bp->b_addr;
		if (scxfs_sb_version_hascrc(&mp->m_sb)) {
			if (!scxfs_symlink_hdr_ok(ip->i_ino, offset,
							byte_cnt, bp)) {
				error = -EFSCORRUPTED;
				scxfs_alert(mp,
"symlink header does not match required off/len/owner (0x%x/Ox%x,0x%llx)",
					offset, byte_cnt, ip->i_ino);
				scxfs_buf_relse(bp);
				goto out;

			}

			cur_chunk += sizeof(struct scxfs_dsymlink_hdr);
		}

		memcpy(link + offset, cur_chunk, byte_cnt);

		pathlen -= byte_cnt;
		offset += byte_cnt;

		scxfs_buf_relse(bp);
	}
	ASSERT(pathlen == 0);

	link[ip->i_d.di_size] = '\0';
	error = 0;

 out:
	return error;
}

int
scxfs_readlink(
	struct scxfs_inode *ip,
	char		*link)
{
	struct scxfs_mount *mp = ip->i_mount;
	scxfs_fsize_t	pathlen;
	int		error = 0;

	trace_scxfs_readlink(ip);

	ASSERT(!(ip->i_df.if_flags & SCXFS_IFINLINE));

	if (SCXFS_FORCED_SHUTDOWN(mp))
		return -EIO;

	scxfs_ilock(ip, SCXFS_ILOCK_SHARED);

	pathlen = ip->i_d.di_size;
	if (!pathlen)
		goto out;

	if (pathlen < 0 || pathlen > SCXFS_SYMLINK_MAXLEN) {
		scxfs_alert(mp, "%s: inode (%llu) bad symlink length (%lld)",
			 __func__, (unsigned long long) ip->i_ino,
			 (long long) pathlen);
		ASSERT(0);
		error = -EFSCORRUPTED;
		goto out;
	}


	error = scxfs_readlink_bmap_ilocked(ip, link);

 out:
	scxfs_iunlock(ip, SCXFS_ILOCK_SHARED);
	return error;
}

int
scxfs_symlink(
	struct scxfs_inode	*dp,
	struct scxfs_name		*link_name,
	const char		*target_path,
	umode_t			mode,
	struct scxfs_inode	**ipp)
{
	struct scxfs_mount	*mp = dp->i_mount;
	struct scxfs_trans	*tp = NULL;
	struct scxfs_inode	*ip = NULL;
	int			error = 0;
	int			pathlen;
	bool                    unlock_dp_on_error = false;
	scxfs_fileoff_t		first_fsb;
	scxfs_filblks_t		fs_blocks;
	int			nmaps;
	struct scxfs_bmbt_irec	mval[SCXFS_SYMLINK_MAPS];
	scxfs_daddr_t		d;
	const char		*cur_chunk;
	int			byte_cnt;
	int			n;
	scxfs_buf_t		*bp;
	prid_t			prid;
	struct scxfs_dquot	*udqp = NULL;
	struct scxfs_dquot	*gdqp = NULL;
	struct scxfs_dquot	*pdqp = NULL;
	uint			resblks;

	*ipp = NULL;

	trace_scxfs_symlink(dp, link_name);

	if (SCXFS_FORCED_SHUTDOWN(mp))
		return -EIO;

	/*
	 * Check component lengths of the target path name.
	 */
	pathlen = strlen(target_path);
	if (pathlen >= SCXFS_SYMLINK_MAXLEN)      /* total string too long */
		return -ENAMETOOLONG;
	ASSERT(pathlen > 0);

	udqp = gdqp = NULL;
	prid = scxfs_get_initial_prid(dp);

	/*
	 * Make sure that we have allocated dquot(s) on disk.
	 */
	error = scxfs_qm_vop_dqalloc(dp,
			scxfs_kuid_to_uid(current_fsuid()),
			scxfs_kgid_to_gid(current_fsgid()), prid,
			SCXFS_QMOPT_QUOTALL | SCXFS_QMOPT_INHERIT,
			&udqp, &gdqp, &pdqp);
	if (error)
		return error;

	/*
	 * The symlink will fit into the inode data fork?
	 * There can't be any attributes so we get the whole variable part.
	 */
	if (pathlen <= SCXFS_LITINO(mp, dp->i_d.di_version))
		fs_blocks = 0;
	else
		fs_blocks = scxfs_symlink_blocks(mp, pathlen);
	resblks = SCXFS_SYMLINK_SPACE_RES(mp, link_name->len, fs_blocks);

	error = scxfs_trans_alloc(mp, &M_RES(mp)->tr_symlink, resblks, 0, 0, &tp);
	if (error)
		goto out_release_inode;

	scxfs_ilock(dp, SCXFS_ILOCK_EXCL | SCXFS_ILOCK_PARENT);
	unlock_dp_on_error = true;

	/*
	 * Check whether the directory allows new symlinks or not.
	 */
	if (dp->i_d.di_flags & SCXFS_DIFLAG_NOSYMLINKS) {
		error = -EPERM;
		goto out_trans_cancel;
	}

	/*
	 * Reserve disk quota : blocks and inode.
	 */
	error = scxfs_trans_reserve_quota(tp, mp, udqp, gdqp,
						pdqp, resblks, 1, 0);
	if (error)
		goto out_trans_cancel;

	/*
	 * Allocate an inode for the symlink.
	 */
	error = scxfs_dir_ialloc(&tp, dp, S_IFLNK | (mode & ~S_IFMT), 1, 0,
			       prid, &ip);
	if (error)
		goto out_trans_cancel;

	/*
	 * Now we join the directory inode to the transaction.  We do not do it
	 * earlier because scxfs_dir_ialloc might commit the previous transaction
	 * (and release all the locks).  An error from here on will result in
	 * the transaction cancel unlocking dp so don't do it explicitly in the
	 * error path.
	 */
	scxfs_trans_ijoin(tp, dp, SCXFS_ILOCK_EXCL);
	unlock_dp_on_error = false;

	/*
	 * Also attach the dquot(s) to it, if applicable.
	 */
	scxfs_qm_vop_create_dqattach(tp, ip, udqp, gdqp, pdqp);

	if (resblks)
		resblks -= SCXFS_IALLOC_SPACE_RES(mp);
	/*
	 * If the symlink will fit into the inode, write it inline.
	 */
	if (pathlen <= SCXFS_IFORK_DSIZE(ip)) {
		scxfs_init_local_fork(ip, SCXFS_DATA_FORK, target_path, pathlen);

		ip->i_d.di_size = pathlen;
		ip->i_d.di_format = SCXFS_DINODE_FMT_LOCAL;
		scxfs_trans_log_inode(tp, ip, SCXFS_ILOG_DDATA | SCXFS_ILOG_CORE);
	} else {
		int	offset;

		first_fsb = 0;
		nmaps = SCXFS_SYMLINK_MAPS;

		error = scxfs_bmapi_write(tp, ip, first_fsb, fs_blocks,
				  SCXFS_BMAPI_METADATA, resblks, mval, &nmaps);
		if (error)
			goto out_trans_cancel;

		if (resblks)
			resblks -= fs_blocks;
		ip->i_d.di_size = pathlen;
		scxfs_trans_log_inode(tp, ip, SCXFS_ILOG_CORE);

		cur_chunk = target_path;
		offset = 0;
		for (n = 0; n < nmaps; n++) {
			char	*buf;

			d = SCXFS_FSB_TO_DADDR(mp, mval[n].br_startblock);
			byte_cnt = SCXFS_FSB_TO_B(mp, mval[n].br_blockcount);
			bp = scxfs_trans_get_buf(tp, mp->m_ddev_targp, d,
					       BTOBB(byte_cnt), 0);
			if (!bp) {
				error = -ENOMEM;
				goto out_trans_cancel;
			}
			bp->b_ops = &scxfs_symlink_buf_ops;

			byte_cnt = SCXFS_SYMLINK_BUF_SPACE(mp, byte_cnt);
			byte_cnt = min(byte_cnt, pathlen);

			buf = bp->b_addr;
			buf += scxfs_symlink_hdr_set(mp, ip->i_ino, offset,
						   byte_cnt, bp);

			memcpy(buf, cur_chunk, byte_cnt);

			cur_chunk += byte_cnt;
			pathlen -= byte_cnt;
			offset += byte_cnt;

			scxfs_trans_buf_set_type(tp, bp, SCXFS_BLFT_SYMLINK_BUF);
			scxfs_trans_log_buf(tp, bp, 0, (buf + byte_cnt - 1) -
							(char *)bp->b_addr);
		}
		ASSERT(pathlen == 0);
	}

	/*
	 * Create the directory entry for the symlink.
	 */
	error = scxfs_dir_createname(tp, dp, link_name, ip->i_ino, resblks);
	if (error)
		goto out_trans_cancel;
	scxfs_trans_ichgtime(tp, dp, SCXFS_ICHGTIME_MOD | SCXFS_ICHGTIME_CHG);
	scxfs_trans_log_inode(tp, dp, SCXFS_ILOG_CORE);

	/*
	 * If this is a synchronous mount, make sure that the
	 * symlink transaction goes to disk before returning to
	 * the user.
	 */
	if (mp->m_flags & (SCXFS_MOUNT_WSYNC|SCXFS_MOUNT_DIRSYNC)) {
		scxfs_trans_set_sync(tp);
	}

	error = scxfs_trans_commit(tp);
	if (error)
		goto out_release_inode;

	scxfs_qm_dqrele(udqp);
	scxfs_qm_dqrele(gdqp);
	scxfs_qm_dqrele(pdqp);

	*ipp = ip;
	return 0;

out_trans_cancel:
	scxfs_trans_cancel(tp);
out_release_inode:
	/*
	 * Wait until after the current transaction is aborted to finish the
	 * setup of the inode and release the inode.  This prevents recursive
	 * transactions and deadlocks from scxfs_inactive.
	 */
	if (ip) {
		scxfs_finish_inode_setup(ip);
		scxfs_irele(ip);
	}

	scxfs_qm_dqrele(udqp);
	scxfs_qm_dqrele(gdqp);
	scxfs_qm_dqrele(pdqp);

	if (unlock_dp_on_error)
		scxfs_iunlock(dp, SCXFS_ILOCK_EXCL);
	return error;
}

/*
 * Free a symlink that has blocks associated with it.
 *
 * Note: zero length symlinks are not allowed to exist. When we set the size to
 * zero, also change it to a regular file so that it does not get written to
 * disk as a zero length symlink. The inode is on the unlinked list already, so
 * userspace cannot find this inode anymore, so this change is not user visible
 * but allows us to catch corrupt zero-length symlinks in the verifiers.
 */
STATIC int
scxfs_inactive_symlink_rmt(
	struct scxfs_inode *ip)
{
	scxfs_buf_t	*bp;
	int		done;
	int		error;
	int		i;
	scxfs_mount_t	*mp;
	scxfs_bmbt_irec_t	mval[SCXFS_SYMLINK_MAPS];
	int		nmaps;
	int		size;
	scxfs_trans_t	*tp;

	mp = ip->i_mount;
	ASSERT(ip->i_df.if_flags & SCXFS_IFEXTENTS);
	/*
	 * We're freeing a symlink that has some
	 * blocks allocated to it.  Free the
	 * blocks here.  We know that we've got
	 * either 1 or 2 extents and that we can
	 * free them all in one bunmapi call.
	 */
	ASSERT(ip->i_d.di_nextents > 0 && ip->i_d.di_nextents <= 2);

	error = scxfs_trans_alloc(mp, &M_RES(mp)->tr_itruncate, 0, 0, 0, &tp);
	if (error)
		return error;

	scxfs_ilock(ip, SCXFS_ILOCK_EXCL);
	scxfs_trans_ijoin(tp, ip, 0);

	/*
	 * Lock the inode, fix the size, turn it into a regular file and join it
	 * to the transaction.  Hold it so in the normal path, we still have it
	 * locked for the second transaction.  In the error paths we need it
	 * held so the cancel won't rele it, see below.
	 */
	size = (int)ip->i_d.di_size;
	ip->i_d.di_size = 0;
	VFS_I(ip)->i_mode = (VFS_I(ip)->i_mode & ~S_IFMT) | S_IFREG;
	scxfs_trans_log_inode(tp, ip, SCXFS_ILOG_CORE);
	/*
	 * Find the block(s) so we can inval and unmap them.
	 */
	done = 0;
	nmaps = ARRAY_SIZE(mval);
	error = scxfs_bmapi_read(ip, 0, scxfs_symlink_blocks(mp, size),
				mval, &nmaps, 0);
	if (error)
		goto error_trans_cancel;
	/*
	 * Invalidate the block(s). No validation is done.
	 */
	for (i = 0; i < nmaps; i++) {
		bp = scxfs_trans_get_buf(tp, mp->m_ddev_targp,
			SCXFS_FSB_TO_DADDR(mp, mval[i].br_startblock),
			SCXFS_FSB_TO_BB(mp, mval[i].br_blockcount), 0);
		if (!bp) {
			error = -ENOMEM;
			goto error_trans_cancel;
		}
		scxfs_trans_binval(tp, bp);
	}
	/*
	 * Unmap the dead block(s) to the dfops.
	 */
	error = scxfs_bunmapi(tp, ip, 0, size, 0, nmaps, &done);
	if (error)
		goto error_trans_cancel;
	ASSERT(done);

	/*
	 * Commit the transaction. This first logs the EFI and the inode, then
	 * rolls and commits the transaction that frees the extents.
	 */
	scxfs_trans_log_inode(tp, ip, SCXFS_ILOG_CORE);
	error = scxfs_trans_commit(tp);
	if (error) {
		ASSERT(SCXFS_FORCED_SHUTDOWN(mp));
		goto error_unlock;
	}

	/*
	 * Remove the memory for extent descriptions (just bookkeeping).
	 */
	if (ip->i_df.if_bytes)
		scxfs_idata_realloc(ip, -ip->i_df.if_bytes, SCXFS_DATA_FORK);
	ASSERT(ip->i_df.if_bytes == 0);

	scxfs_iunlock(ip, SCXFS_ILOCK_EXCL);
	return 0;

error_trans_cancel:
	scxfs_trans_cancel(tp);
error_unlock:
	scxfs_iunlock(ip, SCXFS_ILOCK_EXCL);
	return error;
}

/*
 * scxfs_inactive_symlink - free a symlink
 */
int
scxfs_inactive_symlink(
	struct scxfs_inode	*ip)
{
	struct scxfs_mount	*mp = ip->i_mount;
	int			pathlen;

	trace_scxfs_inactive_symlink(ip);

	if (SCXFS_FORCED_SHUTDOWN(mp))
		return -EIO;

	scxfs_ilock(ip, SCXFS_ILOCK_EXCL);
	pathlen = (int)ip->i_d.di_size;
	ASSERT(pathlen);

	if (pathlen <= 0 || pathlen > SCXFS_SYMLINK_MAXLEN) {
		scxfs_alert(mp, "%s: inode (0x%llx) bad symlink length (%d)",
			 __func__, (unsigned long long)ip->i_ino, pathlen);
		scxfs_iunlock(ip, SCXFS_ILOCK_EXCL);
		ASSERT(0);
		return -EFSCORRUPTED;
	}

	/*
	 * Inline fork state gets removed by scxfs_difree() so we have nothing to
	 * do here in that case.
	 */
	if (ip->i_df.if_flags & SCXFS_IFINLINE) {
		scxfs_iunlock(ip, SCXFS_ILOCK_EXCL);
		return 0;
	}

	scxfs_iunlock(ip, SCXFS_ILOCK_EXCL);

	/* remove the remote symlink */
	return scxfs_inactive_symlink_rmt(ip);
}
