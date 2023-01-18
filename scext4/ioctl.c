// SPDX-License-Identifier: GPL-2.0
/*
 * linux/fs/scext4/ioctl.c
 *
 * Copyright (C) 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 */

#include <linux/fs.h>
#include <linux/capability.h>
#include <linux/time.h>
#include <linux/compat.h>
#include <linux/mount.h>
#include <linux/file.h>
#include <linux/quotaops.h>
#include <linux/random.h>
#include <linux/uuid.h>
#include <linux/uaccess.h>
#include <linux/delay.h>
#include <linux/iversion.h>
#include "scext4_jbd3.h"
#include "scext4.h"
#include <linux/fsmap.h>
#include "fsmap.h"
#include <trace/events/scext4.h>

/**
 * Swap memory between @a and @b for @len bytes.
 *
 * @a:          pointer to first memory area
 * @b:          pointer to second memory area
 * @len:        number of bytes to swap
 *
 */
static void memswap(void *a, void *b, size_t len)
{
	unsigned char *ap, *bp;

	ap = (unsigned char *)a;
	bp = (unsigned char *)b;
	while (len-- > 0) {
		swap(*ap, *bp);
		ap++;
		bp++;
	}
}

/**
 * Swap i_data and associated attributes between @inode1 and @inode2.
 * This function is used for the primary swap between inode1 and inode2
 * and also to revert this primary swap in case of errors.
 *
 * Therefore you have to make sure, that calling this method twice
 * will revert all changes.
 *
 * @inode1:     pointer to first inode
 * @inode2:     pointer to second inode
 */
static void swap_inode_data(struct inode *inode1, struct inode *inode2)
{
	loff_t isize;
	struct scext4_inode_info *ei1;
	struct scext4_inode_info *ei2;
	unsigned long tmp;

	ei1 = SCEXT4_I(inode1);
	ei2 = SCEXT4_I(inode2);

	swap(inode1->i_version, inode2->i_version);
	swap(inode1->i_atime, inode2->i_atime);
	swap(inode1->i_mtime, inode2->i_mtime);

	memswap(ei1->i_data, ei2->i_data, sizeof(ei1->i_data));
	tmp = ei1->i_flags & SCEXT4_FL_SHOULD_SWAP;
	ei1->i_flags = (ei2->i_flags & SCEXT4_FL_SHOULD_SWAP) |
		(ei1->i_flags & ~SCEXT4_FL_SHOULD_SWAP);
	ei2->i_flags = tmp | (ei2->i_flags & ~SCEXT4_FL_SHOULD_SWAP);
	swap(ei1->i_disksize, ei2->i_disksize);
	scext4_es_remove_extent(inode1, 0, EXT_MAX_BLOCKS);
	scext4_es_remove_extent(inode2, 0, EXT_MAX_BLOCKS);

	isize = i_size_read(inode1);
	i_size_write(inode1, i_size_read(inode2));
	i_size_write(inode2, isize);
}

static void reset_inode_seed(struct inode *inode)
{
	struct scext4_inode_info *ei = SCEXT4_I(inode);
	struct scext4_sb_info *sbi = SCEXT4_SB(inode->i_sb);
	__le32 inum = cpu_to_le32(inode->i_ino);
	__le32 gen = cpu_to_le32(inode->i_generation);
	__u32 csum;

	if (!scext4_has_metadata_csum(inode->i_sb))
		return;

	csum = scext4_chksum(sbi, sbi->s_csum_seed, (__u8 *)&inum, sizeof(inum));
	ei->i_csum_seed = scext4_chksum(sbi, csum, (__u8 *)&gen, sizeof(gen));
}

/**
 * Swap the information from the given @inode and the inode
 * SCEXT4_BOOT_LOADER_INO. It will basically swap i_data and all other
 * important fields of the inodes.
 *
 * @sb:         the super block of the filesystem
 * @inode:      the inode to swap with SCEXT4_BOOT_LOADER_INO
 *
 */
static long swap_inode_boot_loader(struct super_block *sb,
				struct inode *inode)
{
	handle_t *handle;
	int err;
	struct inode *inode_bl;
	struct scext4_inode_info *ei_bl;
	qsize_t size, size_bl, diff;
	blkcnt_t blocks;
	unsigned short bytes;

	inode_bl = scext4_iget(sb, SCEXT4_BOOT_LOADER_INO, SCEXT4_IGET_SPECIAL);
	if (IS_ERR(inode_bl))
		return PTR_ERR(inode_bl);
	ei_bl = SCEXT4_I(inode_bl);

	/* Protect orig inodes against a truncate and make sure,
	 * that only 1 swap_inode_boot_loader is running. */
	lock_two_nondirectories(inode, inode_bl);

	if (inode->i_nlink != 1 || !S_ISREG(inode->i_mode) ||
	    IS_SWAPFILE(inode) || IS_ENCRYPTED(inode) ||
	    (SCEXT4_I(inode)->i_flags & SCEXT4_JOURNAL_DATA_FL) ||
	    scext4_has_inline_data(inode)) {
		err = -EINVAL;
		goto journal_err_out;
	}

	if (IS_RDONLY(inode) || IS_APPEND(inode) || IS_IMMUTABLE(inode) ||
	    !inode_owner_or_capable(inode) || !capable(CAP_SYS_ADMIN)) {
		err = -EPERM;
		goto journal_err_out;
	}

	down_write(&SCEXT4_I(inode)->i_mmap_sem);
	err = filemap_write_and_wait(inode->i_mapping);
	if (err)
		goto err_out;

	err = filemap_write_and_wait(inode_bl->i_mapping);
	if (err)
		goto err_out;

	/* Wait for all existing dio workers */
	inode_dio_wait(inode);
	inode_dio_wait(inode_bl);

	truncate_inode_pages(&inode->i_data, 0);
	truncate_inode_pages(&inode_bl->i_data, 0);

	handle = scext4_journal_start(inode_bl, SCEXT4_HT_MOVE_EXTENTS, 2);
	if (IS_ERR(handle)) {
		err = -EINVAL;
		goto err_out;
	}

	/* Protect extent tree against block allocations via delalloc */
	scext4_double_down_write_data_sem(inode, inode_bl);

	if (inode_bl->i_nlink == 0) {
		/* this inode has never been used as a BOOT_LOADER */
		set_nlink(inode_bl, 1);
		i_uid_write(inode_bl, 0);
		i_gid_write(inode_bl, 0);
		inode_bl->i_flags = 0;
		ei_bl->i_flags = 0;
		inode_set_iversion(inode_bl, 1);
		i_size_write(inode_bl, 0);
		inode_bl->i_mode = S_IFREG;
		if (scext4_has_feature_extents(sb)) {
			scext4_set_inode_flag(inode_bl, SCEXT4_INODE_EXTENTS);
			scext4_ext_tree_init(handle, inode_bl);
		} else
			memset(ei_bl->i_data, 0, sizeof(ei_bl->i_data));
	}

	err = dquot_initialize(inode);
	if (err)
		goto err_out1;

	size = (qsize_t)(inode->i_blocks) * (1 << 9) + inode->i_bytes;
	size_bl = (qsize_t)(inode_bl->i_blocks) * (1 << 9) + inode_bl->i_bytes;
	diff = size - size_bl;
	swap_inode_data(inode, inode_bl);

	inode->i_ctime = inode_bl->i_ctime = current_time(inode);

	inode->i_generation = prandom_u32();
	inode_bl->i_generation = prandom_u32();
	reset_inode_seed(inode);
	reset_inode_seed(inode_bl);

	scext4_discard_preallocations(inode);

	err = scext4_mark_inode_dirty(handle, inode);
	if (err < 0) {
		/* No need to update quota information. */
		scext4_warning(inode->i_sb,
			"couldn't mark inode #%lu dirty (err %d)",
			inode->i_ino, err);
		/* Revert all changes: */
		swap_inode_data(inode, inode_bl);
		scext4_mark_inode_dirty(handle, inode);
		goto err_out1;
	}

	blocks = inode_bl->i_blocks;
	bytes = inode_bl->i_bytes;
	inode_bl->i_blocks = inode->i_blocks;
	inode_bl->i_bytes = inode->i_bytes;
	err = scext4_mark_inode_dirty(handle, inode_bl);
	if (err < 0) {
		/* No need to update quota information. */
		scext4_warning(inode_bl->i_sb,
			"couldn't mark inode #%lu dirty (err %d)",
			inode_bl->i_ino, err);
		goto revert;
	}

	/* Bootloader inode should not be counted into quota information. */
	if (diff > 0)
		dquot_free_space(inode, diff);
	else
		err = dquot_alloc_space(inode, -1 * diff);

	if (err < 0) {
revert:
		/* Revert all changes: */
		inode_bl->i_blocks = blocks;
		inode_bl->i_bytes = bytes;
		swap_inode_data(inode, inode_bl);
		scext4_mark_inode_dirty(handle, inode);
		scext4_mark_inode_dirty(handle, inode_bl);
	}

err_out1:
	scext4_journal_stop(handle);
	scext4_double_up_write_data_sem(inode, inode_bl);

err_out:
	up_write(&SCEXT4_I(inode)->i_mmap_sem);
journal_err_out:
	unlock_two_nondirectories(inode, inode_bl);
	iput(inode_bl);
	return err;
}

#ifdef CONFIG_FS_ENCRYPTION
static int uuid_is_zero(__u8 u[16])
{
	int	i;

	for (i = 0; i < 16; i++)
		if (u[i])
			return 0;
	return 1;
}
#endif

/*
 * If immutable is set and we are not clearing it, we're not allowed to change
 * anything else in the inode.  Don't error out if we're only trying to set
 * immutable on an immutable file.
 */
static int scext4_ioctl_check_immutable(struct inode *inode, __u32 new_projid,
				      unsigned int flags)
{
	struct scext4_inode_info *ei = SCEXT4_I(inode);
	unsigned int oldflags = ei->i_flags;

	if (!(oldflags & SCEXT4_IMMUTABLE_FL) || !(flags & SCEXT4_IMMUTABLE_FL))
		return 0;

	if ((oldflags & ~SCEXT4_IMMUTABLE_FL) != (flags & ~SCEXT4_IMMUTABLE_FL))
		return -EPERM;
	if (scext4_has_feature_project(inode->i_sb) &&
	    __kprojid_val(ei->i_projid) != new_projid)
		return -EPERM;

	return 0;
}

static int scext4_ioctl_setflags(struct inode *inode,
			       unsigned int flags)
{
	struct scext4_inode_info *ei = SCEXT4_I(inode);
	handle_t *handle = NULL;
	int err = -EPERM, migrate = 0;
	struct scext4_iloc iloc;
	unsigned int oldflags, mask, i;
	unsigned int jflag;
	struct super_block *sb = inode->i_sb;

	/* Is it quota file? Do not allow user to mess with it */
	if (scext4_is_quota_file(inode))
		goto flags_out;

	oldflags = ei->i_flags;

	/* The JOURNAL_DATA flag is modifiable only by root */
	jflag = flags & SCEXT4_JOURNAL_DATA_FL;

	err = vfs_ioc_setflags_prepare(inode, oldflags, flags);
	if (err)
		goto flags_out;

	/*
	 * The JOURNAL_DATA flag can only be changed by
	 * the relevant capability.
	 */
	if ((jflag ^ oldflags) & (SCEXT4_JOURNAL_DATA_FL)) {
		if (!capable(CAP_SYS_RESOURCE))
			goto flags_out;
	}
	if ((flags ^ oldflags) & SCEXT4_EXTENTS_FL)
		migrate = 1;

	if (flags & SCEXT4_EOFBLOCKS_FL) {
		/* we don't support adding EOFBLOCKS flag */
		if (!(oldflags & SCEXT4_EOFBLOCKS_FL)) {
			err = -EOPNOTSUPP;
			goto flags_out;
		}
	} else if (oldflags & SCEXT4_EOFBLOCKS_FL) {
		err = scext4_truncate(inode);
		if (err)
			goto flags_out;
	}

	if ((flags ^ oldflags) & SCEXT4_CASEFOLD_FL) {
		if (!scext4_has_feature_casefold(sb)) {
			err = -EOPNOTSUPP;
			goto flags_out;
		}

		if (!S_ISDIR(inode->i_mode)) {
			err = -ENOTDIR;
			goto flags_out;
		}

		if (!scext4_empty_dir(inode)) {
			err = -ENOTEMPTY;
			goto flags_out;
		}
	}

	/*
	 * Wait for all pending directio and then flush all the dirty pages
	 * for this file.  The flush marks all the pages readonly, so any
	 * subsequent attempt to write to the file (particularly mmap pages)
	 * will come through the filesystem and fail.
	 */
	if (S_ISREG(inode->i_mode) && !IS_IMMUTABLE(inode) &&
	    (flags & SCEXT4_IMMUTABLE_FL)) {
		inode_dio_wait(inode);
		err = filemap_write_and_wait(inode->i_mapping);
		if (err)
			goto flags_out;
	}

	handle = scext4_journal_start(inode, SCEXT4_HT_INODE, 1);
	if (IS_ERR(handle)) {
		err = PTR_ERR(handle);
		goto flags_out;
	}
	if (IS_SYNC(inode))
		scext4_handle_sync(handle);
	err = scext4_reserve_inode_write(handle, inode, &iloc);
	if (err)
		goto flags_err;

	for (i = 0, mask = 1; i < 32; i++, mask <<= 1) {
		if (!(mask & SCEXT4_FL_USER_MODIFIABLE))
			continue;
		/* These flags get special treatment later */
		if (mask == SCEXT4_JOURNAL_DATA_FL || mask == SCEXT4_EXTENTS_FL)
			continue;
		if (mask & flags)
			scext4_set_inode_flag(inode, i);
		else
			scext4_clear_inode_flag(inode, i);
	}

	scext4_set_inode_flags(inode);
	inode->i_ctime = current_time(inode);

	err = scext4_mark_iloc_dirty(handle, inode, &iloc);
flags_err:
	scext4_journal_stop(handle);
	if (err)
		goto flags_out;

	if ((jflag ^ oldflags) & (SCEXT4_JOURNAL_DATA_FL)) {
		/*
		 * Changes to the journaling mode can cause unsafe changes to
		 * S_DAX if we are using the DAX mount option.
		 */
		if (test_opt(inode->i_sb, DAX)) {
			err = -EBUSY;
			goto flags_out;
		}

		err = scext4_change_inode_journal_flag(inode, jflag);
		if (err)
			goto flags_out;
	}
	if (migrate) {
		if (flags & SCEXT4_EXTENTS_FL)
			err = scext4_ext_migrate(inode);
		else
			err = scext4_ind_migrate(inode);
	}

flags_out:
	return err;
}

#ifdef CONFIG_QUOTA
static int scext4_ioctl_setproject(struct file *filp, __u32 projid)
{
	struct inode *inode = file_inode(filp);
	struct super_block *sb = inode->i_sb;
	struct scext4_inode_info *ei = SCEXT4_I(inode);
	int err, rc;
	handle_t *handle;
	kprojid_t kprojid;
	struct scext4_iloc iloc;
	struct scext4_inode *raw_inode;
	struct dquot *transfer_to[MAXQUOTAS] = { };

	if (!scext4_has_feature_project(sb)) {
		if (projid != SCEXT4_DEF_PROJID)
			return -EOPNOTSUPP;
		else
			return 0;
	}

	if (SCEXT4_INODE_SIZE(sb) <= SCEXT4_GOOD_OLD_INODE_SIZE)
		return -EOPNOTSUPP;

	kprojid = make_kprojid(&init_user_ns, (projid_t)projid);

	if (projid_eq(kprojid, SCEXT4_I(inode)->i_projid))
		return 0;

	err = -EPERM;
	/* Is it quota file? Do not allow user to mess with it */
	if (scext4_is_quota_file(inode))
		return err;

	err = scext4_get_inode_loc(inode, &iloc);
	if (err)
		return err;

	raw_inode = scext4_raw_inode(&iloc);
	if (!SCEXT4_FITS_IN_INODE(raw_inode, ei, i_projid)) {
		err = scext4_expand_extra_isize(inode,
					      SCEXT4_SB(sb)->s_want_extra_isize,
					      &iloc);
		if (err)
			return err;
	} else {
		brelse(iloc.bh);
	}

	err = dquot_initialize(inode);
	if (err)
		return err;

	handle = scext4_journal_start(inode, SCEXT4_HT_QUOTA,
		SCEXT4_QUOTA_INIT_BLOCKS(sb) +
		SCEXT4_QUOTA_DEL_BLOCKS(sb) + 3);
	if (IS_ERR(handle))
		return PTR_ERR(handle);

	err = scext4_reserve_inode_write(handle, inode, &iloc);
	if (err)
		goto out_stop;

	transfer_to[PRJQUOTA] = dqget(sb, make_kqid_projid(kprojid));
	if (!IS_ERR(transfer_to[PRJQUOTA])) {

		/* __dquot_transfer() calls back scext4_get_inode_usage() which
		 * counts xattr inode references.
		 */
		down_read(&SCEXT4_I(inode)->xattr_sem);
		err = __dquot_transfer(inode, transfer_to);
		up_read(&SCEXT4_I(inode)->xattr_sem);
		dqput(transfer_to[PRJQUOTA]);
		if (err)
			goto out_dirty;
	}

	SCEXT4_I(inode)->i_projid = kprojid;
	inode->i_ctime = current_time(inode);
out_dirty:
	rc = scext4_mark_iloc_dirty(handle, inode, &iloc);
	if (!err)
		err = rc;
out_stop:
	scext4_journal_stop(handle);
	return err;
}
#else
static int scext4_ioctl_setproject(struct file *filp, __u32 projid)
{
	if (projid != SCEXT4_DEF_PROJID)
		return -EOPNOTSUPP;
	return 0;
}
#endif

/* Transfer internal flags to xflags */
static inline __u32 scext4_iflags_to_xflags(unsigned long iflags)
{
	__u32 xflags = 0;

	if (iflags & SCEXT4_SYNC_FL)
		xflags |= FS_XFLAG_SYNC;
	if (iflags & SCEXT4_IMMUTABLE_FL)
		xflags |= FS_XFLAG_IMMUTABLE;
	if (iflags & SCEXT4_APPEND_FL)
		xflags |= FS_XFLAG_APPEND;
	if (iflags & SCEXT4_NODUMP_FL)
		xflags |= FS_XFLAG_NODUMP;
	if (iflags & SCEXT4_NOATIME_FL)
		xflags |= FS_XFLAG_NOATIME;
	if (iflags & SCEXT4_PROJINHERIT_FL)
		xflags |= FS_XFLAG_PROJINHERIT;
	return xflags;
}

#define SCEXT4_SUPPORTED_FS_XFLAGS (FS_XFLAG_SYNC | FS_XFLAG_IMMUTABLE | \
				  FS_XFLAG_APPEND | FS_XFLAG_NODUMP | \
				  FS_XFLAG_NOATIME | FS_XFLAG_PROJINHERIT)

/* Transfer xflags flags to internal */
static inline unsigned long scext4_xflags_to_iflags(__u32 xflags)
{
	unsigned long iflags = 0;

	if (xflags & FS_XFLAG_SYNC)
		iflags |= SCEXT4_SYNC_FL;
	if (xflags & FS_XFLAG_IMMUTABLE)
		iflags |= SCEXT4_IMMUTABLE_FL;
	if (xflags & FS_XFLAG_APPEND)
		iflags |= SCEXT4_APPEND_FL;
	if (xflags & FS_XFLAG_NODUMP)
		iflags |= SCEXT4_NODUMP_FL;
	if (xflags & FS_XFLAG_NOATIME)
		iflags |= SCEXT4_NOATIME_FL;
	if (xflags & FS_XFLAG_PROJINHERIT)
		iflags |= SCEXT4_PROJINHERIT_FL;

	return iflags;
}

static int scext4_shutdown(struct super_block *sb, unsigned long arg)
{
	struct scext4_sb_info *sbi = SCEXT4_SB(sb);
	__u32 flags;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (get_user(flags, (__u32 __user *)arg))
		return -EFAULT;

	if (flags > SCEXT4_GOING_FLAGS_NOLOGFLUSH)
		return -EINVAL;

	if (scext4_forced_shutdown(sbi))
		return 0;

	scext4_msg(sb, KERN_ALERT, "shut down requested (%d)", flags);
	trace_scext4_shutdown(sb, flags);

	switch (flags) {
	case SCEXT4_GOING_FLAGS_DEFAULT:
		freeze_bdev(sb->s_bdev);
		set_bit(SCEXT4_FLAGS_SHUTDOWN, &sbi->s_scext4_flags);
		thaw_bdev(sb->s_bdev, sb);
		break;
	case SCEXT4_GOING_FLAGS_LOGFLUSH:
		set_bit(SCEXT4_FLAGS_SHUTDOWN, &sbi->s_scext4_flags);
		if (sbi->s_journal && !is_journal_aborted(sbi->s_journal)) {
			(void) scext4_force_commit(sb);
			jbd3_journal_abort(sbi->s_journal, -ESHUTDOWN);
		}
		break;
	case SCEXT4_GOING_FLAGS_NOLOGFLUSH:
		set_bit(SCEXT4_FLAGS_SHUTDOWN, &sbi->s_scext4_flags);
		if (sbi->s_journal && !is_journal_aborted(sbi->s_journal))
			jbd3_journal_abort(sbi->s_journal, -ESHUTDOWN);
		break;
	default:
		return -EINVAL;
	}
	clear_opt(sb, DISCARD);
	return 0;
}

struct getfsmap_info {
	struct super_block	*gi_sb;
	struct fsmap_head __user *gi_data;
	unsigned int		gi_idx;
	__u32			gi_last_flags;
};

static int scext4_getfsmap_format(struct scext4_fsmap *xfm, void *priv)
{
	struct getfsmap_info *info = priv;
	struct fsmap fm;

	trace_scext4_getfsmap_mapping(info->gi_sb, xfm);

	info->gi_last_flags = xfm->fmr_flags;
	scext4_fsmap_from_internal(info->gi_sb, &fm, xfm);
	if (copy_to_user(&info->gi_data->fmh_recs[info->gi_idx++], &fm,
			sizeof(struct fsmap)))
		return -EFAULT;

	return 0;
}

static int scext4_ioc_getfsmap(struct super_block *sb,
			     struct fsmap_head __user *arg)
{
	struct getfsmap_info info = { NULL };
	struct scext4_fsmap_head xhead = {0};
	struct fsmap_head head;
	bool aborted = false;
	int error;

	if (copy_from_user(&head, arg, sizeof(struct fsmap_head)))
		return -EFAULT;
	if (memchr_inv(head.fmh_reserved, 0, sizeof(head.fmh_reserved)) ||
	    memchr_inv(head.fmh_keys[0].fmr_reserved, 0,
		       sizeof(head.fmh_keys[0].fmr_reserved)) ||
	    memchr_inv(head.fmh_keys[1].fmr_reserved, 0,
		       sizeof(head.fmh_keys[1].fmr_reserved)))
		return -EINVAL;
	/*
	 * scext4 doesn't report file extents at all, so the only valid
	 * file offsets are the magic ones (all zeroes or all ones).
	 */
	if (head.fmh_keys[0].fmr_offset ||
	    (head.fmh_keys[1].fmr_offset != 0 &&
	     head.fmh_keys[1].fmr_offset != -1ULL))
		return -EINVAL;

	xhead.fmh_iflags = head.fmh_iflags;
	xhead.fmh_count = head.fmh_count;
	scext4_fsmap_to_internal(sb, &xhead.fmh_keys[0], &head.fmh_keys[0]);
	scext4_fsmap_to_internal(sb, &xhead.fmh_keys[1], &head.fmh_keys[1]);

	trace_scext4_getfsmap_low_key(sb, &xhead.fmh_keys[0]);
	trace_scext4_getfsmap_high_key(sb, &xhead.fmh_keys[1]);

	info.gi_sb = sb;
	info.gi_data = arg;
	error = scext4_getfsmap(sb, &xhead, scext4_getfsmap_format, &info);
	if (error == SCEXT4_QUERY_RANGE_ABORT) {
		error = 0;
		aborted = true;
	} else if (error)
		return error;

	/* If we didn't abort, set the "last" flag in the last fmx */
	if (!aborted && info.gi_idx) {
		info.gi_last_flags |= FMR_OF_LAST;
		if (copy_to_user(&info.gi_data->fmh_recs[info.gi_idx - 1].fmr_flags,
				 &info.gi_last_flags,
				 sizeof(info.gi_last_flags)))
			return -EFAULT;
	}

	/* copy back header */
	head.fmh_entries = xhead.fmh_entries;
	head.fmh_oflags = xhead.fmh_oflags;
	if (copy_to_user(arg, &head, sizeof(struct fsmap_head)))
		return -EFAULT;

	return 0;
}

static long scext4_ioctl_group_add(struct file *file,
				 struct scext4_new_group_data *input)
{
	struct super_block *sb = file_inode(file)->i_sb;
	int err, err2=0;

	err = scext4_resize_begin(sb);
	if (err)
		return err;

	if (scext4_has_feature_bigalloc(sb)) {
		scext4_msg(sb, KERN_ERR,
			 "Online resizing not supported with bigalloc");
		err = -EOPNOTSUPP;
		goto group_add_out;
	}

	err = mnt_want_write_file(file);
	if (err)
		goto group_add_out;

	err = scext4_group_add(sb, input);
	if (SCEXT4_SB(sb)->s_journal) {
		jbd3_journal_lock_updates(SCEXT4_SB(sb)->s_journal);
		err2 = jbd3_journal_flush(SCEXT4_SB(sb)->s_journal);
		jbd3_journal_unlock_updates(SCEXT4_SB(sb)->s_journal);
	}
	if (err == 0)
		err = err2;
	mnt_drop_write_file(file);
	if (!err && scext4_has_group_desc_csum(sb) &&
	    test_opt(sb, INIT_INODE_TABLE))
		err = scext4_register_li_request(sb, input->group);
group_add_out:
	scext4_resize_end(sb);
	return err;
}

static void scext4_fill_fsxattr(struct inode *inode, struct fsxattr *fa)
{
	struct scext4_inode_info *ei = SCEXT4_I(inode);

	simple_fill_fsxattr(fa, scext4_iflags_to_xflags(ei->i_flags &
						      SCEXT4_FL_USER_VISIBLE));

	if (scext4_has_feature_project(inode->i_sb))
		fa->fsx_projid = from_kprojid(&init_user_ns, ei->i_projid);
}

/* copied from fs/ioctl.c */
static int fiemap_check_ranges(struct super_block *sb,
			       u64 start, u64 len, u64 *new_len)
{
	u64 maxbytes = (u64) sb->s_maxbytes;

	*new_len = len;

	if (len == 0)
		return -EINVAL;

	if (start > maxbytes)
		return -EFBIG;

	/*
	 * Shrink request scope to what the fs can actually handle.
	 */
	if (len > maxbytes || (maxbytes - len) < start)
		*new_len = maxbytes - start;

	return 0;
}

/* So that the fiemap access checks can't overflow on 32 bit machines. */
#define FIEMAP_MAX_EXTENTS	(UINT_MAX / sizeof(struct fiemap_extent))

static int scext4_ioctl_get_es_cache(struct file *filp, unsigned long arg)
{
	struct fiemap fiemap;
	struct fiemap __user *ufiemap = (struct fiemap __user *) arg;
	struct fiemap_extent_info fieinfo = { 0, };
	struct inode *inode = file_inode(filp);
	struct super_block *sb = inode->i_sb;
	u64 len;
	int error;

	if (copy_from_user(&fiemap, ufiemap, sizeof(fiemap)))
		return -EFAULT;

	if (fiemap.fm_extent_count > FIEMAP_MAX_EXTENTS)
		return -EINVAL;

	error = fiemap_check_ranges(sb, fiemap.fm_start, fiemap.fm_length,
				    &len);
	if (error)
		return error;

	fieinfo.fi_flags = fiemap.fm_flags;
	fieinfo.fi_extents_max = fiemap.fm_extent_count;
	fieinfo.fi_extents_start = ufiemap->fm_extents;

	if (fiemap.fm_extent_count != 0 &&
	    !access_ok(fieinfo.fi_extents_start,
		       fieinfo.fi_extents_max * sizeof(struct fiemap_extent)))
		return -EFAULT;

	if (fieinfo.fi_flags & FIEMAP_FLAG_SYNC)
		filemap_write_and_wait(inode->i_mapping);

	error = scext4_get_es_cache(inode, &fieinfo, fiemap.fm_start, len);
	fiemap.fm_flags = fieinfo.fi_flags;
	fiemap.fm_mapped_extents = fieinfo.fi_extents_mapped;
	if (copy_to_user(ufiemap, &fiemap, sizeof(fiemap)))
		error = -EFAULT;

	return error;
}

long scext4_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	struct super_block *sb = inode->i_sb;
	struct scext4_inode_info *ei = SCEXT4_I(inode);
	unsigned int flags;

	scext4_debug("cmd = %u, arg = %lu\n", cmd, arg);

	switch (cmd) {
	case FS_IOC_GETFSMAP:
		return scext4_ioc_getfsmap(sb, (void __user *)arg);
	case SCEXT4_IOC_GETFLAGS:
		flags = ei->i_flags & SCEXT4_FL_USER_VISIBLE;
		if (S_ISREG(inode->i_mode))
			flags &= ~SCEXT4_PROJINHERIT_FL;
		return put_user(flags, (int __user *) arg);
	case SCEXT4_IOC_SETFLAGS: {
		int err;

		if (!inode_owner_or_capable(inode))
			return -EACCES;

		if (get_user(flags, (int __user *) arg))
			return -EFAULT;

		if (flags & ~SCEXT4_FL_USER_VISIBLE)
			return -EOPNOTSUPP;
		/*
		 * chattr(1) grabs flags via GETFLAGS, modifies the result and
		 * passes that to SETFLAGS. So we cannot easily make SETFLAGS
		 * more restrictive than just silently masking off visible but
		 * not settable flags as we always did.
		 */
		flags &= SCEXT4_FL_USER_MODIFIABLE;
		if (scext4_mask_flags(inode->i_mode, flags) != flags)
			return -EOPNOTSUPP;

		err = mnt_want_write_file(filp);
		if (err)
			return err;

		inode_lock(inode);
		err = scext4_ioctl_check_immutable(inode,
				from_kprojid(&init_user_ns, ei->i_projid),
				flags);
		if (!err)
			err = scext4_ioctl_setflags(inode, flags);
		inode_unlock(inode);
		mnt_drop_write_file(filp);
		return err;
	}
	case SCEXT4_IOC_GETVERSION:
	case SCEXT4_IOC_GETVERSION_OLD:
		return put_user(inode->i_generation, (int __user *) arg);
	case SCEXT4_IOC_SETVERSION:
	case SCEXT4_IOC_SETVERSION_OLD: {
		handle_t *handle;
		struct scext4_iloc iloc;
		__u32 generation;
		int err;

		if (!inode_owner_or_capable(inode))
			return -EPERM;

		if (scext4_has_metadata_csum(inode->i_sb)) {
			scext4_warning(sb, "Setting inode version is not "
				     "supported with metadata_csum enabled.");
			return -ENOTTY;
		}

		err = mnt_want_write_file(filp);
		if (err)
			return err;
		if (get_user(generation, (int __user *) arg)) {
			err = -EFAULT;
			goto setversion_out;
		}

		inode_lock(inode);
		handle = scext4_journal_start(inode, SCEXT4_HT_INODE, 1);
		if (IS_ERR(handle)) {
			err = PTR_ERR(handle);
			goto unlock_out;
		}
		err = scext4_reserve_inode_write(handle, inode, &iloc);
		if (err == 0) {
			inode->i_ctime = current_time(inode);
			inode->i_generation = generation;
			err = scext4_mark_iloc_dirty(handle, inode, &iloc);
		}
		scext4_journal_stop(handle);

unlock_out:
		inode_unlock(inode);
setversion_out:
		mnt_drop_write_file(filp);
		return err;
	}
	case SCEXT4_IOC_GROUP_EXTEND: {
		scext4_fsblk_t n_blocks_count;
		int err, err2=0;

		err = scext4_resize_begin(sb);
		if (err)
			return err;

		if (get_user(n_blocks_count, (__u32 __user *)arg)) {
			err = -EFAULT;
			goto group_extend_out;
		}

		if (scext4_has_feature_bigalloc(sb)) {
			scext4_msg(sb, KERN_ERR,
				 "Online resizing not supported with bigalloc");
			err = -EOPNOTSUPP;
			goto group_extend_out;
		}

		err = mnt_want_write_file(filp);
		if (err)
			goto group_extend_out;

		err = scext4_group_extend(sb, SCEXT4_SB(sb)->s_es, n_blocks_count);
		if (SCEXT4_SB(sb)->s_journal) {
			jbd3_journal_lock_updates(SCEXT4_SB(sb)->s_journal);
			err2 = jbd3_journal_flush(SCEXT4_SB(sb)->s_journal);
			jbd3_journal_unlock_updates(SCEXT4_SB(sb)->s_journal);
		}
		if (err == 0)
			err = err2;
		mnt_drop_write_file(filp);
group_extend_out:
		scext4_resize_end(sb);
		return err;
	}

	case EXT4_IOC_MOVE_EXT: {
		struct move_extent me;
		struct fd donor;
		int err;
		//debug
		//printk("in the right ioctl\n");

		if (!(filp->f_mode & FMODE_READ) ||
		    !(filp->f_mode & FMODE_WRITE))
			return -EBADF;

		if (copy_from_user(&me,
			(struct move_extent __user *)arg, sizeof(me)))
			return -EFAULT;
		me.moved_len = 0;

		donor = fdget(me.donor_fd);
		if (!donor.file)
			return -EBADF;

		if (!(donor.file->f_mode & FMODE_WRITE)) {
			err = -EBADF;
			goto mext_out;
		}

		if (scext4_has_feature_bigalloc(sb)) {
			scext4_msg(sb, KERN_ERR,
				 "Online defrag not supported with bigalloc");
			err = -EOPNOTSUPP;
			goto mext_out;
		} else if (IS_DAX(inode)) {
			scext4_msg(sb, KERN_ERR,
				 "Online defrag not supported with DAX");
			err = -EOPNOTSUPP;
			goto mext_out;
		}

		// ziggy: flip is target file
		err = mnt_want_write_file(filp);
		if (err)
			goto mext_out;

		err = scext4_move_extents_async(filp, donor.file, me.orig_start,
					me.donor_start, me.len, &me.moved_len);
		mnt_drop_write_file(filp);

		if (copy_to_user((struct move_extent __user *)arg,
				 &me, sizeof(me)))
			err = -EFAULT;
mext_out:
		fdput(donor);
		return err;
	}

	case SCEXT4_IOC_GROUP_ADD: {
		struct scext4_new_group_data input;

		if (copy_from_user(&input, (struct scext4_new_group_input __user *)arg,
				sizeof(input)))
			return -EFAULT;

		return scext4_ioctl_group_add(filp, &input);
	}

	case SCEXT4_IOC_MIGRATE:
	{
		int err;
		if (!inode_owner_or_capable(inode))
			return -EACCES;

		err = mnt_want_write_file(filp);
		if (err)
			return err;
		/*
		 * inode_mutex prevent write and truncate on the file.
		 * Read still goes through. We take i_data_sem in
		 * scext4_ext_swap_inode_data before we switch the
		 * inode format to prevent read.
		 */
		inode_lock((inode));
		err = scext4_ext_migrate(inode);
		inode_unlock((inode));
		mnt_drop_write_file(filp);
		return err;
	}

	case SCEXT4_IOC_ALLOC_DA_BLKS:
	{
		int err;
		if (!inode_owner_or_capable(inode))
			return -EACCES;

		err = mnt_want_write_file(filp);
		if (err)
			return err;
		err = scext4_alloc_da_blocks(inode);
		mnt_drop_write_file(filp);
		return err;
	}

	case SCEXT4_IOC_SWAP_BOOT:
	{
		int err;
		if (!(filp->f_mode & FMODE_WRITE))
			return -EBADF;
		err = mnt_want_write_file(filp);
		if (err)
			return err;
		err = swap_inode_boot_loader(sb, inode);
		mnt_drop_write_file(filp);
		return err;
	}

	case SCEXT4_IOC_RESIZE_FS: {
		scext4_fsblk_t n_blocks_count;
		int err = 0, err2 = 0;
		scext4_group_t o_group = SCEXT4_SB(sb)->s_groups_count;

		if (copy_from_user(&n_blocks_count, (__u64 __user *)arg,
				   sizeof(__u64))) {
			return -EFAULT;
		}

		err = scext4_resize_begin(sb);
		if (err)
			return err;

		err = mnt_want_write_file(filp);
		if (err)
			goto resizefs_out;

		err = scext4_resize_fs(sb, n_blocks_count);
		if (SCEXT4_SB(sb)->s_journal) {
			jbd3_journal_lock_updates(SCEXT4_SB(sb)->s_journal);
			err2 = jbd3_journal_flush(SCEXT4_SB(sb)->s_journal);
			jbd3_journal_unlock_updates(SCEXT4_SB(sb)->s_journal);
		}
		if (err == 0)
			err = err2;
		mnt_drop_write_file(filp);
		if (!err && (o_group < SCEXT4_SB(sb)->s_groups_count) &&
		    scext4_has_group_desc_csum(sb) &&
		    test_opt(sb, INIT_INODE_TABLE))
			err = scext4_register_li_request(sb, o_group);

resizefs_out:
		scext4_resize_end(sb);
		return err;
	}

	case FITRIM:
	{
		struct request_queue *q = bdev_get_queue(sb->s_bdev);
		struct fstrim_range range;
		int ret = 0;

		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;

		if (!blk_queue_discard(q))
			return -EOPNOTSUPP;

		/*
		 * We haven't replayed the journal, so we cannot use our
		 * block-bitmap-guided storage zapping commands.
		 */
		if (test_opt(sb, NOLOAD) && scext4_has_feature_journal(sb))
			return -EROFS;

		if (copy_from_user(&range, (struct fstrim_range __user *)arg,
		    sizeof(range)))
			return -EFAULT;

		range.minlen = max((unsigned int)range.minlen,
				   q->limits.discard_granularity);
		ret = scext4_trim_fs(sb, &range);
		if (ret < 0)
			return ret;

		if (copy_to_user((struct fstrim_range __user *)arg, &range,
		    sizeof(range)))
			return -EFAULT;

		return 0;
	}
	case SCEXT4_IOC_PRECACHE_EXTENTS:
		return scext4_ext_precache(inode);

	case SCEXT4_IOC_SET_ENCRYPTION_POLICY:
		if (!scext4_has_feature_encrypt(sb))
			return -EOPNOTSUPP;
		return fscrypt_ioctl_set_policy(filp, (const void __user *)arg);

	case SCEXT4_IOC_GET_ENCRYPTION_PWSALT: {
#ifdef CONFIG_FS_ENCRYPTION
		int err, err2;
		struct scext4_sb_info *sbi = SCEXT4_SB(sb);
		handle_t *handle;

		if (!scext4_has_feature_encrypt(sb))
			return -EOPNOTSUPP;
		if (uuid_is_zero(sbi->s_es->s_encrypt_pw_salt)) {
			err = mnt_want_write_file(filp);
			if (err)
				return err;
			handle = scext4_journal_start_sb(sb, SCEXT4_HT_MISC, 1);
			if (IS_ERR(handle)) {
				err = PTR_ERR(handle);
				goto pwsalt_err_exit;
			}
			err = scext4_journal_get_write_access(handle, sbi->s_sbh);
			if (err)
				goto pwsalt_err_journal;
			lock_buffer(sbi->s_sbh);
			generate_random_uuid(sbi->s_es->s_encrypt_pw_salt);
			scext4_superblock_csum_set(sb);
			unlock_buffer(sbi->s_sbh);
			err = scext4_handle_dirty_metadata(handle, NULL,
							 sbi->s_sbh);
		pwsalt_err_journal:
			err2 = scext4_journal_stop(handle);
			if (err2 && !err)
				err = err2;
		pwsalt_err_exit:
			mnt_drop_write_file(filp);
			if (err)
				return err;
		}
		if (copy_to_user((void __user *) arg,
				 sbi->s_es->s_encrypt_pw_salt, 16))
			return -EFAULT;
		return 0;
#else
		return -EOPNOTSUPP;
#endif
	}
	case SCEXT4_IOC_GET_ENCRYPTION_POLICY:
		if (!scext4_has_feature_encrypt(sb))
			return -EOPNOTSUPP;
		return fscrypt_ioctl_get_policy(filp, (void __user *)arg);

	case FS_IOC_GET_ENCRYPTION_POLICY_EX:
		if (!scext4_has_feature_encrypt(sb))
			return -EOPNOTSUPP;
		return fscrypt_ioctl_get_policy_ex(filp, (void __user *)arg);

	case FS_IOC_ADD_ENCRYPTION_KEY:
		if (!scext4_has_feature_encrypt(sb))
			return -EOPNOTSUPP;
		return fscrypt_ioctl_add_key(filp, (void __user *)arg);

	case FS_IOC_REMOVE_ENCRYPTION_KEY:
		if (!scext4_has_feature_encrypt(sb))
			return -EOPNOTSUPP;
		return fscrypt_ioctl_remove_key(filp, (void __user *)arg);

	case FS_IOC_REMOVE_ENCRYPTION_KEY_ALL_USERS:
		if (!scext4_has_feature_encrypt(sb))
			return -EOPNOTSUPP;
		return fscrypt_ioctl_remove_key_all_users(filp,
							  (void __user *)arg);
	case FS_IOC_GET_ENCRYPTION_KEY_STATUS:
		if (!scext4_has_feature_encrypt(sb))
			return -EOPNOTSUPP;
		return fscrypt_ioctl_get_key_status(filp, (void __user *)arg);

	case SCEXT4_IOC_CLEAR_ES_CACHE:
	{
		if (!inode_owner_or_capable(inode))
			return -EACCES;
		scext4_clear_inode_es(inode);
		return 0;
	}

	case SCEXT4_IOC_GETSTATE:
	{
		__u32	state = 0;

		if (scext4_test_inode_state(inode, SCEXT4_STATE_EXT_PRECACHED))
			state |= SCEXT4_STATE_FLAG_EXT_PRECACHED;
		if (scext4_test_inode_state(inode, SCEXT4_STATE_NEW))
			state |= SCEXT4_STATE_FLAG_NEW;
		if (scext4_test_inode_state(inode, SCEXT4_STATE_NEWENTRY))
			state |= SCEXT4_STATE_FLAG_NEWENTRY;
		if (scext4_test_inode_state(inode, SCEXT4_STATE_DA_ALLOC_CLOSE))
			state |= SCEXT4_STATE_FLAG_DA_ALLOC_CLOSE;

		return put_user(state, (__u32 __user *) arg);
	}

	case SCEXT4_IOC_GET_ES_CACHE:
		return scext4_ioctl_get_es_cache(filp, arg);

	case SCEXT4_IOC_FSGETXATTR:
	{
		struct fsxattr fa;

		scext4_fill_fsxattr(inode, &fa);

		if (copy_to_user((struct fsxattr __user *)arg,
				 &fa, sizeof(fa)))
			return -EFAULT;
		return 0;
	}
	case SCEXT4_IOC_FSSETXATTR:
	{
		struct fsxattr fa, old_fa;
		int err;

		if (copy_from_user(&fa, (struct fsxattr __user *)arg,
				   sizeof(fa)))
			return -EFAULT;

		/* Make sure caller has proper permission */
		if (!inode_owner_or_capable(inode))
			return -EACCES;

		if (fa.fsx_xflags & ~SCEXT4_SUPPORTED_FS_XFLAGS)
			return -EOPNOTSUPP;

		flags = scext4_xflags_to_iflags(fa.fsx_xflags);
		if (scext4_mask_flags(inode->i_mode, flags) != flags)
			return -EOPNOTSUPP;

		err = mnt_want_write_file(filp);
		if (err)
			return err;

		inode_lock(inode);
		scext4_fill_fsxattr(inode, &old_fa);
		err = vfs_ioc_fssetxattr_check(inode, &old_fa, &fa);
		if (err)
			goto out;
		flags = (ei->i_flags & ~SCEXT4_FL_XFLAG_VISIBLE) |
			 (flags & SCEXT4_FL_XFLAG_VISIBLE);
		err = scext4_ioctl_check_immutable(inode, fa.fsx_projid, flags);
		if (err)
			goto out;
		err = scext4_ioctl_setflags(inode, flags);
		if (err)
			goto out;
		err = scext4_ioctl_setproject(filp, fa.fsx_projid);
out:
		inode_unlock(inode);
		mnt_drop_write_file(filp);
		return err;
	}
	case SCEXT4_IOC_SHUTDOWN:
		return scext4_shutdown(sb, arg);

	case FS_IOC_ENABLE_VERITY:
		if (!scext4_has_feature_verity(sb))
			return -EOPNOTSUPP;
		return fsverity_ioctl_enable(filp, (const void __user *)arg);

	case FS_IOC_MEASURE_VERITY:
		if (!scext4_has_feature_verity(sb))
			return -EOPNOTSUPP;
		return fsverity_ioctl_measure(filp, (void __user *)arg);

	default:
		return -ENOTTY;
	}
}

#ifdef CONFIG_COMPAT
long scext4_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	/* These are just misnamed, they actually get/put from/to user an int */
	switch (cmd) {
	case SCEXT4_IOC32_GETFLAGS:
		cmd = SCEXT4_IOC_GETFLAGS;
		break;
	case SCEXT4_IOC32_SETFLAGS:
		cmd = SCEXT4_IOC_SETFLAGS;
		break;
	case SCEXT4_IOC32_GETVERSION:
		cmd = SCEXT4_IOC_GETVERSION;
		break;
	case SCEXT4_IOC32_SETVERSION:
		cmd = SCEXT4_IOC_SETVERSION;
		break;
	case SCEXT4_IOC32_GROUP_EXTEND:
		cmd = SCEXT4_IOC_GROUP_EXTEND;
		break;
	case SCEXT4_IOC32_GETVERSION_OLD:
		cmd = SCEXT4_IOC_GETVERSION_OLD;
		break;
	case SCEXT4_IOC32_SETVERSION_OLD:
		cmd = SCEXT4_IOC_SETVERSION_OLD;
		break;
	case SCEXT4_IOC32_GETRSVSZ:
		cmd = SCEXT4_IOC_GETRSVSZ;
		break;
	case SCEXT4_IOC32_SETRSVSZ:
		cmd = SCEXT4_IOC_SETRSVSZ;
		break;
	case SCEXT4_IOC32_GROUP_ADD: {
		struct compat_scext4_new_group_input __user *uinput;
		struct scext4_new_group_data input;
		int err;

		uinput = compat_ptr(arg);
		err = get_user(input.group, &uinput->group);
		err |= get_user(input.block_bitmap, &uinput->block_bitmap);
		err |= get_user(input.inode_bitmap, &uinput->inode_bitmap);
		err |= get_user(input.inode_table, &uinput->inode_table);
		err |= get_user(input.blocks_count, &uinput->blocks_count);
		err |= get_user(input.reserved_blocks,
				&uinput->reserved_blocks);
		if (err)
			return -EFAULT;
		return scext4_ioctl_group_add(file, &input);
	}
	case EXT4_IOC_MOVE_EXT:
	case SCEXT4_IOC_RESIZE_FS:
	case SCEXT4_IOC_PRECACHE_EXTENTS:
	case SCEXT4_IOC_SET_ENCRYPTION_POLICY:
	case SCEXT4_IOC_GET_ENCRYPTION_PWSALT:
	case SCEXT4_IOC_GET_ENCRYPTION_POLICY:
	case FS_IOC_GET_ENCRYPTION_POLICY_EX:
	case FS_IOC_ADD_ENCRYPTION_KEY:
	case FS_IOC_REMOVE_ENCRYPTION_KEY:
	case FS_IOC_REMOVE_ENCRYPTION_KEY_ALL_USERS:
	case FS_IOC_GET_ENCRYPTION_KEY_STATUS:
	case SCEXT4_IOC_SHUTDOWN:
	case FS_IOC_GETFSMAP:
	case FS_IOC_ENABLE_VERITY:
	case FS_IOC_MEASURE_VERITY:
	case SCEXT4_IOC_CLEAR_ES_CACHE:
	case SCEXT4_IOC_GETSTATE:
	case SCEXT4_IOC_GET_ES_CACHE:
		break;
	default:
		return -ENOIOCTLCMD;
	}
	return scext4_ioctl(file, cmd, (unsigned long) compat_ptr(arg));
}
#endif
