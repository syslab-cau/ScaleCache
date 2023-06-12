// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2006 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#include <linux/iversion.h>

#include "scxfs.h"
#include "scxfs_fs.h"
#include "scxfs_shared.h"
#include "scxfs_format.h"
#include "scxfs_log_format.h"
#include "scxfs_trans_resv.h"
#include "scxfs_sb.h"
#include "scxfs_mount.h"
#include "scxfs_defer.h"
#include "scxfs_inode.h"
#include "scxfs_dir2.h"
#include "scxfs_attr.h"
#include "scxfs_trans_space.h"
#include "scxfs_trans.h"
#include "scxfs_buf_item.h"
#include "scxfs_inode_item.h"
#include "scxfs_ialloc.h"
#include "scxfs_bmap.h"
#include "scxfs_bmap_util.h"
#include "scxfs_errortag.h"
#include "scxfs_error.h"
#include "scxfs_quota.h"
#include "scxfs_filestream.h"
#include "scxfs_trace.h"
#include "scxfs_icache.h"
#include "scxfs_symlink.h"
#include "scxfs_trans_priv.h"
#include "scxfs_log.h"
#include "scxfs_bmap_btree.h"
#include "scxfs_reflink.h"

kmem_zone_t *scxfs_inode_zone;

/*
 * Used in scxfs_itruncate_extents().  This is the maximum number of extents
 * freed from a file in a single transaction.
 */
#define	SCXFS_ITRUNC_MAX_EXTENTS	2

STATIC int scxfs_iflush_int(struct scxfs_inode *, struct scxfs_buf *);
STATIC int scxfs_iunlink(struct scxfs_trans *, struct scxfs_inode *);
STATIC int scxfs_iunlink_remove(struct scxfs_trans *, struct scxfs_inode *);

/*
 * helper function to extract extent size hint from inode
 */
scxfs_extlen_t
scxfs_get_extsz_hint(
	struct scxfs_inode	*ip)
{
	if ((ip->i_d.di_flags & SCXFS_DIFLAG_EXTSIZE) && ip->i_d.di_extsize)
		return ip->i_d.di_extsize;
	if (SCXFS_IS_REALTIME_INODE(ip))
		return ip->i_mount->m_sb.sb_rextsize;
	return 0;
}

/*
 * Helper function to extract CoW extent size hint from inode.
 * Between the extent size hint and the CoW extent size hint, we
 * return the greater of the two.  If the value is zero (automatic),
 * use the default size.
 */
scxfs_extlen_t
scxfs_get_cowextsz_hint(
	struct scxfs_inode	*ip)
{
	scxfs_extlen_t		a, b;

	a = 0;
	if (ip->i_d.di_flags2 & SCXFS_DIFLAG2_COWEXTSIZE)
		a = ip->i_d.di_cowextsize;
	b = scxfs_get_extsz_hint(ip);

	a = max(a, b);
	if (a == 0)
		return SCXFS_DEFAULT_COWEXTSZ_HINT;
	return a;
}

/*
 * These two are wrapper routines around the scxfs_ilock() routine used to
 * centralize some grungy code.  They are used in places that wish to lock the
 * inode solely for reading the extents.  The reason these places can't just
 * call scxfs_ilock(ip, SCXFS_ILOCK_SHARED) is that the inode lock also guards to
 * bringing in of the extents from disk for a file in b-tree format.  If the
 * inode is in b-tree format, then we need to lock the inode exclusively until
 * the extents are read in.  Locking it exclusively all the time would limit
 * our parallelism unnecessarily, though.  What we do instead is check to see
 * if the extents have been read in yet, and only lock the inode exclusively
 * if they have not.
 *
 * The functions return a value which should be given to the corresponding
 * scxfs_iunlock() call.
 */
uint
scxfs_ilock_data_map_shared(
	struct scxfs_inode	*ip)
{
	uint			lock_mode = SCXFS_ILOCK_SHARED;

	if (ip->i_d.di_format == SCXFS_DINODE_FMT_BTREE &&
	    (ip->i_df.if_flags & SCXFS_IFEXTENTS) == 0)
		lock_mode = SCXFS_ILOCK_EXCL;
	scxfs_ilock(ip, lock_mode);
	return lock_mode;
}

uint
scxfs_ilock_attr_map_shared(
	struct scxfs_inode	*ip)
{
	uint			lock_mode = SCXFS_ILOCK_SHARED;

	if (ip->i_d.di_aformat == SCXFS_DINODE_FMT_BTREE &&
	    (ip->i_afp->if_flags & SCXFS_IFEXTENTS) == 0)
		lock_mode = SCXFS_ILOCK_EXCL;
	scxfs_ilock(ip, lock_mode);
	return lock_mode;
}

/*
 * In addition to i_rwsem in the VFS inode, the scxfs inode contains 2
 * multi-reader locks: i_mmap_lock and the i_lock.  This routine allows
 * various combinations of the locks to be obtained.
 *
 * The 3 locks should always be ordered so that the IO lock is obtained first,
 * the mmap lock second and the ilock last in order to prevent deadlock.
 *
 * Basic locking order:
 *
 * i_rwsem -> i_mmap_lock -> page_lock -> i_ilock
 *
 * mmap_sem locking order:
 *
 * i_rwsem -> page lock -> mmap_sem
 * mmap_sem -> i_mmap_lock -> page_lock
 *
 * The difference in mmap_sem locking order mean that we cannot hold the
 * i_mmap_lock over syscall based read(2)/write(2) based IO. These IO paths can
 * fault in pages during copy in/out (for buffered IO) or require the mmap_sem
 * in get_user_pages() to map the user pages into the kernel address space for
 * direct IO. Similarly the i_rwsem cannot be taken inside a page fault because
 * page faults already hold the mmap_sem.
 *
 * Hence to serialise fully against both syscall and mmap based IO, we need to
 * take both the i_rwsem and the i_mmap_lock. These locks should *only* be both
 * taken in places where we need to invalidate the page cache in a race
 * free manner (e.g. truncate, hole punch and other extent manipulation
 * functions).
 */
void
scxfs_ilock(
	scxfs_inode_t		*ip,
	uint			lock_flags)
{
	trace_scxfs_ilock(ip, lock_flags, _RET_IP_);

	/*
	 * You can't set both SHARED and EXCL for the same lock,
	 * and only SCXFS_IOLOCK_SHARED, SCXFS_IOLOCK_EXCL, SCXFS_ILOCK_SHARED,
	 * and SCXFS_ILOCK_EXCL are valid values to set in lock_flags.
	 */
	ASSERT((lock_flags & (SCXFS_IOLOCK_SHARED | SCXFS_IOLOCK_EXCL)) !=
	       (SCXFS_IOLOCK_SHARED | SCXFS_IOLOCK_EXCL));
	ASSERT((lock_flags & (SCXFS_MMAPLOCK_SHARED | SCXFS_MMAPLOCK_EXCL)) !=
	       (SCXFS_MMAPLOCK_SHARED | SCXFS_MMAPLOCK_EXCL));
	ASSERT((lock_flags & (SCXFS_ILOCK_SHARED | SCXFS_ILOCK_EXCL)) !=
	       (SCXFS_ILOCK_SHARED | SCXFS_ILOCK_EXCL));
	ASSERT((lock_flags & ~(SCXFS_LOCK_MASK | SCXFS_LOCK_SUBCLASS_MASK)) == 0);

	if (lock_flags & SCXFS_IOLOCK_EXCL) {
		down_write_nested(&VFS_I(ip)->i_rwsem,
				  SCXFS_IOLOCK_DEP(lock_flags));
	} else if (lock_flags & SCXFS_IOLOCK_SHARED) {
		down_read_nested(&VFS_I(ip)->i_rwsem,
				 SCXFS_IOLOCK_DEP(lock_flags));
	}

	if (lock_flags & SCXFS_MMAPLOCK_EXCL)
		mrupdate_nested(&ip->i_mmaplock, SCXFS_MMAPLOCK_DEP(lock_flags));
	else if (lock_flags & SCXFS_MMAPLOCK_SHARED)
		mraccess_nested(&ip->i_mmaplock, SCXFS_MMAPLOCK_DEP(lock_flags));

	if (lock_flags & SCXFS_ILOCK_EXCL)
		mrupdate_nested(&ip->i_lock, SCXFS_ILOCK_DEP(lock_flags));
	else if (lock_flags & SCXFS_ILOCK_SHARED)
		mraccess_nested(&ip->i_lock, SCXFS_ILOCK_DEP(lock_flags));
}

/*
 * This is just like scxfs_ilock(), except that the caller
 * is guaranteed not to sleep.  It returns 1 if it gets
 * the requested locks and 0 otherwise.  If the IO lock is
 * obtained but the inode lock cannot be, then the IO lock
 * is dropped before returning.
 *
 * ip -- the inode being locked
 * lock_flags -- this parameter indicates the inode's locks to be
 *       to be locked.  See the comment for scxfs_ilock() for a list
 *	 of valid values.
 */
int
scxfs_ilock_nowait(
	scxfs_inode_t		*ip,
	uint			lock_flags)
{
	trace_scxfs_ilock_nowait(ip, lock_flags, _RET_IP_);

	/*
	 * You can't set both SHARED and EXCL for the same lock,
	 * and only SCXFS_IOLOCK_SHARED, SCXFS_IOLOCK_EXCL, SCXFS_ILOCK_SHARED,
	 * and SCXFS_ILOCK_EXCL are valid values to set in lock_flags.
	 */
	ASSERT((lock_flags & (SCXFS_IOLOCK_SHARED | SCXFS_IOLOCK_EXCL)) !=
	       (SCXFS_IOLOCK_SHARED | SCXFS_IOLOCK_EXCL));
	ASSERT((lock_flags & (SCXFS_MMAPLOCK_SHARED | SCXFS_MMAPLOCK_EXCL)) !=
	       (SCXFS_MMAPLOCK_SHARED | SCXFS_MMAPLOCK_EXCL));
	ASSERT((lock_flags & (SCXFS_ILOCK_SHARED | SCXFS_ILOCK_EXCL)) !=
	       (SCXFS_ILOCK_SHARED | SCXFS_ILOCK_EXCL));
	ASSERT((lock_flags & ~(SCXFS_LOCK_MASK | SCXFS_LOCK_SUBCLASS_MASK)) == 0);

	if (lock_flags & SCXFS_IOLOCK_EXCL) {
		if (!down_write_trylock(&VFS_I(ip)->i_rwsem))
			goto out;
	} else if (lock_flags & SCXFS_IOLOCK_SHARED) {
		if (!down_read_trylock(&VFS_I(ip)->i_rwsem))
			goto out;
	}

	if (lock_flags & SCXFS_MMAPLOCK_EXCL) {
		if (!mrtryupdate(&ip->i_mmaplock))
			goto out_undo_iolock;
	} else if (lock_flags & SCXFS_MMAPLOCK_SHARED) {
		if (!mrtryaccess(&ip->i_mmaplock))
			goto out_undo_iolock;
	}

	if (lock_flags & SCXFS_ILOCK_EXCL) {
		if (!mrtryupdate(&ip->i_lock))
			goto out_undo_mmaplock;
	} else if (lock_flags & SCXFS_ILOCK_SHARED) {
		if (!mrtryaccess(&ip->i_lock))
			goto out_undo_mmaplock;
	}
	return 1;

out_undo_mmaplock:
	if (lock_flags & SCXFS_MMAPLOCK_EXCL)
		mrunlock_excl(&ip->i_mmaplock);
	else if (lock_flags & SCXFS_MMAPLOCK_SHARED)
		mrunlock_shared(&ip->i_mmaplock);
out_undo_iolock:
	if (lock_flags & SCXFS_IOLOCK_EXCL)
		up_write(&VFS_I(ip)->i_rwsem);
	else if (lock_flags & SCXFS_IOLOCK_SHARED)
		up_read(&VFS_I(ip)->i_rwsem);
out:
	return 0;
}

/*
 * scxfs_iunlock() is used to drop the inode locks acquired with
 * scxfs_ilock() and scxfs_ilock_nowait().  The caller must pass
 * in the flags given to scxfs_ilock() or scxfs_ilock_nowait() so
 * that we know which locks to drop.
 *
 * ip -- the inode being unlocked
 * lock_flags -- this parameter indicates the inode's locks to be
 *       to be unlocked.  See the comment for scxfs_ilock() for a list
 *	 of valid values for this parameter.
 *
 */
void
scxfs_iunlock(
	scxfs_inode_t		*ip,
	uint			lock_flags)
{
	/*
	 * You can't set both SHARED and EXCL for the same lock,
	 * and only SCXFS_IOLOCK_SHARED, SCXFS_IOLOCK_EXCL, SCXFS_ILOCK_SHARED,
	 * and SCXFS_ILOCK_EXCL are valid values to set in lock_flags.
	 */
	ASSERT((lock_flags & (SCXFS_IOLOCK_SHARED | SCXFS_IOLOCK_EXCL)) !=
	       (SCXFS_IOLOCK_SHARED | SCXFS_IOLOCK_EXCL));
	ASSERT((lock_flags & (SCXFS_MMAPLOCK_SHARED | SCXFS_MMAPLOCK_EXCL)) !=
	       (SCXFS_MMAPLOCK_SHARED | SCXFS_MMAPLOCK_EXCL));
	ASSERT((lock_flags & (SCXFS_ILOCK_SHARED | SCXFS_ILOCK_EXCL)) !=
	       (SCXFS_ILOCK_SHARED | SCXFS_ILOCK_EXCL));
	ASSERT((lock_flags & ~(SCXFS_LOCK_MASK | SCXFS_LOCK_SUBCLASS_MASK)) == 0);
	ASSERT(lock_flags != 0);

	if (lock_flags & SCXFS_IOLOCK_EXCL)
		up_write(&VFS_I(ip)->i_rwsem);
	else if (lock_flags & SCXFS_IOLOCK_SHARED)
		up_read(&VFS_I(ip)->i_rwsem);

	if (lock_flags & SCXFS_MMAPLOCK_EXCL)
		mrunlock_excl(&ip->i_mmaplock);
	else if (lock_flags & SCXFS_MMAPLOCK_SHARED)
		mrunlock_shared(&ip->i_mmaplock);

	if (lock_flags & SCXFS_ILOCK_EXCL)
		mrunlock_excl(&ip->i_lock);
	else if (lock_flags & SCXFS_ILOCK_SHARED)
		mrunlock_shared(&ip->i_lock);

	trace_scxfs_iunlock(ip, lock_flags, _RET_IP_);
}

/*
 * give up write locks.  the i/o lock cannot be held nested
 * if it is being demoted.
 */
void
scxfs_ilock_demote(
	scxfs_inode_t		*ip,
	uint			lock_flags)
{
	ASSERT(lock_flags & (SCXFS_IOLOCK_EXCL|SCXFS_MMAPLOCK_EXCL|SCXFS_ILOCK_EXCL));
	ASSERT((lock_flags &
		~(SCXFS_IOLOCK_EXCL|SCXFS_MMAPLOCK_EXCL|SCXFS_ILOCK_EXCL)) == 0);

	if (lock_flags & SCXFS_ILOCK_EXCL)
		mrdemote(&ip->i_lock);
	if (lock_flags & SCXFS_MMAPLOCK_EXCL)
		mrdemote(&ip->i_mmaplock);
	if (lock_flags & SCXFS_IOLOCK_EXCL)
		downgrade_write(&VFS_I(ip)->i_rwsem);

	trace_scxfs_ilock_demote(ip, lock_flags, _RET_IP_);
}

#if defined(DEBUG) || defined(SCXFS_WARN)
int
scxfs_isilocked(
	scxfs_inode_t		*ip,
	uint			lock_flags)
{
	if (lock_flags & (SCXFS_ILOCK_EXCL|SCXFS_ILOCK_SHARED)) {
		if (!(lock_flags & SCXFS_ILOCK_SHARED))
			return !!ip->i_lock.mr_writer;
		return rwsem_is_locked(&ip->i_lock.mr_lock);
	}

	if (lock_flags & (SCXFS_MMAPLOCK_EXCL|SCXFS_MMAPLOCK_SHARED)) {
		if (!(lock_flags & SCXFS_MMAPLOCK_SHARED))
			return !!ip->i_mmaplock.mr_writer;
		return rwsem_is_locked(&ip->i_mmaplock.mr_lock);
	}

	if (lock_flags & (SCXFS_IOLOCK_EXCL|SCXFS_IOLOCK_SHARED)) {
		if (!(lock_flags & SCXFS_IOLOCK_SHARED))
			return !debug_locks ||
				lockdep_is_held_type(&VFS_I(ip)->i_rwsem, 0);
		return rwsem_is_locked(&VFS_I(ip)->i_rwsem);
	}

	ASSERT(0);
	return 0;
}
#endif

/*
 * scxfs_lockdep_subclass_ok() is only used in an ASSERT, so is only called when
 * DEBUG or SCXFS_WARN is set. And MAX_LOCKDEP_SUBCLASSES is then only defined
 * when CONFIG_LOCKDEP is set. Hence the complex define below to avoid build
 * errors and warnings.
 */
#if (defined(DEBUG) || defined(SCXFS_WARN)) && defined(CONFIG_LOCKDEP)
static bool
scxfs_lockdep_subclass_ok(
	int subclass)
{
	return subclass < MAX_LOCKDEP_SUBCLASSES;
}
#else
#define scxfs_lockdep_subclass_ok(subclass)	(true)
#endif

/*
 * Bump the subclass so scxfs_lock_inodes() acquires each lock with a different
 * value. This can be called for any type of inode lock combination, including
 * parent locking. Care must be taken to ensure we don't overrun the subclass
 * storage fields in the class mask we build.
 */
static inline int
scxfs_lock_inumorder(int lock_mode, int subclass)
{
	int	class = 0;

	ASSERT(!(lock_mode & (SCXFS_ILOCK_PARENT | SCXFS_ILOCK_RTBITMAP |
			      SCXFS_ILOCK_RTSUM)));
	ASSERT(scxfs_lockdep_subclass_ok(subclass));

	if (lock_mode & (SCXFS_IOLOCK_SHARED|SCXFS_IOLOCK_EXCL)) {
		ASSERT(subclass <= SCXFS_IOLOCK_MAX_SUBCLASS);
		class += subclass << SCXFS_IOLOCK_SHIFT;
	}

	if (lock_mode & (SCXFS_MMAPLOCK_SHARED|SCXFS_MMAPLOCK_EXCL)) {
		ASSERT(subclass <= SCXFS_MMAPLOCK_MAX_SUBCLASS);
		class += subclass << SCXFS_MMAPLOCK_SHIFT;
	}

	if (lock_mode & (SCXFS_ILOCK_SHARED|SCXFS_ILOCK_EXCL)) {
		ASSERT(subclass <= SCXFS_ILOCK_MAX_SUBCLASS);
		class += subclass << SCXFS_ILOCK_SHIFT;
	}

	return (lock_mode & ~SCXFS_LOCK_SUBCLASS_MASK) | class;
}

/*
 * The following routine will lock n inodes in exclusive mode.  We assume the
 * caller calls us with the inodes in i_ino order.
 *
 * We need to detect deadlock where an inode that we lock is in the AIL and we
 * start waiting for another inode that is locked by a thread in a long running
 * transaction (such as truncate). This can result in deadlock since the long
 * running trans might need to wait for the inode we just locked in order to
 * push the tail and free space in the log.
 *
 * scxfs_lock_inodes() can only be used to lock one type of lock at a time -
 * the iolock, the mmaplock or the ilock, but not more than one at a time. If we
 * lock more than one at a time, lockdep will report false positives saying we
 * have violated locking orders.
 */
static void
scxfs_lock_inodes(
	struct scxfs_inode	**ips,
	int			inodes,
	uint			lock_mode)
{
	int			attempts = 0, i, j, try_lock;
	struct scxfs_log_item	*lp;

	/*
	 * Currently supports between 2 and 5 inodes with exclusive locking.  We
	 * support an arbitrary depth of locking here, but absolute limits on
	 * inodes depend on the the type of locking and the limits placed by
	 * lockdep annotations in scxfs_lock_inumorder.  These are all checked by
	 * the asserts.
	 */
	ASSERT(ips && inodes >= 2 && inodes <= 5);
	ASSERT(lock_mode & (SCXFS_IOLOCK_EXCL | SCXFS_MMAPLOCK_EXCL |
			    SCXFS_ILOCK_EXCL));
	ASSERT(!(lock_mode & (SCXFS_IOLOCK_SHARED | SCXFS_MMAPLOCK_SHARED |
			      SCXFS_ILOCK_SHARED)));
	ASSERT(!(lock_mode & SCXFS_MMAPLOCK_EXCL) ||
		inodes <= SCXFS_MMAPLOCK_MAX_SUBCLASS + 1);
	ASSERT(!(lock_mode & SCXFS_ILOCK_EXCL) ||
		inodes <= SCXFS_ILOCK_MAX_SUBCLASS + 1);

	if (lock_mode & SCXFS_IOLOCK_EXCL) {
		ASSERT(!(lock_mode & (SCXFS_MMAPLOCK_EXCL | SCXFS_ILOCK_EXCL)));
	} else if (lock_mode & SCXFS_MMAPLOCK_EXCL)
		ASSERT(!(lock_mode & SCXFS_ILOCK_EXCL));

	try_lock = 0;
	i = 0;
again:
	for (; i < inodes; i++) {
		ASSERT(ips[i]);

		if (i && (ips[i] == ips[i - 1]))	/* Already locked */
			continue;

		/*
		 * If try_lock is not set yet, make sure all locked inodes are
		 * not in the AIL.  If any are, set try_lock to be used later.
		 */
		if (!try_lock) {
			for (j = (i - 1); j >= 0 && !try_lock; j--) {
				lp = &ips[j]->i_itemp->ili_item;
				if (lp && test_bit(SCXFS_LI_IN_AIL, &lp->li_flags))
					try_lock++;
			}
		}

		/*
		 * If any of the previous locks we have locked is in the AIL,
		 * we must TRY to get the second and subsequent locks. If
		 * we can't get any, we must release all we have
		 * and try again.
		 */
		if (!try_lock) {
			scxfs_ilock(ips[i], scxfs_lock_inumorder(lock_mode, i));
			continue;
		}

		/* try_lock means we have an inode locked that is in the AIL. */
		ASSERT(i != 0);
		if (scxfs_ilock_nowait(ips[i], scxfs_lock_inumorder(lock_mode, i)))
			continue;

		/*
		 * Unlock all previous guys and try again.  scxfs_iunlock will try
		 * to push the tail if the inode is in the AIL.
		 */
		attempts++;
		for (j = i - 1; j >= 0; j--) {
			/*
			 * Check to see if we've already unlocked this one.  Not
			 * the first one going back, and the inode ptr is the
			 * same.
			 */
			if (j != (i - 1) && ips[j] == ips[j + 1])
				continue;

			scxfs_iunlock(ips[j], lock_mode);
		}

		if ((attempts % 5) == 0) {
			delay(1); /* Don't just spin the CPU */
		}
		i = 0;
		try_lock = 0;
		goto again;
	}
}

/*
 * scxfs_lock_two_inodes() can only be used to lock one type of lock at a time -
 * the mmaplock or the ilock, but not more than one type at a time. If we lock
 * more than one at a time, lockdep will report false positives saying we have
 * violated locking orders.  The iolock must be double-locked separately since
 * we use i_rwsem for that.  We now support taking one lock EXCL and the other
 * SHARED.
 */
void
scxfs_lock_two_inodes(
	struct scxfs_inode	*ip0,
	uint			ip0_mode,
	struct scxfs_inode	*ip1,
	uint			ip1_mode)
{
	struct scxfs_inode	*temp;
	uint			mode_temp;
	int			attempts = 0;
	struct scxfs_log_item	*lp;

	ASSERT(hweight32(ip0_mode) == 1);
	ASSERT(hweight32(ip1_mode) == 1);
	ASSERT(!(ip0_mode & (SCXFS_IOLOCK_SHARED|SCXFS_IOLOCK_EXCL)));
	ASSERT(!(ip1_mode & (SCXFS_IOLOCK_SHARED|SCXFS_IOLOCK_EXCL)));
	ASSERT(!(ip0_mode & (SCXFS_MMAPLOCK_SHARED|SCXFS_MMAPLOCK_EXCL)) ||
	       !(ip0_mode & (SCXFS_ILOCK_SHARED|SCXFS_ILOCK_EXCL)));
	ASSERT(!(ip1_mode & (SCXFS_MMAPLOCK_SHARED|SCXFS_MMAPLOCK_EXCL)) ||
	       !(ip1_mode & (SCXFS_ILOCK_SHARED|SCXFS_ILOCK_EXCL)));
	ASSERT(!(ip1_mode & (SCXFS_MMAPLOCK_SHARED|SCXFS_MMAPLOCK_EXCL)) ||
	       !(ip0_mode & (SCXFS_ILOCK_SHARED|SCXFS_ILOCK_EXCL)));
	ASSERT(!(ip0_mode & (SCXFS_MMAPLOCK_SHARED|SCXFS_MMAPLOCK_EXCL)) ||
	       !(ip1_mode & (SCXFS_ILOCK_SHARED|SCXFS_ILOCK_EXCL)));

	ASSERT(ip0->i_ino != ip1->i_ino);

	if (ip0->i_ino > ip1->i_ino) {
		temp = ip0;
		ip0 = ip1;
		ip1 = temp;
		mode_temp = ip0_mode;
		ip0_mode = ip1_mode;
		ip1_mode = mode_temp;
	}

 again:
	scxfs_ilock(ip0, scxfs_lock_inumorder(ip0_mode, 0));

	/*
	 * If the first lock we have locked is in the AIL, we must TRY to get
	 * the second lock. If we can't get it, we must release the first one
	 * and try again.
	 */
	lp = &ip0->i_itemp->ili_item;
	if (lp && test_bit(SCXFS_LI_IN_AIL, &lp->li_flags)) {
		if (!scxfs_ilock_nowait(ip1, scxfs_lock_inumorder(ip1_mode, 1))) {
			scxfs_iunlock(ip0, ip0_mode);
			if ((++attempts % 5) == 0)
				delay(1); /* Don't just spin the CPU */
			goto again;
		}
	} else {
		scxfs_ilock(ip1, scxfs_lock_inumorder(ip1_mode, 1));
	}
}

void
__scxfs_iflock(
	struct scxfs_inode	*ip)
{
	wait_queue_head_t *wq = bit_waitqueue(&ip->i_flags, __SCXFS_IFLOCK_BIT);
	DEFINE_WAIT_BIT(wait, &ip->i_flags, __SCXFS_IFLOCK_BIT);

	do {
		prepare_to_wait_exclusive(wq, &wait.wq_entry, TASK_UNINTERRUPTIBLE);
		if (scxfs_isiflocked(ip))
			io_schedule();
	} while (!scxfs_iflock_nowait(ip));

	finish_wait(wq, &wait.wq_entry);
}

STATIC uint
_scxfs_dic2xflags(
	uint16_t		di_flags,
	uint64_t		di_flags2,
	bool			has_attr)
{
	uint			flags = 0;

	if (di_flags & SCXFS_DIFLAG_ANY) {
		if (di_flags & SCXFS_DIFLAG_REALTIME)
			flags |= FS_XFLAG_REALTIME;
		if (di_flags & SCXFS_DIFLAG_PREALLOC)
			flags |= FS_XFLAG_PREALLOC;
		if (di_flags & SCXFS_DIFLAG_IMMUTABLE)
			flags |= FS_XFLAG_IMMUTABLE;
		if (di_flags & SCXFS_DIFLAG_APPEND)
			flags |= FS_XFLAG_APPEND;
		if (di_flags & SCXFS_DIFLAG_SYNC)
			flags |= FS_XFLAG_SYNC;
		if (di_flags & SCXFS_DIFLAG_NOATIME)
			flags |= FS_XFLAG_NOATIME;
		if (di_flags & SCXFS_DIFLAG_NODUMP)
			flags |= FS_XFLAG_NODUMP;
		if (di_flags & SCXFS_DIFLAG_RTINHERIT)
			flags |= FS_XFLAG_RTINHERIT;
		if (di_flags & SCXFS_DIFLAG_PROJINHERIT)
			flags |= FS_XFLAG_PROJINHERIT;
		if (di_flags & SCXFS_DIFLAG_NOSYMLINKS)
			flags |= FS_XFLAG_NOSYMLINKS;
		if (di_flags & SCXFS_DIFLAG_EXTSIZE)
			flags |= FS_XFLAG_EXTSIZE;
		if (di_flags & SCXFS_DIFLAG_EXTSZINHERIT)
			flags |= FS_XFLAG_EXTSZINHERIT;
		if (di_flags & SCXFS_DIFLAG_NODEFRAG)
			flags |= FS_XFLAG_NODEFRAG;
		if (di_flags & SCXFS_DIFLAG_FILESTREAM)
			flags |= FS_XFLAG_FILESTREAM;
	}

	if (di_flags2 & SCXFS_DIFLAG2_ANY) {
		if (di_flags2 & SCXFS_DIFLAG2_DAX)
			flags |= FS_XFLAG_DAX;
		if (di_flags2 & SCXFS_DIFLAG2_COWEXTSIZE)
			flags |= FS_XFLAG_COWEXTSIZE;
	}

	if (has_attr)
		flags |= FS_XFLAG_HASATTR;

	return flags;
}

uint
scxfs_ip2xflags(
	struct scxfs_inode	*ip)
{
	struct scxfs_icdinode	*dic = &ip->i_d;

	return _scxfs_dic2xflags(dic->di_flags, dic->di_flags2, SCXFS_IFORK_Q(ip));
}

/*
 * Lookups up an inode from "name". If ci_name is not NULL, then a CI match
 * is allowed, otherwise it has to be an exact match. If a CI match is found,
 * ci_name->name will point to a the actual name (caller must free) or
 * will be set to NULL if an exact match is found.
 */
int
scxfs_lookup(
	scxfs_inode_t		*dp,
	struct scxfs_name		*name,
	scxfs_inode_t		**ipp,
	struct scxfs_name		*ci_name)
{
	scxfs_ino_t		inum;
	int			error;

	trace_scxfs_lookup(dp, name);

	if (SCXFS_FORCED_SHUTDOWN(dp->i_mount))
		return -EIO;

	error = scxfs_dir_lookup(NULL, dp, name, &inum, ci_name);
	if (error)
		goto out_unlock;

	error = scxfs_iget(dp->i_mount, NULL, inum, 0, 0, ipp);
	if (error)
		goto out_free_name;

	return 0;

out_free_name:
	if (ci_name)
		kmem_free(ci_name->name);
out_unlock:
	*ipp = NULL;
	return error;
}

/*
 * Allocate an inode on disk and return a copy of its in-core version.
 * The in-core inode is locked exclusively.  Set mode, nlink, and rdev
 * appropriately within the inode.  The uid and gid for the inode are
 * set according to the contents of the given cred structure.
 *
 * Use scxfs_dialloc() to allocate the on-disk inode. If scxfs_dialloc()
 * has a free inode available, call scxfs_iget() to obtain the in-core
 * version of the allocated inode.  Finally, fill in the inode and
 * log its initial contents.  In this case, ialloc_context would be
 * set to NULL.
 *
 * If scxfs_dialloc() does not have an available inode, it will replenish
 * its supply by doing an allocation. Since we can only do one
 * allocation within a transaction without deadlocks, we must commit
 * the current transaction before returning the inode itself.
 * In this case, therefore, we will set ialloc_context and return.
 * The caller should then commit the current transaction, start a new
 * transaction, and call scxfs_ialloc() again to actually get the inode.
 *
 * To ensure that some other process does not grab the inode that
 * was allocated during the first call to scxfs_ialloc(), this routine
 * also returns the [locked] bp pointing to the head of the freelist
 * as ialloc_context.  The caller should hold this buffer across
 * the commit and pass it back into this routine on the second call.
 *
 * If we are allocating quota inodes, we do not have a parent inode
 * to attach to or associate with (i.e. pip == NULL) because they
 * are not linked into the directory structure - they are attached
 * directly to the superblock - and so have no parent.
 */
static int
scxfs_ialloc(
	scxfs_trans_t	*tp,
	scxfs_inode_t	*pip,
	umode_t		mode,
	scxfs_nlink_t	nlink,
	dev_t		rdev,
	prid_t		prid,
	scxfs_buf_t	**ialloc_context,
	scxfs_inode_t	**ipp)
{
	struct scxfs_mount *mp = tp->t_mountp;
	scxfs_ino_t	ino;
	scxfs_inode_t	*ip;
	uint		flags;
	int		error;
	struct timespec64 tv;
	struct inode	*inode;

	/*
	 * Call the space management code to pick
	 * the on-disk inode to be allocated.
	 */
	error = scxfs_dialloc(tp, pip ? pip->i_ino : 0, mode,
			    ialloc_context, &ino);
	if (error)
		return error;
	if (*ialloc_context || ino == NULLFSINO) {
		*ipp = NULL;
		return 0;
	}
	ASSERT(*ialloc_context == NULL);

	/*
	 * Protect against obviously corrupt allocation btree records. Later
	 * scxfs_iget checks will catch re-allocation of other active in-memory
	 * and on-disk inodes. If we don't catch reallocating the parent inode
	 * here we will deadlock in scxfs_iget() so we have to do these checks
	 * first.
	 */
	if ((pip && ino == pip->i_ino) || !scxfs_verify_dir_ino(mp, ino)) {
		scxfs_alert(mp, "Allocated a known in-use inode 0x%llx!", ino);
		return -EFSCORRUPTED;
	}

	/*
	 * Get the in-core inode with the lock held exclusively.
	 * This is because we're setting fields here we need
	 * to prevent others from looking at until we're done.
	 */
	error = scxfs_iget(mp, tp, ino, SCXFS_IGET_CREATE,
			 SCXFS_ILOCK_EXCL, &ip);
	if (error)
		return error;
	ASSERT(ip != NULL);
	inode = VFS_I(ip);

	/*
	 * We always convert v1 inodes to v2 now - we only support filesystems
	 * with >= v2 inode capability, so there is no reason for ever leaving
	 * an inode in v1 format.
	 */
	if (ip->i_d.di_version == 1)
		ip->i_d.di_version = 2;

	inode->i_mode = mode;
	set_nlink(inode, nlink);
	ip->i_d.di_uid = scxfs_kuid_to_uid(current_fsuid());
	ip->i_d.di_gid = scxfs_kgid_to_gid(current_fsgid());
	inode->i_rdev = rdev;
	scxfs_set_projid(ip, prid);

	if (pip && SCXFS_INHERIT_GID(pip)) {
		ip->i_d.di_gid = pip->i_d.di_gid;
		if ((VFS_I(pip)->i_mode & S_ISGID) && S_ISDIR(mode))
			inode->i_mode |= S_ISGID;
	}

	/*
	 * If the group ID of the new file does not match the effective group
	 * ID or one of the supplementary group IDs, the S_ISGID bit is cleared
	 * (and only if the irix_sgid_inherit compatibility variable is set).
	 */
	if ((irix_sgid_inherit) &&
	    (inode->i_mode & S_ISGID) &&
	    (!in_group_p(scxfs_gid_to_kgid(ip->i_d.di_gid))))
		inode->i_mode &= ~S_ISGID;

	ip->i_d.di_size = 0;
	ip->i_d.di_nextents = 0;
	ASSERT(ip->i_d.di_nblocks == 0);

	tv = current_time(inode);
	inode->i_mtime = tv;
	inode->i_atime = tv;
	inode->i_ctime = tv;

	ip->i_d.di_extsize = 0;
	ip->i_d.di_dmevmask = 0;
	ip->i_d.di_dmstate = 0;
	ip->i_d.di_flags = 0;

	if (ip->i_d.di_version == 3) {
		inode_set_iversion(inode, 1);
		ip->i_d.di_flags2 = 0;
		ip->i_d.di_cowextsize = 0;
		ip->i_d.di_crtime.t_sec = (int32_t)tv.tv_sec;
		ip->i_d.di_crtime.t_nsec = (int32_t)tv.tv_nsec;
	}


	flags = SCXFS_ILOG_CORE;
	switch (mode & S_IFMT) {
	case S_IFIFO:
	case S_IFCHR:
	case S_IFBLK:
	case S_IFSOCK:
		ip->i_d.di_format = SCXFS_DINODE_FMT_DEV;
		ip->i_df.if_flags = 0;
		flags |= SCXFS_ILOG_DEV;
		break;
	case S_IFREG:
	case S_IFDIR:
		if (pip && (pip->i_d.di_flags & SCXFS_DIFLAG_ANY)) {
			uint		di_flags = 0;

			if (S_ISDIR(mode)) {
				if (pip->i_d.di_flags & SCXFS_DIFLAG_RTINHERIT)
					di_flags |= SCXFS_DIFLAG_RTINHERIT;
				if (pip->i_d.di_flags & SCXFS_DIFLAG_EXTSZINHERIT) {
					di_flags |= SCXFS_DIFLAG_EXTSZINHERIT;
					ip->i_d.di_extsize = pip->i_d.di_extsize;
				}
				if (pip->i_d.di_flags & SCXFS_DIFLAG_PROJINHERIT)
					di_flags |= SCXFS_DIFLAG_PROJINHERIT;
			} else if (S_ISREG(mode)) {
				if (pip->i_d.di_flags & SCXFS_DIFLAG_RTINHERIT)
					di_flags |= SCXFS_DIFLAG_REALTIME;
				if (pip->i_d.di_flags & SCXFS_DIFLAG_EXTSZINHERIT) {
					di_flags |= SCXFS_DIFLAG_EXTSIZE;
					ip->i_d.di_extsize = pip->i_d.di_extsize;
				}
			}
			if ((pip->i_d.di_flags & SCXFS_DIFLAG_NOATIME) &&
			    scxfs_inherit_noatime)
				di_flags |= SCXFS_DIFLAG_NOATIME;
			if ((pip->i_d.di_flags & SCXFS_DIFLAG_NODUMP) &&
			    scxfs_inherit_nodump)
				di_flags |= SCXFS_DIFLAG_NODUMP;
			if ((pip->i_d.di_flags & SCXFS_DIFLAG_SYNC) &&
			    scxfs_inherit_sync)
				di_flags |= SCXFS_DIFLAG_SYNC;
			if ((pip->i_d.di_flags & SCXFS_DIFLAG_NOSYMLINKS) &&
			    scxfs_inherit_nosymlinks)
				di_flags |= SCXFS_DIFLAG_NOSYMLINKS;
			if ((pip->i_d.di_flags & SCXFS_DIFLAG_NODEFRAG) &&
			    scxfs_inherit_nodefrag)
				di_flags |= SCXFS_DIFLAG_NODEFRAG;
			if (pip->i_d.di_flags & SCXFS_DIFLAG_FILESTREAM)
				di_flags |= SCXFS_DIFLAG_FILESTREAM;

			ip->i_d.di_flags |= di_flags;
		}
		if (pip &&
		    (pip->i_d.di_flags2 & SCXFS_DIFLAG2_ANY) &&
		    pip->i_d.di_version == 3 &&
		    ip->i_d.di_version == 3) {
			uint64_t	di_flags2 = 0;

			if (pip->i_d.di_flags2 & SCXFS_DIFLAG2_COWEXTSIZE) {
				di_flags2 |= SCXFS_DIFLAG2_COWEXTSIZE;
				ip->i_d.di_cowextsize = pip->i_d.di_cowextsize;
			}
			if (pip->i_d.di_flags2 & SCXFS_DIFLAG2_DAX)
				di_flags2 |= SCXFS_DIFLAG2_DAX;

			ip->i_d.di_flags2 |= di_flags2;
		}
		/* FALLTHROUGH */
	case S_IFLNK:
		ip->i_d.di_format = SCXFS_DINODE_FMT_EXTENTS;
		ip->i_df.if_flags = SCXFS_IFEXTENTS;
		ip->i_df.if_bytes = 0;
		ip->i_df.if_u1.if_root = NULL;
		break;
	default:
		ASSERT(0);
	}
	/*
	 * Attribute fork settings for new inode.
	 */
	ip->i_d.di_aformat = SCXFS_DINODE_FMT_EXTENTS;
	ip->i_d.di_anextents = 0;

	/*
	 * Log the new values stuffed into the inode.
	 */
	scxfs_trans_ijoin(tp, ip, SCXFS_ILOCK_EXCL);
	scxfs_trans_log_inode(tp, ip, flags);

	/* now that we have an i_mode we can setup the inode structure */
	scxfs_setup_inode(ip);

	*ipp = ip;
	return 0;
}

/*
 * Allocates a new inode from disk and return a pointer to the
 * incore copy. This routine will internally commit the current
 * transaction and allocate a new one if the Space Manager needed
 * to do an allocation to replenish the inode free-list.
 *
 * This routine is designed to be called from scxfs_create and
 * scxfs_create_dir.
 *
 */
int
scxfs_dir_ialloc(
	scxfs_trans_t	**tpp,		/* input: current transaction;
					   output: may be a new transaction. */
	scxfs_inode_t	*dp,		/* directory within whose allocate
					   the inode. */
	umode_t		mode,
	scxfs_nlink_t	nlink,
	dev_t		rdev,
	prid_t		prid,		/* project id */
	scxfs_inode_t	**ipp)		/* pointer to inode; it will be
					   locked. */
{
	scxfs_trans_t	*tp;
	scxfs_inode_t	*ip;
	scxfs_buf_t	*ialloc_context = NULL;
	int		code;
	void		*dqinfo;
	uint		tflags;

	tp = *tpp;
	ASSERT(tp->t_flags & SCXFS_TRANS_PERM_LOG_RES);

	/*
	 * scxfs_ialloc will return a pointer to an incore inode if
	 * the Space Manager has an available inode on the free
	 * list. Otherwise, it will do an allocation and replenish
	 * the freelist.  Since we can only do one allocation per
	 * transaction without deadlocks, we will need to commit the
	 * current transaction and start a new one.  We will then
	 * need to call scxfs_ialloc again to get the inode.
	 *
	 * If scxfs_ialloc did an allocation to replenish the freelist,
	 * it returns the bp containing the head of the freelist as
	 * ialloc_context. We will hold a lock on it across the
	 * transaction commit so that no other process can steal
	 * the inode(s) that we've just allocated.
	 */
	code = scxfs_ialloc(tp, dp, mode, nlink, rdev, prid, &ialloc_context,
			&ip);

	/*
	 * Return an error if we were unable to allocate a new inode.
	 * This should only happen if we run out of space on disk or
	 * encounter a disk error.
	 */
	if (code) {
		*ipp = NULL;
		return code;
	}
	if (!ialloc_context && !ip) {
		*ipp = NULL;
		return -ENOSPC;
	}

	/*
	 * If the AGI buffer is non-NULL, then we were unable to get an
	 * inode in one operation.  We need to commit the current
	 * transaction and call scxfs_ialloc() again.  It is guaranteed
	 * to succeed the second time.
	 */
	if (ialloc_context) {
		/*
		 * Normally, scxfs_trans_commit releases all the locks.
		 * We call bhold to hang on to the ialloc_context across
		 * the commit.  Holding this buffer prevents any other
		 * processes from doing any allocations in this
		 * allocation group.
		 */
		scxfs_trans_bhold(tp, ialloc_context);

		/*
		 * We want the quota changes to be associated with the next
		 * transaction, NOT this one. So, detach the dqinfo from this
		 * and attach it to the next transaction.
		 */
		dqinfo = NULL;
		tflags = 0;
		if (tp->t_dqinfo) {
			dqinfo = (void *)tp->t_dqinfo;
			tp->t_dqinfo = NULL;
			tflags = tp->t_flags & SCXFS_TRANS_DQ_DIRTY;
			tp->t_flags &= ~(SCXFS_TRANS_DQ_DIRTY);
		}

		code = scxfs_trans_roll(&tp);

		/*
		 * Re-attach the quota info that we detached from prev trx.
		 */
		if (dqinfo) {
			tp->t_dqinfo = dqinfo;
			tp->t_flags |= tflags;
		}

		if (code) {
			scxfs_buf_relse(ialloc_context);
			*tpp = tp;
			*ipp = NULL;
			return code;
		}
		scxfs_trans_bjoin(tp, ialloc_context);

		/*
		 * Call ialloc again. Since we've locked out all
		 * other allocations in this allocation group,
		 * this call should always succeed.
		 */
		code = scxfs_ialloc(tp, dp, mode, nlink, rdev, prid,
				  &ialloc_context, &ip);

		/*
		 * If we get an error at this point, return to the caller
		 * so that the current transaction can be aborted.
		 */
		if (code) {
			*tpp = tp;
			*ipp = NULL;
			return code;
		}
		ASSERT(!ialloc_context && ip);

	}

	*ipp = ip;
	*tpp = tp;

	return 0;
}

/*
 * Decrement the link count on an inode & log the change.  If this causes the
 * link count to go to zero, move the inode to AGI unlinked list so that it can
 * be freed when the last active reference goes away via scxfs_inactive().
 */
static int			/* error */
scxfs_droplink(
	scxfs_trans_t *tp,
	scxfs_inode_t *ip)
{
	scxfs_trans_ichgtime(tp, ip, SCXFS_ICHGTIME_CHG);

	drop_nlink(VFS_I(ip));
	scxfs_trans_log_inode(tp, ip, SCXFS_ILOG_CORE);

	if (VFS_I(ip)->i_nlink)
		return 0;

	return scxfs_iunlink(tp, ip);
}

/*
 * Increment the link count on an inode & log the change.
 */
static void
scxfs_bumplink(
	scxfs_trans_t *tp,
	scxfs_inode_t *ip)
{
	scxfs_trans_ichgtime(tp, ip, SCXFS_ICHGTIME_CHG);

	ASSERT(ip->i_d.di_version > 1);
	inc_nlink(VFS_I(ip));
	scxfs_trans_log_inode(tp, ip, SCXFS_ILOG_CORE);
}

int
scxfs_create(
	scxfs_inode_t		*dp,
	struct scxfs_name		*name,
	umode_t			mode,
	dev_t			rdev,
	scxfs_inode_t		**ipp)
{
	int			is_dir = S_ISDIR(mode);
	struct scxfs_mount	*mp = dp->i_mount;
	struct scxfs_inode	*ip = NULL;
	struct scxfs_trans	*tp = NULL;
	int			error;
	bool                    unlock_dp_on_error = false;
	prid_t			prid;
	struct scxfs_dquot	*udqp = NULL;
	struct scxfs_dquot	*gdqp = NULL;
	struct scxfs_dquot	*pdqp = NULL;
	struct scxfs_trans_res	*tres;
	uint			resblks;

	trace_scxfs_create(dp, name);

	if (SCXFS_FORCED_SHUTDOWN(mp))
		return -EIO;

	prid = scxfs_get_initial_prid(dp);

	/*
	 * Make sure that we have allocated dquot(s) on disk.
	 */
	error = scxfs_qm_vop_dqalloc(dp, scxfs_kuid_to_uid(current_fsuid()),
					scxfs_kgid_to_gid(current_fsgid()), prid,
					SCXFS_QMOPT_QUOTALL | SCXFS_QMOPT_INHERIT,
					&udqp, &gdqp, &pdqp);
	if (error)
		return error;

	if (is_dir) {
		resblks = SCXFS_MKDIR_SPACE_RES(mp, name->len);
		tres = &M_RES(mp)->tr_mkdir;
	} else {
		resblks = SCXFS_CREATE_SPACE_RES(mp, name->len);
		tres = &M_RES(mp)->tr_create;
	}

	/*
	 * Initially assume that the file does not exist and
	 * reserve the resources for that case.  If that is not
	 * the case we'll drop the one we have and get a more
	 * appropriate transaction later.
	 */
	error = scxfs_trans_alloc(mp, tres, resblks, 0, 0, &tp);
	if (error == -ENOSPC) {
		/* flush outstanding delalloc blocks and retry */
		scxfs_flush_inodes(mp);
		error = scxfs_trans_alloc(mp, tres, resblks, 0, 0, &tp);
	}
	if (error)
		goto out_release_inode;

	scxfs_ilock(dp, SCXFS_ILOCK_EXCL | SCXFS_ILOCK_PARENT);
	unlock_dp_on_error = true;

	/*
	 * Reserve disk quota and the inode.
	 */
	error = scxfs_trans_reserve_quota(tp, mp, udqp, gdqp,
						pdqp, resblks, 1, 0);
	if (error)
		goto out_trans_cancel;

	/*
	 * A newly created regular or special file just has one directory
	 * entry pointing to them, but a directory also the "." entry
	 * pointing to itself.
	 */
	error = scxfs_dir_ialloc(&tp, dp, mode, is_dir ? 2 : 1, rdev, prid, &ip);
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

	error = scxfs_dir_createname(tp, dp, name, ip->i_ino,
				   resblks ?
					resblks - SCXFS_IALLOC_SPACE_RES(mp) : 0);
	if (error) {
		ASSERT(error != -ENOSPC);
		goto out_trans_cancel;
	}
	scxfs_trans_ichgtime(tp, dp, SCXFS_ICHGTIME_MOD | SCXFS_ICHGTIME_CHG);
	scxfs_trans_log_inode(tp, dp, SCXFS_ILOG_CORE);

	if (is_dir) {
		error = scxfs_dir_init(tp, ip, dp);
		if (error)
			goto out_trans_cancel;

		scxfs_bumplink(tp, dp);
	}

	/*
	 * If this is a synchronous mount, make sure that the
	 * create transaction goes to disk before returning to
	 * the user.
	 */
	if (mp->m_flags & (SCXFS_MOUNT_WSYNC|SCXFS_MOUNT_DIRSYNC))
		scxfs_trans_set_sync(tp);

	/*
	 * Attach the dquot(s) to the inodes and modify them incore.
	 * These ids of the inode couldn't have changed since the new
	 * inode has been locked ever since it was created.
	 */
	scxfs_qm_vop_create_dqattach(tp, ip, udqp, gdqp, pdqp);

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

int
scxfs_create_tmpfile(
	struct scxfs_inode	*dp,
	umode_t			mode,
	struct scxfs_inode	**ipp)
{
	struct scxfs_mount	*mp = dp->i_mount;
	struct scxfs_inode	*ip = NULL;
	struct scxfs_trans	*tp = NULL;
	int			error;
	prid_t                  prid;
	struct scxfs_dquot	*udqp = NULL;
	struct scxfs_dquot	*gdqp = NULL;
	struct scxfs_dquot	*pdqp = NULL;
	struct scxfs_trans_res	*tres;
	uint			resblks;

	if (SCXFS_FORCED_SHUTDOWN(mp))
		return -EIO;

	prid = scxfs_get_initial_prid(dp);

	/*
	 * Make sure that we have allocated dquot(s) on disk.
	 */
	error = scxfs_qm_vop_dqalloc(dp, scxfs_kuid_to_uid(current_fsuid()),
				scxfs_kgid_to_gid(current_fsgid()), prid,
				SCXFS_QMOPT_QUOTALL | SCXFS_QMOPT_INHERIT,
				&udqp, &gdqp, &pdqp);
	if (error)
		return error;

	resblks = SCXFS_IALLOC_SPACE_RES(mp);
	tres = &M_RES(mp)->tr_create_tmpfile;

	error = scxfs_trans_alloc(mp, tres, resblks, 0, 0, &tp);
	if (error)
		goto out_release_inode;

	error = scxfs_trans_reserve_quota(tp, mp, udqp, gdqp,
						pdqp, resblks, 1, 0);
	if (error)
		goto out_trans_cancel;

	error = scxfs_dir_ialloc(&tp, dp, mode, 0, 0, prid, &ip);
	if (error)
		goto out_trans_cancel;

	if (mp->m_flags & SCXFS_MOUNT_WSYNC)
		scxfs_trans_set_sync(tp);

	/*
	 * Attach the dquot(s) to the inodes and modify them incore.
	 * These ids of the inode couldn't have changed since the new
	 * inode has been locked ever since it was created.
	 */
	scxfs_qm_vop_create_dqattach(tp, ip, udqp, gdqp, pdqp);

	error = scxfs_iunlink(tp, ip);
	if (error)
		goto out_trans_cancel;

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

	return error;
}

int
scxfs_link(
	scxfs_inode_t		*tdp,
	scxfs_inode_t		*sip,
	struct scxfs_name		*target_name)
{
	scxfs_mount_t		*mp = tdp->i_mount;
	scxfs_trans_t		*tp;
	int			error;
	int			resblks;

	trace_scxfs_link(tdp, target_name);

	ASSERT(!S_ISDIR(VFS_I(sip)->i_mode));

	if (SCXFS_FORCED_SHUTDOWN(mp))
		return -EIO;

	error = scxfs_qm_dqattach(sip);
	if (error)
		goto std_return;

	error = scxfs_qm_dqattach(tdp);
	if (error)
		goto std_return;

	resblks = SCXFS_LINK_SPACE_RES(mp, target_name->len);
	error = scxfs_trans_alloc(mp, &M_RES(mp)->tr_link, resblks, 0, 0, &tp);
	if (error == -ENOSPC) {
		resblks = 0;
		error = scxfs_trans_alloc(mp, &M_RES(mp)->tr_link, 0, 0, 0, &tp);
	}
	if (error)
		goto std_return;

	scxfs_lock_two_inodes(sip, SCXFS_ILOCK_EXCL, tdp, SCXFS_ILOCK_EXCL);

	scxfs_trans_ijoin(tp, sip, SCXFS_ILOCK_EXCL);
	scxfs_trans_ijoin(tp, tdp, SCXFS_ILOCK_EXCL);

	/*
	 * If we are using project inheritance, we only allow hard link
	 * creation in our tree when the project IDs are the same; else
	 * the tree quota mechanism could be circumvented.
	 */
	if (unlikely((tdp->i_d.di_flags & SCXFS_DIFLAG_PROJINHERIT) &&
		     (scxfs_get_projid(tdp) != scxfs_get_projid(sip)))) {
		error = -EXDEV;
		goto error_return;
	}

	if (!resblks) {
		error = scxfs_dir_canenter(tp, tdp, target_name);
		if (error)
			goto error_return;
	}

	/*
	 * Handle initial link state of O_TMPFILE inode
	 */
	if (VFS_I(sip)->i_nlink == 0) {
		error = scxfs_iunlink_remove(tp, sip);
		if (error)
			goto error_return;
	}

	error = scxfs_dir_createname(tp, tdp, target_name, sip->i_ino,
				   resblks);
	if (error)
		goto error_return;
	scxfs_trans_ichgtime(tp, tdp, SCXFS_ICHGTIME_MOD | SCXFS_ICHGTIME_CHG);
	scxfs_trans_log_inode(tp, tdp, SCXFS_ILOG_CORE);

	scxfs_bumplink(tp, sip);

	/*
	 * If this is a synchronous mount, make sure that the
	 * link transaction goes to disk before returning to
	 * the user.
	 */
	if (mp->m_flags & (SCXFS_MOUNT_WSYNC|SCXFS_MOUNT_DIRSYNC))
		scxfs_trans_set_sync(tp);

	return scxfs_trans_commit(tp);

 error_return:
	scxfs_trans_cancel(tp);
 std_return:
	return error;
}

/* Clear the reflink flag and the cowblocks tag if possible. */
static void
scxfs_itruncate_clear_reflink_flags(
	struct scxfs_inode	*ip)
{
	struct scxfs_ifork	*dfork;
	struct scxfs_ifork	*cfork;

	if (!scxfs_is_reflink_inode(ip))
		return;
	dfork = SCXFS_IFORK_PTR(ip, SCXFS_DATA_FORK);
	cfork = SCXFS_IFORK_PTR(ip, SCXFS_COW_FORK);
	if (dfork->if_bytes == 0 && cfork->if_bytes == 0)
		ip->i_d.di_flags2 &= ~SCXFS_DIFLAG2_REFLINK;
	if (cfork->if_bytes == 0)
		scxfs_inode_clear_cowblocks_tag(ip);
}

/*
 * Free up the underlying blocks past new_size.  The new size must be smaller
 * than the current size.  This routine can be used both for the attribute and
 * data fork, and does not modify the inode size, which is left to the caller.
 *
 * The transaction passed to this routine must have made a permanent log
 * reservation of at least SCXFS_ITRUNCATE_LOG_RES.  This routine may commit the
 * given transaction and start new ones, so make sure everything involved in
 * the transaction is tidy before calling here.  Some transaction will be
 * returned to the caller to be committed.  The incoming transaction must
 * already include the inode, and both inode locks must be held exclusively.
 * The inode must also be "held" within the transaction.  On return the inode
 * will be "held" within the returned transaction.  This routine does NOT
 * require any disk space to be reserved for it within the transaction.
 *
 * If we get an error, we must return with the inode locked and linked into the
 * current transaction. This keeps things simple for the higher level code,
 * because it always knows that the inode is locked and held in the transaction
 * that returns to it whether errors occur or not.  We don't mark the inode
 * dirty on error so that transactions can be easily aborted if possible.
 */
int
scxfs_itruncate_extents_flags(
	struct scxfs_trans	**tpp,
	struct scxfs_inode	*ip,
	int			whichfork,
	scxfs_fsize_t		new_size,
	int			flags)
{
	struct scxfs_mount	*mp = ip->i_mount;
	struct scxfs_trans	*tp = *tpp;
	scxfs_fileoff_t		first_unmap_block;
	scxfs_fileoff_t		last_block;
	scxfs_filblks_t		unmap_len;
	int			error = 0;
	int			done = 0;

	ASSERT(scxfs_isilocked(ip, SCXFS_ILOCK_EXCL));
	ASSERT(!atomic_read(&VFS_I(ip)->i_count) ||
	       scxfs_isilocked(ip, SCXFS_IOLOCK_EXCL));
	ASSERT(new_size <= SCXFS_ISIZE(ip));
	ASSERT(tp->t_flags & SCXFS_TRANS_PERM_LOG_RES);
	ASSERT(ip->i_itemp != NULL);
	ASSERT(ip->i_itemp->ili_lock_flags == 0);
	ASSERT(!SCXFS_NOT_DQATTACHED(mp, ip));

	trace_scxfs_itruncate_extents_start(ip, new_size);

	flags |= scxfs_bmapi_aflag(whichfork);

	/*
	 * Since it is possible for space to become allocated beyond
	 * the end of the file (in a crash where the space is allocated
	 * but the inode size is not yet updated), simply remove any
	 * blocks which show up between the new EOF and the maximum
	 * possible file size.  If the first block to be removed is
	 * beyond the maximum file size (ie it is the same as last_block),
	 * then there is nothing to do.
	 */
	first_unmap_block = SCXFS_B_TO_FSB(mp, (scxfs_ufsize_t)new_size);
	last_block = SCXFS_B_TO_FSB(mp, mp->m_super->s_maxbytes);
	if (first_unmap_block == last_block)
		return 0;

	ASSERT(first_unmap_block < last_block);
	unmap_len = last_block - first_unmap_block + 1;
	while (!done) {
		ASSERT(tp->t_firstblock == NULLFSBLOCK);
		error = scxfs_bunmapi(tp, ip, first_unmap_block, unmap_len, flags,
				    SCXFS_ITRUNC_MAX_EXTENTS, &done);
		if (error)
			goto out;

		/*
		 * Duplicate the transaction that has the permanent
		 * reservation and commit the old transaction.
		 */
		error = scxfs_defer_finish(&tp);
		if (error)
			goto out;

		error = scxfs_trans_roll_inode(&tp, ip);
		if (error)
			goto out;
	}

	if (whichfork == SCXFS_DATA_FORK) {
		/* Remove all pending CoW reservations. */
		error = scxfs_reflink_cancel_cow_blocks(ip, &tp,
				first_unmap_block, last_block, true);
		if (error)
			goto out;

		scxfs_itruncate_clear_reflink_flags(ip);
	}

	/*
	 * Always re-log the inode so that our permanent transaction can keep
	 * on rolling it forward in the log.
	 */
	scxfs_trans_log_inode(tp, ip, SCXFS_ILOG_CORE);

	trace_scxfs_itruncate_extents_end(ip, new_size);

out:
	*tpp = tp;
	return error;
}

int
scxfs_release(
	scxfs_inode_t	*ip)
{
	scxfs_mount_t	*mp = ip->i_mount;
	int		error;

	if (!S_ISREG(VFS_I(ip)->i_mode) || (VFS_I(ip)->i_mode == 0))
		return 0;

	/* If this is a read-only mount, don't do this (would generate I/O) */
	if (mp->m_flags & SCXFS_MOUNT_RDONLY)
		return 0;

	if (!SCXFS_FORCED_SHUTDOWN(mp)) {
		int truncated;

		/*
		 * If we previously truncated this file and removed old data
		 * in the process, we want to initiate "early" writeout on
		 * the last close.  This is an attempt to combat the notorious
		 * NULL files problem which is particularly noticeable from a
		 * truncate down, buffered (re-)write (delalloc), followed by
		 * a crash.  What we are effectively doing here is
		 * significantly reducing the time window where we'd otherwise
		 * be exposed to that problem.
		 */
		truncated = scxfs_iflags_test_and_clear(ip, SCXFS_ITRUNCATED);
		if (truncated) {
			scxfs_iflags_clear(ip, SCXFS_IDIRTY_RELEASE);
			if (ip->i_delayed_blks > 0) {
				error = filemap_flush(VFS_I(ip)->i_mapping);
				if (error)
					return error;
			}
		}
	}

	if (VFS_I(ip)->i_nlink == 0)
		return 0;

	if (scxfs_can_free_eofblocks(ip, false)) {

		/*
		 * Check if the inode is being opened, written and closed
		 * frequently and we have delayed allocation blocks outstanding
		 * (e.g. streaming writes from the NFS server), truncating the
		 * blocks past EOF will cause fragmentation to occur.
		 *
		 * In this case don't do the truncation, but we have to be
		 * careful how we detect this case. Blocks beyond EOF show up as
		 * i_delayed_blks even when the inode is clean, so we need to
		 * truncate them away first before checking for a dirty release.
		 * Hence on the first dirty close we will still remove the
		 * speculative allocation, but after that we will leave it in
		 * place.
		 */
		if (scxfs_iflags_test(ip, SCXFS_IDIRTY_RELEASE))
			return 0;
		/*
		 * If we can't get the iolock just skip truncating the blocks
		 * past EOF because we could deadlock with the mmap_sem
		 * otherwise. We'll get another chance to drop them once the
		 * last reference to the inode is dropped, so we'll never leak
		 * blocks permanently.
		 */
		if (scxfs_ilock_nowait(ip, SCXFS_IOLOCK_EXCL)) {
			error = scxfs_free_eofblocks(ip);
			scxfs_iunlock(ip, SCXFS_IOLOCK_EXCL);
			if (error)
				return error;
		}

		/* delalloc blocks after truncation means it really is dirty */
		if (ip->i_delayed_blks)
			scxfs_iflags_set(ip, SCXFS_IDIRTY_RELEASE);
	}
	return 0;
}

/*
 * scxfs_inactive_truncate
 *
 * Called to perform a truncate when an inode becomes unlinked.
 */
STATIC int
scxfs_inactive_truncate(
	struct scxfs_inode *ip)
{
	struct scxfs_mount	*mp = ip->i_mount;
	struct scxfs_trans	*tp;
	int			error;

	error = scxfs_trans_alloc(mp, &M_RES(mp)->tr_itruncate, 0, 0, 0, &tp);
	if (error) {
		ASSERT(SCXFS_FORCED_SHUTDOWN(mp));
		return error;
	}
	scxfs_ilock(ip, SCXFS_ILOCK_EXCL);
	scxfs_trans_ijoin(tp, ip, 0);

	/*
	 * Log the inode size first to prevent stale data exposure in the event
	 * of a system crash before the truncate completes. See the related
	 * comment in scxfs_vn_setattr_size() for details.
	 */
	ip->i_d.di_size = 0;
	scxfs_trans_log_inode(tp, ip, SCXFS_ILOG_CORE);

	error = scxfs_itruncate_extents(&tp, ip, SCXFS_DATA_FORK, 0);
	if (error)
		goto error_trans_cancel;

	ASSERT(ip->i_d.di_nextents == 0);

	error = scxfs_trans_commit(tp);
	if (error)
		goto error_unlock;

	scxfs_iunlock(ip, SCXFS_ILOCK_EXCL);
	return 0;

error_trans_cancel:
	scxfs_trans_cancel(tp);
error_unlock:
	scxfs_iunlock(ip, SCXFS_ILOCK_EXCL);
	return error;
}

/*
 * scxfs_inactive_ifree()
 *
 * Perform the inode free when an inode is unlinked.
 */
STATIC int
scxfs_inactive_ifree(
	struct scxfs_inode *ip)
{
	struct scxfs_mount	*mp = ip->i_mount;
	struct scxfs_trans	*tp;
	int			error;

	/*
	 * We try to use a per-AG reservation for any block needed by the finobt
	 * tree, but as the finobt feature predates the per-AG reservation
	 * support a degraded file system might not have enough space for the
	 * reservation at mount time.  In that case try to dip into the reserved
	 * pool and pray.
	 *
	 * Send a warning if the reservation does happen to fail, as the inode
	 * now remains allocated and sits on the unlinked list until the fs is
	 * repaired.
	 */
	if (unlikely(mp->m_finobt_nores)) {
		error = scxfs_trans_alloc(mp, &M_RES(mp)->tr_ifree,
				SCXFS_IFREE_SPACE_RES(mp), 0, SCXFS_TRANS_RESERVE,
				&tp);
	} else {
		error = scxfs_trans_alloc(mp, &M_RES(mp)->tr_ifree, 0, 0, 0, &tp);
	}
	if (error) {
		if (error == -ENOSPC) {
			scxfs_warn_ratelimited(mp,
			"Failed to remove inode(s) from unlinked list. "
			"Please free space, unmount and run scxfs_repair.");
		} else {
			ASSERT(SCXFS_FORCED_SHUTDOWN(mp));
		}
		return error;
	}

	/*
	 * We do not hold the inode locked across the entire rolling transaction
	 * here. We only need to hold it for the first transaction that
	 * scxfs_ifree() builds, which may mark the inode SCXFS_ISTALE if the
	 * underlying cluster buffer is freed. Relogging an SCXFS_ISTALE inode
	 * here breaks the relationship between cluster buffer invalidation and
	 * stale inode invalidation on cluster buffer item journal commit
	 * completion, and can result in leaving dirty stale inodes hanging
	 * around in memory.
	 *
	 * We have no need for serialising this inode operation against other
	 * operations - we freed the inode and hence reallocation is required
	 * and that will serialise on reallocating the space the deferops need
	 * to free. Hence we can unlock the inode on the first commit of
	 * the transaction rather than roll it right through the deferops. This
	 * avoids relogging the SCXFS_ISTALE inode.
	 *
	 * We check that scxfs_ifree() hasn't grown an internal transaction roll
	 * by asserting that the inode is still locked when it returns.
	 */
	scxfs_ilock(ip, SCXFS_ILOCK_EXCL);
	scxfs_trans_ijoin(tp, ip, SCXFS_ILOCK_EXCL);

	error = scxfs_ifree(tp, ip);
	ASSERT(scxfs_isilocked(ip, SCXFS_ILOCK_EXCL));
	if (error) {
		/*
		 * If we fail to free the inode, shut down.  The cancel
		 * might do that, we need to make sure.  Otherwise the
		 * inode might be lost for a long time or forever.
		 */
		if (!SCXFS_FORCED_SHUTDOWN(mp)) {
			scxfs_notice(mp, "%s: scxfs_ifree returned error %d",
				__func__, error);
			scxfs_force_shutdown(mp, SHUTDOWN_META_IO_ERROR);
		}
		scxfs_trans_cancel(tp);
		return error;
	}

	/*
	 * Credit the quota account(s). The inode is gone.
	 */
	scxfs_trans_mod_dquot_byino(tp, ip, SCXFS_TRANS_DQ_ICOUNT, -1);

	/*
	 * Just ignore errors at this point.  There is nothing we can do except
	 * to try to keep going. Make sure it's not a silent error.
	 */
	error = scxfs_trans_commit(tp);
	if (error)
		scxfs_notice(mp, "%s: scxfs_trans_commit returned error %d",
			__func__, error);

	return 0;
}

/*
 * scxfs_inactive
 *
 * This is called when the vnode reference count for the vnode
 * goes to zero.  If the file has been unlinked, then it must
 * now be truncated.  Also, we clear all of the read-ahead state
 * kept for the inode here since the file is now closed.
 */
void
scxfs_inactive(
	scxfs_inode_t	*ip)
{
	struct scxfs_mount	*mp;
	int			error;
	int			truncate = 0;

	/*
	 * If the inode is already free, then there can be nothing
	 * to clean up here.
	 */
	if (VFS_I(ip)->i_mode == 0) {
		ASSERT(ip->i_df.if_broot_bytes == 0);
		return;
	}

	mp = ip->i_mount;
	ASSERT(!scxfs_iflags_test(ip, SCXFS_IRECOVERY));

	/* If this is a read-only mount, don't do this (would generate I/O) */
	if (mp->m_flags & SCXFS_MOUNT_RDONLY)
		return;

	/* Try to clean out the cow blocks if there are any. */
	if (scxfs_inode_has_cow_data(ip))
		scxfs_reflink_cancel_cow_range(ip, 0, NULLFILEOFF, true);

	if (VFS_I(ip)->i_nlink != 0) {
		/*
		 * force is true because we are evicting an inode from the
		 * cache. Post-eof blocks must be freed, lest we end up with
		 * broken free space accounting.
		 *
		 * Note: don't bother with iolock here since lockdep complains
		 * about acquiring it in reclaim context. We have the only
		 * reference to the inode at this point anyways.
		 */
		if (scxfs_can_free_eofblocks(ip, true))
			scxfs_free_eofblocks(ip);

		return;
	}

	if (S_ISREG(VFS_I(ip)->i_mode) &&
	    (ip->i_d.di_size != 0 || SCXFS_ISIZE(ip) != 0 ||
	     ip->i_d.di_nextents > 0 || ip->i_delayed_blks > 0))
		truncate = 1;

	error = scxfs_qm_dqattach(ip);
	if (error)
		return;

	if (S_ISLNK(VFS_I(ip)->i_mode))
		error = scxfs_inactive_symlink(ip);
	else if (truncate)
		error = scxfs_inactive_truncate(ip);
	if (error)
		return;

	/*
	 * If there are attributes associated with the file then blow them away
	 * now.  The code calls a routine that recursively deconstructs the
	 * attribute fork. If also blows away the in-core attribute fork.
	 */
	if (SCXFS_IFORK_Q(ip)) {
		error = scxfs_attr_inactive(ip);
		if (error)
			return;
	}

	ASSERT(!ip->i_afp);
	ASSERT(ip->i_d.di_anextents == 0);
	ASSERT(ip->i_d.di_forkoff == 0);

	/*
	 * Free the inode.
	 */
	error = scxfs_inactive_ifree(ip);
	if (error)
		return;

	/*
	 * Release the dquots held by inode, if any.
	 */
	scxfs_qm_dqdetach(ip);
}

/*
 * In-Core Unlinked List Lookups
 * =============================
 *
 * Every inode is supposed to be reachable from some other piece of metadata
 * with the exception of the root directory.  Inodes with a connection to a
 * file descriptor but not linked from anywhere in the on-disk directory tree
 * are collectively known as unlinked inodes, though the filesystem itself
 * maintains links to these inodes so that on-disk metadata are consistent.
 *
 * SCXFS implements a per-AG on-disk hash table of unlinked inodes.  The AGI
 * header contains a number of buckets that point to an inode, and each inode
 * record has a pointer to the next inode in the hash chain.  This
 * singly-linked list causes scaling problems in the iunlink remove function
 * because we must walk that list to find the inode that points to the inode
 * being removed from the unlinked hash bucket list.
 *
 * What if we modelled the unlinked list as a collection of records capturing
 * "X.next_unlinked = Y" relations?  If we indexed those records on Y, we'd
 * have a fast way to look up unlinked list predecessors, which avoids the
 * slow list walk.  That's exactly what we do here (in-core) with a per-AG
 * rhashtable.
 *
 * Because this is a backref cache, we ignore operational failures since the
 * iunlink code can fall back to the slow bucket walk.  The only errors that
 * should bubble out are for obviously incorrect situations.
 *
 * All users of the backref cache MUST hold the AGI buffer lock to serialize
 * access or have otherwise provided for concurrency control.
 */

/* Capture a "X.next_unlinked = Y" relationship. */
struct scxfs_iunlink {
	struct rhash_head	iu_rhash_head;
	scxfs_agino_t		iu_agino;		/* X */
	scxfs_agino_t		iu_next_unlinked;	/* Y */
};

/* Unlinked list predecessor lookup hashtable construction */
static int
scxfs_iunlink_obj_cmpfn(
	struct rhashtable_compare_arg	*arg,
	const void			*obj)
{
	const scxfs_agino_t		*key = arg->key;
	const struct scxfs_iunlink	*iu = obj;

	if (iu->iu_next_unlinked != *key)
		return 1;
	return 0;
}

static const struct rhashtable_params scxfs_iunlink_hash_params = {
	.min_size		= SCXFS_AGI_UNLINKED_BUCKETS,
	.key_len		= sizeof(scxfs_agino_t),
	.key_offset		= offsetof(struct scxfs_iunlink,
					   iu_next_unlinked),
	.head_offset		= offsetof(struct scxfs_iunlink, iu_rhash_head),
	.automatic_shrinking	= true,
	.obj_cmpfn		= scxfs_iunlink_obj_cmpfn,
};

/*
 * Return X, where X.next_unlinked == @agino.  Returns NULLAGINO if no such
 * relation is found.
 */
static scxfs_agino_t
scxfs_iunlink_lookup_backref(
	struct scxfs_perag	*pag,
	scxfs_agino_t		agino)
{
	struct scxfs_iunlink	*iu;

	iu = rhashtable_lookup_fast(&pag->pagi_unlinked_hash, &agino,
			scxfs_iunlink_hash_params);
	return iu ? iu->iu_agino : NULLAGINO;
}

/*
 * Take ownership of an iunlink cache entry and insert it into the hash table.
 * If successful, the entry will be owned by the cache; if not, it is freed.
 * Either way, the caller does not own @iu after this call.
 */
static int
scxfs_iunlink_insert_backref(
	struct scxfs_perag	*pag,
	struct scxfs_iunlink	*iu)
{
	int			error;

	error = rhashtable_insert_fast(&pag->pagi_unlinked_hash,
			&iu->iu_rhash_head, scxfs_iunlink_hash_params);
	/*
	 * Fail loudly if there already was an entry because that's a sign of
	 * corruption of in-memory data.  Also fail loudly if we see an error
	 * code we didn't anticipate from the rhashtable code.  Currently we
	 * only anticipate ENOMEM.
	 */
	if (error) {
		WARN(error != -ENOMEM, "iunlink cache insert error %d", error);
		kmem_free(iu);
	}
	/*
	 * Absorb any runtime errors that aren't a result of corruption because
	 * this is a cache and we can always fall back to bucket list scanning.
	 */
	if (error != 0 && error != -EEXIST)
		error = 0;
	return error;
}

/* Remember that @prev_agino.next_unlinked = @this_agino. */
static int
scxfs_iunlink_add_backref(
	struct scxfs_perag	*pag,
	scxfs_agino_t		prev_agino,
	scxfs_agino_t		this_agino)
{
	struct scxfs_iunlink	*iu;

	if (SCXFS_TEST_ERROR(false, pag->pag_mount, SCXFS_ERRTAG_IUNLINK_FALLBACK))
		return 0;

	iu = kmem_zalloc(sizeof(*iu), KM_NOFS);
	iu->iu_agino = prev_agino;
	iu->iu_next_unlinked = this_agino;

	return scxfs_iunlink_insert_backref(pag, iu);
}

/*
 * Replace X.next_unlinked = @agino with X.next_unlinked = @next_unlinked.
 * If @next_unlinked is NULLAGINO, we drop the backref and exit.  If there
 * wasn't any such entry then we don't bother.
 */
static int
scxfs_iunlink_change_backref(
	struct scxfs_perag	*pag,
	scxfs_agino_t		agino,
	scxfs_agino_t		next_unlinked)
{
	struct scxfs_iunlink	*iu;
	int			error;

	/* Look up the old entry; if there wasn't one then exit. */
	iu = rhashtable_lookup_fast(&pag->pagi_unlinked_hash, &agino,
			scxfs_iunlink_hash_params);
	if (!iu)
		return 0;

	/*
	 * Remove the entry.  This shouldn't ever return an error, but if we
	 * couldn't remove the old entry we don't want to add it again to the
	 * hash table, and if the entry disappeared on us then someone's
	 * violated the locking rules and we need to fail loudly.  Either way
	 * we cannot remove the inode because internal state is or would have
	 * been corrupt.
	 */
	error = rhashtable_remove_fast(&pag->pagi_unlinked_hash,
			&iu->iu_rhash_head, scxfs_iunlink_hash_params);
	if (error)
		return error;

	/* If there is no new next entry just free our item and return. */
	if (next_unlinked == NULLAGINO) {
		kmem_free(iu);
		return 0;
	}

	/* Update the entry and re-add it to the hash table. */
	iu->iu_next_unlinked = next_unlinked;
	return scxfs_iunlink_insert_backref(pag, iu);
}

/* Set up the in-core predecessor structures. */
int
scxfs_iunlink_init(
	struct scxfs_perag	*pag)
{
	return rhashtable_init(&pag->pagi_unlinked_hash,
			&scxfs_iunlink_hash_params);
}

/* Free the in-core predecessor structures. */
static void
scxfs_iunlink_free_item(
	void			*ptr,
	void			*arg)
{
	struct scxfs_iunlink	*iu = ptr;
	bool			*freed_anything = arg;

	*freed_anything = true;
	kmem_free(iu);
}

void
scxfs_iunlink_destroy(
	struct scxfs_perag	*pag)
{
	bool			freed_anything = false;

	rhashtable_free_and_destroy(&pag->pagi_unlinked_hash,
			scxfs_iunlink_free_item, &freed_anything);

	ASSERT(freed_anything == false || SCXFS_FORCED_SHUTDOWN(pag->pag_mount));
}

/*
 * Point the AGI unlinked bucket at an inode and log the results.  The caller
 * is responsible for validating the old value.
 */
STATIC int
scxfs_iunlink_update_bucket(
	struct scxfs_trans	*tp,
	scxfs_agnumber_t		agno,
	struct scxfs_buf		*agibp,
	unsigned int		bucket_index,
	scxfs_agino_t		new_agino)
{
	struct scxfs_agi		*agi = SCXFS_BUF_TO_AGI(agibp);
	scxfs_agino_t		old_value;
	int			offset;

	ASSERT(scxfs_verify_agino_or_null(tp->t_mountp, agno, new_agino));

	old_value = be32_to_cpu(agi->agi_unlinked[bucket_index]);
	trace_scxfs_iunlink_update_bucket(tp->t_mountp, agno, bucket_index,
			old_value, new_agino);

	/*
	 * We should never find the head of the list already set to the value
	 * passed in because either we're adding or removing ourselves from the
	 * head of the list.
	 */
	if (old_value == new_agino)
		return -EFSCORRUPTED;

	agi->agi_unlinked[bucket_index] = cpu_to_be32(new_agino);
	offset = offsetof(struct scxfs_agi, agi_unlinked) +
			(sizeof(scxfs_agino_t) * bucket_index);
	scxfs_trans_log_buf(tp, agibp, offset, offset + sizeof(scxfs_agino_t) - 1);
	return 0;
}

/* Set an on-disk inode's next_unlinked pointer. */
STATIC void
scxfs_iunlink_update_dinode(
	struct scxfs_trans	*tp,
	scxfs_agnumber_t		agno,
	scxfs_agino_t		agino,
	struct scxfs_buf		*ibp,
	struct scxfs_dinode	*dip,
	struct scxfs_imap		*imap,
	scxfs_agino_t		next_agino)
{
	struct scxfs_mount	*mp = tp->t_mountp;
	int			offset;

	ASSERT(scxfs_verify_agino_or_null(mp, agno, next_agino));

	trace_scxfs_iunlink_update_dinode(mp, agno, agino,
			be32_to_cpu(dip->di_next_unlinked), next_agino);

	dip->di_next_unlinked = cpu_to_be32(next_agino);
	offset = imap->im_boffset +
			offsetof(struct scxfs_dinode, di_next_unlinked);

	/* need to recalc the inode CRC if appropriate */
	scxfs_dinode_calc_crc(mp, dip);
	scxfs_trans_inode_buf(tp, ibp);
	scxfs_trans_log_buf(tp, ibp, offset, offset + sizeof(scxfs_agino_t) - 1);
	scxfs_inobp_check(mp, ibp);
}

/* Set an in-core inode's unlinked pointer and return the old value. */
STATIC int
scxfs_iunlink_update_inode(
	struct scxfs_trans	*tp,
	struct scxfs_inode	*ip,
	scxfs_agnumber_t		agno,
	scxfs_agino_t		next_agino,
	scxfs_agino_t		*old_next_agino)
{
	struct scxfs_mount	*mp = tp->t_mountp;
	struct scxfs_dinode	*dip;
	struct scxfs_buf		*ibp;
	scxfs_agino_t		old_value;
	int			error;

	ASSERT(scxfs_verify_agino_or_null(mp, agno, next_agino));

	error = scxfs_imap_to_bp(mp, tp, &ip->i_imap, &dip, &ibp, 0, 0);
	if (error)
		return error;

	/* Make sure the old pointer isn't garbage. */
	old_value = be32_to_cpu(dip->di_next_unlinked);
	if (!scxfs_verify_agino_or_null(mp, agno, old_value)) {
		error = -EFSCORRUPTED;
		goto out;
	}

	/*
	 * Since we're updating a linked list, we should never find that the
	 * current pointer is the same as the new value, unless we're
	 * terminating the list.
	 */
	*old_next_agino = old_value;
	if (old_value == next_agino) {
		if (next_agino != NULLAGINO)
			error = -EFSCORRUPTED;
		goto out;
	}

	/* Ok, update the new pointer. */
	scxfs_iunlink_update_dinode(tp, agno, SCXFS_INO_TO_AGINO(mp, ip->i_ino),
			ibp, dip, &ip->i_imap, next_agino);
	return 0;
out:
	scxfs_trans_brelse(tp, ibp);
	return error;
}

/*
 * This is called when the inode's link count has gone to 0 or we are creating
 * a tmpfile via O_TMPFILE.  The inode @ip must have nlink == 0.
 *
 * We place the on-disk inode on a list in the AGI.  It will be pulled from this
 * list when the inode is freed.
 */
STATIC int
scxfs_iunlink(
	struct scxfs_trans	*tp,
	struct scxfs_inode	*ip)
{
	struct scxfs_mount	*mp = tp->t_mountp;
	struct scxfs_agi		*agi;
	struct scxfs_buf		*agibp;
	scxfs_agino_t		next_agino;
	scxfs_agnumber_t		agno = SCXFS_INO_TO_AGNO(mp, ip->i_ino);
	scxfs_agino_t		agino = SCXFS_INO_TO_AGINO(mp, ip->i_ino);
	short			bucket_index = agino % SCXFS_AGI_UNLINKED_BUCKETS;
	int			error;

	ASSERT(VFS_I(ip)->i_nlink == 0);
	ASSERT(VFS_I(ip)->i_mode != 0);
	trace_scxfs_iunlink(ip);

	/* Get the agi buffer first.  It ensures lock ordering on the list. */
	error = scxfs_read_agi(mp, tp, agno, &agibp);
	if (error)
		return error;
	agi = SCXFS_BUF_TO_AGI(agibp);

	/*
	 * Get the index into the agi hash table for the list this inode will
	 * go on.  Make sure the pointer isn't garbage and that this inode
	 * isn't already on the list.
	 */
	next_agino = be32_to_cpu(agi->agi_unlinked[bucket_index]);
	if (next_agino == agino ||
	    !scxfs_verify_agino_or_null(mp, agno, next_agino))
		return -EFSCORRUPTED;

	if (next_agino != NULLAGINO) {
		struct scxfs_perag	*pag;
		scxfs_agino_t		old_agino;

		/*
		 * There is already another inode in the bucket, so point this
		 * inode to the current head of the list.
		 */
		error = scxfs_iunlink_update_inode(tp, ip, agno, next_agino,
				&old_agino);
		if (error)
			return error;
		ASSERT(old_agino == NULLAGINO);

		/*
		 * agino has been unlinked, add a backref from the next inode
		 * back to agino.
		 */
		pag = scxfs_perag_get(mp, agno);
		error = scxfs_iunlink_add_backref(pag, agino, next_agino);
		scxfs_perag_put(pag);
		if (error)
			return error;
	}

	/* Point the head of the list to point to this inode. */
	return scxfs_iunlink_update_bucket(tp, agno, agibp, bucket_index, agino);
}

/* Return the imap, dinode pointer, and buffer for an inode. */
STATIC int
scxfs_iunlink_map_ino(
	struct scxfs_trans	*tp,
	scxfs_agnumber_t		agno,
	scxfs_agino_t		agino,
	struct scxfs_imap		*imap,
	struct scxfs_dinode	**dipp,
	struct scxfs_buf		**bpp)
{
	struct scxfs_mount	*mp = tp->t_mountp;
	int			error;

	imap->im_blkno = 0;
	error = scxfs_imap(mp, tp, SCXFS_AGINO_TO_INO(mp, agno, agino), imap, 0);
	if (error) {
		scxfs_warn(mp, "%s: scxfs_imap returned error %d.",
				__func__, error);
		return error;
	}

	error = scxfs_imap_to_bp(mp, tp, imap, dipp, bpp, 0, 0);
	if (error) {
		scxfs_warn(mp, "%s: scxfs_imap_to_bp returned error %d.",
				__func__, error);
		return error;
	}

	return 0;
}

/*
 * Walk the unlinked chain from @head_agino until we find the inode that
 * points to @target_agino.  Return the inode number, map, dinode pointer,
 * and inode cluster buffer of that inode as @agino, @imap, @dipp, and @bpp.
 *
 * @tp, @pag, @head_agino, and @target_agino are input parameters.
 * @agino, @imap, @dipp, and @bpp are all output parameters.
 *
 * Do not call this function if @target_agino is the head of the list.
 */
STATIC int
scxfs_iunlink_map_prev(
	struct scxfs_trans	*tp,
	scxfs_agnumber_t		agno,
	scxfs_agino_t		head_agino,
	scxfs_agino_t		target_agino,
	scxfs_agino_t		*agino,
	struct scxfs_imap		*imap,
	struct scxfs_dinode	**dipp,
	struct scxfs_buf		**bpp,
	struct scxfs_perag	*pag)
{
	struct scxfs_mount	*mp = tp->t_mountp;
	scxfs_agino_t		next_agino;
	int			error;

	ASSERT(head_agino != target_agino);
	*bpp = NULL;

	/* See if our backref cache can find it faster. */
	*agino = scxfs_iunlink_lookup_backref(pag, target_agino);
	if (*agino != NULLAGINO) {
		error = scxfs_iunlink_map_ino(tp, agno, *agino, imap, dipp, bpp);
		if (error)
			return error;

		if (be32_to_cpu((*dipp)->di_next_unlinked) == target_agino)
			return 0;

		/*
		 * If we get here the cache contents were corrupt, so drop the
		 * buffer and fall back to walking the bucket list.
		 */
		scxfs_trans_brelse(tp, *bpp);
		*bpp = NULL;
		WARN_ON_ONCE(1);
	}

	trace_scxfs_iunlink_map_prev_fallback(mp, agno);

	/* Otherwise, walk the entire bucket until we find it. */
	next_agino = head_agino;
	while (next_agino != target_agino) {
		scxfs_agino_t	unlinked_agino;

		if (*bpp)
			scxfs_trans_brelse(tp, *bpp);

		*agino = next_agino;
		error = scxfs_iunlink_map_ino(tp, agno, next_agino, imap, dipp,
				bpp);
		if (error)
			return error;

		unlinked_agino = be32_to_cpu((*dipp)->di_next_unlinked);
		/*
		 * Make sure this pointer is valid and isn't an obvious
		 * infinite loop.
		 */
		if (!scxfs_verify_agino(mp, agno, unlinked_agino) ||
		    next_agino == unlinked_agino) {
			SCXFS_CORRUPTION_ERROR(__func__,
					SCXFS_ERRLEVEL_LOW, mp,
					*dipp, sizeof(**dipp));
			error = -EFSCORRUPTED;
			return error;
		}
		next_agino = unlinked_agino;
	}

	return 0;
}

/*
 * Pull the on-disk inode from the AGI unlinked list.
 */
STATIC int
scxfs_iunlink_remove(
	struct scxfs_trans	*tp,
	struct scxfs_inode	*ip)
{
	struct scxfs_mount	*mp = tp->t_mountp;
	struct scxfs_agi		*agi;
	struct scxfs_buf		*agibp;
	struct scxfs_buf		*last_ibp;
	struct scxfs_dinode	*last_dip = NULL;
	struct scxfs_perag	*pag = NULL;
	scxfs_agnumber_t		agno = SCXFS_INO_TO_AGNO(mp, ip->i_ino);
	scxfs_agino_t		agino = SCXFS_INO_TO_AGINO(mp, ip->i_ino);
	scxfs_agino_t		next_agino;
	scxfs_agino_t		head_agino;
	short			bucket_index = agino % SCXFS_AGI_UNLINKED_BUCKETS;
	int			error;

	trace_scxfs_iunlink_remove(ip);

	/* Get the agi buffer first.  It ensures lock ordering on the list. */
	error = scxfs_read_agi(mp, tp, agno, &agibp);
	if (error)
		return error;
	agi = SCXFS_BUF_TO_AGI(agibp);

	/*
	 * Get the index into the agi hash table for the list this inode will
	 * go on.  Make sure the head pointer isn't garbage.
	 */
	head_agino = be32_to_cpu(agi->agi_unlinked[bucket_index]);
	if (!scxfs_verify_agino(mp, agno, head_agino)) {
		SCXFS_CORRUPTION_ERROR(__func__, SCXFS_ERRLEVEL_LOW, mp,
				agi, sizeof(*agi));
		return -EFSCORRUPTED;
	}

	/*
	 * Set our inode's next_unlinked pointer to NULL and then return
	 * the old pointer value so that we can update whatever was previous
	 * to us in the list to point to whatever was next in the list.
	 */
	error = scxfs_iunlink_update_inode(tp, ip, agno, NULLAGINO, &next_agino);
	if (error)
		return error;

	/*
	 * If there was a backref pointing from the next inode back to this
	 * one, remove it because we've removed this inode from the list.
	 *
	 * Later, if this inode was in the middle of the list we'll update
	 * this inode's backref to point from the next inode.
	 */
	if (next_agino != NULLAGINO) {
		pag = scxfs_perag_get(mp, agno);
		error = scxfs_iunlink_change_backref(pag, next_agino,
				NULLAGINO);
		if (error)
			goto out;
	}

	if (head_agino == agino) {
		/* Point the head of the list to the next unlinked inode. */
		error = scxfs_iunlink_update_bucket(tp, agno, agibp, bucket_index,
				next_agino);
		if (error)
			goto out;
	} else {
		struct scxfs_imap	imap;
		scxfs_agino_t	prev_agino;

		if (!pag)
			pag = scxfs_perag_get(mp, agno);

		/* We need to search the list for the inode being freed. */
		error = scxfs_iunlink_map_prev(tp, agno, head_agino, agino,
				&prev_agino, &imap, &last_dip, &last_ibp,
				pag);
		if (error)
			goto out;

		/* Point the previous inode on the list to the next inode. */
		scxfs_iunlink_update_dinode(tp, agno, prev_agino, last_ibp,
				last_dip, &imap, next_agino);

		/*
		 * Now we deal with the backref for this inode.  If this inode
		 * pointed at a real inode, change the backref that pointed to
		 * us to point to our old next.  If this inode was the end of
		 * the list, delete the backref that pointed to us.  Note that
		 * change_backref takes care of deleting the backref if
		 * next_agino is NULLAGINO.
		 */
		error = scxfs_iunlink_change_backref(pag, agino, next_agino);
		if (error)
			goto out;
	}

out:
	if (pag)
		scxfs_perag_put(pag);
	return error;
}

/*
 * A big issue when freeing the inode cluster is that we _cannot_ skip any
 * inodes that are in memory - they all must be marked stale and attached to
 * the cluster buffer.
 */
STATIC int
scxfs_ifree_cluster(
	scxfs_inode_t		*free_ip,
	scxfs_trans_t		*tp,
	struct scxfs_icluster	*xic)
{
	scxfs_mount_t		*mp = free_ip->i_mount;
	int			nbufs;
	int			i, j;
	int			ioffset;
	scxfs_daddr_t		blkno;
	scxfs_buf_t		*bp;
	scxfs_inode_t		*ip;
	scxfs_inode_log_item_t	*iip;
	struct scxfs_log_item	*lip;
	struct scxfs_perag	*pag;
	struct scxfs_ino_geometry	*igeo = M_IGEO(mp);
	scxfs_ino_t		inum;

	inum = xic->first_ino;
	pag = scxfs_perag_get(mp, SCXFS_INO_TO_AGNO(mp, inum));
	nbufs = igeo->ialloc_blks / igeo->blocks_per_cluster;

	for (j = 0; j < nbufs; j++, inum += igeo->inodes_per_cluster) {
		/*
		 * The allocation bitmap tells us which inodes of the chunk were
		 * physically allocated. Skip the cluster if an inode falls into
		 * a sparse region.
		 */
		ioffset = inum - xic->first_ino;
		if ((xic->alloc & SCXFS_INOBT_MASK(ioffset)) == 0) {
			ASSERT(ioffset % igeo->inodes_per_cluster == 0);
			continue;
		}

		blkno = SCXFS_AGB_TO_DADDR(mp, SCXFS_INO_TO_AGNO(mp, inum),
					 SCXFS_INO_TO_AGBNO(mp, inum));

		/*
		 * We obtain and lock the backing buffer first in the process
		 * here, as we have to ensure that any dirty inode that we
		 * can't get the flush lock on is attached to the buffer.
		 * If we scan the in-memory inodes first, then buffer IO can
		 * complete before we get a lock on it, and hence we may fail
		 * to mark all the active inodes on the buffer stale.
		 */
		bp = scxfs_trans_get_buf(tp, mp->m_ddev_targp, blkno,
					mp->m_bsize * igeo->blocks_per_cluster,
					XBF_UNMAPPED);

		if (!bp)
			return -ENOMEM;

		/*
		 * This buffer may not have been correctly initialised as we
		 * didn't read it from disk. That's not important because we are
		 * only using to mark the buffer as stale in the log, and to
		 * attach stale cached inodes on it. That means it will never be
		 * dispatched for IO. If it is, we want to know about it, and we
		 * want it to fail. We can acheive this by adding a write
		 * verifier to the buffer.
		 */
		bp->b_ops = &scxfs_inode_buf_ops;

		/*
		 * Walk the inodes already attached to the buffer and mark them
		 * stale. These will all have the flush locks held, so an
		 * in-memory inode walk can't lock them. By marking them all
		 * stale first, we will not attempt to lock them in the loop
		 * below as the SCXFS_ISTALE flag will be set.
		 */
		list_for_each_entry(lip, &bp->b_li_list, li_bio_list) {
			if (lip->li_type == SCXFS_LI_INODE) {
				iip = (scxfs_inode_log_item_t *)lip;
				ASSERT(iip->ili_logged == 1);
				lip->li_cb = scxfs_istale_done;
				scxfs_trans_ail_copy_lsn(mp->m_ail,
							&iip->ili_flush_lsn,
							&iip->ili_item.li_lsn);
				scxfs_iflags_set(iip->ili_inode, SCXFS_ISTALE);
			}
		}


		/*
		 * For each inode in memory attempt to add it to the inode
		 * buffer and set it up for being staled on buffer IO
		 * completion.  This is safe as we've locked out tail pushing
		 * and flushing by locking the buffer.
		 *
		 * We have already marked every inode that was part of a
		 * transaction stale above, which means there is no point in
		 * even trying to lock them.
		 */
		for (i = 0; i < igeo->inodes_per_cluster; i++) {
retry:
			rcu_read_lock();
			ip = radix_tree_lookup(&pag->pag_ici_root,
					SCXFS_INO_TO_AGINO(mp, (inum + i)));

			/* Inode not in memory, nothing to do */
			if (!ip) {
				rcu_read_unlock();
				continue;
			}

			/*
			 * because this is an RCU protected lookup, we could
			 * find a recently freed or even reallocated inode
			 * during the lookup. We need to check under the
			 * i_flags_lock for a valid inode here. Skip it if it
			 * is not valid, the wrong inode or stale.
			 */
			spin_lock(&ip->i_flags_lock);
			if (ip->i_ino != inum + i ||
			    __scxfs_iflags_test(ip, SCXFS_ISTALE)) {
				spin_unlock(&ip->i_flags_lock);
				rcu_read_unlock();
				continue;
			}
			spin_unlock(&ip->i_flags_lock);

			/*
			 * Don't try to lock/unlock the current inode, but we
			 * _cannot_ skip the other inodes that we did not find
			 * in the list attached to the buffer and are not
			 * already marked stale. If we can't lock it, back off
			 * and retry.
			 */
			if (ip != free_ip) {
				if (!scxfs_ilock_nowait(ip, SCXFS_ILOCK_EXCL)) {
					rcu_read_unlock();
					delay(1);
					goto retry;
				}

				/*
				 * Check the inode number again in case we're
				 * racing with freeing in scxfs_reclaim_inode().
				 * See the comments in that function for more
				 * information as to why the initial check is
				 * not sufficient.
				 */
				if (ip->i_ino != inum + i) {
					scxfs_iunlock(ip, SCXFS_ILOCK_EXCL);
					rcu_read_unlock();
					continue;
				}
			}
			rcu_read_unlock();

			scxfs_iflock(ip);
			scxfs_iflags_set(ip, SCXFS_ISTALE);

			/*
			 * we don't need to attach clean inodes or those only
			 * with unlogged changes (which we throw away, anyway).
			 */
			iip = ip->i_itemp;
			if (!iip || scxfs_inode_clean(ip)) {
				ASSERT(ip != free_ip);
				scxfs_ifunlock(ip);
				scxfs_iunlock(ip, SCXFS_ILOCK_EXCL);
				continue;
			}

			iip->ili_last_fields = iip->ili_fields;
			iip->ili_fields = 0;
			iip->ili_fsync_fields = 0;
			iip->ili_logged = 1;
			scxfs_trans_ail_copy_lsn(mp->m_ail, &iip->ili_flush_lsn,
						&iip->ili_item.li_lsn);

			scxfs_buf_attach_iodone(bp, scxfs_istale_done,
						  &iip->ili_item);

			if (ip != free_ip)
				scxfs_iunlock(ip, SCXFS_ILOCK_EXCL);
		}

		scxfs_trans_stale_inode_buf(tp, bp);
		scxfs_trans_binval(tp, bp);
	}

	scxfs_perag_put(pag);
	return 0;
}

/*
 * Free any local-format buffers sitting around before we reset to
 * extents format.
 */
static inline void
scxfs_ifree_local_data(
	struct scxfs_inode	*ip,
	int			whichfork)
{
	struct scxfs_ifork	*ifp;

	if (SCXFS_IFORK_FORMAT(ip, whichfork) != SCXFS_DINODE_FMT_LOCAL)
		return;

	ifp = SCXFS_IFORK_PTR(ip, whichfork);
	scxfs_idata_realloc(ip, -ifp->if_bytes, whichfork);
}

/*
 * This is called to return an inode to the inode free list.
 * The inode should already be truncated to 0 length and have
 * no pages associated with it.  This routine also assumes that
 * the inode is already a part of the transaction.
 *
 * The on-disk copy of the inode will have been added to the list
 * of unlinked inodes in the AGI. We need to remove the inode from
 * that list atomically with respect to freeing it here.
 */
int
scxfs_ifree(
	struct scxfs_trans	*tp,
	struct scxfs_inode	*ip)
{
	int			error;
	struct scxfs_icluster	xic = { 0 };

	ASSERT(scxfs_isilocked(ip, SCXFS_ILOCK_EXCL));
	ASSERT(VFS_I(ip)->i_nlink == 0);
	ASSERT(ip->i_d.di_nextents == 0);
	ASSERT(ip->i_d.di_anextents == 0);
	ASSERT(ip->i_d.di_size == 0 || !S_ISREG(VFS_I(ip)->i_mode));
	ASSERT(ip->i_d.di_nblocks == 0);

	/*
	 * Pull the on-disk inode from the AGI unlinked list.
	 */
	error = scxfs_iunlink_remove(tp, ip);
	if (error)
		return error;

	error = scxfs_difree(tp, ip->i_ino, &xic);
	if (error)
		return error;

	scxfs_ifree_local_data(ip, SCXFS_DATA_FORK);
	scxfs_ifree_local_data(ip, SCXFS_ATTR_FORK);

	VFS_I(ip)->i_mode = 0;		/* mark incore inode as free */
	ip->i_d.di_flags = 0;
	ip->i_d.di_flags2 = 0;
	ip->i_d.di_dmevmask = 0;
	ip->i_d.di_forkoff = 0;		/* mark the attr fork not in use */
	ip->i_d.di_format = SCXFS_DINODE_FMT_EXTENTS;
	ip->i_d.di_aformat = SCXFS_DINODE_FMT_EXTENTS;

	/* Don't attempt to replay owner changes for a deleted inode */
	ip->i_itemp->ili_fields &= ~(SCXFS_ILOG_AOWNER|SCXFS_ILOG_DOWNER);

	/*
	 * Bump the generation count so no one will be confused
	 * by reincarnations of this inode.
	 */
	VFS_I(ip)->i_generation++;
	scxfs_trans_log_inode(tp, ip, SCXFS_ILOG_CORE);

	if (xic.deleted)
		error = scxfs_ifree_cluster(ip, tp, &xic);

	return error;
}

/*
 * This is called to unpin an inode.  The caller must have the inode locked
 * in at least shared mode so that the buffer cannot be subsequently pinned
 * once someone is waiting for it to be unpinned.
 */
static void
scxfs_iunpin(
	struct scxfs_inode	*ip)
{
	ASSERT(scxfs_isilocked(ip, SCXFS_ILOCK_EXCL|SCXFS_ILOCK_SHARED));

	trace_scxfs_inode_unpin_nowait(ip, _RET_IP_);

	/* Give the log a push to start the unpinning I/O */
	scxfs_log_force_lsn(ip->i_mount, ip->i_itemp->ili_last_lsn, 0, NULL);

}

static void
__scxfs_iunpin_wait(
	struct scxfs_inode	*ip)
{
	wait_queue_head_t *wq = bit_waitqueue(&ip->i_flags, __SCXFS_IPINNED_BIT);
	DEFINE_WAIT_BIT(wait, &ip->i_flags, __SCXFS_IPINNED_BIT);

	scxfs_iunpin(ip);

	do {
		prepare_to_wait(wq, &wait.wq_entry, TASK_UNINTERRUPTIBLE);
		if (scxfs_ipincount(ip))
			io_schedule();
	} while (scxfs_ipincount(ip));
	finish_wait(wq, &wait.wq_entry);
}

void
scxfs_iunpin_wait(
	struct scxfs_inode	*ip)
{
	if (scxfs_ipincount(ip))
		__scxfs_iunpin_wait(ip);
}

/*
 * Removing an inode from the namespace involves removing the directory entry
 * and dropping the link count on the inode. Removing the directory entry can
 * result in locking an AGF (directory blocks were freed) and removing a link
 * count can result in placing the inode on an unlinked list which results in
 * locking an AGI.
 *
 * The big problem here is that we have an ordering constraint on AGF and AGI
 * locking - inode allocation locks the AGI, then can allocate a new extent for
 * new inodes, locking the AGF after the AGI. Similarly, freeing the inode
 * removes the inode from the unlinked list, requiring that we lock the AGI
 * first, and then freeing the inode can result in an inode chunk being freed
 * and hence freeing disk space requiring that we lock an AGF.
 *
 * Hence the ordering that is imposed by other parts of the code is AGI before
 * AGF. This means we cannot remove the directory entry before we drop the inode
 * reference count and put it on the unlinked list as this results in a lock
 * order of AGF then AGI, and this can deadlock against inode allocation and
 * freeing. Therefore we must drop the link counts before we remove the
 * directory entry.
 *
 * This is still safe from a transactional point of view - it is not until we
 * get to scxfs_defer_finish() that we have the possibility of multiple
 * transactions in this operation. Hence as long as we remove the directory
 * entry and drop the link count in the first transaction of the remove
 * operation, there are no transactional constraints on the ordering here.
 */
int
scxfs_remove(
	scxfs_inode_t             *dp,
	struct scxfs_name		*name,
	scxfs_inode_t		*ip)
{
	scxfs_mount_t		*mp = dp->i_mount;
	scxfs_trans_t             *tp = NULL;
	int			is_dir = S_ISDIR(VFS_I(ip)->i_mode);
	int                     error = 0;
	uint			resblks;

	trace_scxfs_remove(dp, name);

	if (SCXFS_FORCED_SHUTDOWN(mp))
		return -EIO;

	error = scxfs_qm_dqattach(dp);
	if (error)
		goto std_return;

	error = scxfs_qm_dqattach(ip);
	if (error)
		goto std_return;

	/*
	 * We try to get the real space reservation first,
	 * allowing for directory btree deletion(s) implying
	 * possible bmap insert(s).  If we can't get the space
	 * reservation then we use 0 instead, and avoid the bmap
	 * btree insert(s) in the directory code by, if the bmap
	 * insert tries to happen, instead trimming the LAST
	 * block from the directory.
	 */
	resblks = SCXFS_REMOVE_SPACE_RES(mp);
	error = scxfs_trans_alloc(mp, &M_RES(mp)->tr_remove, resblks, 0, 0, &tp);
	if (error == -ENOSPC) {
		resblks = 0;
		error = scxfs_trans_alloc(mp, &M_RES(mp)->tr_remove, 0, 0, 0,
				&tp);
	}
	if (error) {
		ASSERT(error != -ENOSPC);
		goto std_return;
	}

	scxfs_lock_two_inodes(dp, SCXFS_ILOCK_EXCL, ip, SCXFS_ILOCK_EXCL);

	scxfs_trans_ijoin(tp, dp, SCXFS_ILOCK_EXCL);
	scxfs_trans_ijoin(tp, ip, SCXFS_ILOCK_EXCL);

	/*
	 * If we're removing a directory perform some additional validation.
	 */
	if (is_dir) {
		ASSERT(VFS_I(ip)->i_nlink >= 2);
		if (VFS_I(ip)->i_nlink != 2) {
			error = -ENOTEMPTY;
			goto out_trans_cancel;
		}
		if (!scxfs_dir_isempty(ip)) {
			error = -ENOTEMPTY;
			goto out_trans_cancel;
		}

		/* Drop the link from ip's "..".  */
		error = scxfs_droplink(tp, dp);
		if (error)
			goto out_trans_cancel;

		/* Drop the "." link from ip to self.  */
		error = scxfs_droplink(tp, ip);
		if (error)
			goto out_trans_cancel;
	} else {
		/*
		 * When removing a non-directory we need to log the parent
		 * inode here.  For a directory this is done implicitly
		 * by the scxfs_droplink call for the ".." entry.
		 */
		scxfs_trans_log_inode(tp, dp, SCXFS_ILOG_CORE);
	}
	scxfs_trans_ichgtime(tp, dp, SCXFS_ICHGTIME_MOD | SCXFS_ICHGTIME_CHG);

	/* Drop the link from dp to ip. */
	error = scxfs_droplink(tp, ip);
	if (error)
		goto out_trans_cancel;

	error = scxfs_dir_removename(tp, dp, name, ip->i_ino, resblks);
	if (error) {
		ASSERT(error != -ENOENT);
		goto out_trans_cancel;
	}

	/*
	 * If this is a synchronous mount, make sure that the
	 * remove transaction goes to disk before returning to
	 * the user.
	 */
	if (mp->m_flags & (SCXFS_MOUNT_WSYNC|SCXFS_MOUNT_DIRSYNC))
		scxfs_trans_set_sync(tp);

	error = scxfs_trans_commit(tp);
	if (error)
		goto std_return;

	if (is_dir && scxfs_inode_is_filestream(ip))
		scxfs_filestream_deassociate(ip);

	return 0;

 out_trans_cancel:
	scxfs_trans_cancel(tp);
 std_return:
	return error;
}

/*
 * Enter all inodes for a rename transaction into a sorted array.
 */
#define __SCXFS_SORT_INODES	5
STATIC void
scxfs_sort_for_rename(
	struct scxfs_inode	*dp1,	/* in: old (source) directory inode */
	struct scxfs_inode	*dp2,	/* in: new (target) directory inode */
	struct scxfs_inode	*ip1,	/* in: inode of old entry */
	struct scxfs_inode	*ip2,	/* in: inode of new entry */
	struct scxfs_inode	*wip,	/* in: whiteout inode */
	struct scxfs_inode	**i_tab,/* out: sorted array of inodes */
	int			*num_inodes)  /* in/out: inodes in array */
{
	int			i, j;

	ASSERT(*num_inodes == __SCXFS_SORT_INODES);
	memset(i_tab, 0, *num_inodes * sizeof(struct scxfs_inode *));

	/*
	 * i_tab contains a list of pointers to inodes.  We initialize
	 * the table here & we'll sort it.  We will then use it to
	 * order the acquisition of the inode locks.
	 *
	 * Note that the table may contain duplicates.  e.g., dp1 == dp2.
	 */
	i = 0;
	i_tab[i++] = dp1;
	i_tab[i++] = dp2;
	i_tab[i++] = ip1;
	if (ip2)
		i_tab[i++] = ip2;
	if (wip)
		i_tab[i++] = wip;
	*num_inodes = i;

	/*
	 * Sort the elements via bubble sort.  (Remember, there are at
	 * most 5 elements to sort, so this is adequate.)
	 */
	for (i = 0; i < *num_inodes; i++) {
		for (j = 1; j < *num_inodes; j++) {
			if (i_tab[j]->i_ino < i_tab[j-1]->i_ino) {
				struct scxfs_inode *temp = i_tab[j];
				i_tab[j] = i_tab[j-1];
				i_tab[j-1] = temp;
			}
		}
	}
}

static int
scxfs_finish_rename(
	struct scxfs_trans	*tp)
{
	/*
	 * If this is a synchronous mount, make sure that the rename transaction
	 * goes to disk before returning to the user.
	 */
	if (tp->t_mountp->m_flags & (SCXFS_MOUNT_WSYNC|SCXFS_MOUNT_DIRSYNC))
		scxfs_trans_set_sync(tp);

	return scxfs_trans_commit(tp);
}

/*
 * scxfs_cross_rename()
 *
 * responsible for handling RENAME_EXCHANGE flag in renameat2() sytemcall
 */
STATIC int
scxfs_cross_rename(
	struct scxfs_trans	*tp,
	struct scxfs_inode	*dp1,
	struct scxfs_name		*name1,
	struct scxfs_inode	*ip1,
	struct scxfs_inode	*dp2,
	struct scxfs_name		*name2,
	struct scxfs_inode	*ip2,
	int			spaceres)
{
	int		error = 0;
	int		ip1_flags = 0;
	int		ip2_flags = 0;
	int		dp2_flags = 0;

	/* Swap inode number for dirent in first parent */
	error = scxfs_dir_replace(tp, dp1, name1, ip2->i_ino, spaceres);
	if (error)
		goto out_trans_abort;

	/* Swap inode number for dirent in second parent */
	error = scxfs_dir_replace(tp, dp2, name2, ip1->i_ino, spaceres);
	if (error)
		goto out_trans_abort;

	/*
	 * If we're renaming one or more directories across different parents,
	 * update the respective ".." entries (and link counts) to match the new
	 * parents.
	 */
	if (dp1 != dp2) {
		dp2_flags = SCXFS_ICHGTIME_MOD | SCXFS_ICHGTIME_CHG;

		if (S_ISDIR(VFS_I(ip2)->i_mode)) {
			error = scxfs_dir_replace(tp, ip2, &scxfs_name_dotdot,
						dp1->i_ino, spaceres);
			if (error)
				goto out_trans_abort;

			/* transfer ip2 ".." reference to dp1 */
			if (!S_ISDIR(VFS_I(ip1)->i_mode)) {
				error = scxfs_droplink(tp, dp2);
				if (error)
					goto out_trans_abort;
				scxfs_bumplink(tp, dp1);
			}

			/*
			 * Although ip1 isn't changed here, userspace needs
			 * to be warned about the change, so that applications
			 * relying on it (like backup ones), will properly
			 * notify the change
			 */
			ip1_flags |= SCXFS_ICHGTIME_CHG;
			ip2_flags |= SCXFS_ICHGTIME_MOD | SCXFS_ICHGTIME_CHG;
		}

		if (S_ISDIR(VFS_I(ip1)->i_mode)) {
			error = scxfs_dir_replace(tp, ip1, &scxfs_name_dotdot,
						dp2->i_ino, spaceres);
			if (error)
				goto out_trans_abort;

			/* transfer ip1 ".." reference to dp2 */
			if (!S_ISDIR(VFS_I(ip2)->i_mode)) {
				error = scxfs_droplink(tp, dp1);
				if (error)
					goto out_trans_abort;
				scxfs_bumplink(tp, dp2);
			}

			/*
			 * Although ip2 isn't changed here, userspace needs
			 * to be warned about the change, so that applications
			 * relying on it (like backup ones), will properly
			 * notify the change
			 */
			ip1_flags |= SCXFS_ICHGTIME_MOD | SCXFS_ICHGTIME_CHG;
			ip2_flags |= SCXFS_ICHGTIME_CHG;
		}
	}

	if (ip1_flags) {
		scxfs_trans_ichgtime(tp, ip1, ip1_flags);
		scxfs_trans_log_inode(tp, ip1, SCXFS_ILOG_CORE);
	}
	if (ip2_flags) {
		scxfs_trans_ichgtime(tp, ip2, ip2_flags);
		scxfs_trans_log_inode(tp, ip2, SCXFS_ILOG_CORE);
	}
	if (dp2_flags) {
		scxfs_trans_ichgtime(tp, dp2, dp2_flags);
		scxfs_trans_log_inode(tp, dp2, SCXFS_ILOG_CORE);
	}
	scxfs_trans_ichgtime(tp, dp1, SCXFS_ICHGTIME_MOD | SCXFS_ICHGTIME_CHG);
	scxfs_trans_log_inode(tp, dp1, SCXFS_ILOG_CORE);
	return scxfs_finish_rename(tp);

out_trans_abort:
	scxfs_trans_cancel(tp);
	return error;
}

/*
 * scxfs_rename_alloc_whiteout()
 *
 * Return a referenced, unlinked, unlocked inode that that can be used as a
 * whiteout in a rename transaction. We use a tmpfile inode here so that if we
 * crash between allocating the inode and linking it into the rename transaction
 * recovery will free the inode and we won't leak it.
 */
static int
scxfs_rename_alloc_whiteout(
	struct scxfs_inode	*dp,
	struct scxfs_inode	**wip)
{
	struct scxfs_inode	*tmpfile;
	int			error;

	error = scxfs_create_tmpfile(dp, S_IFCHR | WHITEOUT_MODE, &tmpfile);
	if (error)
		return error;

	/*
	 * Prepare the tmpfile inode as if it were created through the VFS.
	 * Complete the inode setup and flag it as linkable.  nlink is already
	 * zero, so we can skip the drop_nlink.
	 */
	scxfs_setup_iops(tmpfile);
	scxfs_finish_inode_setup(tmpfile);
	VFS_I(tmpfile)->i_state |= I_LINKABLE;

	*wip = tmpfile;
	return 0;
}

/*
 * scxfs_rename
 */
int
scxfs_rename(
	struct scxfs_inode	*src_dp,
	struct scxfs_name		*src_name,
	struct scxfs_inode	*src_ip,
	struct scxfs_inode	*target_dp,
	struct scxfs_name		*target_name,
	struct scxfs_inode	*target_ip,
	unsigned int		flags)
{
	struct scxfs_mount	*mp = src_dp->i_mount;
	struct scxfs_trans	*tp;
	struct scxfs_inode	*wip = NULL;		/* whiteout inode */
	struct scxfs_inode	*inodes[__SCXFS_SORT_INODES];
	int			num_inodes = __SCXFS_SORT_INODES;
	bool			new_parent = (src_dp != target_dp);
	bool			src_is_directory = S_ISDIR(VFS_I(src_ip)->i_mode);
	int			spaceres;
	int			error;

	trace_scxfs_rename(src_dp, target_dp, src_name, target_name);

	if ((flags & RENAME_EXCHANGE) && !target_ip)
		return -EINVAL;

	/*
	 * If we are doing a whiteout operation, allocate the whiteout inode
	 * we will be placing at the target and ensure the type is set
	 * appropriately.
	 */
	if (flags & RENAME_WHITEOUT) {
		ASSERT(!(flags & (RENAME_NOREPLACE | RENAME_EXCHANGE)));
		error = scxfs_rename_alloc_whiteout(target_dp, &wip);
		if (error)
			return error;

		/* setup target dirent info as whiteout */
		src_name->type = SCXFS_DIR3_FT_CHRDEV;
	}

	scxfs_sort_for_rename(src_dp, target_dp, src_ip, target_ip, wip,
				inodes, &num_inodes);

	spaceres = SCXFS_RENAME_SPACE_RES(mp, target_name->len);
	error = scxfs_trans_alloc(mp, &M_RES(mp)->tr_rename, spaceres, 0, 0, &tp);
	if (error == -ENOSPC) {
		spaceres = 0;
		error = scxfs_trans_alloc(mp, &M_RES(mp)->tr_rename, 0, 0, 0,
				&tp);
	}
	if (error)
		goto out_release_wip;

	/*
	 * Attach the dquots to the inodes
	 */
	error = scxfs_qm_vop_rename_dqattach(inodes);
	if (error)
		goto out_trans_cancel;

	/*
	 * Lock all the participating inodes. Depending upon whether
	 * the target_name exists in the target directory, and
	 * whether the target directory is the same as the source
	 * directory, we can lock from 2 to 4 inodes.
	 */
	scxfs_lock_inodes(inodes, num_inodes, SCXFS_ILOCK_EXCL);

	/*
	 * Join all the inodes to the transaction. From this point on,
	 * we can rely on either trans_commit or trans_cancel to unlock
	 * them.
	 */
	scxfs_trans_ijoin(tp, src_dp, SCXFS_ILOCK_EXCL);
	if (new_parent)
		scxfs_trans_ijoin(tp, target_dp, SCXFS_ILOCK_EXCL);
	scxfs_trans_ijoin(tp, src_ip, SCXFS_ILOCK_EXCL);
	if (target_ip)
		scxfs_trans_ijoin(tp, target_ip, SCXFS_ILOCK_EXCL);
	if (wip)
		scxfs_trans_ijoin(tp, wip, SCXFS_ILOCK_EXCL);

	/*
	 * If we are using project inheritance, we only allow renames
	 * into our tree when the project IDs are the same; else the
	 * tree quota mechanism would be circumvented.
	 */
	if (unlikely((target_dp->i_d.di_flags & SCXFS_DIFLAG_PROJINHERIT) &&
		     (scxfs_get_projid(target_dp) != scxfs_get_projid(src_ip)))) {
		error = -EXDEV;
		goto out_trans_cancel;
	}

	/* RENAME_EXCHANGE is unique from here on. */
	if (flags & RENAME_EXCHANGE)
		return scxfs_cross_rename(tp, src_dp, src_name, src_ip,
					target_dp, target_name, target_ip,
					spaceres);

	/*
	 * Check for expected errors before we dirty the transaction
	 * so we can return an error without a transaction abort.
	 */
	if (target_ip == NULL) {
		/*
		 * If there's no space reservation, check the entry will
		 * fit before actually inserting it.
		 */
		if (!spaceres) {
			error = scxfs_dir_canenter(tp, target_dp, target_name);
			if (error)
				goto out_trans_cancel;
		}
	} else {
		/*
		 * If target exists and it's a directory, check that whether
		 * it can be destroyed.
		 */
		if (S_ISDIR(VFS_I(target_ip)->i_mode) &&
		    (!scxfs_dir_isempty(target_ip) ||
		     (VFS_I(target_ip)->i_nlink > 2))) {
			error = -EEXIST;
			goto out_trans_cancel;
		}
	}

	/*
	 * Directory entry creation below may acquire the AGF. Remove
	 * the whiteout from the unlinked list first to preserve correct
	 * AGI/AGF locking order. This dirties the transaction so failures
	 * after this point will abort and log recovery will clean up the
	 * mess.
	 *
	 * For whiteouts, we need to bump the link count on the whiteout
	 * inode. After this point, we have a real link, clear the tmpfile
	 * state flag from the inode so it doesn't accidentally get misused
	 * in future.
	 */
	if (wip) {
		ASSERT(VFS_I(wip)->i_nlink == 0);
		error = scxfs_iunlink_remove(tp, wip);
		if (error)
			goto out_trans_cancel;

		scxfs_bumplink(tp, wip);
		scxfs_trans_log_inode(tp, wip, SCXFS_ILOG_CORE);
		VFS_I(wip)->i_state &= ~I_LINKABLE;
	}

	/*
	 * Set up the target.
	 */
	if (target_ip == NULL) {
		/*
		 * If target does not exist and the rename crosses
		 * directories, adjust the target directory link count
		 * to account for the ".." reference from the new entry.
		 */
		error = scxfs_dir_createname(tp, target_dp, target_name,
					   src_ip->i_ino, spaceres);
		if (error)
			goto out_trans_cancel;

		scxfs_trans_ichgtime(tp, target_dp,
					SCXFS_ICHGTIME_MOD | SCXFS_ICHGTIME_CHG);

		if (new_parent && src_is_directory) {
			scxfs_bumplink(tp, target_dp);
		}
	} else { /* target_ip != NULL */
		/*
		 * Link the source inode under the target name.
		 * If the source inode is a directory and we are moving
		 * it across directories, its ".." entry will be
		 * inconsistent until we replace that down below.
		 *
		 * In case there is already an entry with the same
		 * name at the destination directory, remove it first.
		 */
		error = scxfs_dir_replace(tp, target_dp, target_name,
					src_ip->i_ino, spaceres);
		if (error)
			goto out_trans_cancel;

		scxfs_trans_ichgtime(tp, target_dp,
					SCXFS_ICHGTIME_MOD | SCXFS_ICHGTIME_CHG);

		/*
		 * Decrement the link count on the target since the target
		 * dir no longer points to it.
		 */
		error = scxfs_droplink(tp, target_ip);
		if (error)
			goto out_trans_cancel;

		if (src_is_directory) {
			/*
			 * Drop the link from the old "." entry.
			 */
			error = scxfs_droplink(tp, target_ip);
			if (error)
				goto out_trans_cancel;
		}
	} /* target_ip != NULL */

	/*
	 * Remove the source.
	 */
	if (new_parent && src_is_directory) {
		/*
		 * Rewrite the ".." entry to point to the new
		 * directory.
		 */
		error = scxfs_dir_replace(tp, src_ip, &scxfs_name_dotdot,
					target_dp->i_ino, spaceres);
		ASSERT(error != -EEXIST);
		if (error)
			goto out_trans_cancel;
	}

	/*
	 * We always want to hit the ctime on the source inode.
	 *
	 * This isn't strictly required by the standards since the source
	 * inode isn't really being changed, but old unix file systems did
	 * it and some incremental backup programs won't work without it.
	 */
	scxfs_trans_ichgtime(tp, src_ip, SCXFS_ICHGTIME_CHG);
	scxfs_trans_log_inode(tp, src_ip, SCXFS_ILOG_CORE);

	/*
	 * Adjust the link count on src_dp.  This is necessary when
	 * renaming a directory, either within one parent when
	 * the target existed, or across two parent directories.
	 */
	if (src_is_directory && (new_parent || target_ip != NULL)) {

		/*
		 * Decrement link count on src_directory since the
		 * entry that's moved no longer points to it.
		 */
		error = scxfs_droplink(tp, src_dp);
		if (error)
			goto out_trans_cancel;
	}

	/*
	 * For whiteouts, we only need to update the source dirent with the
	 * inode number of the whiteout inode rather than removing it
	 * altogether.
	 */
	if (wip) {
		error = scxfs_dir_replace(tp, src_dp, src_name, wip->i_ino,
					spaceres);
	} else
		error = scxfs_dir_removename(tp, src_dp, src_name, src_ip->i_ino,
					   spaceres);
	if (error)
		goto out_trans_cancel;

	scxfs_trans_ichgtime(tp, src_dp, SCXFS_ICHGTIME_MOD | SCXFS_ICHGTIME_CHG);
	scxfs_trans_log_inode(tp, src_dp, SCXFS_ILOG_CORE);
	if (new_parent)
		scxfs_trans_log_inode(tp, target_dp, SCXFS_ILOG_CORE);

	error = scxfs_finish_rename(tp);
	if (wip)
		scxfs_irele(wip);
	return error;

out_trans_cancel:
	scxfs_trans_cancel(tp);
out_release_wip:
	if (wip)
		scxfs_irele(wip);
	return error;
}

STATIC int
scxfs_iflush_cluster(
	struct scxfs_inode	*ip,
	struct scxfs_buf		*bp)
{
	struct scxfs_mount	*mp = ip->i_mount;
	struct scxfs_perag	*pag;
	unsigned long		first_index, mask;
	int			cilist_size;
	struct scxfs_inode	**cilist;
	struct scxfs_inode	*cip;
	struct scxfs_ino_geometry	*igeo = M_IGEO(mp);
	int			nr_found;
	int			clcount = 0;
	int			i;

	pag = scxfs_perag_get(mp, SCXFS_INO_TO_AGNO(mp, ip->i_ino));

	cilist_size = igeo->inodes_per_cluster * sizeof(struct scxfs_inode *);
	cilist = kmem_alloc(cilist_size, KM_MAYFAIL|KM_NOFS);
	if (!cilist)
		goto out_put;

	mask = ~(igeo->inodes_per_cluster - 1);
	first_index = SCXFS_INO_TO_AGINO(mp, ip->i_ino) & mask;
	rcu_read_lock();
	/* really need a gang lookup range call here */
	nr_found = radix_tree_gang_lookup(&pag->pag_ici_root, (void**)cilist,
					first_index, igeo->inodes_per_cluster);
	if (nr_found == 0)
		goto out_free;

	for (i = 0; i < nr_found; i++) {
		cip = cilist[i];
		if (cip == ip)
			continue;

		/*
		 * because this is an RCU protected lookup, we could find a
		 * recently freed or even reallocated inode during the lookup.
		 * We need to check under the i_flags_lock for a valid inode
		 * here. Skip it if it is not valid or the wrong inode.
		 */
		spin_lock(&cip->i_flags_lock);
		if (!cip->i_ino ||
		    __scxfs_iflags_test(cip, SCXFS_ISTALE)) {
			spin_unlock(&cip->i_flags_lock);
			continue;
		}

		/*
		 * Once we fall off the end of the cluster, no point checking
		 * any more inodes in the list because they will also all be
		 * outside the cluster.
		 */
		if ((SCXFS_INO_TO_AGINO(mp, cip->i_ino) & mask) != first_index) {
			spin_unlock(&cip->i_flags_lock);
			break;
		}
		spin_unlock(&cip->i_flags_lock);

		/*
		 * Do an un-protected check to see if the inode is dirty and
		 * is a candidate for flushing.  These checks will be repeated
		 * later after the appropriate locks are acquired.
		 */
		if (scxfs_inode_clean(cip) && scxfs_ipincount(cip) == 0)
			continue;

		/*
		 * Try to get locks.  If any are unavailable or it is pinned,
		 * then this inode cannot be flushed and is skipped.
		 */

		if (!scxfs_ilock_nowait(cip, SCXFS_ILOCK_SHARED))
			continue;
		if (!scxfs_iflock_nowait(cip)) {
			scxfs_iunlock(cip, SCXFS_ILOCK_SHARED);
			continue;
		}
		if (scxfs_ipincount(cip)) {
			scxfs_ifunlock(cip);
			scxfs_iunlock(cip, SCXFS_ILOCK_SHARED);
			continue;
		}


		/*
		 * Check the inode number again, just to be certain we are not
		 * racing with freeing in scxfs_reclaim_inode(). See the comments
		 * in that function for more information as to why the initial
		 * check is not sufficient.
		 */
		if (!cip->i_ino) {
			scxfs_ifunlock(cip);
			scxfs_iunlock(cip, SCXFS_ILOCK_SHARED);
			continue;
		}

		/*
		 * arriving here means that this inode can be flushed.  First
		 * re-check that it's dirty before flushing.
		 */
		if (!scxfs_inode_clean(cip)) {
			int	error;
			error = scxfs_iflush_int(cip, bp);
			if (error) {
				scxfs_iunlock(cip, SCXFS_ILOCK_SHARED);
				goto cluster_corrupt_out;
			}
			clcount++;
		} else {
			scxfs_ifunlock(cip);
		}
		scxfs_iunlock(cip, SCXFS_ILOCK_SHARED);
	}

	if (clcount) {
		SCXFS_STATS_INC(mp, xs_icluster_flushcnt);
		SCXFS_STATS_ADD(mp, xs_icluster_flushinode, clcount);
	}

out_free:
	rcu_read_unlock();
	kmem_free(cilist);
out_put:
	scxfs_perag_put(pag);
	return 0;


cluster_corrupt_out:
	/*
	 * Corruption detected in the clustering loop.  Invalidate the
	 * inode buffer and shut down the filesystem.
	 */
	rcu_read_unlock();

	/*
	 * We'll always have an inode attached to the buffer for completion
	 * process by the time we are called from scxfs_iflush(). Hence we have
	 * always need to do IO completion processing to abort the inodes
	 * attached to the buffer.  handle them just like the shutdown case in
	 * scxfs_buf_submit().
	 */
	ASSERT(bp->b_iodone);
	bp->b_flags |= XBF_ASYNC;
	bp->b_flags &= ~XBF_DONE;
	scxfs_buf_stale(bp);
	scxfs_buf_ioerror(bp, -EIO);
	scxfs_buf_ioend(bp);

	scxfs_force_shutdown(mp, SHUTDOWN_CORRUPT_INCORE);

	/* abort the corrupt inode, as it was not attached to the buffer */
	scxfs_iflush_abort(cip, false);
	kmem_free(cilist);
	scxfs_perag_put(pag);
	return -EFSCORRUPTED;
}

/*
 * Flush dirty inode metadata into the backing buffer.
 *
 * The caller must have the inode lock and the inode flush lock held.  The
 * inode lock will still be held upon return to the caller, and the inode
 * flush lock will be released after the inode has reached the disk.
 *
 * The caller must write out the buffer returned in *bpp and release it.
 */
int
scxfs_iflush(
	struct scxfs_inode	*ip,
	struct scxfs_buf		**bpp)
{
	struct scxfs_mount	*mp = ip->i_mount;
	struct scxfs_buf		*bp = NULL;
	struct scxfs_dinode	*dip;
	int			error;

	SCXFS_STATS_INC(mp, xs_iflush_count);

	ASSERT(scxfs_isilocked(ip, SCXFS_ILOCK_EXCL|SCXFS_ILOCK_SHARED));
	ASSERT(scxfs_isiflocked(ip));
	ASSERT(ip->i_d.di_format != SCXFS_DINODE_FMT_BTREE ||
	       ip->i_d.di_nextents > SCXFS_IFORK_MAXEXT(ip, SCXFS_DATA_FORK));

	*bpp = NULL;

	scxfs_iunpin_wait(ip);

	/*
	 * For stale inodes we cannot rely on the backing buffer remaining
	 * stale in cache for the remaining life of the stale inode and so
	 * scxfs_imap_to_bp() below may give us a buffer that no longer contains
	 * inodes below. We have to check this after ensuring the inode is
	 * unpinned so that it is safe to reclaim the stale inode after the
	 * flush call.
	 */
	if (scxfs_iflags_test(ip, SCXFS_ISTALE)) {
		scxfs_ifunlock(ip);
		return 0;
	}

	/*
	 * This may have been unpinned because the filesystem is shutting
	 * down forcibly. If that's the case we must not write this inode
	 * to disk, because the log record didn't make it to disk.
	 *
	 * We also have to remove the log item from the AIL in this case,
	 * as we wait for an empty AIL as part of the unmount process.
	 */
	if (SCXFS_FORCED_SHUTDOWN(mp)) {
		error = -EIO;
		goto abort_out;
	}

	/*
	 * Get the buffer containing the on-disk inode. We are doing a try-lock
	 * operation here, so we may get  an EAGAIN error. In that case, we
	 * simply want to return with the inode still dirty.
	 *
	 * If we get any other error, we effectively have a corruption situation
	 * and we cannot flush the inode, so we treat it the same as failing
	 * scxfs_iflush_int().
	 */
	error = scxfs_imap_to_bp(mp, NULL, &ip->i_imap, &dip, &bp, XBF_TRYLOCK,
			       0);
	if (error == -EAGAIN) {
		scxfs_ifunlock(ip);
		return error;
	}
	if (error)
		goto corrupt_out;

	/*
	 * First flush out the inode that scxfs_iflush was called with.
	 */
	error = scxfs_iflush_int(ip, bp);
	if (error)
		goto corrupt_out;

	/*
	 * If the buffer is pinned then push on the log now so we won't
	 * get stuck waiting in the write for too long.
	 */
	if (scxfs_buf_ispinned(bp))
		scxfs_log_force(mp, 0);

	/*
	 * inode clustering: try to gather other inodes into this write
	 *
	 * Note: Any error during clustering will result in the filesystem
	 * being shut down and completion callbacks run on the cluster buffer.
	 * As we have already flushed and attached this inode to the buffer,
	 * it has already been aborted and released by scxfs_iflush_cluster() and
	 * so we have no further error handling to do here.
	 */
	error = scxfs_iflush_cluster(ip, bp);
	if (error)
		return error;

	*bpp = bp;
	return 0;

corrupt_out:
	if (bp)
		scxfs_buf_relse(bp);
	scxfs_force_shutdown(mp, SHUTDOWN_CORRUPT_INCORE);
abort_out:
	/* abort the corrupt inode, as it was not attached to the buffer */
	scxfs_iflush_abort(ip, false);
	return error;
}

/*
 * If there are inline format data / attr forks attached to this inode,
 * make sure they're not corrupt.
 */
bool
scxfs_inode_verify_forks(
	struct scxfs_inode	*ip)
{
	struct scxfs_ifork	*ifp;
	scxfs_failaddr_t		fa;

	fa = scxfs_ifork_verify_data(ip, &scxfs_default_ifork_ops);
	if (fa) {
		ifp = SCXFS_IFORK_PTR(ip, SCXFS_DATA_FORK);
		scxfs_inode_verifier_error(ip, -EFSCORRUPTED, "data fork",
				ifp->if_u1.if_data, ifp->if_bytes, fa);
		return false;
	}

	fa = scxfs_ifork_verify_attr(ip, &scxfs_default_ifork_ops);
	if (fa) {
		ifp = SCXFS_IFORK_PTR(ip, SCXFS_ATTR_FORK);
		scxfs_inode_verifier_error(ip, -EFSCORRUPTED, "attr fork",
				ifp ? ifp->if_u1.if_data : NULL,
				ifp ? ifp->if_bytes : 0, fa);
		return false;
	}
	return true;
}

STATIC int
scxfs_iflush_int(
	struct scxfs_inode	*ip,
	struct scxfs_buf		*bp)
{
	struct scxfs_inode_log_item *iip = ip->i_itemp;
	struct scxfs_dinode	*dip;
	struct scxfs_mount	*mp = ip->i_mount;

	ASSERT(scxfs_isilocked(ip, SCXFS_ILOCK_EXCL|SCXFS_ILOCK_SHARED));
	ASSERT(scxfs_isiflocked(ip));
	ASSERT(ip->i_d.di_format != SCXFS_DINODE_FMT_BTREE ||
	       ip->i_d.di_nextents > SCXFS_IFORK_MAXEXT(ip, SCXFS_DATA_FORK));
	ASSERT(iip != NULL && iip->ili_fields != 0);
	ASSERT(ip->i_d.di_version > 1);

	/* set *dip = inode's place in the buffer */
	dip = scxfs_buf_offset(bp, ip->i_imap.im_boffset);

	if (SCXFS_TEST_ERROR(dip->di_magic != cpu_to_be16(SCXFS_DINODE_MAGIC),
			       mp, SCXFS_ERRTAG_IFLUSH_1)) {
		scxfs_alert_tag(mp, SCXFS_PTAG_IFLUSH,
			"%s: Bad inode %Lu magic number 0x%x, ptr "PTR_FMT,
			__func__, ip->i_ino, be16_to_cpu(dip->di_magic), dip);
		goto corrupt_out;
	}
	if (S_ISREG(VFS_I(ip)->i_mode)) {
		if (SCXFS_TEST_ERROR(
		    (ip->i_d.di_format != SCXFS_DINODE_FMT_EXTENTS) &&
		    (ip->i_d.di_format != SCXFS_DINODE_FMT_BTREE),
		    mp, SCXFS_ERRTAG_IFLUSH_3)) {
			scxfs_alert_tag(mp, SCXFS_PTAG_IFLUSH,
				"%s: Bad regular inode %Lu, ptr "PTR_FMT,
				__func__, ip->i_ino, ip);
			goto corrupt_out;
		}
	} else if (S_ISDIR(VFS_I(ip)->i_mode)) {
		if (SCXFS_TEST_ERROR(
		    (ip->i_d.di_format != SCXFS_DINODE_FMT_EXTENTS) &&
		    (ip->i_d.di_format != SCXFS_DINODE_FMT_BTREE) &&
		    (ip->i_d.di_format != SCXFS_DINODE_FMT_LOCAL),
		    mp, SCXFS_ERRTAG_IFLUSH_4)) {
			scxfs_alert_tag(mp, SCXFS_PTAG_IFLUSH,
				"%s: Bad directory inode %Lu, ptr "PTR_FMT,
				__func__, ip->i_ino, ip);
			goto corrupt_out;
		}
	}
	if (SCXFS_TEST_ERROR(ip->i_d.di_nextents + ip->i_d.di_anextents >
				ip->i_d.di_nblocks, mp, SCXFS_ERRTAG_IFLUSH_5)) {
		scxfs_alert_tag(mp, SCXFS_PTAG_IFLUSH,
			"%s: detected corrupt incore inode %Lu, "
			"total extents = %d, nblocks = %Ld, ptr "PTR_FMT,
			__func__, ip->i_ino,
			ip->i_d.di_nextents + ip->i_d.di_anextents,
			ip->i_d.di_nblocks, ip);
		goto corrupt_out;
	}
	if (SCXFS_TEST_ERROR(ip->i_d.di_forkoff > mp->m_sb.sb_inodesize,
				mp, SCXFS_ERRTAG_IFLUSH_6)) {
		scxfs_alert_tag(mp, SCXFS_PTAG_IFLUSH,
			"%s: bad inode %Lu, forkoff 0x%x, ptr "PTR_FMT,
			__func__, ip->i_ino, ip->i_d.di_forkoff, ip);
		goto corrupt_out;
	}

	/*
	 * Inode item log recovery for v2 inodes are dependent on the
	 * di_flushiter count for correct sequencing. We bump the flush
	 * iteration count so we can detect flushes which postdate a log record
	 * during recovery. This is redundant as we now log every change and
	 * hence this can't happen but we need to still do it to ensure
	 * backwards compatibility with old kernels that predate logging all
	 * inode changes.
	 */
	if (ip->i_d.di_version < 3)
		ip->i_d.di_flushiter++;

	/* Check the inline fork data before we write out. */
	if (!scxfs_inode_verify_forks(ip))
		goto corrupt_out;

	/*
	 * Copy the dirty parts of the inode into the on-disk inode.  We always
	 * copy out the core of the inode, because if the inode is dirty at all
	 * the core must be.
	 */
	scxfs_inode_to_disk(ip, dip, iip->ili_item.li_lsn);

	/* Wrap, we never let the log put out DI_MAX_FLUSH */
	if (ip->i_d.di_flushiter == DI_MAX_FLUSH)
		ip->i_d.di_flushiter = 0;

	scxfs_iflush_fork(ip, dip, iip, SCXFS_DATA_FORK);
	if (SCXFS_IFORK_Q(ip))
		scxfs_iflush_fork(ip, dip, iip, SCXFS_ATTR_FORK);
	scxfs_inobp_check(mp, bp);

	/*
	 * We've recorded everything logged in the inode, so we'd like to clear
	 * the ili_fields bits so we don't log and flush things unnecessarily.
	 * However, we can't stop logging all this information until the data
	 * we've copied into the disk buffer is written to disk.  If we did we
	 * might overwrite the copy of the inode in the log with all the data
	 * after re-logging only part of it, and in the face of a crash we
	 * wouldn't have all the data we need to recover.
	 *
	 * What we do is move the bits to the ili_last_fields field.  When
	 * logging the inode, these bits are moved back to the ili_fields field.
	 * In the scxfs_iflush_done() routine we clear ili_last_fields, since we
	 * know that the information those bits represent is permanently on
	 * disk.  As long as the flush completes before the inode is logged
	 * again, then both ili_fields and ili_last_fields will be cleared.
	 *
	 * We can play with the ili_fields bits here, because the inode lock
	 * must be held exclusively in order to set bits there and the flush
	 * lock protects the ili_last_fields bits.  Set ili_logged so the flush
	 * done routine can tell whether or not to look in the AIL.  Also, store
	 * the current LSN of the inode so that we can tell whether the item has
	 * moved in the AIL from scxfs_iflush_done().  In order to read the lsn we
	 * need the AIL lock, because it is a 64 bit value that cannot be read
	 * atomically.
	 */
	iip->ili_last_fields = iip->ili_fields;
	iip->ili_fields = 0;
	iip->ili_fsync_fields = 0;
	iip->ili_logged = 1;

	scxfs_trans_ail_copy_lsn(mp->m_ail, &iip->ili_flush_lsn,
				&iip->ili_item.li_lsn);

	/*
	 * Attach the function scxfs_iflush_done to the inode's
	 * buffer.  This will remove the inode from the AIL
	 * and unlock the inode's flush lock when the inode is
	 * completely written to disk.
	 */
	scxfs_buf_attach_iodone(bp, scxfs_iflush_done, &iip->ili_item);

	/* generate the checksum. */
	scxfs_dinode_calc_crc(mp, dip);

	ASSERT(!list_empty(&bp->b_li_list));
	ASSERT(bp->b_iodone != NULL);
	return 0;

corrupt_out:
	return -EFSCORRUPTED;
}

/* Release an inode. */
void
scxfs_irele(
	struct scxfs_inode	*ip)
{
	trace_scxfs_irele(ip, _RET_IP_);
	iput(VFS_I(ip));
}
