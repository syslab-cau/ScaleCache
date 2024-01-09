// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#include "scxfs.h"
#include "scxfs_fs.h"
#include "scxfs_shared.h"
#include "scxfs_format.h"
#include "scxfs_log_format.h"
#include "scxfs_trans_resv.h"
#include "scxfs_sb.h"
#include "scxfs_mount.h"
#include "scxfs_inode.h"
#include "scxfs_trans.h"
#include "scxfs_trans_priv.h"
#include "scxfs_inode_item.h"
#include "scxfs_quota.h"
#include "scxfs_trace.h"
#include "scxfs_icache.h"
#include "scxfs_bmap_util.h"
#include "scxfs_dquot_item.h"
#include "scxfs_dquot.h"
#include "scxfs_reflink.h"

#include <linux/iversion.h>

/*
 * Allocate and initialise an scxfs_inode.
 */
struct scxfs_inode *
scxfs_inode_alloc(
	struct scxfs_mount	*mp,
	scxfs_ino_t		ino)
{
	struct scxfs_inode	*ip;

	/*
	 * if this didn't occur in transactions, we could use
	 * KM_MAYFAIL and return NULL here on ENOMEM. Set the
	 * code up to do this anyway.
	 */
	ip = kmem_zone_alloc(scxfs_inode_zone, 0);
	if (!ip)
		return NULL;
	if (inode_init_always(mp->m_super, VFS_I(ip))) {
		kmem_zone_free(scxfs_inode_zone, ip);
		return NULL;
	}

	/* VFS doesn't initialise i_mode! */
	VFS_I(ip)->i_mode = 0;

	SCXFS_STATS_INC(mp, vn_active);
	ASSERT(atomic_read(&ip->i_pincount) == 0);
	ASSERT(!scxfs_isiflocked(ip));
	ASSERT(ip->i_ino == 0);

	/* initialise the scxfs inode */
	ip->i_ino = ino;
	ip->i_mount = mp;
	memset(&ip->i_imap, 0, sizeof(struct scxfs_imap));
	ip->i_afp = NULL;
	ip->i_cowfp = NULL;
	ip->i_cnextents = 0;
	ip->i_cformat = SCXFS_DINODE_FMT_EXTENTS;
	memset(&ip->i_df, 0, sizeof(ip->i_df));
	ip->i_flags = 0;
	ip->i_delayed_blks = 0;
	memset(&ip->i_d, 0, sizeof(ip->i_d));
	ip->i_sick = 0;
	ip->i_checked = 0;
	INIT_WORK(&ip->i_ioend_work, scxfs_end_io);
	INIT_LIST_HEAD(&ip->i_ioend_list);
	spin_lock_init(&ip->i_ioend_lock);

	return ip;
}

STATIC void
scxfs_inode_free_callback(
	struct rcu_head		*head)
{
	struct inode		*inode = container_of(head, struct inode, i_rcu);
	struct scxfs_inode	*ip = SCXFS_I(inode);

	switch (VFS_I(ip)->i_mode & S_IFMT) {
	case S_IFREG:
	case S_IFDIR:
	case S_IFLNK:
		scxfs_idestroy_fork(ip, SCXFS_DATA_FORK);
		break;
	}

	if (ip->i_afp)
		scxfs_idestroy_fork(ip, SCXFS_ATTR_FORK);
	if (ip->i_cowfp)
		scxfs_idestroy_fork(ip, SCXFS_COW_FORK);

	if (ip->i_itemp) {
		ASSERT(!test_bit(SCXFS_LI_IN_AIL,
				 &ip->i_itemp->ili_item.li_flags));
		scxfs_inode_item_destroy(ip);
		ip->i_itemp = NULL;
	}

	kmem_zone_free(scxfs_inode_zone, ip);
}

static void
__scxfs_inode_free(
	struct scxfs_inode	*ip)
{
	/* asserts to verify all state is correct here */
	ASSERT(atomic_read(&ip->i_pincount) == 0);
	SCXFS_STATS_DEC(ip->i_mount, vn_active);

	call_rcu(&VFS_I(ip)->i_rcu, scxfs_inode_free_callback);
}

void
scxfs_inode_free(
	struct scxfs_inode	*ip)
{
	ASSERT(!scxfs_isiflocked(ip));

	/*
	 * Because we use RCU freeing we need to ensure the inode always
	 * appears to be reclaimed with an invalid inode number when in the
	 * free state. The ip->i_flags_lock provides the barrier against lookup
	 * races.
	 */
	spin_lock(&ip->i_flags_lock);
	ip->i_flags = SCXFS_IRECLAIM;
	ip->i_ino = 0;
	spin_unlock(&ip->i_flags_lock);

	__scxfs_inode_free(ip);
}

/*
 * Queue a new inode reclaim pass if there are reclaimable inodes and there
 * isn't a reclaim pass already in progress. By default it runs every 5s based
 * on the scxfs periodic sync default of 30s. Perhaps this should have it's own
 * tunable, but that can be done if this method proves to be ineffective or too
 * aggressive.
 */
static void
scxfs_reclaim_work_queue(
	struct scxfs_mount        *mp)
{

	rcu_read_lock();
	if (radix_tree_tagged(&mp->m_perag_tree, SCXFS_ICI_RECLAIM_TAG)) {
		queue_delayed_work(mp->m_reclaim_workqueue, &mp->m_reclaim_work,
			msecs_to_jiffies(scxfs_syncd_centisecs / 6 * 10));
	}
	rcu_read_unlock();
}

/*
 * This is a fast pass over the inode cache to try to get reclaim moving on as
 * many inodes as possible in a short period of time. It kicks itself every few
 * seconds, as well as being kicked by the inode cache shrinker when memory
 * goes low. It scans as quickly as possible avoiding locked inodes or those
 * already being flushed, and once done schedules a future pass.
 */
void
scxfs_reclaim_worker(
	struct work_struct *work)
{
	struct scxfs_mount *mp = container_of(to_delayed_work(work),
					struct scxfs_mount, m_reclaim_work);

	scxfs_reclaim_inodes(mp, SYNC_TRYLOCK);
	scxfs_reclaim_work_queue(mp);
}

static void
scxfs_perag_set_reclaim_tag(
	struct scxfs_perag	*pag)
{
	struct scxfs_mount	*mp = pag->pag_mount;

	lockdep_assert_held(&pag->pag_ici_lock);
	if (pag->pag_ici_reclaimable++)
		return;

	/* propagate the reclaim tag up into the perag radix tree */
	spin_lock(&mp->m_perag_lock);
	radix_tree_tag_set(&mp->m_perag_tree, pag->pag_agno,
			   SCXFS_ICI_RECLAIM_TAG);
	spin_unlock(&mp->m_perag_lock);

	/* schedule periodic background inode reclaim */
	scxfs_reclaim_work_queue(mp);

	trace_scxfs_perag_set_reclaim(mp, pag->pag_agno, -1, _RET_IP_);
}

static void
scxfs_perag_clear_reclaim_tag(
	struct scxfs_perag	*pag)
{
	struct scxfs_mount	*mp = pag->pag_mount;

	lockdep_assert_held(&pag->pag_ici_lock);
	if (--pag->pag_ici_reclaimable)
		return;

	/* clear the reclaim tag from the perag radix tree */
	spin_lock(&mp->m_perag_lock);
	radix_tree_tag_clear(&mp->m_perag_tree, pag->pag_agno,
			     SCXFS_ICI_RECLAIM_TAG);
	spin_unlock(&mp->m_perag_lock);
	trace_scxfs_perag_clear_reclaim(mp, pag->pag_agno, -1, _RET_IP_);
}


/*
 * We set the inode flag atomically with the radix tree tag.
 * Once we get tag lookups on the radix tree, this inode flag
 * can go away.
 */
void
scxfs_inode_set_reclaim_tag(
	struct scxfs_inode	*ip)
{
	struct scxfs_mount	*mp = ip->i_mount;
	struct scxfs_perag	*pag;

	pag = scxfs_perag_get(mp, SCXFS_INO_TO_AGNO(mp, ip->i_ino));
	spin_lock(&pag->pag_ici_lock);
	spin_lock(&ip->i_flags_lock);

	radix_tree_tag_set(&pag->pag_ici_root, SCXFS_INO_TO_AGINO(mp, ip->i_ino),
			   SCXFS_ICI_RECLAIM_TAG);
	scxfs_perag_set_reclaim_tag(pag);
	__scxfs_iflags_set(ip, SCXFS_IRECLAIMABLE);

	spin_unlock(&ip->i_flags_lock);
	spin_unlock(&pag->pag_ici_lock);
	scxfs_perag_put(pag);
}

STATIC void
scxfs_inode_clear_reclaim_tag(
	struct scxfs_perag	*pag,
	scxfs_ino_t		ino)
{
	radix_tree_tag_clear(&pag->pag_ici_root,
			     SCXFS_INO_TO_AGINO(pag->pag_mount, ino),
			     SCXFS_ICI_RECLAIM_TAG);
	scxfs_perag_clear_reclaim_tag(pag);
}

static void
scxfs_inew_wait(
	struct scxfs_inode	*ip)
{
	wait_queue_head_t *wq = bit_waitqueue(&ip->i_flags, __SCXFS_INEW_BIT);
	DEFINE_WAIT_BIT(wait, &ip->i_flags, __SCXFS_INEW_BIT);

	do {
		prepare_to_wait(wq, &wait.wq_entry, TASK_UNINTERRUPTIBLE);
		if (!scxfs_iflags_test(ip, SCXFS_INEW))
			break;
		schedule();
	} while (true);
	finish_wait(wq, &wait.wq_entry);
}

/*
 * When we recycle a reclaimable inode, we need to re-initialise the VFS inode
 * part of the structure. This is made more complex by the fact we store
 * information about the on-disk values in the VFS inode and so we can't just
 * overwrite the values unconditionally. Hence we save the parameters we
 * need to retain across reinitialisation, and rewrite them into the VFS inode
 * after reinitialisation even if it fails.
 */
static int
scxfs_reinit_inode(
	struct scxfs_mount	*mp,
	struct inode		*inode)
{
	int		error;
	uint32_t	nlink = inode->i_nlink;
	uint32_t	generation = inode->i_generation;
	uint64_t	version = inode_peek_iversion(inode);
	umode_t		mode = inode->i_mode;
	dev_t		dev = inode->i_rdev;

	error = inode_init_always(mp->m_super, inode);

	set_nlink(inode, nlink);
	inode->i_generation = generation;
	inode_set_iversion_queried(inode, version);
	inode->i_mode = mode;
	inode->i_rdev = dev;
	return error;
}

/*
 * If we are allocating a new inode, then check what was returned is
 * actually a free, empty inode. If we are not allocating an inode,
 * then check we didn't find a free inode.
 *
 * Returns:
 *	0		if the inode free state matches the lookup context
 *	-ENOENT		if the inode is free and we are not allocating
 *	-EFSCORRUPTED	if there is any state mismatch at all
 */
static int
scxfs_iget_check_free_state(
	struct scxfs_inode	*ip,
	int			flags)
{
	if (flags & SCXFS_IGET_CREATE) {
		/* should be a free inode */
		if (VFS_I(ip)->i_mode != 0) {
			scxfs_warn(ip->i_mount,
"Corruption detected! Free inode 0x%llx not marked free! (mode 0x%x)",
				ip->i_ino, VFS_I(ip)->i_mode);
			return -EFSCORRUPTED;
		}

		if (ip->i_d.di_nblocks != 0) {
			scxfs_warn(ip->i_mount,
"Corruption detected! Free inode 0x%llx has blocks allocated!",
				ip->i_ino);
			return -EFSCORRUPTED;
		}
		return 0;
	}

	/* should be an allocated inode */
	if (VFS_I(ip)->i_mode == 0)
		return -ENOENT;

	return 0;
}

/*
 * Check the validity of the inode we just found it the cache
 */
static int
scxfs_iget_cache_hit(
	struct scxfs_perag	*pag,
	struct scxfs_inode	*ip,
	scxfs_ino_t		ino,
	int			flags,
	int			lock_flags) __releases(RCU)
{
	struct inode		*inode = VFS_I(ip);
	struct scxfs_mount	*mp = ip->i_mount;
	int			error;

	/*
	 * check for re-use of an inode within an RCU grace period due to the
	 * radix tree nodes not being updated yet. We monitor for this by
	 * setting the inode number to zero before freeing the inode structure.
	 * If the inode has been reallocated and set up, then the inode number
	 * will not match, so check for that, too.
	 */
	spin_lock(&ip->i_flags_lock);
	if (ip->i_ino != ino) {
		trace_scxfs_iget_skip(ip);
		SCXFS_STATS_INC(mp, xs_ig_frecycle);
		error = -EAGAIN;
		goto out_error;
	}


	/*
	 * If we are racing with another cache hit that is currently
	 * instantiating this inode or currently recycling it out of
	 * reclaimabe state, wait for the initialisation to complete
	 * before continuing.
	 *
	 * XXX(hch): eventually we should do something equivalent to
	 *	     wait_on_inode to wait for these flags to be cleared
	 *	     instead of polling for it.
	 */
	if (ip->i_flags & (SCXFS_INEW|SCXFS_IRECLAIM)) {
		trace_scxfs_iget_skip(ip);
		SCXFS_STATS_INC(mp, xs_ig_frecycle);
		error = -EAGAIN;
		goto out_error;
	}

	/*
	 * Check the inode free state is valid. This also detects lookup
	 * racing with unlinks.
	 */
	error = scxfs_iget_check_free_state(ip, flags);
	if (error)
		goto out_error;

	/*
	 * If IRECLAIMABLE is set, we've torn down the VFS inode already.
	 * Need to carefully get it back into useable state.
	 */
	if (ip->i_flags & SCXFS_IRECLAIMABLE) {
		trace_scxfs_iget_reclaim(ip);

		if (flags & SCXFS_IGET_INCORE) {
			error = -EAGAIN;
			goto out_error;
		}

		/*
		 * We need to set SCXFS_IRECLAIM to prevent scxfs_reclaim_inode
		 * from stomping over us while we recycle the inode.  We can't
		 * clear the radix tree reclaimable tag yet as it requires
		 * pag_ici_lock to be held exclusive.
		 */
		ip->i_flags |= SCXFS_IRECLAIM;

		spin_unlock(&ip->i_flags_lock);
		rcu_read_unlock();

		error = scxfs_reinit_inode(mp, inode);
		if (error) {
			bool wake;
			/*
			 * Re-initializing the inode failed, and we are in deep
			 * trouble.  Try to re-add it to the reclaim list.
			 */
			rcu_read_lock();
			spin_lock(&ip->i_flags_lock);
			wake = !!__scxfs_iflags_test(ip, SCXFS_INEW);
			ip->i_flags &= ~(SCXFS_INEW | SCXFS_IRECLAIM);
			if (wake)
				wake_up_bit(&ip->i_flags, __SCXFS_INEW_BIT);
			ASSERT(ip->i_flags & SCXFS_IRECLAIMABLE);
			trace_scxfs_iget_reclaim_fail(ip);
			goto out_error;
		}

		spin_lock(&pag->pag_ici_lock);
		spin_lock(&ip->i_flags_lock);

		/*
		 * Clear the per-lifetime state in the inode as we are now
		 * effectively a new inode and need to return to the initial
		 * state before reuse occurs.
		 */
		ip->i_flags &= ~SCXFS_IRECLAIM_RESET_FLAGS;
		ip->i_flags |= SCXFS_INEW;
		scxfs_inode_clear_reclaim_tag(pag, ip->i_ino);
		inode->i_state = I_NEW;
		ip->i_sick = 0;
		ip->i_checked = 0;

		ASSERT(!rwsem_is_locked(&inode->i_rwsem));
		init_rwsem(&inode->i_rwsem);

		spin_unlock(&ip->i_flags_lock);
		spin_unlock(&pag->pag_ici_lock);
	} else {
		/* If the VFS inode is being torn down, pause and try again. */
		if (!igrab(inode)) {
			trace_scxfs_iget_skip(ip);
			error = -EAGAIN;
			goto out_error;
		}

		/* We've got a live one. */
		spin_unlock(&ip->i_flags_lock);
		rcu_read_unlock();
		trace_scxfs_iget_hit(ip);
	}

	if (lock_flags != 0)
		scxfs_ilock(ip, lock_flags);

	if (!(flags & SCXFS_IGET_INCORE))
		scxfs_iflags_clear(ip, SCXFS_ISTALE | SCXFS_IDONTCACHE);
	SCXFS_STATS_INC(mp, xs_ig_found);

	return 0;

out_error:
	spin_unlock(&ip->i_flags_lock);
	rcu_read_unlock();
	return error;
}


static int
scxfs_iget_cache_miss(
	struct scxfs_mount	*mp,
	struct scxfs_perag	*pag,
	scxfs_trans_t		*tp,
	scxfs_ino_t		ino,
	struct scxfs_inode	**ipp,
	int			flags,
	int			lock_flags)
{
	struct scxfs_inode	*ip;
	int			error;
	scxfs_agino_t		agino = SCXFS_INO_TO_AGINO(mp, ino);
	int			iflags;

	ip = scxfs_inode_alloc(mp, ino);
	if (!ip)
		return -ENOMEM;

	error = scxfs_iread(mp, tp, ip, flags);
	if (error)
		goto out_destroy;

	if (!scxfs_inode_verify_forks(ip)) {
		error = -EFSCORRUPTED;
		goto out_destroy;
	}

	trace_scxfs_iget_miss(ip);


	/*
	 * Check the inode free state is valid. This also detects lookup
	 * racing with unlinks.
	 */
	error = scxfs_iget_check_free_state(ip, flags);
	if (error)
		goto out_destroy;

	/*
	 * Preload the radix tree so we can insert safely under the
	 * write spinlock. Note that we cannot sleep inside the preload
	 * region. Since we can be called from transaction context, don't
	 * recurse into the file system.
	 */
	if (radix_tree_preload(GFP_NOFS)) {
		error = -EAGAIN;
		goto out_destroy;
	}

	/*
	 * Because the inode hasn't been added to the radix-tree yet it can't
	 * be found by another thread, so we can do the non-sleeping lock here.
	 */
	if (lock_flags) {
		if (!scxfs_ilock_nowait(ip, lock_flags))
			BUG();
	}

	/*
	 * These values must be set before inserting the inode into the radix
	 * tree as the moment it is inserted a concurrent lookup (allowed by the
	 * RCU locking mechanism) can find it and that lookup must see that this
	 * is an inode currently under construction (i.e. that SCXFS_INEW is set).
	 * The ip->i_flags_lock that protects the SCXFS_INEW flag forms the
	 * memory barrier that ensures this detection works correctly at lookup
	 * time.
	 */
	iflags = SCXFS_INEW;
	if (flags & SCXFS_IGET_DONTCACHE)
		iflags |= SCXFS_IDONTCACHE;
	ip->i_udquot = NULL;
	ip->i_gdquot = NULL;
	ip->i_pdquot = NULL;
	scxfs_iflags_set(ip, iflags);

	/* insert the new inode */
	spin_lock(&pag->pag_ici_lock);
	error = radix_tree_insert(&pag->pag_ici_root, agino, ip);
	if (unlikely(error)) {
		WARN_ON(error != -EEXIST);
		SCXFS_STATS_INC(mp, xs_ig_dup);
		error = -EAGAIN;
		goto out_preload_end;
	}
	spin_unlock(&pag->pag_ici_lock);
	radix_tree_preload_end();

	*ipp = ip;
	return 0;

out_preload_end:
	spin_unlock(&pag->pag_ici_lock);
	radix_tree_preload_end();
	if (lock_flags)
		scxfs_iunlock(ip, lock_flags);
out_destroy:
	__destroy_inode(VFS_I(ip));
	scxfs_inode_free(ip);
	return error;
}

/*
 * Look up an inode by number in the given file system.
 * The inode is looked up in the cache held in each AG.
 * If the inode is found in the cache, initialise the vfs inode
 * if necessary.
 *
 * If it is not in core, read it in from the file system's device,
 * add it to the cache and initialise the vfs inode.
 *
 * The inode is locked according to the value of the lock_flags parameter.
 * This flag parameter indicates how and if the inode's IO lock and inode lock
 * should be taken.
 *
 * mp -- the mount point structure for the current file system.  It points
 *       to the inode hash table.
 * tp -- a pointer to the current transaction if there is one.  This is
 *       simply passed through to the scxfs_iread() call.
 * ino -- the number of the inode desired.  This is the unique identifier
 *        within the file system for the inode being requested.
 * lock_flags -- flags indicating how to lock the inode.  See the comment
 *		 for scxfs_ilock() for a list of valid values.
 */
int
scxfs_iget(
	scxfs_mount_t	*mp,
	scxfs_trans_t	*tp,
	scxfs_ino_t	ino,
	uint		flags,
	uint		lock_flags,
	scxfs_inode_t	**ipp)
{
	scxfs_inode_t	*ip;
	int		error;
	scxfs_perag_t	*pag;
	scxfs_agino_t	agino;

	/*
	 * scxfs_reclaim_inode() uses the ILOCK to ensure an inode
	 * doesn't get freed while it's being referenced during a
	 * radix tree traversal here.  It assumes this function
	 * aqcuires only the ILOCK (and therefore it has no need to
	 * involve the IOLOCK in this synchronization).
	 */
	ASSERT((lock_flags & (SCXFS_IOLOCK_EXCL | SCXFS_IOLOCK_SHARED)) == 0);

	/* reject inode numbers outside existing AGs */
	if (!ino || SCXFS_INO_TO_AGNO(mp, ino) >= mp->m_sb.sb_agcount)
		return -EINVAL;

	SCXFS_STATS_INC(mp, xs_ig_attempts);

	/* get the perag structure and ensure that it's inode capable */
	pag = scxfs_perag_get(mp, SCXFS_INO_TO_AGNO(mp, ino));
	agino = SCXFS_INO_TO_AGINO(mp, ino);

again:
	error = 0;
	rcu_read_lock();
	ip = radix_tree_lookup(&pag->pag_ici_root, agino);

	if (ip) {
		error = scxfs_iget_cache_hit(pag, ip, ino, flags, lock_flags);
		if (error)
			goto out_error_or_again;
	} else {
		rcu_read_unlock();
		if (flags & SCXFS_IGET_INCORE) {
			error = -ENODATA;
			goto out_error_or_again;
		}
		SCXFS_STATS_INC(mp, xs_ig_missed);

		error = scxfs_iget_cache_miss(mp, pag, tp, ino, &ip,
							flags, lock_flags);
		if (error)
			goto out_error_or_again;
	}
	scxfs_perag_put(pag);

	*ipp = ip;

	/*
	 * If we have a real type for an on-disk inode, we can setup the inode
	 * now.	 If it's a new inode being created, scxfs_ialloc will handle it.
	 */
	if (scxfs_iflags_test(ip, SCXFS_INEW) && VFS_I(ip)->i_mode != 0)
		scxfs_setup_existing_inode(ip);
	return 0;

out_error_or_again:
	if (!(flags & SCXFS_IGET_INCORE) && error == -EAGAIN) {
		delay(1);
		goto again;
	}
	scxfs_perag_put(pag);
	return error;
}

/*
 * "Is this a cached inode that's also allocated?"
 *
 * Look up an inode by number in the given file system.  If the inode is
 * in cache and isn't in purgatory, return 1 if the inode is allocated
 * and 0 if it is not.  For all other cases (not in cache, being torn
 * down, etc.), return a negative error code.
 *
 * The caller has to prevent inode allocation and freeing activity,
 * presumably by locking the AGI buffer.   This is to ensure that an
 * inode cannot transition from allocated to freed until the caller is
 * ready to allow that.  If the inode is in an intermediate state (new,
 * reclaimable, or being reclaimed), -EAGAIN will be returned; if the
 * inode is not in the cache, -ENOENT will be returned.  The caller must
 * deal with these scenarios appropriately.
 *
 * This is a specialized use case for the online scrubber; if you're
 * reading this, you probably want scxfs_iget.
 */
int
scxfs_icache_inode_is_allocated(
	struct scxfs_mount	*mp,
	struct scxfs_trans	*tp,
	scxfs_ino_t		ino,
	bool			*inuse)
{
	struct scxfs_inode	*ip;
	int			error;

	error = scxfs_iget(mp, tp, ino, SCXFS_IGET_INCORE, 0, &ip);
	if (error)
		return error;

	*inuse = !!(VFS_I(ip)->i_mode);
	scxfs_irele(ip);
	return 0;
}

/*
 * The inode lookup is done in batches to keep the amount of lock traffic and
 * radix tree lookups to a minimum. The batch size is a trade off between
 * lookup reduction and stack usage. This is in the reclaim path, so we can't
 * be too greedy.
 */
#define SCXFS_LOOKUP_BATCH	32

STATIC int
scxfs_inode_ag_walk_grab(
	struct scxfs_inode	*ip,
	int			flags)
{
	struct inode		*inode = VFS_I(ip);
	bool			newinos = !!(flags & SCXFS_AGITER_INEW_WAIT);

	ASSERT(rcu_read_lock_held());

	/*
	 * check for stale RCU freed inode
	 *
	 * If the inode has been reallocated, it doesn't matter if it's not in
	 * the AG we are walking - we are walking for writeback, so if it
	 * passes all the "valid inode" checks and is dirty, then we'll write
	 * it back anyway.  If it has been reallocated and still being
	 * initialised, the SCXFS_INEW check below will catch it.
	 */
	spin_lock(&ip->i_flags_lock);
	if (!ip->i_ino)
		goto out_unlock_noent;

	/* avoid new or reclaimable inodes. Leave for reclaim code to flush */
	if ((!newinos && __scxfs_iflags_test(ip, SCXFS_INEW)) ||
	    __scxfs_iflags_test(ip, SCXFS_IRECLAIMABLE | SCXFS_IRECLAIM))
		goto out_unlock_noent;
	spin_unlock(&ip->i_flags_lock);

	/* nothing to sync during shutdown */
	if (SCXFS_FORCED_SHUTDOWN(ip->i_mount))
		return -EFSCORRUPTED;

	/* If we can't grab the inode, it must on it's way to reclaim. */
	if (!igrab(inode))
		return -ENOENT;

	/* inode is valid */
	return 0;

out_unlock_noent:
	spin_unlock(&ip->i_flags_lock);
	return -ENOENT;
}

STATIC int
scxfs_inode_ag_walk(
	struct scxfs_mount	*mp,
	struct scxfs_perag	*pag,
	int			(*execute)(struct scxfs_inode *ip, int flags,
					   void *args),
	int			flags,
	void			*args,
	int			tag,
	int			iter_flags)
{
	uint32_t		first_index;
	int			last_error = 0;
	int			skipped;
	int			done;
	int			nr_found;

restart:
	done = 0;
	skipped = 0;
	first_index = 0;
	nr_found = 0;
	do {
		struct scxfs_inode *batch[SCXFS_LOOKUP_BATCH];
		int		error = 0;
		int		i;

		rcu_read_lock();

		if (tag == -1)
			nr_found = radix_tree_gang_lookup(&pag->pag_ici_root,
					(void **)batch, first_index,
					SCXFS_LOOKUP_BATCH);
		else
			nr_found = radix_tree_gang_lookup_tag(
					&pag->pag_ici_root,
					(void **) batch, first_index,
					SCXFS_LOOKUP_BATCH, tag);

		if (!nr_found) {
			rcu_read_unlock();
			break;
		}

		/*
		 * Grab the inodes before we drop the lock. if we found
		 * nothing, nr == 0 and the loop will be skipped.
		 */
		for (i = 0; i < nr_found; i++) {
			struct scxfs_inode *ip = batch[i];

			if (done || scxfs_inode_ag_walk_grab(ip, iter_flags))
				batch[i] = NULL;

			/*
			 * Update the index for the next lookup. Catch
			 * overflows into the next AG range which can occur if
			 * we have inodes in the last block of the AG and we
			 * are currently pointing to the last inode.
			 *
			 * Because we may see inodes that are from the wrong AG
			 * due to RCU freeing and reallocation, only update the
			 * index if it lies in this AG. It was a race that lead
			 * us to see this inode, so another lookup from the
			 * same index will not find it again.
			 */
			if (SCXFS_INO_TO_AGNO(mp, ip->i_ino) != pag->pag_agno)
				continue;
			first_index = SCXFS_INO_TO_AGINO(mp, ip->i_ino + 1);
			if (first_index < SCXFS_INO_TO_AGINO(mp, ip->i_ino))
				done = 1;
		}

		/* unlock now we've grabbed the inodes. */
		rcu_read_unlock();

		for (i = 0; i < nr_found; i++) {
			if (!batch[i])
				continue;
			if ((iter_flags & SCXFS_AGITER_INEW_WAIT) &&
			    scxfs_iflags_test(batch[i], SCXFS_INEW))
				scxfs_inew_wait(batch[i]);
			error = execute(batch[i], flags, args);
			scxfs_irele(batch[i]);
			if (error == -EAGAIN) {
				skipped++;
				continue;
			}
			if (error && last_error != -EFSCORRUPTED)
				last_error = error;
		}

		/* bail out if the filesystem is corrupted.  */
		if (error == -EFSCORRUPTED)
			break;

		cond_resched();

	} while (nr_found && !done);

	if (skipped) {
		delay(1);
		goto restart;
	}
	return last_error;
}

/*
 * Background scanning to trim post-EOF preallocated space. This is queued
 * based on the 'speculative_prealloc_lifetime' tunable (5m by default).
 */
void
scxfs_queue_eofblocks(
	struct scxfs_mount *mp)
{
	rcu_read_lock();
	if (radix_tree_tagged(&mp->m_perag_tree, SCXFS_ICI_EOFBLOCKS_TAG))
		queue_delayed_work(mp->m_eofblocks_workqueue,
				   &mp->m_eofblocks_work,
				   msecs_to_jiffies(scxfs_eofb_secs * 1000));
	rcu_read_unlock();
}

void
scxfs_eofblocks_worker(
	struct work_struct *work)
{
	struct scxfs_mount *mp = container_of(to_delayed_work(work),
				struct scxfs_mount, m_eofblocks_work);

	if (!sb_start_write_trylock(mp->m_super))
		return;
	scxfs_icache_free_eofblocks(mp, NULL);
	sb_end_write(mp->m_super);

	scxfs_queue_eofblocks(mp);
}

/*
 * Background scanning to trim preallocated CoW space. This is queued
 * based on the 'speculative_cow_prealloc_lifetime' tunable (5m by default).
 * (We'll just piggyback on the post-EOF prealloc space workqueue.)
 */
void
scxfs_queue_cowblocks(
	struct scxfs_mount *mp)
{
	rcu_read_lock();
	if (radix_tree_tagged(&mp->m_perag_tree, SCXFS_ICI_COWBLOCKS_TAG))
		queue_delayed_work(mp->m_eofblocks_workqueue,
				   &mp->m_cowblocks_work,
				   msecs_to_jiffies(scxfs_cowb_secs * 1000));
	rcu_read_unlock();
}

void
scxfs_cowblocks_worker(
	struct work_struct *work)
{
	struct scxfs_mount *mp = container_of(to_delayed_work(work),
				struct scxfs_mount, m_cowblocks_work);

	if (!sb_start_write_trylock(mp->m_super))
		return;
	scxfs_icache_free_cowblocks(mp, NULL);
	sb_end_write(mp->m_super);

	scxfs_queue_cowblocks(mp);
}

int
scxfs_inode_ag_iterator_flags(
	struct scxfs_mount	*mp,
	int			(*execute)(struct scxfs_inode *ip, int flags,
					   void *args),
	int			flags,
	void			*args,
	int			iter_flags)
{
	struct scxfs_perag	*pag;
	int			error = 0;
	int			last_error = 0;
	scxfs_agnumber_t		ag;

	ag = 0;
	while ((pag = scxfs_perag_get(mp, ag))) {
		ag = pag->pag_agno + 1;
		error = scxfs_inode_ag_walk(mp, pag, execute, flags, args, -1,
					  iter_flags);
		scxfs_perag_put(pag);
		if (error) {
			last_error = error;
			if (error == -EFSCORRUPTED)
				break;
		}
	}
	return last_error;
}

int
scxfs_inode_ag_iterator(
	struct scxfs_mount	*mp,
	int			(*execute)(struct scxfs_inode *ip, int flags,
					   void *args),
	int			flags,
	void			*args)
{
	return scxfs_inode_ag_iterator_flags(mp, execute, flags, args, 0);
}

int
scxfs_inode_ag_iterator_tag(
	struct scxfs_mount	*mp,
	int			(*execute)(struct scxfs_inode *ip, int flags,
					   void *args),
	int			flags,
	void			*args,
	int			tag)
{
	struct scxfs_perag	*pag;
	int			error = 0;
	int			last_error = 0;
	scxfs_agnumber_t		ag;

	ag = 0;
	while ((pag = scxfs_perag_get_tag(mp, ag, tag))) {
		ag = pag->pag_agno + 1;
		error = scxfs_inode_ag_walk(mp, pag, execute, flags, args, tag,
					  0);
		scxfs_perag_put(pag);
		if (error) {
			last_error = error;
			if (error == -EFSCORRUPTED)
				break;
		}
	}
	return last_error;
}

/*
 * Grab the inode for reclaim exclusively.
 * Return 0 if we grabbed it, non-zero otherwise.
 */
STATIC int
scxfs_reclaim_inode_grab(
	struct scxfs_inode	*ip,
	int			flags)
{
	ASSERT(rcu_read_lock_held());

	/* quick check for stale RCU freed inode */
	if (!ip->i_ino)
		return 1;

	/*
	 * If we are asked for non-blocking operation, do unlocked checks to
	 * see if the inode already is being flushed or in reclaim to avoid
	 * lock traffic.
	 */
	if ((flags & SYNC_TRYLOCK) &&
	    __scxfs_iflags_test(ip, SCXFS_IFLOCK | SCXFS_IRECLAIM))
		return 1;

	/*
	 * The radix tree lock here protects a thread in scxfs_iget from racing
	 * with us starting reclaim on the inode.  Once we have the
	 * SCXFS_IRECLAIM flag set it will not touch us.
	 *
	 * Due to RCU lookup, we may find inodes that have been freed and only
	 * have SCXFS_IRECLAIM set.  Indeed, we may see reallocated inodes that
	 * aren't candidates for reclaim at all, so we must check the
	 * SCXFS_IRECLAIMABLE is set first before proceeding to reclaim.
	 */
	spin_lock(&ip->i_flags_lock);
	if (!__scxfs_iflags_test(ip, SCXFS_IRECLAIMABLE) ||
	    __scxfs_iflags_test(ip, SCXFS_IRECLAIM)) {
		/* not a reclaim candidate. */
		spin_unlock(&ip->i_flags_lock);
		return 1;
	}
	__scxfs_iflags_set(ip, SCXFS_IRECLAIM);
	spin_unlock(&ip->i_flags_lock);
	return 0;
}

/*
 * Inodes in different states need to be treated differently. The following
 * table lists the inode states and the reclaim actions necessary:
 *
 *	inode state	     iflush ret		required action
 *      ---------------      ----------         ---------------
 *	bad			-		reclaim
 *	shutdown		EIO		unpin and reclaim
 *	clean, unpinned		0		reclaim
 *	stale, unpinned		0		reclaim
 *	clean, pinned(*)	0		requeue
 *	stale, pinned		EAGAIN		requeue
 *	dirty, async		-		requeue
 *	dirty, sync		0		reclaim
 *
 * (*) dgc: I don't think the clean, pinned state is possible but it gets
 * handled anyway given the order of checks implemented.
 *
 * Also, because we get the flush lock first, we know that any inode that has
 * been flushed delwri has had the flush completed by the time we check that
 * the inode is clean.
 *
 * Note that because the inode is flushed delayed write by AIL pushing, the
 * flush lock may already be held here and waiting on it can result in very
 * long latencies.  Hence for sync reclaims, where we wait on the flush lock,
 * the caller should push the AIL first before trying to reclaim inodes to
 * minimise the amount of time spent waiting.  For background relaim, we only
 * bother to reclaim clean inodes anyway.
 *
 * Hence the order of actions after gaining the locks should be:
 *	bad		=> reclaim
 *	shutdown	=> unpin and reclaim
 *	pinned, async	=> requeue
 *	pinned, sync	=> unpin
 *	stale		=> reclaim
 *	clean		=> reclaim
 *	dirty, async	=> requeue
 *	dirty, sync	=> flush, wait and reclaim
 */
STATIC int
scxfs_reclaim_inode(
	struct scxfs_inode	*ip,
	struct scxfs_perag	*pag,
	int			sync_mode)
{
	struct scxfs_buf		*bp = NULL;
	scxfs_ino_t		ino = ip->i_ino; /* for radix_tree_delete */
	int			error;

restart:
	error = 0;
	scxfs_ilock(ip, SCXFS_ILOCK_EXCL);
	if (!scxfs_iflock_nowait(ip)) {
		if (!(sync_mode & SYNC_WAIT))
			goto out;
		scxfs_iflock(ip);
	}

	if (SCXFS_FORCED_SHUTDOWN(ip->i_mount)) {
		scxfs_iunpin_wait(ip);
		/* scxfs_iflush_abort() drops the flush lock */
		scxfs_iflush_abort(ip, false);
		goto reclaim;
	}
	if (scxfs_ipincount(ip)) {
		if (!(sync_mode & SYNC_WAIT))
			goto out_ifunlock;
		scxfs_iunpin_wait(ip);
	}
	if (scxfs_inode_clean(ip)) {
		scxfs_ifunlock(ip);
		goto reclaim;
	}

	/*
	 * Never flush out dirty data during non-blocking reclaim, as it would
	 * just contend with AIL pushing trying to do the same job.
	 */
	if (!(sync_mode & SYNC_WAIT))
		goto out_ifunlock;

	/*
	 * Now we have an inode that needs flushing.
	 *
	 * Note that scxfs_iflush will never block on the inode buffer lock, as
	 * scxfs_ifree_cluster() can lock the inode buffer before it locks the
	 * ip->i_lock, and we are doing the exact opposite here.  As a result,
	 * doing a blocking scxfs_imap_to_bp() to get the cluster buffer would
	 * result in an ABBA deadlock with scxfs_ifree_cluster().
	 *
	 * As scxfs_ifree_cluser() must gather all inodes that are active in the
	 * cache to mark them stale, if we hit this case we don't actually want
	 * to do IO here - we want the inode marked stale so we can simply
	 * reclaim it.  Hence if we get an EAGAIN error here,  just unlock the
	 * inode, back off and try again.  Hopefully the next pass through will
	 * see the stale flag set on the inode.
	 */
	error = scxfs_iflush(ip, &bp);
	if (error == -EAGAIN) {
		scxfs_iunlock(ip, SCXFS_ILOCK_EXCL);
		/* backoff longer than in scxfs_ifree_cluster */
		delay(2);
		goto restart;
	}

	if (!error) {
		error = scxfs_bwrite(bp);
		scxfs_buf_relse(bp);
	}

reclaim:
	ASSERT(!scxfs_isiflocked(ip));

	/*
	 * Because we use RCU freeing we need to ensure the inode always appears
	 * to be reclaimed with an invalid inode number when in the free state.
	 * We do this as early as possible under the ILOCK so that
	 * scxfs_iflush_cluster() and scxfs_ifree_cluster() can be guaranteed to
	 * detect races with us here. By doing this, we guarantee that once
	 * scxfs_iflush_cluster() or scxfs_ifree_cluster() has locked SCXFS_ILOCK that
	 * it will see either a valid inode that will serialise correctly, or it
	 * will see an invalid inode that it can skip.
	 */
	spin_lock(&ip->i_flags_lock);
	ip->i_flags = SCXFS_IRECLAIM;
	ip->i_ino = 0;
	spin_unlock(&ip->i_flags_lock);

	scxfs_iunlock(ip, SCXFS_ILOCK_EXCL);

	SCXFS_STATS_INC(ip->i_mount, xs_ig_reclaims);
	/*
	 * Remove the inode from the per-AG radix tree.
	 *
	 * Because radix_tree_delete won't complain even if the item was never
	 * added to the tree assert that it's been there before to catch
	 * problems with the inode life time early on.
	 */
	spin_lock(&pag->pag_ici_lock);
	if (!radix_tree_delete(&pag->pag_ici_root,
				SCXFS_INO_TO_AGINO(ip->i_mount, ino)))
		ASSERT(0);
	scxfs_perag_clear_reclaim_tag(pag);
	spin_unlock(&pag->pag_ici_lock);

	/*
	 * Here we do an (almost) spurious inode lock in order to coordinate
	 * with inode cache radix tree lookups.  This is because the lookup
	 * can reference the inodes in the cache without taking references.
	 *
	 * We make that OK here by ensuring that we wait until the inode is
	 * unlocked after the lookup before we go ahead and free it.
	 */
	scxfs_ilock(ip, SCXFS_ILOCK_EXCL);
	scxfs_qm_dqdetach(ip);
	scxfs_iunlock(ip, SCXFS_ILOCK_EXCL);
	ASSERT(scxfs_inode_clean(ip));

	__scxfs_inode_free(ip);
	return error;

out_ifunlock:
	scxfs_ifunlock(ip);
out:
	scxfs_iflags_clear(ip, SCXFS_IRECLAIM);
	scxfs_iunlock(ip, SCXFS_ILOCK_EXCL);
	/*
	 * We could return -EAGAIN here to make reclaim rescan the inode tree in
	 * a short while. However, this just burns CPU time scanning the tree
	 * waiting for IO to complete and the reclaim work never goes back to
	 * the idle state. Instead, return 0 to let the next scheduled
	 * background reclaim attempt to reclaim the inode again.
	 */
	return 0;
}

/*
 * Walk the AGs and reclaim the inodes in them. Even if the filesystem is
 * corrupted, we still want to try to reclaim all the inodes. If we don't,
 * then a shut down during filesystem unmount reclaim walk leak all the
 * unreclaimed inodes.
 */
STATIC int
scxfs_reclaim_inodes_ag(
	struct scxfs_mount	*mp,
	int			flags,
	int			*nr_to_scan)
{
	struct scxfs_perag	*pag;
	int			error = 0;
	int			last_error = 0;
	scxfs_agnumber_t		ag;
	int			trylock = flags & SYNC_TRYLOCK;
	int			skipped;

restart:
	ag = 0;
	skipped = 0;
	while ((pag = scxfs_perag_get_tag(mp, ag, SCXFS_ICI_RECLAIM_TAG))) {
		unsigned long	first_index = 0;
		int		done = 0;
		int		nr_found = 0;

		ag = pag->pag_agno + 1;

		if (trylock) {
			if (!mutex_trylock(&pag->pag_ici_reclaim_lock)) {
				skipped++;
				scxfs_perag_put(pag);
				continue;
			}
			first_index = pag->pag_ici_reclaim_cursor;
		} else
			mutex_lock(&pag->pag_ici_reclaim_lock);

		do {
			struct scxfs_inode *batch[SCXFS_LOOKUP_BATCH];
			int	i;

			rcu_read_lock();
			nr_found = radix_tree_gang_lookup_tag(
					&pag->pag_ici_root,
					(void **)batch, first_index,
					SCXFS_LOOKUP_BATCH,
					SCXFS_ICI_RECLAIM_TAG);
			if (!nr_found) {
				done = 1;
				rcu_read_unlock();
				break;
			}

			/*
			 * Grab the inodes before we drop the lock. if we found
			 * nothing, nr == 0 and the loop will be skipped.
			 */
			for (i = 0; i < nr_found; i++) {
				struct scxfs_inode *ip = batch[i];

				if (done || scxfs_reclaim_inode_grab(ip, flags))
					batch[i] = NULL;

				/*
				 * Update the index for the next lookup. Catch
				 * overflows into the next AG range which can
				 * occur if we have inodes in the last block of
				 * the AG and we are currently pointing to the
				 * last inode.
				 *
				 * Because we may see inodes that are from the
				 * wrong AG due to RCU freeing and
				 * reallocation, only update the index if it
				 * lies in this AG. It was a race that lead us
				 * to see this inode, so another lookup from
				 * the same index will not find it again.
				 */
				if (SCXFS_INO_TO_AGNO(mp, ip->i_ino) !=
								pag->pag_agno)
					continue;
				first_index = SCXFS_INO_TO_AGINO(mp, ip->i_ino + 1);
				if (first_index < SCXFS_INO_TO_AGINO(mp, ip->i_ino))
					done = 1;
			}

			/* unlock now we've grabbed the inodes. */
			rcu_read_unlock();

			for (i = 0; i < nr_found; i++) {
				if (!batch[i])
					continue;
				error = scxfs_reclaim_inode(batch[i], pag, flags);
				if (error && last_error != -EFSCORRUPTED)
					last_error = error;
			}

			*nr_to_scan -= SCXFS_LOOKUP_BATCH;

			cond_resched();

		} while (nr_found && !done && *nr_to_scan > 0);

		if (trylock && !done)
			pag->pag_ici_reclaim_cursor = first_index;
		else
			pag->pag_ici_reclaim_cursor = 0;
		mutex_unlock(&pag->pag_ici_reclaim_lock);
		scxfs_perag_put(pag);
	}

	/*
	 * if we skipped any AG, and we still have scan count remaining, do
	 * another pass this time using blocking reclaim semantics (i.e
	 * waiting on the reclaim locks and ignoring the reclaim cursors). This
	 * ensure that when we get more reclaimers than AGs we block rather
	 * than spin trying to execute reclaim.
	 */
	if (skipped && (flags & SYNC_WAIT) && *nr_to_scan > 0) {
		trylock = 0;
		goto restart;
	}
	return last_error;
}

int
scxfs_reclaim_inodes(
	scxfs_mount_t	*mp,
	int		mode)
{
	int		nr_to_scan = INT_MAX;

	return scxfs_reclaim_inodes_ag(mp, mode, &nr_to_scan);
}

/*
 * Scan a certain number of inodes for reclaim.
 *
 * When called we make sure that there is a background (fast) inode reclaim in
 * progress, while we will throttle the speed of reclaim via doing synchronous
 * reclaim of inodes. That means if we come across dirty inodes, we wait for
 * them to be cleaned, which we hope will not be very long due to the
 * background walker having already kicked the IO off on those dirty inodes.
 */
long
scxfs_reclaim_inodes_nr(
	struct scxfs_mount	*mp,
	int			nr_to_scan)
{
	/* kick background reclaimer and push the AIL */
	scxfs_reclaim_work_queue(mp);
	scxfs_ail_push_all(mp->m_ail);

	return scxfs_reclaim_inodes_ag(mp, SYNC_TRYLOCK | SYNC_WAIT, &nr_to_scan);
}

/*
 * Return the number of reclaimable inodes in the filesystem for
 * the shrinker to determine how much to reclaim.
 */
int
scxfs_reclaim_inodes_count(
	struct scxfs_mount	*mp)
{
	struct scxfs_perag	*pag;
	scxfs_agnumber_t		ag = 0;
	int			reclaimable = 0;

	while ((pag = scxfs_perag_get_tag(mp, ag, SCXFS_ICI_RECLAIM_TAG))) {
		ag = pag->pag_agno + 1;
		reclaimable += pag->pag_ici_reclaimable;
		scxfs_perag_put(pag);
	}
	return reclaimable;
}

STATIC int
scxfs_inode_match_id(
	struct scxfs_inode	*ip,
	struct scxfs_eofblocks	*eofb)
{
	if ((eofb->eof_flags & SCXFS_EOF_FLAGS_UID) &&
	    !uid_eq(VFS_I(ip)->i_uid, eofb->eof_uid))
		return 0;

	if ((eofb->eof_flags & SCXFS_EOF_FLAGS_GID) &&
	    !gid_eq(VFS_I(ip)->i_gid, eofb->eof_gid))
		return 0;

	if ((eofb->eof_flags & SCXFS_EOF_FLAGS_PRID) &&
	    scxfs_get_projid(ip) != eofb->eof_prid)
		return 0;

	return 1;
}

/*
 * A union-based inode filtering algorithm. Process the inode if any of the
 * criteria match. This is for global/internal scans only.
 */
STATIC int
scxfs_inode_match_id_union(
	struct scxfs_inode	*ip,
	struct scxfs_eofblocks	*eofb)
{
	if ((eofb->eof_flags & SCXFS_EOF_FLAGS_UID) &&
	    uid_eq(VFS_I(ip)->i_uid, eofb->eof_uid))
		return 1;

	if ((eofb->eof_flags & SCXFS_EOF_FLAGS_GID) &&
	    gid_eq(VFS_I(ip)->i_gid, eofb->eof_gid))
		return 1;

	if ((eofb->eof_flags & SCXFS_EOF_FLAGS_PRID) &&
	    scxfs_get_projid(ip) == eofb->eof_prid)
		return 1;

	return 0;
}

STATIC int
scxfs_inode_free_eofblocks(
	struct scxfs_inode	*ip,
	int			flags,
	void			*args)
{
	int ret = 0;
	struct scxfs_eofblocks *eofb = args;
	int match;

	if (!scxfs_can_free_eofblocks(ip, false)) {
		/* inode could be preallocated or append-only */
		trace_scxfs_inode_free_eofblocks_invalid(ip);
		scxfs_inode_clear_eofblocks_tag(ip);
		return 0;
	}

	/*
	 * If the mapping is dirty the operation can block and wait for some
	 * time. Unless we are waiting, skip it.
	 */
	if (!(flags & SYNC_WAIT) &&
	    mapping_tagged(VFS_I(ip)->i_mapping, PAGECACHE_TAG_DIRTY))
		return 0;

	if (eofb) {
		if (eofb->eof_flags & SCXFS_EOF_FLAGS_UNION)
			match = scxfs_inode_match_id_union(ip, eofb);
		else
			match = scxfs_inode_match_id(ip, eofb);
		if (!match)
			return 0;

		/* skip the inode if the file size is too small */
		if (eofb->eof_flags & SCXFS_EOF_FLAGS_MINFILESIZE &&
		    SCXFS_ISIZE(ip) < eofb->eof_min_file_size)
			return 0;
	}

	/*
	 * If the caller is waiting, return -EAGAIN to keep the background
	 * scanner moving and revisit the inode in a subsequent pass.
	 */
	if (!scxfs_ilock_nowait(ip, SCXFS_IOLOCK_EXCL)) {
		if (flags & SYNC_WAIT)
			ret = -EAGAIN;
		return ret;
	}
	ret = scxfs_free_eofblocks(ip);
	scxfs_iunlock(ip, SCXFS_IOLOCK_EXCL);

	return ret;
}

static int
__scxfs_icache_free_eofblocks(
	struct scxfs_mount	*mp,
	struct scxfs_eofblocks	*eofb,
	int			(*execute)(struct scxfs_inode *ip, int flags,
					   void *args),
	int			tag)
{
	int flags = SYNC_TRYLOCK;

	if (eofb && (eofb->eof_flags & SCXFS_EOF_FLAGS_SYNC))
		flags = SYNC_WAIT;

	return scxfs_inode_ag_iterator_tag(mp, execute, flags,
					 eofb, tag);
}

int
scxfs_icache_free_eofblocks(
	struct scxfs_mount	*mp,
	struct scxfs_eofblocks	*eofb)
{
	return __scxfs_icache_free_eofblocks(mp, eofb, scxfs_inode_free_eofblocks,
			SCXFS_ICI_EOFBLOCKS_TAG);
}

/*
 * Run eofblocks scans on the quotas applicable to the inode. For inodes with
 * multiple quotas, we don't know exactly which quota caused an allocation
 * failure. We make a best effort by including each quota under low free space
 * conditions (less than 1% free space) in the scan.
 */
static int
__scxfs_inode_free_quota_eofblocks(
	struct scxfs_inode	*ip,
	int			(*execute)(struct scxfs_mount *mp,
					   struct scxfs_eofblocks	*eofb))
{
	int scan = 0;
	struct scxfs_eofblocks eofb = {0};
	struct scxfs_dquot *dq;

	/*
	 * Run a sync scan to increase effectiveness and use the union filter to
	 * cover all applicable quotas in a single scan.
	 */
	eofb.eof_flags = SCXFS_EOF_FLAGS_UNION|SCXFS_EOF_FLAGS_SYNC;

	if (SCXFS_IS_UQUOTA_ENFORCED(ip->i_mount)) {
		dq = scxfs_inode_dquot(ip, SCXFS_DQ_USER);
		if (dq && scxfs_dquot_lowsp(dq)) {
			eofb.eof_uid = VFS_I(ip)->i_uid;
			eofb.eof_flags |= SCXFS_EOF_FLAGS_UID;
			scan = 1;
		}
	}

	if (SCXFS_IS_GQUOTA_ENFORCED(ip->i_mount)) {
		dq = scxfs_inode_dquot(ip, SCXFS_DQ_GROUP);
		if (dq && scxfs_dquot_lowsp(dq)) {
			eofb.eof_gid = VFS_I(ip)->i_gid;
			eofb.eof_flags |= SCXFS_EOF_FLAGS_GID;
			scan = 1;
		}
	}

	if (scan)
		execute(ip->i_mount, &eofb);

	return scan;
}

int
scxfs_inode_free_quota_eofblocks(
	struct scxfs_inode *ip)
{
	return __scxfs_inode_free_quota_eofblocks(ip, scxfs_icache_free_eofblocks);
}

static inline unsigned long
scxfs_iflag_for_tag(
	int		tag)
{
	switch (tag) {
	case SCXFS_ICI_EOFBLOCKS_TAG:
		return SCXFS_IEOFBLOCKS;
	case SCXFS_ICI_COWBLOCKS_TAG:
		return SCXFS_ICOWBLOCKS;
	default:
		ASSERT(0);
		return 0;
	}
}

static void
__scxfs_inode_set_blocks_tag(
	scxfs_inode_t	*ip,
	void		(*execute)(struct scxfs_mount *mp),
	void		(*set_tp)(struct scxfs_mount *mp, scxfs_agnumber_t agno,
				  int error, unsigned long caller_ip),
	int		tag)
{
	struct scxfs_mount *mp = ip->i_mount;
	struct scxfs_perag *pag;
	int tagged;

	/*
	 * Don't bother locking the AG and looking up in the radix trees
	 * if we already know that we have the tag set.
	 */
	if (ip->i_flags & scxfs_iflag_for_tag(tag))
		return;
	spin_lock(&ip->i_flags_lock);
	ip->i_flags |= scxfs_iflag_for_tag(tag);
	spin_unlock(&ip->i_flags_lock);

	pag = scxfs_perag_get(mp, SCXFS_INO_TO_AGNO(mp, ip->i_ino));
	spin_lock(&pag->pag_ici_lock);

	tagged = radix_tree_tagged(&pag->pag_ici_root, tag);
	radix_tree_tag_set(&pag->pag_ici_root,
			   SCXFS_INO_TO_AGINO(ip->i_mount, ip->i_ino), tag);
	if (!tagged) {
		/* propagate the eofblocks tag up into the perag radix tree */
		spin_lock(&ip->i_mount->m_perag_lock);
		radix_tree_tag_set(&ip->i_mount->m_perag_tree,
				   SCXFS_INO_TO_AGNO(ip->i_mount, ip->i_ino),
				   tag);
		spin_unlock(&ip->i_mount->m_perag_lock);

		/* kick off background trimming */
		execute(ip->i_mount);

		set_tp(ip->i_mount, pag->pag_agno, -1, _RET_IP_);
	}

	spin_unlock(&pag->pag_ici_lock);
	scxfs_perag_put(pag);
}

void
scxfs_inode_set_eofblocks_tag(
	scxfs_inode_t	*ip)
{
	trace_scxfs_inode_set_eofblocks_tag(ip);
	return __scxfs_inode_set_blocks_tag(ip, scxfs_queue_eofblocks,
			trace_scxfs_perag_set_eofblocks,
			SCXFS_ICI_EOFBLOCKS_TAG);
}

static void
__scxfs_inode_clear_blocks_tag(
	scxfs_inode_t	*ip,
	void		(*clear_tp)(struct scxfs_mount *mp, scxfs_agnumber_t agno,
				    int error, unsigned long caller_ip),
	int		tag)
{
	struct scxfs_mount *mp = ip->i_mount;
	struct scxfs_perag *pag;

	spin_lock(&ip->i_flags_lock);
	ip->i_flags &= ~scxfs_iflag_for_tag(tag);
	spin_unlock(&ip->i_flags_lock);

	pag = scxfs_perag_get(mp, SCXFS_INO_TO_AGNO(mp, ip->i_ino));
	spin_lock(&pag->pag_ici_lock);

	radix_tree_tag_clear(&pag->pag_ici_root,
			     SCXFS_INO_TO_AGINO(ip->i_mount, ip->i_ino), tag);
	if (!radix_tree_tagged(&pag->pag_ici_root, tag)) {
		/* clear the eofblocks tag from the perag radix tree */
		spin_lock(&ip->i_mount->m_perag_lock);
		radix_tree_tag_clear(&ip->i_mount->m_perag_tree,
				     SCXFS_INO_TO_AGNO(ip->i_mount, ip->i_ino),
				     tag);
		spin_unlock(&ip->i_mount->m_perag_lock);
		clear_tp(ip->i_mount, pag->pag_agno, -1, _RET_IP_);
	}

	spin_unlock(&pag->pag_ici_lock);
	scxfs_perag_put(pag);
}

void
scxfs_inode_clear_eofblocks_tag(
	scxfs_inode_t	*ip)
{
	trace_scxfs_inode_clear_eofblocks_tag(ip);
	return __scxfs_inode_clear_blocks_tag(ip,
			trace_scxfs_perag_clear_eofblocks, SCXFS_ICI_EOFBLOCKS_TAG);
}

/*
 * Set ourselves up to free CoW blocks from this file.  If it's already clean
 * then we can bail out quickly, but otherwise we must back off if the file
 * is undergoing some kind of write.
 */
static bool
scxfs_prep_free_cowblocks(
	struct scxfs_inode	*ip)
{
	/*
	 * Just clear the tag if we have an empty cow fork or none at all. It's
	 * possible the inode was fully unshared since it was originally tagged.
	 */
	if (!scxfs_inode_has_cow_data(ip)) {
		trace_scxfs_inode_free_cowblocks_invalid(ip);
		scxfs_inode_clear_cowblocks_tag(ip);
		return false;
	}

	/*
	 * If the mapping is dirty or under writeback we cannot touch the
	 * CoW fork.  Leave it alone if we're in the midst of a directio.
	 */
	if ((VFS_I(ip)->i_state & I_DIRTY_PAGES) ||
	    mapping_tagged(VFS_I(ip)->i_mapping, PAGECACHE_TAG_DIRTY) ||
	    mapping_tagged(VFS_I(ip)->i_mapping, PAGECACHE_TAG_WRITEBACK) ||
	    atomic_read(&VFS_I(ip)->i_dio_count))
		return false;

	return true;
}

/*
 * Automatic CoW Reservation Freeing
 *
 * These functions automatically garbage collect leftover CoW reservations
 * that were made on behalf of a cowextsize hint when we start to run out
 * of quota or when the reservations sit around for too long.  If the file
 * has dirty pages or is undergoing writeback, its CoW reservations will
 * be retained.
 *
 * The actual garbage collection piggybacks off the same code that runs
 * the speculative EOF preallocation garbage collector.
 */
STATIC int
scxfs_inode_free_cowblocks(
	struct scxfs_inode	*ip,
	int			flags,
	void			*args)
{
	struct scxfs_eofblocks	*eofb = args;
	int			match;
	int			ret = 0;

	if (!scxfs_prep_free_cowblocks(ip))
		return 0;

	if (eofb) {
		if (eofb->eof_flags & SCXFS_EOF_FLAGS_UNION)
			match = scxfs_inode_match_id_union(ip, eofb);
		else
			match = scxfs_inode_match_id(ip, eofb);
		if (!match)
			return 0;

		/* skip the inode if the file size is too small */
		if (eofb->eof_flags & SCXFS_EOF_FLAGS_MINFILESIZE &&
		    SCXFS_ISIZE(ip) < eofb->eof_min_file_size)
			return 0;
	}

	/* Free the CoW blocks */
	scxfs_ilock(ip, SCXFS_IOLOCK_EXCL);
	scxfs_ilock(ip, SCXFS_MMAPLOCK_EXCL);

	/*
	 * Check again, nobody else should be able to dirty blocks or change
	 * the reflink iflag now that we have the first two locks held.
	 */
	if (scxfs_prep_free_cowblocks(ip))
		ret = scxfs_reflink_cancel_cow_range(ip, 0, NULLFILEOFF, false);

	scxfs_iunlock(ip, SCXFS_MMAPLOCK_EXCL);
	scxfs_iunlock(ip, SCXFS_IOLOCK_EXCL);

	return ret;
}

int
scxfs_icache_free_cowblocks(
	struct scxfs_mount	*mp,
	struct scxfs_eofblocks	*eofb)
{
	return __scxfs_icache_free_eofblocks(mp, eofb, scxfs_inode_free_cowblocks,
			SCXFS_ICI_COWBLOCKS_TAG);
}

int
scxfs_inode_free_quota_cowblocks(
	struct scxfs_inode *ip)
{
	return __scxfs_inode_free_quota_eofblocks(ip, scxfs_icache_free_cowblocks);
}

void
scxfs_inode_set_cowblocks_tag(
	scxfs_inode_t	*ip)
{
	trace_scxfs_inode_set_cowblocks_tag(ip);
	return __scxfs_inode_set_blocks_tag(ip, scxfs_queue_cowblocks,
			trace_scxfs_perag_set_cowblocks,
			SCXFS_ICI_COWBLOCKS_TAG);
}

void
scxfs_inode_clear_cowblocks_tag(
	scxfs_inode_t	*ip)
{
	trace_scxfs_inode_clear_cowblocks_tag(ip);
	return __scxfs_inode_clear_blocks_tag(ip,
			trace_scxfs_perag_clear_cowblocks, SCXFS_ICI_COWBLOCKS_TAG);
}

/* Disable post-EOF and CoW block auto-reclamation. */
void
scxfs_stop_block_reaping(
	struct scxfs_mount	*mp)
{
	cancel_delayed_work_sync(&mp->m_eofblocks_work);
	cancel_delayed_work_sync(&mp->m_cowblocks_work);
}

/* Enable post-EOF and CoW block auto-reclamation. */
void
scxfs_start_block_reaping(
	struct scxfs_mount	*mp)
{
	scxfs_queue_eofblocks(mp);
	scxfs_queue_cowblocks(mp);
}
