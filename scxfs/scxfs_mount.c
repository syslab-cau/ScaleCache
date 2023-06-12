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
#include "scxfs_bit.h"
#include "scxfs_sb.h"
#include "scxfs_mount.h"
#include "scxfs_inode.h"
#include "scxfs_dir2.h"
#include "scxfs_ialloc.h"
#include "scxfs_alloc.h"
#include "scxfs_rtalloc.h"
#include "scxfs_bmap.h"
#include "scxfs_trans.h"
#include "scxfs_trans_priv.h"
#include "scxfs_log.h"
#include "scxfs_error.h"
#include "scxfs_quota.h"
#include "scxfs_fsops.h"
#include "scxfs_icache.h"
#include "scxfs_sysfs.h"
#include "scxfs_rmap_btree.h"
#include "scxfs_refcount_btree.h"
#include "scxfs_reflink.h"
#include "scxfs_extent_busy.h"
#include "scxfs_health.h"


static DEFINE_MUTEX(scxfs_uuid_table_mutex);
static int scxfs_uuid_table_size;
static uuid_t *scxfs_uuid_table;

void
scxfs_uuid_table_free(void)
{
	if (scxfs_uuid_table_size == 0)
		return;
	kmem_free(scxfs_uuid_table);
	scxfs_uuid_table = NULL;
	scxfs_uuid_table_size = 0;
}

/*
 * See if the UUID is unique among mounted SCXFS filesystems.
 * Mount fails if UUID is nil or a FS with the same UUID is already mounted.
 */
STATIC int
scxfs_uuid_mount(
	struct scxfs_mount	*mp)
{
	uuid_t			*uuid = &mp->m_sb.sb_uuid;
	int			hole, i;

	/* Publish UUID in struct super_block */
	uuid_copy(&mp->m_super->s_uuid, uuid);

	if (mp->m_flags & SCXFS_MOUNT_NOUUID)
		return 0;

	if (uuid_is_null(uuid)) {
		scxfs_warn(mp, "Filesystem has null UUID - can't mount");
		return -EINVAL;
	}

	mutex_lock(&scxfs_uuid_table_mutex);
	for (i = 0, hole = -1; i < scxfs_uuid_table_size; i++) {
		if (uuid_is_null(&scxfs_uuid_table[i])) {
			hole = i;
			continue;
		}
		if (uuid_equal(uuid, &scxfs_uuid_table[i]))
			goto out_duplicate;
	}

	if (hole < 0) {
		scxfs_uuid_table = kmem_realloc(scxfs_uuid_table,
			(scxfs_uuid_table_size + 1) * sizeof(*scxfs_uuid_table),
			0);
		hole = scxfs_uuid_table_size++;
	}
	scxfs_uuid_table[hole] = *uuid;
	mutex_unlock(&scxfs_uuid_table_mutex);

	return 0;

 out_duplicate:
	mutex_unlock(&scxfs_uuid_table_mutex);
	scxfs_warn(mp, "Filesystem has duplicate UUID %pU - can't mount", uuid);
	return -EINVAL;
}

STATIC void
scxfs_uuid_unmount(
	struct scxfs_mount	*mp)
{
	uuid_t			*uuid = &mp->m_sb.sb_uuid;
	int			i;

	if (mp->m_flags & SCXFS_MOUNT_NOUUID)
		return;

	mutex_lock(&scxfs_uuid_table_mutex);
	for (i = 0; i < scxfs_uuid_table_size; i++) {
		if (uuid_is_null(&scxfs_uuid_table[i]))
			continue;
		if (!uuid_equal(uuid, &scxfs_uuid_table[i]))
			continue;
		memset(&scxfs_uuid_table[i], 0, sizeof(uuid_t));
		break;
	}
	ASSERT(i < scxfs_uuid_table_size);
	mutex_unlock(&scxfs_uuid_table_mutex);
}


STATIC void
__scxfs_free_perag(
	struct rcu_head	*head)
{
	struct scxfs_perag *pag = container_of(head, struct scxfs_perag, rcu_head);

	ASSERT(atomic_read(&pag->pag_ref) == 0);
	kmem_free(pag);
}

/*
 * Free up the per-ag resources associated with the mount structure.
 */
STATIC void
scxfs_free_perag(
	scxfs_mount_t	*mp)
{
	scxfs_agnumber_t	agno;
	struct scxfs_perag *pag;

	for (agno = 0; agno < mp->m_sb.sb_agcount; agno++) {
		spin_lock(&mp->m_perag_lock);
		pag = radix_tree_delete(&mp->m_perag_tree, agno);
		spin_unlock(&mp->m_perag_lock);
		ASSERT(pag);
		ASSERT(atomic_read(&pag->pag_ref) == 0);
		scxfs_iunlink_destroy(pag);
		scxfs_buf_hash_destroy(pag);
		mutex_destroy(&pag->pag_ici_reclaim_lock);
		call_rcu(&pag->rcu_head, __scxfs_free_perag);
	}
}

/*
 * Check size of device based on the (data/realtime) block count.
 * Note: this check is used by the growfs code as well as mount.
 */
int
scxfs_sb_validate_fsb_count(
	scxfs_sb_t	*sbp,
	uint64_t	nblocks)
{
	ASSERT(PAGE_SHIFT >= sbp->sb_blocklog);
	ASSERT(sbp->sb_blocklog >= BBSHIFT);

	/* Limited by ULONG_MAX of page cache index */
	if (nblocks >> (PAGE_SHIFT - sbp->sb_blocklog) > ULONG_MAX)
		return -EFBIG;
	return 0;
}

int
scxfs_initialize_perag(
	scxfs_mount_t	*mp,
	scxfs_agnumber_t	agcount,
	scxfs_agnumber_t	*maxagi)
{
	scxfs_agnumber_t	index;
	scxfs_agnumber_t	first_initialised = NULLAGNUMBER;
	scxfs_perag_t	*pag;
	int		error = -ENOMEM;

	/*
	 * Walk the current per-ag tree so we don't try to initialise AGs
	 * that already exist (growfs case). Allocate and insert all the
	 * AGs we don't find ready for initialisation.
	 */
	for (index = 0; index < agcount; index++) {
		pag = scxfs_perag_get(mp, index);
		if (pag) {
			scxfs_perag_put(pag);
			continue;
		}

		pag = kmem_zalloc(sizeof(*pag), KM_MAYFAIL);
		if (!pag) {
			error = -ENOMEM;
			goto out_unwind_new_pags;
		}
		pag->pag_agno = index;
		pag->pag_mount = mp;
		spin_lock_init(&pag->pag_ici_lock);
		mutex_init(&pag->pag_ici_reclaim_lock);
		INIT_RADIX_TREE(&pag->pag_ici_root, GFP_ATOMIC);

		error = scxfs_buf_hash_init(pag);
		if (error)
			goto out_free_pag;
		init_waitqueue_head(&pag->pagb_wait);
		spin_lock_init(&pag->pagb_lock);
		pag->pagb_count = 0;
		pag->pagb_tree = RB_ROOT;

		error = radix_tree_preload(GFP_NOFS);
		if (error)
			goto out_hash_destroy;

		spin_lock(&mp->m_perag_lock);
		if (radix_tree_insert(&mp->m_perag_tree, index, pag)) {
			WARN_ON_ONCE(1);
			spin_unlock(&mp->m_perag_lock);
			radix_tree_preload_end();
			error = -EEXIST;
			goto out_hash_destroy;
		}
		spin_unlock(&mp->m_perag_lock);
		radix_tree_preload_end();
		/* first new pag is fully initialized */
		if (first_initialised == NULLAGNUMBER)
			first_initialised = index;
		error = scxfs_iunlink_init(pag);
		if (error)
			goto out_hash_destroy;
		spin_lock_init(&pag->pag_state_lock);
	}

	index = scxfs_set_inode_alloc(mp, agcount);

	if (maxagi)
		*maxagi = index;

	mp->m_ag_prealloc_blocks = scxfs_prealloc_blocks(mp);
	return 0;

out_hash_destroy:
	scxfs_buf_hash_destroy(pag);
out_free_pag:
	mutex_destroy(&pag->pag_ici_reclaim_lock);
	kmem_free(pag);
out_unwind_new_pags:
	/* unwind any prior newly initialized pags */
	for (index = first_initialised; index < agcount; index++) {
		pag = radix_tree_delete(&mp->m_perag_tree, index);
		if (!pag)
			break;
		scxfs_buf_hash_destroy(pag);
		scxfs_iunlink_destroy(pag);
		mutex_destroy(&pag->pag_ici_reclaim_lock);
		kmem_free(pag);
	}
	return error;
}

/*
 * scxfs_readsb
 *
 * Does the initial read of the superblock.
 */
int
scxfs_readsb(
	struct scxfs_mount *mp,
	int		flags)
{
	unsigned int	sector_size;
	struct scxfs_buf	*bp;
	struct scxfs_sb	*sbp = &mp->m_sb;
	int		error;
	int		loud = !(flags & SCXFS_MFSI_QUIET);
	const struct scxfs_buf_ops *buf_ops;

	ASSERT(mp->m_sb_bp == NULL);
	ASSERT(mp->m_ddev_targp != NULL);

	/*
	 * For the initial read, we must guess at the sector
	 * size based on the block device.  It's enough to
	 * get the sb_sectsize out of the superblock and
	 * then reread with the proper length.
	 * We don't verify it yet, because it may not be complete.
	 */
	sector_size = scxfs_getsize_buftarg(mp->m_ddev_targp);
	buf_ops = NULL;

	/*
	 * Allocate a (locked) buffer to hold the superblock. This will be kept
	 * around at all times to optimize access to the superblock. Therefore,
	 * set XBF_NO_IOACCT to make sure it doesn't hold the buftarg count
	 * elevated.
	 */
reread:
	error = scxfs_buf_read_uncached(mp->m_ddev_targp, SCXFS_SB_DADDR,
				      BTOBB(sector_size), XBF_NO_IOACCT, &bp,
				      buf_ops);
	if (error) {
		if (loud)
			scxfs_warn(mp, "SB validate failed with error %d.", error);
		/* bad CRC means corrupted metadata */
		if (error == -EFSBADCRC)
			error = -EFSCORRUPTED;
		return error;
	}

	/*
	 * Initialize the mount structure from the superblock.
	 */
	scxfs_sb_from_disk(sbp, SCXFS_BUF_TO_SBP(bp));

	/*
	 * If we haven't validated the superblock, do so now before we try
	 * to check the sector size and reread the superblock appropriately.
	 */
	if (sbp->sb_magicnum != SCXFS_SB_MAGIC) {
		if (loud)
			scxfs_warn(mp, "Invalid superblock magic number");
		error = -EINVAL;
		goto release_buf;
	}

	/*
	 * We must be able to do sector-sized and sector-aligned IO.
	 */
	if (sector_size > sbp->sb_sectsize) {
		if (loud)
			scxfs_warn(mp, "device supports %u byte sectors (not %u)",
				sector_size, sbp->sb_sectsize);
		error = -ENOSYS;
		goto release_buf;
	}

	if (buf_ops == NULL) {
		/*
		 * Re-read the superblock so the buffer is correctly sized,
		 * and properly verified.
		 */
		scxfs_buf_relse(bp);
		sector_size = sbp->sb_sectsize;
		buf_ops = loud ? &scxfs_sb_buf_ops : &scxfs_sb_quiet_buf_ops;
		goto reread;
	}

	scxfs_reinit_percpu_counters(mp);

	/* no need to be quiet anymore, so reset the buf ops */
	bp->b_ops = &scxfs_sb_buf_ops;

	mp->m_sb_bp = bp;
	scxfs_buf_unlock(bp);
	return 0;

release_buf:
	scxfs_buf_relse(bp);
	return error;
}

/*
 * Update alignment values based on mount options and sb values
 */
STATIC int
scxfs_update_alignment(scxfs_mount_t *mp)
{
	scxfs_sb_t	*sbp = &(mp->m_sb);

	if (mp->m_dalign) {
		/*
		 * If stripe unit and stripe width are not multiples
		 * of the fs blocksize turn off alignment.
		 */
		if ((BBTOB(mp->m_dalign) & mp->m_blockmask) ||
		    (BBTOB(mp->m_swidth) & mp->m_blockmask)) {
			scxfs_warn(mp,
		"alignment check failed: sunit/swidth vs. blocksize(%d)",
				sbp->sb_blocksize);
			return -EINVAL;
		} else {
			/*
			 * Convert the stripe unit and width to FSBs.
			 */
			mp->m_dalign = SCXFS_BB_TO_FSBT(mp, mp->m_dalign);
			if (mp->m_dalign && (sbp->sb_agblocks % mp->m_dalign)) {
				scxfs_warn(mp,
			"alignment check failed: sunit/swidth vs. agsize(%d)",
					 sbp->sb_agblocks);
				return -EINVAL;
			} else if (mp->m_dalign) {
				mp->m_swidth = SCXFS_BB_TO_FSBT(mp, mp->m_swidth);
			} else {
				scxfs_warn(mp,
			"alignment check failed: sunit(%d) less than bsize(%d)",
					 mp->m_dalign, sbp->sb_blocksize);
				return -EINVAL;
			}
		}

		/*
		 * Update superblock with new values
		 * and log changes
		 */
		if (scxfs_sb_version_hasdalign(sbp)) {
			if (sbp->sb_unit != mp->m_dalign) {
				sbp->sb_unit = mp->m_dalign;
				mp->m_update_sb = true;
			}
			if (sbp->sb_width != mp->m_swidth) {
				sbp->sb_width = mp->m_swidth;
				mp->m_update_sb = true;
			}
		} else {
			scxfs_warn(mp,
	"cannot change alignment: superblock does not support data alignment");
			return -EINVAL;
		}
	} else if ((mp->m_flags & SCXFS_MOUNT_NOALIGN) != SCXFS_MOUNT_NOALIGN &&
		    scxfs_sb_version_hasdalign(&mp->m_sb)) {
			mp->m_dalign = sbp->sb_unit;
			mp->m_swidth = sbp->sb_width;
	}

	return 0;
}

/*
 * Set the default minimum read and write sizes unless
 * already specified in a mount option.
 * We use smaller I/O sizes when the file system
 * is being used for NFS service (wsync mount option).
 */
STATIC void
scxfs_set_rw_sizes(scxfs_mount_t *mp)
{
	scxfs_sb_t	*sbp = &(mp->m_sb);
	int		readio_log, writeio_log;

	if (!(mp->m_flags & SCXFS_MOUNT_DFLT_IOSIZE)) {
		if (mp->m_flags & SCXFS_MOUNT_WSYNC) {
			readio_log = SCXFS_WSYNC_READIO_LOG;
			writeio_log = SCXFS_WSYNC_WRITEIO_LOG;
		} else {
			readio_log = SCXFS_READIO_LOG_LARGE;
			writeio_log = SCXFS_WRITEIO_LOG_LARGE;
		}
	} else {
		readio_log = mp->m_readio_log;
		writeio_log = mp->m_writeio_log;
	}

	if (sbp->sb_blocklog > readio_log) {
		mp->m_readio_log = sbp->sb_blocklog;
	} else {
		mp->m_readio_log = readio_log;
	}
	mp->m_readio_blocks = 1 << (mp->m_readio_log - sbp->sb_blocklog);
	if (sbp->sb_blocklog > writeio_log) {
		mp->m_writeio_log = sbp->sb_blocklog;
	} else {
		mp->m_writeio_log = writeio_log;
	}
	mp->m_writeio_blocks = 1 << (mp->m_writeio_log - sbp->sb_blocklog);
}

/*
 * precalculate the low space thresholds for dynamic speculative preallocation.
 */
void
scxfs_set_low_space_thresholds(
	struct scxfs_mount	*mp)
{
	int i;

	for (i = 0; i < SCXFS_LOWSP_MAX; i++) {
		uint64_t space = mp->m_sb.sb_dblocks;

		do_div(space, 100);
		mp->m_low_space[i] = space * (i + 1);
	}
}

/*
 * Check that the data (and log if separate) is an ok size.
 */
STATIC int
scxfs_check_sizes(
	struct scxfs_mount *mp)
{
	struct scxfs_buf	*bp;
	scxfs_daddr_t	d;
	int		error;

	d = (scxfs_daddr_t)SCXFS_FSB_TO_BB(mp, mp->m_sb.sb_dblocks);
	if (SCXFS_BB_TO_FSB(mp, d) != mp->m_sb.sb_dblocks) {
		scxfs_warn(mp, "filesystem size mismatch detected");
		return -EFBIG;
	}
	error = scxfs_buf_read_uncached(mp->m_ddev_targp,
					d - SCXFS_FSS_TO_BB(mp, 1),
					SCXFS_FSS_TO_BB(mp, 1), 0, &bp, NULL);
	if (error) {
		scxfs_warn(mp, "last sector read failed");
		return error;
	}
	scxfs_buf_relse(bp);

	if (mp->m_logdev_targp == mp->m_ddev_targp)
		return 0;

	d = (scxfs_daddr_t)SCXFS_FSB_TO_BB(mp, mp->m_sb.sb_logblocks);
	if (SCXFS_BB_TO_FSB(mp, d) != mp->m_sb.sb_logblocks) {
		scxfs_warn(mp, "log size mismatch detected");
		return -EFBIG;
	}
	error = scxfs_buf_read_uncached(mp->m_logdev_targp,
					d - SCXFS_FSB_TO_BB(mp, 1),
					SCXFS_FSB_TO_BB(mp, 1), 0, &bp, NULL);
	if (error) {
		scxfs_warn(mp, "log device read failed");
		return error;
	}
	scxfs_buf_relse(bp);
	return 0;
}

/*
 * Clear the quotaflags in memory and in the superblock.
 */
int
scxfs_mount_reset_sbqflags(
	struct scxfs_mount	*mp)
{
	mp->m_qflags = 0;

	/* It is OK to look at sb_qflags in the mount path without m_sb_lock. */
	if (mp->m_sb.sb_qflags == 0)
		return 0;
	spin_lock(&mp->m_sb_lock);
	mp->m_sb.sb_qflags = 0;
	spin_unlock(&mp->m_sb_lock);

	if (!scxfs_fs_writable(mp, SB_FREEZE_WRITE))
		return 0;

	return scxfs_sync_sb(mp, false);
}

uint64_t
scxfs_default_resblks(scxfs_mount_t *mp)
{
	uint64_t resblks;

	/*
	 * We default to 5% or 8192 fsbs of space reserved, whichever is
	 * smaller.  This is intended to cover concurrent allocation
	 * transactions when we initially hit enospc. These each require a 4
	 * block reservation. Hence by default we cover roughly 2000 concurrent
	 * allocation reservations.
	 */
	resblks = mp->m_sb.sb_dblocks;
	do_div(resblks, 20);
	resblks = min_t(uint64_t, resblks, 8192);
	return resblks;
}

/* Ensure the summary counts are correct. */
STATIC int
scxfs_check_summary_counts(
	struct scxfs_mount	*mp)
{
	/*
	 * The AG0 superblock verifier rejects in-progress filesystems,
	 * so we should never see the flag set this far into mounting.
	 */
	if (mp->m_sb.sb_inprogress) {
		scxfs_err(mp, "sb_inprogress set after log recovery??");
		WARN_ON(1);
		return -EFSCORRUPTED;
	}

	/*
	 * Now the log is mounted, we know if it was an unclean shutdown or
	 * not. If it was, with the first phase of recovery has completed, we
	 * have consistent AG blocks on disk. We have not recovered EFIs yet,
	 * but they are recovered transactionally in the second recovery phase
	 * later.
	 *
	 * If the log was clean when we mounted, we can check the summary
	 * counters.  If any of them are obviously incorrect, we can recompute
	 * them from the AGF headers in the next step.
	 */
	if (SCXFS_LAST_UNMOUNT_WAS_CLEAN(mp) &&
	    (mp->m_sb.sb_fdblocks > mp->m_sb.sb_dblocks ||
	     !scxfs_verify_icount(mp, mp->m_sb.sb_icount) ||
	     mp->m_sb.sb_ifree > mp->m_sb.sb_icount))
		scxfs_fs_mark_sick(mp, SCXFS_SICK_FS_COUNTERS);

	/*
	 * We can safely re-initialise incore superblock counters from the
	 * per-ag data. These may not be correct if the filesystem was not
	 * cleanly unmounted, so we waited for recovery to finish before doing
	 * this.
	 *
	 * If the filesystem was cleanly unmounted or the previous check did
	 * not flag anything weird, then we can trust the values in the
	 * superblock to be correct and we don't need to do anything here.
	 * Otherwise, recalculate the summary counters.
	 */
	if ((!scxfs_sb_version_haslazysbcount(&mp->m_sb) ||
	     SCXFS_LAST_UNMOUNT_WAS_CLEAN(mp)) &&
	    !scxfs_fs_has_sickness(mp, SCXFS_SICK_FS_COUNTERS))
		return 0;

	return scxfs_initialize_perag_data(mp, mp->m_sb.sb_agcount);
}

/*
 * This function does the following on an initial mount of a file system:
 *	- reads the superblock from disk and init the mount struct
 *	- if we're a 32-bit kernel, do a size check on the superblock
 *		so we don't mount terabyte filesystems
 *	- init mount struct realtime fields
 *	- allocate inode hash table for fs
 *	- init directory manager
 *	- perform recovery and init the log manager
 */
int
scxfs_mountfs(
	struct scxfs_mount	*mp)
{
	struct scxfs_sb		*sbp = &(mp->m_sb);
	struct scxfs_inode	*rip;
	struct scxfs_ino_geometry	*igeo = M_IGEO(mp);
	uint64_t		resblks;
	uint			quotamount = 0;
	uint			quotaflags = 0;
	int			error = 0;

	scxfs_sb_mount_common(mp, sbp);

	/*
	 * Check for a mismatched features2 values.  Older kernels read & wrote
	 * into the wrong sb offset for sb_features2 on some platforms due to
	 * scxfs_sb_t not being 64bit size aligned when sb_features2 was added,
	 * which made older superblock reading/writing routines swap it as a
	 * 64-bit value.
	 *
	 * For backwards compatibility, we make both slots equal.
	 *
	 * If we detect a mismatched field, we OR the set bits into the existing
	 * features2 field in case it has already been modified; we don't want
	 * to lose any features.  We then update the bad location with the ORed
	 * value so that older kernels will see any features2 flags. The
	 * superblock writeback code ensures the new sb_features2 is copied to
	 * sb_bad_features2 before it is logged or written to disk.
	 */
	if (scxfs_sb_has_mismatched_features2(sbp)) {
		scxfs_warn(mp, "correcting sb_features alignment problem");
		sbp->sb_features2 |= sbp->sb_bad_features2;
		mp->m_update_sb = true;

		/*
		 * Re-check for ATTR2 in case it was found in bad_features2
		 * slot.
		 */
		if (scxfs_sb_version_hasattr2(&mp->m_sb) &&
		   !(mp->m_flags & SCXFS_MOUNT_NOATTR2))
			mp->m_flags |= SCXFS_MOUNT_ATTR2;
	}

	if (scxfs_sb_version_hasattr2(&mp->m_sb) &&
	   (mp->m_flags & SCXFS_MOUNT_NOATTR2)) {
		scxfs_sb_version_removeattr2(&mp->m_sb);
		mp->m_update_sb = true;

		/* update sb_versionnum for the clearing of the morebits */
		if (!sbp->sb_features2)
			mp->m_update_sb = true;
	}

	/* always use v2 inodes by default now */
	if (!(mp->m_sb.sb_versionnum & SCXFS_SB_VERSION_NLINKBIT)) {
		mp->m_sb.sb_versionnum |= SCXFS_SB_VERSION_NLINKBIT;
		mp->m_update_sb = true;
	}

	/*
	 * Check if sb_agblocks is aligned at stripe boundary
	 * If sb_agblocks is NOT aligned turn off m_dalign since
	 * allocator alignment is within an ag, therefore ag has
	 * to be aligned at stripe boundary.
	 */
	error = scxfs_update_alignment(mp);
	if (error)
		goto out;

	scxfs_alloc_compute_maxlevels(mp);
	scxfs_bmap_compute_maxlevels(mp, SCXFS_DATA_FORK);
	scxfs_bmap_compute_maxlevels(mp, SCXFS_ATTR_FORK);
	scxfs_ialloc_setup_geometry(mp);
	scxfs_rmapbt_compute_maxlevels(mp);
	scxfs_refcountbt_compute_maxlevels(mp);

	/* enable fail_at_unmount as default */
	mp->m_fail_unmount = true;

	error = scxfs_sysfs_init(&mp->m_kobj, &scxfs_mp_ktype, NULL, mp->m_fsname);
	if (error)
		goto out;

	error = scxfs_sysfs_init(&mp->m_stats.xs_kobj, &scxfs_stats_ktype,
			       &mp->m_kobj, "stats");
	if (error)
		goto out_remove_sysfs;

	error = scxfs_error_sysfs_init(mp);
	if (error)
		goto out_del_stats;

	error = scxfs_errortag_init(mp);
	if (error)
		goto out_remove_error_sysfs;

	error = scxfs_uuid_mount(mp);
	if (error)
		goto out_remove_errortag;

	/*
	 * Set the minimum read and write sizes
	 */
	scxfs_set_rw_sizes(mp);

	/* set the low space thresholds for dynamic preallocation */
	scxfs_set_low_space_thresholds(mp);

	/*
	 * If enabled, sparse inode chunk alignment is expected to match the
	 * cluster size. Full inode chunk alignment must match the chunk size,
	 * but that is checked on sb read verification...
	 */
	if (scxfs_sb_version_hassparseinodes(&mp->m_sb) &&
	    mp->m_sb.sb_spino_align !=
			SCXFS_B_TO_FSBT(mp, igeo->inode_cluster_size_raw)) {
		scxfs_warn(mp,
	"Sparse inode block alignment (%u) must match cluster size (%llu).",
			 mp->m_sb.sb_spino_align,
			 SCXFS_B_TO_FSBT(mp, igeo->inode_cluster_size_raw));
		error = -EINVAL;
		goto out_remove_uuid;
	}

	/*
	 * Check that the data (and log if separate) is an ok size.
	 */
	error = scxfs_check_sizes(mp);
	if (error)
		goto out_remove_uuid;

	/*
	 * Initialize realtime fields in the mount structure
	 */
	error = scxfs_rtmount_init(mp);
	if (error) {
		scxfs_warn(mp, "RT mount failed");
		goto out_remove_uuid;
	}

	/*
	 *  Copies the low order bits of the timestamp and the randomly
	 *  set "sequence" number out of a UUID.
	 */
	mp->m_fixedfsid[0] =
		(get_unaligned_be16(&sbp->sb_uuid.b[8]) << 16) |
		 get_unaligned_be16(&sbp->sb_uuid.b[4]);
	mp->m_fixedfsid[1] = get_unaligned_be32(&sbp->sb_uuid.b[0]);

	error = scxfs_da_mount(mp);
	if (error) {
		scxfs_warn(mp, "Failed dir/attr init: %d", error);
		goto out_remove_uuid;
	}

	/*
	 * Initialize the precomputed transaction reservations values.
	 */
	scxfs_trans_init(mp);

	/*
	 * Allocate and initialize the per-ag data.
	 */
	error = scxfs_initialize_perag(mp, sbp->sb_agcount, &mp->m_maxagi);
	if (error) {
		scxfs_warn(mp, "Failed per-ag init: %d", error);
		goto out_free_dir;
	}

	if (!sbp->sb_logblocks) {
		scxfs_warn(mp, "no log defined");
		SCXFS_ERROR_REPORT("scxfs_mountfs", SCXFS_ERRLEVEL_LOW, mp);
		error = -EFSCORRUPTED;
		goto out_free_perag;
	}

	/*
	 * Log's mount-time initialization. The first part of recovery can place
	 * some items on the AIL, to be handled when recovery is finished or
	 * cancelled.
	 */
	error = scxfs_log_mount(mp, mp->m_logdev_targp,
			      SCXFS_FSB_TO_DADDR(mp, sbp->sb_logstart),
			      SCXFS_FSB_TO_BB(mp, sbp->sb_logblocks));
	if (error) {
		scxfs_warn(mp, "log mount failed");
		goto out_fail_wait;
	}

	/* Make sure the summary counts are ok. */
	error = scxfs_check_summary_counts(mp);
	if (error)
		goto out_log_dealloc;

	/*
	 * Get and sanity-check the root inode.
	 * Save the pointer to it in the mount structure.
	 */
	error = scxfs_iget(mp, NULL, sbp->sb_rootino, SCXFS_IGET_UNTRUSTED,
			 SCXFS_ILOCK_EXCL, &rip);
	if (error) {
		scxfs_warn(mp,
			"Failed to read root inode 0x%llx, error %d",
			sbp->sb_rootino, -error);
		goto out_log_dealloc;
	}

	ASSERT(rip != NULL);

	if (unlikely(!S_ISDIR(VFS_I(rip)->i_mode))) {
		scxfs_warn(mp, "corrupted root inode %llu: not a directory",
			(unsigned long long)rip->i_ino);
		scxfs_iunlock(rip, SCXFS_ILOCK_EXCL);
		SCXFS_ERROR_REPORT("scxfs_mountfs_int(2)", SCXFS_ERRLEVEL_LOW,
				 mp);
		error = -EFSCORRUPTED;
		goto out_rele_rip;
	}
	mp->m_rootip = rip;	/* save it */

	scxfs_iunlock(rip, SCXFS_ILOCK_EXCL);

	/*
	 * Initialize realtime inode pointers in the mount structure
	 */
	error = scxfs_rtmount_inodes(mp);
	if (error) {
		/*
		 * Free up the root inode.
		 */
		scxfs_warn(mp, "failed to read RT inodes");
		goto out_rele_rip;
	}

	/*
	 * If this is a read-only mount defer the superblock updates until
	 * the next remount into writeable mode.  Otherwise we would never
	 * perform the update e.g. for the root filesystem.
	 */
	if (mp->m_update_sb && !(mp->m_flags & SCXFS_MOUNT_RDONLY)) {
		error = scxfs_sync_sb(mp, false);
		if (error) {
			scxfs_warn(mp, "failed to write sb changes");
			goto out_rtunmount;
		}
	}

	/*
	 * Initialise the SCXFS quota management subsystem for this mount
	 */
	if (SCXFS_IS_QUOTA_RUNNING(mp)) {
		error = scxfs_qm_newmount(mp, &quotamount, &quotaflags);
		if (error)
			goto out_rtunmount;
	} else {
		ASSERT(!SCXFS_IS_QUOTA_ON(mp));

		/*
		 * If a file system had quotas running earlier, but decided to
		 * mount without -o uquota/pquota/gquota options, revoke the
		 * quotachecked license.
		 */
		if (mp->m_sb.sb_qflags & SCXFS_ALL_QUOTA_ACCT) {
			scxfs_notice(mp, "resetting quota flags");
			error = scxfs_mount_reset_sbqflags(mp);
			if (error)
				goto out_rtunmount;
		}
	}

	/*
	 * Finish recovering the file system.  This part needed to be delayed
	 * until after the root and real-time bitmap inodes were consistently
	 * read in.
	 */
	error = scxfs_log_mount_finish(mp);
	if (error) {
		scxfs_warn(mp, "log mount finish failed");
		goto out_rtunmount;
	}

	/*
	 * Now the log is fully replayed, we can transition to full read-only
	 * mode for read-only mounts. This will sync all the metadata and clean
	 * the log so that the recovery we just performed does not have to be
	 * replayed again on the next mount.
	 *
	 * We use the same quiesce mechanism as the rw->ro remount, as they are
	 * semantically identical operations.
	 */
	if ((mp->m_flags & (SCXFS_MOUNT_RDONLY|SCXFS_MOUNT_NORECOVERY)) ==
							SCXFS_MOUNT_RDONLY) {
		scxfs_quiesce_attr(mp);
	}

	/*
	 * Complete the quota initialisation, post-log-replay component.
	 */
	if (quotamount) {
		ASSERT(mp->m_qflags == 0);
		mp->m_qflags = quotaflags;

		scxfs_qm_mount_quotas(mp);
	}

	/*
	 * Now we are mounted, reserve a small amount of unused space for
	 * privileged transactions. This is needed so that transaction
	 * space required for critical operations can dip into this pool
	 * when at ENOSPC. This is needed for operations like create with
	 * attr, unwritten extent conversion at ENOSPC, etc. Data allocations
	 * are not allowed to use this reserved space.
	 *
	 * This may drive us straight to ENOSPC on mount, but that implies
	 * we were already there on the last unmount. Warn if this occurs.
	 */
	if (!(mp->m_flags & SCXFS_MOUNT_RDONLY)) {
		resblks = scxfs_default_resblks(mp);
		error = scxfs_reserve_blocks(mp, &resblks, NULL);
		if (error)
			scxfs_warn(mp,
	"Unable to allocate reserve blocks. Continuing without reserve pool.");

		/* Recover any CoW blocks that never got remapped. */
		error = scxfs_reflink_recover_cow(mp);
		if (error) {
			scxfs_err(mp,
	"Error %d recovering leftover CoW allocations.", error);
			scxfs_force_shutdown(mp, SHUTDOWN_CORRUPT_INCORE);
			goto out_quota;
		}

		/* Reserve AG blocks for future btree expansion. */
		error = scxfs_fs_reserve_ag_blocks(mp);
		if (error && error != -ENOSPC)
			goto out_agresv;
	}

	return 0;

 out_agresv:
	scxfs_fs_unreserve_ag_blocks(mp);
 out_quota:
	scxfs_qm_unmount_quotas(mp);
 out_rtunmount:
	scxfs_rtunmount_inodes(mp);
 out_rele_rip:
	scxfs_irele(rip);
	/* Clean out dquots that might be in memory after quotacheck. */
	scxfs_qm_unmount(mp);
	/*
	 * Cancel all delayed reclaim work and reclaim the inodes directly.
	 * We have to do this /after/ rtunmount and qm_unmount because those
	 * two will have scheduled delayed reclaim for the rt/quota inodes.
	 *
	 * This is slightly different from the unmountfs call sequence
	 * because we could be tearing down a partially set up mount.  In
	 * particular, if log_mount_finish fails we bail out without calling
	 * qm_unmount_quotas and therefore rely on qm_unmount to release the
	 * quota inodes.
	 */
	cancel_delayed_work_sync(&mp->m_reclaim_work);
	scxfs_reclaim_inodes(mp, SYNC_WAIT);
	scxfs_health_unmount(mp);
 out_log_dealloc:
	mp->m_flags |= SCXFS_MOUNT_UNMOUNTING;
	scxfs_log_mount_cancel(mp);
 out_fail_wait:
	if (mp->m_logdev_targp && mp->m_logdev_targp != mp->m_ddev_targp)
		scxfs_wait_buftarg(mp->m_logdev_targp);
	scxfs_wait_buftarg(mp->m_ddev_targp);
 out_free_perag:
	scxfs_free_perag(mp);
 out_free_dir:
	scxfs_da_unmount(mp);
 out_remove_uuid:
	scxfs_uuid_unmount(mp);
 out_remove_errortag:
	scxfs_errortag_del(mp);
 out_remove_error_sysfs:
	scxfs_error_sysfs_del(mp);
 out_del_stats:
	scxfs_sysfs_del(&mp->m_stats.xs_kobj);
 out_remove_sysfs:
	scxfs_sysfs_del(&mp->m_kobj);
 out:
	return error;
}

/*
 * This flushes out the inodes,dquots and the superblock, unmounts the
 * log and makes sure that incore structures are freed.
 */
void
scxfs_unmountfs(
	struct scxfs_mount	*mp)
{
	uint64_t		resblks;
	int			error;

	scxfs_stop_block_reaping(mp);
	scxfs_fs_unreserve_ag_blocks(mp);
	scxfs_qm_unmount_quotas(mp);
	scxfs_rtunmount_inodes(mp);
	scxfs_irele(mp->m_rootip);

	/*
	 * We can potentially deadlock here if we have an inode cluster
	 * that has been freed has its buffer still pinned in memory because
	 * the transaction is still sitting in a iclog. The stale inodes
	 * on that buffer will have their flush locks held until the
	 * transaction hits the disk and the callbacks run. the inode
	 * flush takes the flush lock unconditionally and with nothing to
	 * push out the iclog we will never get that unlocked. hence we
	 * need to force the log first.
	 */
	scxfs_log_force(mp, SCXFS_LOG_SYNC);

	/*
	 * Wait for all busy extents to be freed, including completion of
	 * any discard operation.
	 */
	scxfs_extent_busy_wait_all(mp);
	flush_workqueue(scxfs_discard_wq);

	/*
	 * We now need to tell the world we are unmounting. This will allow
	 * us to detect that the filesystem is going away and we should error
	 * out anything that we have been retrying in the background. This will
	 * prevent neverending retries in AIL pushing from hanging the unmount.
	 */
	mp->m_flags |= SCXFS_MOUNT_UNMOUNTING;

	/*
	 * Flush all pending changes from the AIL.
	 */
	scxfs_ail_push_all_sync(mp->m_ail);

	/*
	 * And reclaim all inodes.  At this point there should be no dirty
	 * inodes and none should be pinned or locked, but use synchronous
	 * reclaim just to be sure. We can stop background inode reclaim
	 * here as well if it is still running.
	 */
	cancel_delayed_work_sync(&mp->m_reclaim_work);
	scxfs_reclaim_inodes(mp, SYNC_WAIT);
	scxfs_health_unmount(mp);

	scxfs_qm_unmount(mp);

	/*
	 * Unreserve any blocks we have so that when we unmount we don't account
	 * the reserved free space as used. This is really only necessary for
	 * lazy superblock counting because it trusts the incore superblock
	 * counters to be absolutely correct on clean unmount.
	 *
	 * We don't bother correcting this elsewhere for lazy superblock
	 * counting because on mount of an unclean filesystem we reconstruct the
	 * correct counter value and this is irrelevant.
	 *
	 * For non-lazy counter filesystems, this doesn't matter at all because
	 * we only every apply deltas to the superblock and hence the incore
	 * value does not matter....
	 */
	resblks = 0;
	error = scxfs_reserve_blocks(mp, &resblks, NULL);
	if (error)
		scxfs_warn(mp, "Unable to free reserved block pool. "
				"Freespace may not be correct on next mount.");

	error = scxfs_log_sbcount(mp);
	if (error)
		scxfs_warn(mp, "Unable to update superblock counters. "
				"Freespace may not be correct on next mount.");


	scxfs_log_unmount(mp);
	scxfs_da_unmount(mp);
	scxfs_uuid_unmount(mp);

#if defined(DEBUG)
	scxfs_errortag_clearall(mp);
#endif
	scxfs_free_perag(mp);

	scxfs_errortag_del(mp);
	scxfs_error_sysfs_del(mp);
	scxfs_sysfs_del(&mp->m_stats.xs_kobj);
	scxfs_sysfs_del(&mp->m_kobj);
}

/*
 * Determine whether modifications can proceed. The caller specifies the minimum
 * freeze level for which modifications should not be allowed. This allows
 * certain operations to proceed while the freeze sequence is in progress, if
 * necessary.
 */
bool
scxfs_fs_writable(
	struct scxfs_mount	*mp,
	int			level)
{
	ASSERT(level > SB_UNFROZEN);
	if ((mp->m_super->s_writers.frozen >= level) ||
	    SCXFS_FORCED_SHUTDOWN(mp) || (mp->m_flags & SCXFS_MOUNT_RDONLY))
		return false;

	return true;
}

/*
 * scxfs_log_sbcount
 *
 * Sync the superblock counters to disk.
 *
 * Note this code can be called during the process of freezing, so we use the
 * transaction allocator that does not block when the transaction subsystem is
 * in its frozen state.
 */
int
scxfs_log_sbcount(scxfs_mount_t *mp)
{
	/* allow this to proceed during the freeze sequence... */
	if (!scxfs_fs_writable(mp, SB_FREEZE_COMPLETE))
		return 0;

	/*
	 * we don't need to do this if we are updating the superblock
	 * counters on every modification.
	 */
	if (!scxfs_sb_version_haslazysbcount(&mp->m_sb))
		return 0;

	return scxfs_sync_sb(mp, true);
}

/*
 * Deltas for the inode count are +/-64, hence we use a large batch size
 * of 128 so we don't need to take the counter lock on every update.
 */
#define SCXFS_ICOUNT_BATCH	128
int
scxfs_mod_icount(
	struct scxfs_mount	*mp,
	int64_t			delta)
{
	percpu_counter_add_batch(&mp->m_icount, delta, SCXFS_ICOUNT_BATCH);
	if (__percpu_counter_compare(&mp->m_icount, 0, SCXFS_ICOUNT_BATCH) < 0) {
		ASSERT(0);
		percpu_counter_add(&mp->m_icount, -delta);
		return -EINVAL;
	}
	return 0;
}

int
scxfs_mod_ifree(
	struct scxfs_mount	*mp,
	int64_t			delta)
{
	percpu_counter_add(&mp->m_ifree, delta);
	if (percpu_counter_compare(&mp->m_ifree, 0) < 0) {
		ASSERT(0);
		percpu_counter_add(&mp->m_ifree, -delta);
		return -EINVAL;
	}
	return 0;
}

/*
 * Deltas for the block count can vary from 1 to very large, but lock contention
 * only occurs on frequent small block count updates such as in the delayed
 * allocation path for buffered writes (page a time updates). Hence we set
 * a large batch count (1024) to minimise global counter updates except when
 * we get near to ENOSPC and we have to be very accurate with our updates.
 */
#define SCXFS_FDBLOCKS_BATCH	1024
int
scxfs_mod_fdblocks(
	struct scxfs_mount	*mp,
	int64_t			delta,
	bool			rsvd)
{
	int64_t			lcounter;
	long long		res_used;
	s32			batch;

	if (delta > 0) {
		/*
		 * If the reserve pool is depleted, put blocks back into it
		 * first. Most of the time the pool is full.
		 */
		if (likely(mp->m_resblks == mp->m_resblks_avail)) {
			percpu_counter_add(&mp->m_fdblocks, delta);
			return 0;
		}

		spin_lock(&mp->m_sb_lock);
		res_used = (long long)(mp->m_resblks - mp->m_resblks_avail);

		if (res_used > delta) {
			mp->m_resblks_avail += delta;
		} else {
			delta -= res_used;
			mp->m_resblks_avail = mp->m_resblks;
			percpu_counter_add(&mp->m_fdblocks, delta);
		}
		spin_unlock(&mp->m_sb_lock);
		return 0;
	}

	/*
	 * Taking blocks away, need to be more accurate the closer we
	 * are to zero.
	 *
	 * If the counter has a value of less than 2 * max batch size,
	 * then make everything serialise as we are real close to
	 * ENOSPC.
	 */
	if (__percpu_counter_compare(&mp->m_fdblocks, 2 * SCXFS_FDBLOCKS_BATCH,
				     SCXFS_FDBLOCKS_BATCH) < 0)
		batch = 1;
	else
		batch = SCXFS_FDBLOCKS_BATCH;

	percpu_counter_add_batch(&mp->m_fdblocks, delta, batch);
	if (__percpu_counter_compare(&mp->m_fdblocks, mp->m_alloc_set_aside,
				     SCXFS_FDBLOCKS_BATCH) >= 0) {
		/* we had space! */
		return 0;
	}

	/*
	 * lock up the sb for dipping into reserves before releasing the space
	 * that took us to ENOSPC.
	 */
	spin_lock(&mp->m_sb_lock);
	percpu_counter_add(&mp->m_fdblocks, -delta);
	if (!rsvd)
		goto fdblocks_enospc;

	lcounter = (long long)mp->m_resblks_avail + delta;
	if (lcounter >= 0) {
		mp->m_resblks_avail = lcounter;
		spin_unlock(&mp->m_sb_lock);
		return 0;
	}
	printk_once(KERN_WARNING
		"Filesystem \"%s\": reserve blocks depleted! "
		"Consider increasing reserve pool size.",
		mp->m_fsname);
fdblocks_enospc:
	spin_unlock(&mp->m_sb_lock);
	return -ENOSPC;
}

int
scxfs_mod_frextents(
	struct scxfs_mount	*mp,
	int64_t			delta)
{
	int64_t			lcounter;
	int			ret = 0;

	spin_lock(&mp->m_sb_lock);
	lcounter = mp->m_sb.sb_frextents + delta;
	if (lcounter < 0)
		ret = -ENOSPC;
	else
		mp->m_sb.sb_frextents = lcounter;
	spin_unlock(&mp->m_sb_lock);
	return ret;
}

/*
 * scxfs_getsb() is called to obtain the buffer for the superblock.
 * The buffer is returned locked and read in from disk.
 * The buffer should be released with a call to scxfs_brelse().
 */
struct scxfs_buf *
scxfs_getsb(
	struct scxfs_mount	*mp)
{
	struct scxfs_buf		*bp = mp->m_sb_bp;

	scxfs_buf_lock(bp);
	scxfs_buf_hold(bp);
	ASSERT(bp->b_flags & XBF_DONE);
	return bp;
}

/*
 * Used to free the superblock along various error paths.
 */
void
scxfs_freesb(
	struct scxfs_mount	*mp)
{
	struct scxfs_buf		*bp = mp->m_sb_bp;

	scxfs_buf_lock(bp);
	mp->m_sb_bp = NULL;
	scxfs_buf_relse(bp);
}

/*
 * If the underlying (data/log/rt) device is readonly, there are some
 * operations that cannot proceed.
 */
int
scxfs_dev_is_read_only(
	struct scxfs_mount	*mp,
	char			*message)
{
	if (scxfs_readonly_buftarg(mp->m_ddev_targp) ||
	    scxfs_readonly_buftarg(mp->m_logdev_targp) ||
	    (mp->m_rtdev_targp && scxfs_readonly_buftarg(mp->m_rtdev_targp))) {
		scxfs_notice(mp, "%s required on read-only device.", message);
		scxfs_notice(mp, "write access unavailable, cannot proceed.");
		return -EROFS;
	}
	return 0;
}

/* Force the summary counters to be recalculated at next mount. */
void
scxfs_force_summary_recalc(
	struct scxfs_mount	*mp)
{
	if (!scxfs_sb_version_haslazysbcount(&mp->m_sb))
		return;

	scxfs_fs_mark_sick(mp, SCXFS_SICK_FS_COUNTERS);
}

/*
 * Update the in-core delayed block counter.
 *
 * We prefer to update the counter without having to take a spinlock for every
 * counter update (i.e. batching).  Each change to delayed allocation
 * reservations can change can easily exceed the default percpu counter
 * batching, so we use a larger batch factor here.
 *
 * Note that we don't currently have any callers requiring fast summation
 * (e.g. percpu_counter_read) so we can use a big batch value here.
 */
#define SCXFS_DELALLOC_BATCH	(4096)
void
scxfs_mod_delalloc(
	struct scxfs_mount	*mp,
	int64_t			delta)
{
	percpu_counter_add_batch(&mp->m_delalloc_blks, delta,
			SCXFS_DELALLOC_BATCH);
}
