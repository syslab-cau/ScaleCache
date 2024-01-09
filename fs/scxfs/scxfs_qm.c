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
#include "scxfs_iwalk.h"
#include "scxfs_quota.h"
#include "scxfs_bmap.h"
#include "scxfs_bmap_util.h"
#include "scxfs_trans.h"
#include "scxfs_trans_space.h"
#include "scxfs_qm.h"
#include "scxfs_trace.h"
#include "scxfs_icache.h"

/*
 * The global quota manager. There is only one of these for the entire
 * system, _not_ one per file system. XQM keeps track of the overall
 * quota functionality, including maintaining the freelist and hash
 * tables of dquots.
 */
STATIC int	scxfs_qm_init_quotainos(scxfs_mount_t *);
STATIC int	scxfs_qm_init_quotainfo(scxfs_mount_t *);

STATIC void	scxfs_qm_destroy_quotainos(scxfs_quotainfo_t *qi);
STATIC void	scxfs_qm_dqfree_one(struct scxfs_dquot *dqp);
/*
 * We use the batch lookup interface to iterate over the dquots as it
 * currently is the only interface into the radix tree code that allows
 * fuzzy lookups instead of exact matches.  Holding the lock over multiple
 * operations is fine as all callers are used either during mount/umount
 * or quotaoff.
 */
#define SCXFS_DQ_LOOKUP_BATCH	32

STATIC int
scxfs_qm_dquot_walk(
	struct scxfs_mount	*mp,
	int			type,
	int			(*execute)(struct scxfs_dquot *dqp, void *data),
	void			*data)
{
	struct scxfs_quotainfo	*qi = mp->m_quotainfo;
	struct radix_tree_root	*tree = scxfs_dquot_tree(qi, type);
	uint32_t		next_index;
	int			last_error = 0;
	int			skipped;
	int			nr_found;

restart:
	skipped = 0;
	next_index = 0;
	nr_found = 0;

	while (1) {
		struct scxfs_dquot *batch[SCXFS_DQ_LOOKUP_BATCH];
		int		error = 0;
		int		i;

		mutex_lock(&qi->qi_tree_lock);
		nr_found = radix_tree_gang_lookup(tree, (void **)batch,
					next_index, SCXFS_DQ_LOOKUP_BATCH);
		if (!nr_found) {
			mutex_unlock(&qi->qi_tree_lock);
			break;
		}

		for (i = 0; i < nr_found; i++) {
			struct scxfs_dquot *dqp = batch[i];

			next_index = be32_to_cpu(dqp->q_core.d_id) + 1;

			error = execute(batch[i], data);
			if (error == -EAGAIN) {
				skipped++;
				continue;
			}
			if (error && last_error != -EFSCORRUPTED)
				last_error = error;
		}

		mutex_unlock(&qi->qi_tree_lock);

		/* bail out if the filesystem is corrupted.  */
		if (last_error == -EFSCORRUPTED) {
			skipped = 0;
			break;
		}
		/* we're done if id overflows back to zero */
		if (!next_index)
			break;
	}

	if (skipped) {
		delay(1);
		goto restart;
	}

	return last_error;
}


/*
 * Purge a dquot from all tracking data structures and free it.
 */
STATIC int
scxfs_qm_dqpurge(
	struct scxfs_dquot	*dqp,
	void			*data)
{
	struct scxfs_mount	*mp = dqp->q_mount;
	struct scxfs_quotainfo	*qi = mp->m_quotainfo;

	scxfs_dqlock(dqp);
	if ((dqp->dq_flags & SCXFS_DQ_FREEING) || dqp->q_nrefs != 0) {
		scxfs_dqunlock(dqp);
		return -EAGAIN;
	}

	dqp->dq_flags |= SCXFS_DQ_FREEING;

	scxfs_dqflock(dqp);

	/*
	 * If we are turning this type of quotas off, we don't care
	 * about the dirty metadata sitting in this dquot. OTOH, if
	 * we're unmounting, we do care, so we flush it and wait.
	 */
	if (SCXFS_DQ_IS_DIRTY(dqp)) {
		struct scxfs_buf	*bp = NULL;
		int		error;

		/*
		 * We don't care about getting disk errors here. We need
		 * to purge this dquot anyway, so we go ahead regardless.
		 */
		error = scxfs_qm_dqflush(dqp, &bp);
		if (!error) {
			error = scxfs_bwrite(bp);
			scxfs_buf_relse(bp);
		}
		scxfs_dqflock(dqp);
	}

	ASSERT(atomic_read(&dqp->q_pincount) == 0);
	ASSERT(SCXFS_FORCED_SHUTDOWN(mp) ||
		!test_bit(SCXFS_LI_IN_AIL, &dqp->q_logitem.qli_item.li_flags));

	scxfs_dqfunlock(dqp);
	scxfs_dqunlock(dqp);

	radix_tree_delete(scxfs_dquot_tree(qi, dqp->q_core.d_flags),
			  be32_to_cpu(dqp->q_core.d_id));
	qi->qi_dquots--;

	/*
	 * We move dquots to the freelist as soon as their reference count
	 * hits zero, so it really should be on the freelist here.
	 */
	ASSERT(!list_empty(&dqp->q_lru));
	list_lru_del(&qi->qi_lru, &dqp->q_lru);
	SCXFS_STATS_DEC(mp, xs_qm_dquot_unused);

	scxfs_qm_dqdestroy(dqp);
	return 0;
}

/*
 * Purge the dquot cache.
 */
void
scxfs_qm_dqpurge_all(
	struct scxfs_mount	*mp,
	uint			flags)
{
	if (flags & SCXFS_QMOPT_UQUOTA)
		scxfs_qm_dquot_walk(mp, SCXFS_DQ_USER, scxfs_qm_dqpurge, NULL);
	if (flags & SCXFS_QMOPT_GQUOTA)
		scxfs_qm_dquot_walk(mp, SCXFS_DQ_GROUP, scxfs_qm_dqpurge, NULL);
	if (flags & SCXFS_QMOPT_PQUOTA)
		scxfs_qm_dquot_walk(mp, SCXFS_DQ_PROJ, scxfs_qm_dqpurge, NULL);
}

/*
 * Just destroy the quotainfo structure.
 */
void
scxfs_qm_unmount(
	struct scxfs_mount	*mp)
{
	if (mp->m_quotainfo) {
		scxfs_qm_dqpurge_all(mp, SCXFS_QMOPT_QUOTALL);
		scxfs_qm_destroy_quotainfo(mp);
	}
}

/*
 * Called from the vfsops layer.
 */
void
scxfs_qm_unmount_quotas(
	scxfs_mount_t	*mp)
{
	/*
	 * Release the dquots that root inode, et al might be holding,
	 * before we flush quotas and blow away the quotainfo structure.
	 */
	ASSERT(mp->m_rootip);
	scxfs_qm_dqdetach(mp->m_rootip);
	if (mp->m_rbmip)
		scxfs_qm_dqdetach(mp->m_rbmip);
	if (mp->m_rsumip)
		scxfs_qm_dqdetach(mp->m_rsumip);

	/*
	 * Release the quota inodes.
	 */
	if (mp->m_quotainfo) {
		if (mp->m_quotainfo->qi_uquotaip) {
			scxfs_irele(mp->m_quotainfo->qi_uquotaip);
			mp->m_quotainfo->qi_uquotaip = NULL;
		}
		if (mp->m_quotainfo->qi_gquotaip) {
			scxfs_irele(mp->m_quotainfo->qi_gquotaip);
			mp->m_quotainfo->qi_gquotaip = NULL;
		}
		if (mp->m_quotainfo->qi_pquotaip) {
			scxfs_irele(mp->m_quotainfo->qi_pquotaip);
			mp->m_quotainfo->qi_pquotaip = NULL;
		}
	}
}

STATIC int
scxfs_qm_dqattach_one(
	scxfs_inode_t	*ip,
	scxfs_dqid_t	id,
	uint		type,
	bool		doalloc,
	scxfs_dquot_t	**IO_idqpp)
{
	scxfs_dquot_t	*dqp;
	int		error;

	ASSERT(scxfs_isilocked(ip, SCXFS_ILOCK_EXCL));
	error = 0;

	/*
	 * See if we already have it in the inode itself. IO_idqpp is &i_udquot
	 * or &i_gdquot. This made the code look weird, but made the logic a lot
	 * simpler.
	 */
	dqp = *IO_idqpp;
	if (dqp) {
		trace_scxfs_dqattach_found(dqp);
		return 0;
	}

	/*
	 * Find the dquot from somewhere. This bumps the reference count of
	 * dquot and returns it locked.  This can return ENOENT if dquot didn't
	 * exist on disk and we didn't ask it to allocate; ESRCH if quotas got
	 * turned off suddenly.
	 */
	error = scxfs_qm_dqget_inode(ip, type, doalloc, &dqp);
	if (error)
		return error;

	trace_scxfs_dqattach_get(dqp);

	/*
	 * dqget may have dropped and re-acquired the ilock, but it guarantees
	 * that the dquot returned is the one that should go in the inode.
	 */
	*IO_idqpp = dqp;
	scxfs_dqunlock(dqp);
	return 0;
}

static bool
scxfs_qm_need_dqattach(
	struct scxfs_inode	*ip)
{
	struct scxfs_mount	*mp = ip->i_mount;

	if (!SCXFS_IS_QUOTA_RUNNING(mp))
		return false;
	if (!SCXFS_IS_QUOTA_ON(mp))
		return false;
	if (!SCXFS_NOT_DQATTACHED(mp, ip))
		return false;
	if (scxfs_is_quota_inode(&mp->m_sb, ip->i_ino))
		return false;
	return true;
}

/*
 * Given a locked inode, attach dquot(s) to it, taking U/G/P-QUOTAON
 * into account.
 * If @doalloc is true, the dquot(s) will be allocated if needed.
 * Inode may get unlocked and relocked in here, and the caller must deal with
 * the consequences.
 */
int
scxfs_qm_dqattach_locked(
	scxfs_inode_t	*ip,
	bool		doalloc)
{
	scxfs_mount_t	*mp = ip->i_mount;
	int		error = 0;

	if (!scxfs_qm_need_dqattach(ip))
		return 0;

	ASSERT(scxfs_isilocked(ip, SCXFS_ILOCK_EXCL));

	if (SCXFS_IS_UQUOTA_ON(mp) && !ip->i_udquot) {
		error = scxfs_qm_dqattach_one(ip, ip->i_d.di_uid, SCXFS_DQ_USER,
				doalloc, &ip->i_udquot);
		if (error)
			goto done;
		ASSERT(ip->i_udquot);
	}

	if (SCXFS_IS_GQUOTA_ON(mp) && !ip->i_gdquot) {
		error = scxfs_qm_dqattach_one(ip, ip->i_d.di_gid, SCXFS_DQ_GROUP,
				doalloc, &ip->i_gdquot);
		if (error)
			goto done;
		ASSERT(ip->i_gdquot);
	}

	if (SCXFS_IS_PQUOTA_ON(mp) && !ip->i_pdquot) {
		error = scxfs_qm_dqattach_one(ip, scxfs_get_projid(ip), SCXFS_DQ_PROJ,
				doalloc, &ip->i_pdquot);
		if (error)
			goto done;
		ASSERT(ip->i_pdquot);
	}

done:
	/*
	 * Don't worry about the dquots that we may have attached before any
	 * error - they'll get detached later if it has not already been done.
	 */
	ASSERT(scxfs_isilocked(ip, SCXFS_ILOCK_EXCL));
	return error;
}

int
scxfs_qm_dqattach(
	struct scxfs_inode	*ip)
{
	int			error;

	if (!scxfs_qm_need_dqattach(ip))
		return 0;

	scxfs_ilock(ip, SCXFS_ILOCK_EXCL);
	error = scxfs_qm_dqattach_locked(ip, false);
	scxfs_iunlock(ip, SCXFS_ILOCK_EXCL);

	return error;
}

/*
 * Release dquots (and their references) if any.
 * The inode should be locked EXCL except when this's called by
 * scxfs_ireclaim.
 */
void
scxfs_qm_dqdetach(
	scxfs_inode_t	*ip)
{
	if (!(ip->i_udquot || ip->i_gdquot || ip->i_pdquot))
		return;

	trace_scxfs_dquot_dqdetach(ip);

	ASSERT(!scxfs_is_quota_inode(&ip->i_mount->m_sb, ip->i_ino));
	if (ip->i_udquot) {
		scxfs_qm_dqrele(ip->i_udquot);
		ip->i_udquot = NULL;
	}
	if (ip->i_gdquot) {
		scxfs_qm_dqrele(ip->i_gdquot);
		ip->i_gdquot = NULL;
	}
	if (ip->i_pdquot) {
		scxfs_qm_dqrele(ip->i_pdquot);
		ip->i_pdquot = NULL;
	}
}

struct scxfs_qm_isolate {
	struct list_head	buffers;
	struct list_head	dispose;
};

static enum lru_status
scxfs_qm_dquot_isolate(
	struct list_head	*item,
	struct list_lru_one	*lru,
	spinlock_t		*lru_lock,
	void			*arg)
		__releases(lru_lock) __acquires(lru_lock)
{
	struct scxfs_dquot	*dqp = container_of(item,
						struct scxfs_dquot, q_lru);
	struct scxfs_qm_isolate	*isol = arg;

	if (!scxfs_dqlock_nowait(dqp))
		goto out_miss_busy;

	/*
	 * This dquot has acquired a reference in the meantime remove it from
	 * the freelist and try again.
	 */
	if (dqp->q_nrefs) {
		scxfs_dqunlock(dqp);
		SCXFS_STATS_INC(dqp->q_mount, xs_qm_dqwants);

		trace_scxfs_dqreclaim_want(dqp);
		list_lru_isolate(lru, &dqp->q_lru);
		SCXFS_STATS_DEC(dqp->q_mount, xs_qm_dquot_unused);
		return LRU_REMOVED;
	}

	/*
	 * If the dquot is dirty, flush it. If it's already being flushed, just
	 * skip it so there is time for the IO to complete before we try to
	 * reclaim it again on the next LRU pass.
	 */
	if (!scxfs_dqflock_nowait(dqp)) {
		scxfs_dqunlock(dqp);
		goto out_miss_busy;
	}

	if (SCXFS_DQ_IS_DIRTY(dqp)) {
		struct scxfs_buf	*bp = NULL;
		int		error;

		trace_scxfs_dqreclaim_dirty(dqp);

		/* we have to drop the LRU lock to flush the dquot */
		spin_unlock(lru_lock);

		error = scxfs_qm_dqflush(dqp, &bp);
		if (error)
			goto out_unlock_dirty;

		scxfs_buf_delwri_queue(bp, &isol->buffers);
		scxfs_buf_relse(bp);
		goto out_unlock_dirty;
	}
	scxfs_dqfunlock(dqp);

	/*
	 * Prevent lookups now that we are past the point of no return.
	 */
	dqp->dq_flags |= SCXFS_DQ_FREEING;
	scxfs_dqunlock(dqp);

	ASSERT(dqp->q_nrefs == 0);
	list_lru_isolate_move(lru, &dqp->q_lru, &isol->dispose);
	SCXFS_STATS_DEC(dqp->q_mount, xs_qm_dquot_unused);
	trace_scxfs_dqreclaim_done(dqp);
	SCXFS_STATS_INC(dqp->q_mount, xs_qm_dqreclaims);
	return LRU_REMOVED;

out_miss_busy:
	trace_scxfs_dqreclaim_busy(dqp);
	SCXFS_STATS_INC(dqp->q_mount, xs_qm_dqreclaim_misses);
	return LRU_SKIP;

out_unlock_dirty:
	trace_scxfs_dqreclaim_busy(dqp);
	SCXFS_STATS_INC(dqp->q_mount, xs_qm_dqreclaim_misses);
	scxfs_dqunlock(dqp);
	spin_lock(lru_lock);
	return LRU_RETRY;
}

static unsigned long
scxfs_qm_shrink_scan(
	struct shrinker		*shrink,
	struct shrink_control	*sc)
{
	struct scxfs_quotainfo	*qi = container_of(shrink,
					struct scxfs_quotainfo, qi_shrinker);
	struct scxfs_qm_isolate	isol;
	unsigned long		freed;
	int			error;

	if ((sc->gfp_mask & (__GFP_FS|__GFP_DIRECT_RECLAIM)) != (__GFP_FS|__GFP_DIRECT_RECLAIM))
		return 0;

	INIT_LIST_HEAD(&isol.buffers);
	INIT_LIST_HEAD(&isol.dispose);

	freed = list_lru_shrink_walk(&qi->qi_lru, sc,
				     scxfs_qm_dquot_isolate, &isol);

	error = scxfs_buf_delwri_submit(&isol.buffers);
	if (error)
		scxfs_warn(NULL, "%s: dquot reclaim failed", __func__);

	while (!list_empty(&isol.dispose)) {
		struct scxfs_dquot	*dqp;

		dqp = list_first_entry(&isol.dispose, struct scxfs_dquot, q_lru);
		list_del_init(&dqp->q_lru);
		scxfs_qm_dqfree_one(dqp);
	}

	return freed;
}

static unsigned long
scxfs_qm_shrink_count(
	struct shrinker		*shrink,
	struct shrink_control	*sc)
{
	struct scxfs_quotainfo	*qi = container_of(shrink,
					struct scxfs_quotainfo, qi_shrinker);

	return list_lru_shrink_count(&qi->qi_lru, sc);
}

STATIC void
scxfs_qm_set_defquota(
	scxfs_mount_t	*mp,
	uint		type,
	scxfs_quotainfo_t	*qinf)
{
	scxfs_dquot_t		*dqp;
	struct scxfs_def_quota    *defq;
	struct scxfs_disk_dquot	*ddqp;
	int			error;

	error = scxfs_qm_dqget_uncached(mp, 0, type, &dqp);
	if (error)
		return;

	ddqp = &dqp->q_core;
	defq = scxfs_get_defquota(dqp, qinf);

	/*
	 * Timers and warnings have been already set, let's just set the
	 * default limits for this quota type
	 */
	defq->bhardlimit = be64_to_cpu(ddqp->d_blk_hardlimit);
	defq->bsoftlimit = be64_to_cpu(ddqp->d_blk_softlimit);
	defq->ihardlimit = be64_to_cpu(ddqp->d_ino_hardlimit);
	defq->isoftlimit = be64_to_cpu(ddqp->d_ino_softlimit);
	defq->rtbhardlimit = be64_to_cpu(ddqp->d_rtb_hardlimit);
	defq->rtbsoftlimit = be64_to_cpu(ddqp->d_rtb_softlimit);
	scxfs_qm_dqdestroy(dqp);
}

/* Initialize quota time limits from the root dquot. */
static void
scxfs_qm_init_timelimits(
	struct scxfs_mount	*mp,
	struct scxfs_quotainfo	*qinf)
{
	struct scxfs_disk_dquot	*ddqp;
	struct scxfs_dquot	*dqp;
	uint			type;
	int			error;

	qinf->qi_btimelimit = SCXFS_QM_BTIMELIMIT;
	qinf->qi_itimelimit = SCXFS_QM_ITIMELIMIT;
	qinf->qi_rtbtimelimit = SCXFS_QM_RTBTIMELIMIT;
	qinf->qi_bwarnlimit = SCXFS_QM_BWARNLIMIT;
	qinf->qi_iwarnlimit = SCXFS_QM_IWARNLIMIT;
	qinf->qi_rtbwarnlimit = SCXFS_QM_RTBWARNLIMIT;

	/*
	 * We try to get the limits from the superuser's limits fields.
	 * This is quite hacky, but it is standard quota practice.
	 *
	 * Since we may not have done a quotacheck by this point, just read
	 * the dquot without attaching it to any hashtables or lists.
	 *
	 * Timers and warnings are globally set by the first timer found in
	 * user/group/proj quota types, otherwise a default value is used.
	 * This should be split into different fields per quota type.
	 */
	if (SCXFS_IS_UQUOTA_RUNNING(mp))
		type = SCXFS_DQ_USER;
	else if (SCXFS_IS_GQUOTA_RUNNING(mp))
		type = SCXFS_DQ_GROUP;
	else
		type = SCXFS_DQ_PROJ;
	error = scxfs_qm_dqget_uncached(mp, 0, type, &dqp);
	if (error)
		return;

	ddqp = &dqp->q_core;
	/*
	 * The warnings and timers set the grace period given to
	 * a user or group before he or she can not perform any
	 * more writing. If it is zero, a default is used.
	 */
	if (ddqp->d_btimer)
		qinf->qi_btimelimit = be32_to_cpu(ddqp->d_btimer);
	if (ddqp->d_itimer)
		qinf->qi_itimelimit = be32_to_cpu(ddqp->d_itimer);
	if (ddqp->d_rtbtimer)
		qinf->qi_rtbtimelimit = be32_to_cpu(ddqp->d_rtbtimer);
	if (ddqp->d_bwarns)
		qinf->qi_bwarnlimit = be16_to_cpu(ddqp->d_bwarns);
	if (ddqp->d_iwarns)
		qinf->qi_iwarnlimit = be16_to_cpu(ddqp->d_iwarns);
	if (ddqp->d_rtbwarns)
		qinf->qi_rtbwarnlimit = be16_to_cpu(ddqp->d_rtbwarns);

	scxfs_qm_dqdestroy(dqp);
}

/*
 * This initializes all the quota information that's kept in the
 * mount structure
 */
STATIC int
scxfs_qm_init_quotainfo(
	struct scxfs_mount	*mp)
{
	struct scxfs_quotainfo	*qinf;
	int			error;

	ASSERT(SCXFS_IS_QUOTA_RUNNING(mp));

	qinf = mp->m_quotainfo = kmem_zalloc(sizeof(scxfs_quotainfo_t), 0);

	error = list_lru_init(&qinf->qi_lru);
	if (error)
		goto out_free_qinf;

	/*
	 * See if quotainodes are setup, and if not, allocate them,
	 * and change the superblock accordingly.
	 */
	error = scxfs_qm_init_quotainos(mp);
	if (error)
		goto out_free_lru;

	INIT_RADIX_TREE(&qinf->qi_uquota_tree, GFP_NOFS);
	INIT_RADIX_TREE(&qinf->qi_gquota_tree, GFP_NOFS);
	INIT_RADIX_TREE(&qinf->qi_pquota_tree, GFP_NOFS);
	mutex_init(&qinf->qi_tree_lock);

	/* mutex used to serialize quotaoffs */
	mutex_init(&qinf->qi_quotaofflock);

	/* Precalc some constants */
	qinf->qi_dqchunklen = SCXFS_FSB_TO_BB(mp, SCXFS_DQUOT_CLUSTER_SIZE_FSB);
	qinf->qi_dqperchunk = scxfs_calc_dquots_per_chunk(qinf->qi_dqchunklen);

	mp->m_qflags |= (mp->m_sb.sb_qflags & SCXFS_ALL_QUOTA_CHKD);

	scxfs_qm_init_timelimits(mp, qinf);

	if (SCXFS_IS_UQUOTA_RUNNING(mp))
		scxfs_qm_set_defquota(mp, SCXFS_DQ_USER, qinf);
	if (SCXFS_IS_GQUOTA_RUNNING(mp))
		scxfs_qm_set_defquota(mp, SCXFS_DQ_GROUP, qinf);
	if (SCXFS_IS_PQUOTA_RUNNING(mp))
		scxfs_qm_set_defquota(mp, SCXFS_DQ_PROJ, qinf);

	qinf->qi_shrinker.count_objects = scxfs_qm_shrink_count;
	qinf->qi_shrinker.scan_objects = scxfs_qm_shrink_scan;
	qinf->qi_shrinker.seeks = DEFAULT_SEEKS;
	qinf->qi_shrinker.flags = SHRINKER_NUMA_AWARE;

	error = register_shrinker(&qinf->qi_shrinker);
	if (error)
		goto out_free_inos;

	return 0;

out_free_inos:
	mutex_destroy(&qinf->qi_quotaofflock);
	mutex_destroy(&qinf->qi_tree_lock);
	scxfs_qm_destroy_quotainos(qinf);
out_free_lru:
	list_lru_destroy(&qinf->qi_lru);
out_free_qinf:
	kmem_free(qinf);
	mp->m_quotainfo = NULL;
	return error;
}

/*
 * Gets called when unmounting a filesystem or when all quotas get
 * turned off.
 * This purges the quota inodes, destroys locks and frees itself.
 */
void
scxfs_qm_destroy_quotainfo(
	scxfs_mount_t	*mp)
{
	scxfs_quotainfo_t *qi;

	qi = mp->m_quotainfo;
	ASSERT(qi != NULL);

	unregister_shrinker(&qi->qi_shrinker);
	list_lru_destroy(&qi->qi_lru);
	scxfs_qm_destroy_quotainos(qi);
	mutex_destroy(&qi->qi_tree_lock);
	mutex_destroy(&qi->qi_quotaofflock);
	kmem_free(qi);
	mp->m_quotainfo = NULL;
}

/*
 * Create an inode and return with a reference already taken, but unlocked
 * This is how we create quota inodes
 */
STATIC int
scxfs_qm_qino_alloc(
	scxfs_mount_t	*mp,
	scxfs_inode_t	**ip,
	uint		flags)
{
	scxfs_trans_t	*tp;
	int		error;
	bool		need_alloc = true;

	*ip = NULL;
	/*
	 * With superblock that doesn't have separate pquotino, we
	 * share an inode between gquota and pquota. If the on-disk
	 * superblock has GQUOTA and the filesystem is now mounted
	 * with PQUOTA, just use sb_gquotino for sb_pquotino and
	 * vice-versa.
	 */
	if (!scxfs_sb_version_has_pquotino(&mp->m_sb) &&
			(flags & (SCXFS_QMOPT_PQUOTA|SCXFS_QMOPT_GQUOTA))) {
		scxfs_ino_t ino = NULLFSINO;

		if ((flags & SCXFS_QMOPT_PQUOTA) &&
			     (mp->m_sb.sb_gquotino != NULLFSINO)) {
			ino = mp->m_sb.sb_gquotino;
			ASSERT(mp->m_sb.sb_pquotino == NULLFSINO);
		} else if ((flags & SCXFS_QMOPT_GQUOTA) &&
			     (mp->m_sb.sb_pquotino != NULLFSINO)) {
			ino = mp->m_sb.sb_pquotino;
			ASSERT(mp->m_sb.sb_gquotino == NULLFSINO);
		}
		if (ino != NULLFSINO) {
			error = scxfs_iget(mp, NULL, ino, 0, 0, ip);
			if (error)
				return error;
			mp->m_sb.sb_gquotino = NULLFSINO;
			mp->m_sb.sb_pquotino = NULLFSINO;
			need_alloc = false;
		}
	}

	error = scxfs_trans_alloc(mp, &M_RES(mp)->tr_create,
			SCXFS_QM_QINOCREATE_SPACE_RES(mp), 0, 0, &tp);
	if (error)
		return error;

	if (need_alloc) {
		error = scxfs_dir_ialloc(&tp, NULL, S_IFREG, 1, 0, 0, ip);
		if (error) {
			scxfs_trans_cancel(tp);
			return error;
		}
	}

	/*
	 * Make the changes in the superblock, and log those too.
	 * sbfields arg may contain fields other than *QUOTINO;
	 * VERSIONNUM for example.
	 */
	spin_lock(&mp->m_sb_lock);
	if (flags & SCXFS_QMOPT_SBVERSION) {
		ASSERT(!scxfs_sb_version_hasquota(&mp->m_sb));

		scxfs_sb_version_addquota(&mp->m_sb);
		mp->m_sb.sb_uquotino = NULLFSINO;
		mp->m_sb.sb_gquotino = NULLFSINO;
		mp->m_sb.sb_pquotino = NULLFSINO;

		/* qflags will get updated fully _after_ quotacheck */
		mp->m_sb.sb_qflags = mp->m_qflags & SCXFS_ALL_QUOTA_ACCT;
	}
	if (flags & SCXFS_QMOPT_UQUOTA)
		mp->m_sb.sb_uquotino = (*ip)->i_ino;
	else if (flags & SCXFS_QMOPT_GQUOTA)
		mp->m_sb.sb_gquotino = (*ip)->i_ino;
	else
		mp->m_sb.sb_pquotino = (*ip)->i_ino;
	spin_unlock(&mp->m_sb_lock);
	scxfs_log_sb(tp);

	error = scxfs_trans_commit(tp);
	if (error) {
		ASSERT(SCXFS_FORCED_SHUTDOWN(mp));
		scxfs_alert(mp, "%s failed (error %d)!", __func__, error);
	}
	if (need_alloc)
		scxfs_finish_inode_setup(*ip);
	return error;
}


STATIC void
scxfs_qm_reset_dqcounts(
	scxfs_mount_t	*mp,
	scxfs_buf_t	*bp,
	scxfs_dqid_t	id,
	uint		type)
{
	struct scxfs_dqblk	*dqb;
	int			j;
	scxfs_failaddr_t		fa;

	trace_scxfs_reset_dqcounts(bp, _RET_IP_);

	/*
	 * Reset all counters and timers. They'll be
	 * started afresh by scxfs_qm_quotacheck.
	 */
#ifdef DEBUG
	j = (int)SCXFS_FSB_TO_B(mp, SCXFS_DQUOT_CLUSTER_SIZE_FSB) /
		sizeof(scxfs_dqblk_t);
	ASSERT(mp->m_quotainfo->qi_dqperchunk == j);
#endif
	dqb = bp->b_addr;
	for (j = 0; j < mp->m_quotainfo->qi_dqperchunk; j++) {
		struct scxfs_disk_dquot	*ddq;

		ddq = (struct scxfs_disk_dquot *)&dqb[j];

		/*
		 * Do a sanity check, and if needed, repair the dqblk. Don't
		 * output any warnings because it's perfectly possible to
		 * find uninitialised dquot blks. See comment in
		 * scxfs_dquot_verify.
		 */
		fa = scxfs_dqblk_verify(mp, &dqb[j], id + j, type);
		if (fa)
			scxfs_dqblk_repair(mp, &dqb[j], id + j, type);

		/*
		 * Reset type in case we are reusing group quota file for
		 * project quotas or vice versa
		 */
		ddq->d_flags = type;
		ddq->d_bcount = 0;
		ddq->d_icount = 0;
		ddq->d_rtbcount = 0;
		ddq->d_btimer = 0;
		ddq->d_itimer = 0;
		ddq->d_rtbtimer = 0;
		ddq->d_bwarns = 0;
		ddq->d_iwarns = 0;
		ddq->d_rtbwarns = 0;

		if (scxfs_sb_version_hascrc(&mp->m_sb)) {
			scxfs_update_cksum((char *)&dqb[j],
					 sizeof(struct scxfs_dqblk),
					 SCXFS_DQUOT_CRC_OFF);
		}
	}
}

STATIC int
scxfs_qm_reset_dqcounts_all(
	struct scxfs_mount	*mp,
	scxfs_dqid_t		firstid,
	scxfs_fsblock_t		bno,
	scxfs_filblks_t		blkcnt,
	uint			flags,
	struct list_head	*buffer_list)
{
	struct scxfs_buf		*bp;
	int			error;
	int			type;

	ASSERT(blkcnt > 0);
	type = flags & SCXFS_QMOPT_UQUOTA ? SCXFS_DQ_USER :
		(flags & SCXFS_QMOPT_PQUOTA ? SCXFS_DQ_PROJ : SCXFS_DQ_GROUP);
	error = 0;

	/*
	 * Blkcnt arg can be a very big number, and might even be
	 * larger than the log itself. So, we have to break it up into
	 * manageable-sized transactions.
	 * Note that we don't start a permanent transaction here; we might
	 * not be able to get a log reservation for the whole thing up front,
	 * and we don't really care to either, because we just discard
	 * everything if we were to crash in the middle of this loop.
	 */
	while (blkcnt--) {
		error = scxfs_trans_read_buf(mp, NULL, mp->m_ddev_targp,
			      SCXFS_FSB_TO_DADDR(mp, bno),
			      mp->m_quotainfo->qi_dqchunklen, 0, &bp,
			      &scxfs_dquot_buf_ops);

		/*
		 * CRC and validation errors will return a EFSCORRUPTED here. If
		 * this occurs, re-read without CRC validation so that we can
		 * repair the damage via scxfs_qm_reset_dqcounts(). This process
		 * will leave a trace in the log indicating corruption has
		 * been detected.
		 */
		if (error == -EFSCORRUPTED) {
			error = scxfs_trans_read_buf(mp, NULL, mp->m_ddev_targp,
				      SCXFS_FSB_TO_DADDR(mp, bno),
				      mp->m_quotainfo->qi_dqchunklen, 0, &bp,
				      NULL);
		}

		if (error)
			break;

		/*
		 * A corrupt buffer might not have a verifier attached, so
		 * make sure we have the correct one attached before writeback
		 * occurs.
		 */
		bp->b_ops = &scxfs_dquot_buf_ops;
		scxfs_qm_reset_dqcounts(mp, bp, firstid, type);
		scxfs_buf_delwri_queue(bp, buffer_list);
		scxfs_buf_relse(bp);

		/* goto the next block. */
		bno++;
		firstid += mp->m_quotainfo->qi_dqperchunk;
	}

	return error;
}

/*
 * Iterate over all allocated dquot blocks in this quota inode, zeroing all
 * counters for every chunk of dquots that we find.
 */
STATIC int
scxfs_qm_reset_dqcounts_buf(
	struct scxfs_mount	*mp,
	struct scxfs_inode	*qip,
	uint			flags,
	struct list_head	*buffer_list)
{
	struct scxfs_bmbt_irec	*map;
	int			i, nmaps;	/* number of map entries */
	int			error;		/* return value */
	scxfs_fileoff_t		lblkno;
	scxfs_filblks_t		maxlblkcnt;
	scxfs_dqid_t		firstid;
	scxfs_fsblock_t		rablkno;
	scxfs_filblks_t		rablkcnt;

	error = 0;
	/*
	 * This looks racy, but we can't keep an inode lock across a
	 * trans_reserve. But, this gets called during quotacheck, and that
	 * happens only at mount time which is single threaded.
	 */
	if (qip->i_d.di_nblocks == 0)
		return 0;

	map = kmem_alloc(SCXFS_DQITER_MAP_SIZE * sizeof(*map), 0);

	lblkno = 0;
	maxlblkcnt = SCXFS_B_TO_FSB(mp, mp->m_super->s_maxbytes);
	do {
		uint		lock_mode;

		nmaps = SCXFS_DQITER_MAP_SIZE;
		/*
		 * We aren't changing the inode itself. Just changing
		 * some of its data. No new blocks are added here, and
		 * the inode is never added to the transaction.
		 */
		lock_mode = scxfs_ilock_data_map_shared(qip);
		error = scxfs_bmapi_read(qip, lblkno, maxlblkcnt - lblkno,
				       map, &nmaps, 0);
		scxfs_iunlock(qip, lock_mode);
		if (error)
			break;

		ASSERT(nmaps <= SCXFS_DQITER_MAP_SIZE);
		for (i = 0; i < nmaps; i++) {
			ASSERT(map[i].br_startblock != DELAYSTARTBLOCK);
			ASSERT(map[i].br_blockcount);


			lblkno += map[i].br_blockcount;

			if (map[i].br_startblock == HOLESTARTBLOCK)
				continue;

			firstid = (scxfs_dqid_t) map[i].br_startoff *
				mp->m_quotainfo->qi_dqperchunk;
			/*
			 * Do a read-ahead on the next extent.
			 */
			if ((i+1 < nmaps) &&
			    (map[i+1].br_startblock != HOLESTARTBLOCK)) {
				rablkcnt =  map[i+1].br_blockcount;
				rablkno = map[i+1].br_startblock;
				while (rablkcnt--) {
					scxfs_buf_readahead(mp->m_ddev_targp,
					       SCXFS_FSB_TO_DADDR(mp, rablkno),
					       mp->m_quotainfo->qi_dqchunklen,
					       &scxfs_dquot_buf_ops);
					rablkno++;
				}
			}
			/*
			 * Iterate thru all the blks in the extent and
			 * reset the counters of all the dquots inside them.
			 */
			error = scxfs_qm_reset_dqcounts_all(mp, firstid,
						   map[i].br_startblock,
						   map[i].br_blockcount,
						   flags, buffer_list);
			if (error)
				goto out;
		}
	} while (nmaps > 0);

out:
	kmem_free(map);
	return error;
}

/*
 * Called by dqusage_adjust in doing a quotacheck.
 *
 * Given the inode, and a dquot id this updates both the incore dqout as well
 * as the buffer copy. This is so that once the quotacheck is done, we can
 * just log all the buffers, as opposed to logging numerous updates to
 * individual dquots.
 */
STATIC int
scxfs_qm_quotacheck_dqadjust(
	struct scxfs_inode	*ip,
	uint			type,
	scxfs_qcnt_t		nblks,
	scxfs_qcnt_t		rtblks)
{
	struct scxfs_mount	*mp = ip->i_mount;
	struct scxfs_dquot	*dqp;
	scxfs_dqid_t		id;
	int			error;

	id = scxfs_qm_id_for_quotatype(ip, type);
	error = scxfs_qm_dqget(mp, id, type, true, &dqp);
	if (error) {
		/*
		 * Shouldn't be able to turn off quotas here.
		 */
		ASSERT(error != -ESRCH);
		ASSERT(error != -ENOENT);
		return error;
	}

	trace_scxfs_dqadjust(dqp);

	/*
	 * Adjust the inode count and the block count to reflect this inode's
	 * resource usage.
	 */
	be64_add_cpu(&dqp->q_core.d_icount, 1);
	dqp->q_res_icount++;
	if (nblks) {
		be64_add_cpu(&dqp->q_core.d_bcount, nblks);
		dqp->q_res_bcount += nblks;
	}
	if (rtblks) {
		be64_add_cpu(&dqp->q_core.d_rtbcount, rtblks);
		dqp->q_res_rtbcount += rtblks;
	}

	/*
	 * Set default limits, adjust timers (since we changed usages)
	 *
	 * There are no timers for the default values set in the root dquot.
	 */
	if (dqp->q_core.d_id) {
		scxfs_qm_adjust_dqlimits(mp, dqp);
		scxfs_qm_adjust_dqtimers(mp, &dqp->q_core);
	}

	dqp->dq_flags |= SCXFS_DQ_DIRTY;
	scxfs_qm_dqput(dqp);
	return 0;
}

/*
 * callback routine supplied to bulkstat(). Given an inumber, find its
 * dquots and update them to account for resources taken by that inode.
 */
/* ARGSUSED */
STATIC int
scxfs_qm_dqusage_adjust(
	struct scxfs_mount	*mp,
	struct scxfs_trans	*tp,
	scxfs_ino_t		ino,
	void			*data)
{
	struct scxfs_inode	*ip;
	scxfs_qcnt_t		nblks;
	scxfs_filblks_t		rtblks = 0;	/* total rt blks */
	int			error;

	ASSERT(SCXFS_IS_QUOTA_RUNNING(mp));

	/*
	 * rootino must have its resources accounted for, not so with the quota
	 * inodes.
	 */
	if (scxfs_is_quota_inode(&mp->m_sb, ino))
		return 0;

	/*
	 * We don't _need_ to take the ilock EXCL here because quotacheck runs
	 * at mount time and therefore nobody will be racing chown/chproj.
	 */
	error = scxfs_iget(mp, tp, ino, SCXFS_IGET_DONTCACHE, 0, &ip);
	if (error == -EINVAL || error == -ENOENT)
		return 0;
	if (error)
		return error;

	ASSERT(ip->i_delayed_blks == 0);

	if (SCXFS_IS_REALTIME_INODE(ip)) {
		struct scxfs_ifork	*ifp = SCXFS_IFORK_PTR(ip, SCXFS_DATA_FORK);

		if (!(ifp->if_flags & SCXFS_IFEXTENTS)) {
			error = scxfs_iread_extents(tp, ip, SCXFS_DATA_FORK);
			if (error)
				goto error0;
		}

		scxfs_bmap_count_leaves(ifp, &rtblks);
	}

	nblks = (scxfs_qcnt_t)ip->i_d.di_nblocks - rtblks;

	/*
	 * Add the (disk blocks and inode) resources occupied by this
	 * inode to its dquots. We do this adjustment in the incore dquot,
	 * and also copy the changes to its buffer.
	 * We don't care about putting these changes in a transaction
	 * envelope because if we crash in the middle of a 'quotacheck'
	 * we have to start from the beginning anyway.
	 * Once we're done, we'll log all the dquot bufs.
	 *
	 * The *QUOTA_ON checks below may look pretty racy, but quotachecks
	 * and quotaoffs don't race. (Quotachecks happen at mount time only).
	 */
	if (SCXFS_IS_UQUOTA_ON(mp)) {
		error = scxfs_qm_quotacheck_dqadjust(ip, SCXFS_DQ_USER, nblks,
				rtblks);
		if (error)
			goto error0;
	}

	if (SCXFS_IS_GQUOTA_ON(mp)) {
		error = scxfs_qm_quotacheck_dqadjust(ip, SCXFS_DQ_GROUP, nblks,
				rtblks);
		if (error)
			goto error0;
	}

	if (SCXFS_IS_PQUOTA_ON(mp)) {
		error = scxfs_qm_quotacheck_dqadjust(ip, SCXFS_DQ_PROJ, nblks,
				rtblks);
		if (error)
			goto error0;
	}

error0:
	scxfs_irele(ip);
	return error;
}

STATIC int
scxfs_qm_flush_one(
	struct scxfs_dquot	*dqp,
	void			*data)
{
	struct scxfs_mount	*mp = dqp->q_mount;
	struct list_head	*buffer_list = data;
	struct scxfs_buf		*bp = NULL;
	int			error = 0;

	scxfs_dqlock(dqp);
	if (dqp->dq_flags & SCXFS_DQ_FREEING)
		goto out_unlock;
	if (!SCXFS_DQ_IS_DIRTY(dqp))
		goto out_unlock;

	/*
	 * The only way the dquot is already flush locked by the time quotacheck
	 * gets here is if reclaim flushed it before the dqadjust walk dirtied
	 * it for the final time. Quotacheck collects all dquot bufs in the
	 * local delwri queue before dquots are dirtied, so reclaim can't have
	 * possibly queued it for I/O. The only way out is to push the buffer to
	 * cycle the flush lock.
	 */
	if (!scxfs_dqflock_nowait(dqp)) {
		/* buf is pinned in-core by delwri list */
		bp = scxfs_buf_incore(mp->m_ddev_targp, dqp->q_blkno,
				mp->m_quotainfo->qi_dqchunklen, 0);
		if (!bp) {
			error = -EINVAL;
			goto out_unlock;
		}
		scxfs_buf_unlock(bp);

		scxfs_buf_delwri_pushbuf(bp, buffer_list);
		scxfs_buf_rele(bp);

		error = -EAGAIN;
		goto out_unlock;
	}

	error = scxfs_qm_dqflush(dqp, &bp);
	if (error)
		goto out_unlock;

	scxfs_buf_delwri_queue(bp, buffer_list);
	scxfs_buf_relse(bp);
out_unlock:
	scxfs_dqunlock(dqp);
	return error;
}

/*
 * Walk thru all the filesystem inodes and construct a consistent view
 * of the disk quota world. If the quotacheck fails, disable quotas.
 */
STATIC int
scxfs_qm_quotacheck(
	scxfs_mount_t	*mp)
{
	int			error, error2;
	uint			flags;
	LIST_HEAD		(buffer_list);
	struct scxfs_inode	*uip = mp->m_quotainfo->qi_uquotaip;
	struct scxfs_inode	*gip = mp->m_quotainfo->qi_gquotaip;
	struct scxfs_inode	*pip = mp->m_quotainfo->qi_pquotaip;

	flags = 0;

	ASSERT(uip || gip || pip);
	ASSERT(SCXFS_IS_QUOTA_RUNNING(mp));

	scxfs_notice(mp, "Quotacheck needed: Please wait.");

	/*
	 * First we go thru all the dquots on disk, USR and GRP/PRJ, and reset
	 * their counters to zero. We need a clean slate.
	 * We don't log our changes till later.
	 */
	if (uip) {
		error = scxfs_qm_reset_dqcounts_buf(mp, uip, SCXFS_QMOPT_UQUOTA,
					 &buffer_list);
		if (error)
			goto error_return;
		flags |= SCXFS_UQUOTA_CHKD;
	}

	if (gip) {
		error = scxfs_qm_reset_dqcounts_buf(mp, gip, SCXFS_QMOPT_GQUOTA,
					 &buffer_list);
		if (error)
			goto error_return;
		flags |= SCXFS_GQUOTA_CHKD;
	}

	if (pip) {
		error = scxfs_qm_reset_dqcounts_buf(mp, pip, SCXFS_QMOPT_PQUOTA,
					 &buffer_list);
		if (error)
			goto error_return;
		flags |= SCXFS_PQUOTA_CHKD;
	}

	error = scxfs_iwalk_threaded(mp, 0, 0, scxfs_qm_dqusage_adjust, 0, true,
			NULL);
	if (error)
		goto error_return;

	/*
	 * We've made all the changes that we need to make incore.  Flush them
	 * down to disk buffers if everything was updated successfully.
	 */
	if (SCXFS_IS_UQUOTA_ON(mp)) {
		error = scxfs_qm_dquot_walk(mp, SCXFS_DQ_USER, scxfs_qm_flush_one,
					  &buffer_list);
	}
	if (SCXFS_IS_GQUOTA_ON(mp)) {
		error2 = scxfs_qm_dquot_walk(mp, SCXFS_DQ_GROUP, scxfs_qm_flush_one,
					   &buffer_list);
		if (!error)
			error = error2;
	}
	if (SCXFS_IS_PQUOTA_ON(mp)) {
		error2 = scxfs_qm_dquot_walk(mp, SCXFS_DQ_PROJ, scxfs_qm_flush_one,
					   &buffer_list);
		if (!error)
			error = error2;
	}

	error2 = scxfs_buf_delwri_submit(&buffer_list);
	if (!error)
		error = error2;

	/*
	 * We can get this error if we couldn't do a dquot allocation inside
	 * scxfs_qm_dqusage_adjust (via bulkstat). We don't care about the
	 * dirty dquots that might be cached, we just want to get rid of them
	 * and turn quotaoff. The dquots won't be attached to any of the inodes
	 * at this point (because we intentionally didn't in dqget_noattach).
	 */
	if (error) {
		scxfs_qm_dqpurge_all(mp, SCXFS_QMOPT_QUOTALL);
		goto error_return;
	}

	/*
	 * If one type of quotas is off, then it will lose its
	 * quotachecked status, since we won't be doing accounting for
	 * that type anymore.
	 */
	mp->m_qflags &= ~SCXFS_ALL_QUOTA_CHKD;
	mp->m_qflags |= flags;

 error_return:
	scxfs_buf_delwri_cancel(&buffer_list);

	if (error) {
		scxfs_warn(mp,
	"Quotacheck: Unsuccessful (Error %d): Disabling quotas.",
			error);
		/*
		 * We must turn off quotas.
		 */
		ASSERT(mp->m_quotainfo != NULL);
		scxfs_qm_destroy_quotainfo(mp);
		if (scxfs_mount_reset_sbqflags(mp)) {
			scxfs_warn(mp,
				"Quotacheck: Failed to reset quota flags.");
		}
	} else
		scxfs_notice(mp, "Quotacheck: Done.");
	return error;
}

/*
 * This is called from scxfs_mountfs to start quotas and initialize all
 * necessary data structures like quotainfo.  This is also responsible for
 * running a quotacheck as necessary.  We are guaranteed that the superblock
 * is consistently read in at this point.
 *
 * If we fail here, the mount will continue with quota turned off. We don't
 * need to inidicate success or failure at all.
 */
void
scxfs_qm_mount_quotas(
	struct scxfs_mount	*mp)
{
	int			error = 0;
	uint			sbf;

	/*
	 * If quotas on realtime volumes is not supported, we disable
	 * quotas immediately.
	 */
	if (mp->m_sb.sb_rextents) {
		scxfs_notice(mp, "Cannot turn on quotas for realtime filesystem");
		mp->m_qflags = 0;
		goto write_changes;
	}

	ASSERT(SCXFS_IS_QUOTA_RUNNING(mp));

	/*
	 * Allocate the quotainfo structure inside the mount struct, and
	 * create quotainode(s), and change/rev superblock if necessary.
	 */
	error = scxfs_qm_init_quotainfo(mp);
	if (error) {
		/*
		 * We must turn off quotas.
		 */
		ASSERT(mp->m_quotainfo == NULL);
		mp->m_qflags = 0;
		goto write_changes;
	}
	/*
	 * If any of the quotas are not consistent, do a quotacheck.
	 */
	if (SCXFS_QM_NEED_QUOTACHECK(mp)) {
		error = scxfs_qm_quotacheck(mp);
		if (error) {
			/* Quotacheck failed and disabled quotas. */
			return;
		}
	}
	/*
	 * If one type of quotas is off, then it will lose its
	 * quotachecked status, since we won't be doing accounting for
	 * that type anymore.
	 */
	if (!SCXFS_IS_UQUOTA_ON(mp))
		mp->m_qflags &= ~SCXFS_UQUOTA_CHKD;
	if (!SCXFS_IS_GQUOTA_ON(mp))
		mp->m_qflags &= ~SCXFS_GQUOTA_CHKD;
	if (!SCXFS_IS_PQUOTA_ON(mp))
		mp->m_qflags &= ~SCXFS_PQUOTA_CHKD;

 write_changes:
	/*
	 * We actually don't have to acquire the m_sb_lock at all.
	 * This can only be called from mount, and that's single threaded. XXX
	 */
	spin_lock(&mp->m_sb_lock);
	sbf = mp->m_sb.sb_qflags;
	mp->m_sb.sb_qflags = mp->m_qflags & SCXFS_MOUNT_QUOTA_ALL;
	spin_unlock(&mp->m_sb_lock);

	if (sbf != (mp->m_qflags & SCXFS_MOUNT_QUOTA_ALL)) {
		if (scxfs_sync_sb(mp, false)) {
			/*
			 * We could only have been turning quotas off.
			 * We aren't in very good shape actually because
			 * the incore structures are convinced that quotas are
			 * off, but the on disk superblock doesn't know that !
			 */
			ASSERT(!(SCXFS_IS_QUOTA_RUNNING(mp)));
			scxfs_alert(mp, "%s: Superblock update failed!",
				__func__);
		}
	}

	if (error) {
		scxfs_warn(mp, "Failed to initialize disk quotas.");
		return;
	}
}

/*
 * This is called after the superblock has been read in and we're ready to
 * iget the quota inodes.
 */
STATIC int
scxfs_qm_init_quotainos(
	scxfs_mount_t	*mp)
{
	struct scxfs_inode	*uip = NULL;
	struct scxfs_inode	*gip = NULL;
	struct scxfs_inode	*pip = NULL;
	int			error;
	uint			flags = 0;

	ASSERT(mp->m_quotainfo);

	/*
	 * Get the uquota and gquota inodes
	 */
	if (scxfs_sb_version_hasquota(&mp->m_sb)) {
		if (SCXFS_IS_UQUOTA_ON(mp) &&
		    mp->m_sb.sb_uquotino != NULLFSINO) {
			ASSERT(mp->m_sb.sb_uquotino > 0);
			error = scxfs_iget(mp, NULL, mp->m_sb.sb_uquotino,
					     0, 0, &uip);
			if (error)
				return error;
		}
		if (SCXFS_IS_GQUOTA_ON(mp) &&
		    mp->m_sb.sb_gquotino != NULLFSINO) {
			ASSERT(mp->m_sb.sb_gquotino > 0);
			error = scxfs_iget(mp, NULL, mp->m_sb.sb_gquotino,
					     0, 0, &gip);
			if (error)
				goto error_rele;
		}
		if (SCXFS_IS_PQUOTA_ON(mp) &&
		    mp->m_sb.sb_pquotino != NULLFSINO) {
			ASSERT(mp->m_sb.sb_pquotino > 0);
			error = scxfs_iget(mp, NULL, mp->m_sb.sb_pquotino,
					     0, 0, &pip);
			if (error)
				goto error_rele;
		}
	} else {
		flags |= SCXFS_QMOPT_SBVERSION;
	}

	/*
	 * Create the three inodes, if they don't exist already. The changes
	 * made above will get added to a transaction and logged in one of
	 * the qino_alloc calls below.  If the device is readonly,
	 * temporarily switch to read-write to do this.
	 */
	if (SCXFS_IS_UQUOTA_ON(mp) && uip == NULL) {
		error = scxfs_qm_qino_alloc(mp, &uip,
					      flags | SCXFS_QMOPT_UQUOTA);
		if (error)
			goto error_rele;

		flags &= ~SCXFS_QMOPT_SBVERSION;
	}
	if (SCXFS_IS_GQUOTA_ON(mp) && gip == NULL) {
		error = scxfs_qm_qino_alloc(mp, &gip,
					  flags | SCXFS_QMOPT_GQUOTA);
		if (error)
			goto error_rele;

		flags &= ~SCXFS_QMOPT_SBVERSION;
	}
	if (SCXFS_IS_PQUOTA_ON(mp) && pip == NULL) {
		error = scxfs_qm_qino_alloc(mp, &pip,
					  flags | SCXFS_QMOPT_PQUOTA);
		if (error)
			goto error_rele;
	}

	mp->m_quotainfo->qi_uquotaip = uip;
	mp->m_quotainfo->qi_gquotaip = gip;
	mp->m_quotainfo->qi_pquotaip = pip;

	return 0;

error_rele:
	if (uip)
		scxfs_irele(uip);
	if (gip)
		scxfs_irele(gip);
	if (pip)
		scxfs_irele(pip);
	return error;
}

STATIC void
scxfs_qm_destroy_quotainos(
	scxfs_quotainfo_t	*qi)
{
	if (qi->qi_uquotaip) {
		scxfs_irele(qi->qi_uquotaip);
		qi->qi_uquotaip = NULL; /* paranoia */
	}
	if (qi->qi_gquotaip) {
		scxfs_irele(qi->qi_gquotaip);
		qi->qi_gquotaip = NULL;
	}
	if (qi->qi_pquotaip) {
		scxfs_irele(qi->qi_pquotaip);
		qi->qi_pquotaip = NULL;
	}
}

STATIC void
scxfs_qm_dqfree_one(
	struct scxfs_dquot	*dqp)
{
	struct scxfs_mount	*mp = dqp->q_mount;
	struct scxfs_quotainfo	*qi = mp->m_quotainfo;

	mutex_lock(&qi->qi_tree_lock);
	radix_tree_delete(scxfs_dquot_tree(qi, dqp->q_core.d_flags),
			  be32_to_cpu(dqp->q_core.d_id));

	qi->qi_dquots--;
	mutex_unlock(&qi->qi_tree_lock);

	scxfs_qm_dqdestroy(dqp);
}

/* --------------- utility functions for vnodeops ---------------- */


/*
 * Given an inode, a uid, gid and prid make sure that we have
 * allocated relevant dquot(s) on disk, and that we won't exceed inode
 * quotas by creating this file.
 * This also attaches dquot(s) to the given inode after locking it,
 * and returns the dquots corresponding to the uid and/or gid.
 *
 * in	: inode (unlocked)
 * out	: udquot, gdquot with references taken and unlocked
 */
int
scxfs_qm_vop_dqalloc(
	struct scxfs_inode	*ip,
	scxfs_dqid_t		uid,
	scxfs_dqid_t		gid,
	prid_t			prid,
	uint			flags,
	struct scxfs_dquot	**O_udqpp,
	struct scxfs_dquot	**O_gdqpp,
	struct scxfs_dquot	**O_pdqpp)
{
	struct scxfs_mount	*mp = ip->i_mount;
	struct scxfs_dquot	*uq = NULL;
	struct scxfs_dquot	*gq = NULL;
	struct scxfs_dquot	*pq = NULL;
	int			error;
	uint			lockflags;

	if (!SCXFS_IS_QUOTA_RUNNING(mp) || !SCXFS_IS_QUOTA_ON(mp))
		return 0;

	lockflags = SCXFS_ILOCK_EXCL;
	scxfs_ilock(ip, lockflags);

	if ((flags & SCXFS_QMOPT_INHERIT) && SCXFS_INHERIT_GID(ip))
		gid = ip->i_d.di_gid;

	/*
	 * Attach the dquot(s) to this inode, doing a dquot allocation
	 * if necessary. The dquot(s) will not be locked.
	 */
	if (SCXFS_NOT_DQATTACHED(mp, ip)) {
		error = scxfs_qm_dqattach_locked(ip, true);
		if (error) {
			scxfs_iunlock(ip, lockflags);
			return error;
		}
	}

	if ((flags & SCXFS_QMOPT_UQUOTA) && SCXFS_IS_UQUOTA_ON(mp)) {
		if (ip->i_d.di_uid != uid) {
			/*
			 * What we need is the dquot that has this uid, and
			 * if we send the inode to dqget, the uid of the inode
			 * takes priority over what's sent in the uid argument.
			 * We must unlock inode here before calling dqget if
			 * we're not sending the inode, because otherwise
			 * we'll deadlock by doing trans_reserve while
			 * holding ilock.
			 */
			scxfs_iunlock(ip, lockflags);
			error = scxfs_qm_dqget(mp, uid, SCXFS_DQ_USER, true, &uq);
			if (error) {
				ASSERT(error != -ENOENT);
				return error;
			}
			/*
			 * Get the ilock in the right order.
			 */
			scxfs_dqunlock(uq);
			lockflags = SCXFS_ILOCK_SHARED;
			scxfs_ilock(ip, lockflags);
		} else {
			/*
			 * Take an extra reference, because we'll return
			 * this to caller
			 */
			ASSERT(ip->i_udquot);
			uq = scxfs_qm_dqhold(ip->i_udquot);
		}
	}
	if ((flags & SCXFS_QMOPT_GQUOTA) && SCXFS_IS_GQUOTA_ON(mp)) {
		if (ip->i_d.di_gid != gid) {
			scxfs_iunlock(ip, lockflags);
			error = scxfs_qm_dqget(mp, gid, SCXFS_DQ_GROUP, true, &gq);
			if (error) {
				ASSERT(error != -ENOENT);
				goto error_rele;
			}
			scxfs_dqunlock(gq);
			lockflags = SCXFS_ILOCK_SHARED;
			scxfs_ilock(ip, lockflags);
		} else {
			ASSERT(ip->i_gdquot);
			gq = scxfs_qm_dqhold(ip->i_gdquot);
		}
	}
	if ((flags & SCXFS_QMOPT_PQUOTA) && SCXFS_IS_PQUOTA_ON(mp)) {
		if (scxfs_get_projid(ip) != prid) {
			scxfs_iunlock(ip, lockflags);
			error = scxfs_qm_dqget(mp, (scxfs_dqid_t)prid, SCXFS_DQ_PROJ,
					true, &pq);
			if (error) {
				ASSERT(error != -ENOENT);
				goto error_rele;
			}
			scxfs_dqunlock(pq);
			lockflags = SCXFS_ILOCK_SHARED;
			scxfs_ilock(ip, lockflags);
		} else {
			ASSERT(ip->i_pdquot);
			pq = scxfs_qm_dqhold(ip->i_pdquot);
		}
	}
	if (uq)
		trace_scxfs_dquot_dqalloc(ip);

	scxfs_iunlock(ip, lockflags);
	if (O_udqpp)
		*O_udqpp = uq;
	else
		scxfs_qm_dqrele(uq);
	if (O_gdqpp)
		*O_gdqpp = gq;
	else
		scxfs_qm_dqrele(gq);
	if (O_pdqpp)
		*O_pdqpp = pq;
	else
		scxfs_qm_dqrele(pq);
	return 0;

error_rele:
	scxfs_qm_dqrele(gq);
	scxfs_qm_dqrele(uq);
	return error;
}

/*
 * Actually transfer ownership, and do dquot modifications.
 * These were already reserved.
 */
scxfs_dquot_t *
scxfs_qm_vop_chown(
	scxfs_trans_t	*tp,
	scxfs_inode_t	*ip,
	scxfs_dquot_t	**IO_olddq,
	scxfs_dquot_t	*newdq)
{
	scxfs_dquot_t	*prevdq;
	uint		bfield = SCXFS_IS_REALTIME_INODE(ip) ?
				 SCXFS_TRANS_DQ_RTBCOUNT : SCXFS_TRANS_DQ_BCOUNT;


	ASSERT(scxfs_isilocked(ip, SCXFS_ILOCK_EXCL));
	ASSERT(SCXFS_IS_QUOTA_RUNNING(ip->i_mount));

	/* old dquot */
	prevdq = *IO_olddq;
	ASSERT(prevdq);
	ASSERT(prevdq != newdq);

	scxfs_trans_mod_dquot(tp, prevdq, bfield, -(ip->i_d.di_nblocks));
	scxfs_trans_mod_dquot(tp, prevdq, SCXFS_TRANS_DQ_ICOUNT, -1);

	/* the sparkling new dquot */
	scxfs_trans_mod_dquot(tp, newdq, bfield, ip->i_d.di_nblocks);
	scxfs_trans_mod_dquot(tp, newdq, SCXFS_TRANS_DQ_ICOUNT, 1);

	/*
	 * Take an extra reference, because the inode is going to keep
	 * this dquot pointer even after the trans_commit.
	 */
	*IO_olddq = scxfs_qm_dqhold(newdq);

	return prevdq;
}

/*
 * Quota reservations for setattr(AT_UID|AT_GID|AT_PROJID).
 */
int
scxfs_qm_vop_chown_reserve(
	struct scxfs_trans	*tp,
	struct scxfs_inode	*ip,
	struct scxfs_dquot	*udqp,
	struct scxfs_dquot	*gdqp,
	struct scxfs_dquot	*pdqp,
	uint			flags)
{
	struct scxfs_mount	*mp = ip->i_mount;
	uint64_t		delblks;
	unsigned int		blkflags, prjflags = 0;
	struct scxfs_dquot	*udq_unres = NULL;
	struct scxfs_dquot	*gdq_unres = NULL;
	struct scxfs_dquot	*pdq_unres = NULL;
	struct scxfs_dquot	*udq_delblks = NULL;
	struct scxfs_dquot	*gdq_delblks = NULL;
	struct scxfs_dquot	*pdq_delblks = NULL;
	int			error;


	ASSERT(scxfs_isilocked(ip, SCXFS_ILOCK_EXCL|SCXFS_ILOCK_SHARED));
	ASSERT(SCXFS_IS_QUOTA_RUNNING(mp));

	delblks = ip->i_delayed_blks;
	blkflags = SCXFS_IS_REALTIME_INODE(ip) ?
			SCXFS_QMOPT_RES_RTBLKS : SCXFS_QMOPT_RES_REGBLKS;

	if (SCXFS_IS_UQUOTA_ON(mp) && udqp &&
	    ip->i_d.di_uid != be32_to_cpu(udqp->q_core.d_id)) {
		udq_delblks = udqp;
		/*
		 * If there are delayed allocation blocks, then we have to
		 * unreserve those from the old dquot, and add them to the
		 * new dquot.
		 */
		if (delblks) {
			ASSERT(ip->i_udquot);
			udq_unres = ip->i_udquot;
		}
	}
	if (SCXFS_IS_GQUOTA_ON(ip->i_mount) && gdqp &&
	    ip->i_d.di_gid != be32_to_cpu(gdqp->q_core.d_id)) {
		gdq_delblks = gdqp;
		if (delblks) {
			ASSERT(ip->i_gdquot);
			gdq_unres = ip->i_gdquot;
		}
	}

	if (SCXFS_IS_PQUOTA_ON(ip->i_mount) && pdqp &&
	    scxfs_get_projid(ip) != be32_to_cpu(pdqp->q_core.d_id)) {
		prjflags = SCXFS_QMOPT_ENOSPC;
		pdq_delblks = pdqp;
		if (delblks) {
			ASSERT(ip->i_pdquot);
			pdq_unres = ip->i_pdquot;
		}
	}

	error = scxfs_trans_reserve_quota_bydquots(tp, ip->i_mount,
				udq_delblks, gdq_delblks, pdq_delblks,
				ip->i_d.di_nblocks, 1,
				flags | blkflags | prjflags);
	if (error)
		return error;

	/*
	 * Do the delayed blks reservations/unreservations now. Since, these
	 * are done without the help of a transaction, if a reservation fails
	 * its previous reservations won't be automatically undone by trans
	 * code. So, we have to do it manually here.
	 */
	if (delblks) {
		/*
		 * Do the reservations first. Unreservation can't fail.
		 */
		ASSERT(udq_delblks || gdq_delblks || pdq_delblks);
		ASSERT(udq_unres || gdq_unres || pdq_unres);
		error = scxfs_trans_reserve_quota_bydquots(NULL, ip->i_mount,
			    udq_delblks, gdq_delblks, pdq_delblks,
			    (scxfs_qcnt_t)delblks, 0,
			    flags | blkflags | prjflags);
		if (error)
			return error;
		scxfs_trans_reserve_quota_bydquots(NULL, ip->i_mount,
				udq_unres, gdq_unres, pdq_unres,
				-((scxfs_qcnt_t)delblks), 0, blkflags);
	}

	return 0;
}

int
scxfs_qm_vop_rename_dqattach(
	struct scxfs_inode	**i_tab)
{
	struct scxfs_mount	*mp = i_tab[0]->i_mount;
	int			i;

	if (!SCXFS_IS_QUOTA_RUNNING(mp) || !SCXFS_IS_QUOTA_ON(mp))
		return 0;

	for (i = 0; (i < 4 && i_tab[i]); i++) {
		struct scxfs_inode	*ip = i_tab[i];
		int			error;

		/*
		 * Watch out for duplicate entries in the table.
		 */
		if (i == 0 || ip != i_tab[i-1]) {
			if (SCXFS_NOT_DQATTACHED(mp, ip)) {
				error = scxfs_qm_dqattach(ip);
				if (error)
					return error;
			}
		}
	}
	return 0;
}

void
scxfs_qm_vop_create_dqattach(
	struct scxfs_trans	*tp,
	struct scxfs_inode	*ip,
	struct scxfs_dquot	*udqp,
	struct scxfs_dquot	*gdqp,
	struct scxfs_dquot	*pdqp)
{
	struct scxfs_mount	*mp = tp->t_mountp;

	if (!SCXFS_IS_QUOTA_RUNNING(mp) || !SCXFS_IS_QUOTA_ON(mp))
		return;

	ASSERT(scxfs_isilocked(ip, SCXFS_ILOCK_EXCL));
	ASSERT(SCXFS_IS_QUOTA_RUNNING(mp));

	if (udqp && SCXFS_IS_UQUOTA_ON(mp)) {
		ASSERT(ip->i_udquot == NULL);
		ASSERT(ip->i_d.di_uid == be32_to_cpu(udqp->q_core.d_id));

		ip->i_udquot = scxfs_qm_dqhold(udqp);
		scxfs_trans_mod_dquot(tp, udqp, SCXFS_TRANS_DQ_ICOUNT, 1);
	}
	if (gdqp && SCXFS_IS_GQUOTA_ON(mp)) {
		ASSERT(ip->i_gdquot == NULL);
		ASSERT(ip->i_d.di_gid == be32_to_cpu(gdqp->q_core.d_id));
		ip->i_gdquot = scxfs_qm_dqhold(gdqp);
		scxfs_trans_mod_dquot(tp, gdqp, SCXFS_TRANS_DQ_ICOUNT, 1);
	}
	if (pdqp && SCXFS_IS_PQUOTA_ON(mp)) {
		ASSERT(ip->i_pdquot == NULL);
		ASSERT(scxfs_get_projid(ip) == be32_to_cpu(pdqp->q_core.d_id));

		ip->i_pdquot = scxfs_qm_dqhold(pdqp);
		scxfs_trans_mod_dquot(tp, pdqp, SCXFS_TRANS_DQ_ICOUNT, 1);
	}
}

