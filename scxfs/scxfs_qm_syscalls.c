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
#include "scxfs_quota.h"
#include "scxfs_qm.h"
#include "scxfs_icache.h"

STATIC int	scxfs_qm_log_quotaoff(scxfs_mount_t *, scxfs_qoff_logitem_t **, uint);
STATIC int	scxfs_qm_log_quotaoff_end(scxfs_mount_t *, scxfs_qoff_logitem_t *,
					uint);

/*
 * Turn off quota accounting and/or enforcement for all udquots and/or
 * gdquots. Called only at unmount time.
 *
 * This assumes that there are no dquots of this file system cached
 * incore, and modifies the ondisk dquot directly. Therefore, for example,
 * it is an error to call this twice, without purging the cache.
 */
int
scxfs_qm_scall_quotaoff(
	scxfs_mount_t		*mp,
	uint			flags)
{
	struct scxfs_quotainfo	*q = mp->m_quotainfo;
	uint			dqtype;
	int			error;
	uint			inactivate_flags;
	scxfs_qoff_logitem_t	*qoffstart;

	/*
	 * No file system can have quotas enabled on disk but not in core.
	 * Note that quota utilities (like quotaoff) _expect_
	 * errno == -EEXIST here.
	 */
	if ((mp->m_qflags & flags) == 0)
		return -EEXIST;
	error = 0;

	flags &= (SCXFS_ALL_QUOTA_ACCT | SCXFS_ALL_QUOTA_ENFD);

	/*
	 * We don't want to deal with two quotaoffs messing up each other,
	 * so we're going to serialize it. quotaoff isn't exactly a performance
	 * critical thing.
	 * If quotaoff, then we must be dealing with the root filesystem.
	 */
	ASSERT(q);
	mutex_lock(&q->qi_quotaofflock);

	/*
	 * If we're just turning off quota enforcement, change mp and go.
	 */
	if ((flags & SCXFS_ALL_QUOTA_ACCT) == 0) {
		mp->m_qflags &= ~(flags);

		spin_lock(&mp->m_sb_lock);
		mp->m_sb.sb_qflags = mp->m_qflags;
		spin_unlock(&mp->m_sb_lock);
		mutex_unlock(&q->qi_quotaofflock);

		/* XXX what to do if error ? Revert back to old vals incore ? */
		return scxfs_sync_sb(mp, false);
	}

	dqtype = 0;
	inactivate_flags = 0;
	/*
	 * If accounting is off, we must turn enforcement off, clear the
	 * quota 'CHKD' certificate to make it known that we have to
	 * do a quotacheck the next time this quota is turned on.
	 */
	if (flags & SCXFS_UQUOTA_ACCT) {
		dqtype |= SCXFS_QMOPT_UQUOTA;
		flags |= (SCXFS_UQUOTA_CHKD | SCXFS_UQUOTA_ENFD);
		inactivate_flags |= SCXFS_UQUOTA_ACTIVE;
	}
	if (flags & SCXFS_GQUOTA_ACCT) {
		dqtype |= SCXFS_QMOPT_GQUOTA;
		flags |= (SCXFS_GQUOTA_CHKD | SCXFS_GQUOTA_ENFD);
		inactivate_flags |= SCXFS_GQUOTA_ACTIVE;
	}
	if (flags & SCXFS_PQUOTA_ACCT) {
		dqtype |= SCXFS_QMOPT_PQUOTA;
		flags |= (SCXFS_PQUOTA_CHKD | SCXFS_PQUOTA_ENFD);
		inactivate_flags |= SCXFS_PQUOTA_ACTIVE;
	}

	/*
	 * Nothing to do?  Don't complain. This happens when we're just
	 * turning off quota enforcement.
	 */
	if ((mp->m_qflags & flags) == 0)
		goto out_unlock;

	/*
	 * Write the LI_QUOTAOFF log record, and do SB changes atomically,
	 * and synchronously. If we fail to write, we should abort the
	 * operation as it cannot be recovered safely if we crash.
	 */
	error = scxfs_qm_log_quotaoff(mp, &qoffstart, flags);
	if (error)
		goto out_unlock;

	/*
	 * Next we clear the SCXFS_MOUNT_*DQ_ACTIVE bit(s) in the mount struct
	 * to take care of the race between dqget and quotaoff. We don't take
	 * any special locks to reset these bits. All processes need to check
	 * these bits *after* taking inode lock(s) to see if the particular
	 * quota type is in the process of being turned off. If *ACTIVE, it is
	 * guaranteed that all dquot structures and all quotainode ptrs will all
	 * stay valid as long as that inode is kept locked.
	 *
	 * There is no turning back after this.
	 */
	mp->m_qflags &= ~inactivate_flags;

	/*
	 * Give back all the dquot reference(s) held by inodes.
	 * Here we go thru every single incore inode in this file system, and
	 * do a dqrele on the i_udquot/i_gdquot that it may have.
	 * Essentially, as long as somebody has an inode locked, this guarantees
	 * that quotas will not be turned off. This is handy because in a
	 * transaction once we lock the inode(s) and check for quotaon, we can
	 * depend on the quota inodes (and other things) being valid as long as
	 * we keep the lock(s).
	 */
	scxfs_qm_dqrele_all_inodes(mp, flags);

	/*
	 * Next we make the changes in the quota flag in the mount struct.
	 * This isn't protected by a particular lock directly, because we
	 * don't want to take a mrlock every time we depend on quotas being on.
	 */
	mp->m_qflags &= ~flags;

	/*
	 * Go through all the dquots of this file system and purge them,
	 * according to what was turned off.
	 */
	scxfs_qm_dqpurge_all(mp, dqtype);

	/*
	 * Transactions that had started before ACTIVE state bit was cleared
	 * could have logged many dquots, so they'd have higher LSNs than
	 * the first QUOTAOFF log record does. If we happen to crash when
	 * the tail of the log has gone past the QUOTAOFF record, but
	 * before the last dquot modification, those dquots __will__
	 * recover, and that's not good.
	 *
	 * So, we have QUOTAOFF start and end logitems; the start
	 * logitem won't get overwritten until the end logitem appears...
	 */
	error = scxfs_qm_log_quotaoff_end(mp, qoffstart, flags);
	if (error) {
		/* We're screwed now. Shutdown is the only option. */
		scxfs_force_shutdown(mp, SHUTDOWN_CORRUPT_INCORE);
		goto out_unlock;
	}

	/*
	 * If all quotas are completely turned off, close shop.
	 */
	if (mp->m_qflags == 0) {
		mutex_unlock(&q->qi_quotaofflock);
		scxfs_qm_destroy_quotainfo(mp);
		return 0;
	}

	/*
	 * Release our quotainode references if we don't need them anymore.
	 */
	if ((dqtype & SCXFS_QMOPT_UQUOTA) && q->qi_uquotaip) {
		scxfs_irele(q->qi_uquotaip);
		q->qi_uquotaip = NULL;
	}
	if ((dqtype & SCXFS_QMOPT_GQUOTA) && q->qi_gquotaip) {
		scxfs_irele(q->qi_gquotaip);
		q->qi_gquotaip = NULL;
	}
	if ((dqtype & SCXFS_QMOPT_PQUOTA) && q->qi_pquotaip) {
		scxfs_irele(q->qi_pquotaip);
		q->qi_pquotaip = NULL;
	}

out_unlock:
	mutex_unlock(&q->qi_quotaofflock);
	return error;
}

STATIC int
scxfs_qm_scall_trunc_qfile(
	struct scxfs_mount	*mp,
	scxfs_ino_t		ino)
{
	struct scxfs_inode	*ip;
	struct scxfs_trans	*tp;
	int			error;

	if (ino == NULLFSINO)
		return 0;

	error = scxfs_iget(mp, NULL, ino, 0, 0, &ip);
	if (error)
		return error;

	scxfs_ilock(ip, SCXFS_IOLOCK_EXCL);

	error = scxfs_trans_alloc(mp, &M_RES(mp)->tr_itruncate, 0, 0, 0, &tp);
	if (error) {
		scxfs_iunlock(ip, SCXFS_IOLOCK_EXCL);
		goto out_put;
	}

	scxfs_ilock(ip, SCXFS_ILOCK_EXCL);
	scxfs_trans_ijoin(tp, ip, 0);

	ip->i_d.di_size = 0;
	scxfs_trans_log_inode(tp, ip, SCXFS_ILOG_CORE);

	error = scxfs_itruncate_extents(&tp, ip, SCXFS_DATA_FORK, 0);
	if (error) {
		scxfs_trans_cancel(tp);
		goto out_unlock;
	}

	ASSERT(ip->i_d.di_nextents == 0);

	scxfs_trans_ichgtime(tp, ip, SCXFS_ICHGTIME_MOD | SCXFS_ICHGTIME_CHG);
	error = scxfs_trans_commit(tp);

out_unlock:
	scxfs_iunlock(ip, SCXFS_ILOCK_EXCL | SCXFS_IOLOCK_EXCL);
out_put:
	scxfs_irele(ip);
	return error;
}

int
scxfs_qm_scall_trunc_qfiles(
	scxfs_mount_t	*mp,
	uint		flags)
{
	int		error = -EINVAL;

	if (!scxfs_sb_version_hasquota(&mp->m_sb) || flags == 0 ||
	    (flags & ~SCXFS_DQ_ALLTYPES)) {
		scxfs_debug(mp, "%s: flags=%x m_qflags=%x",
			__func__, flags, mp->m_qflags);
		return -EINVAL;
	}

	if (flags & SCXFS_DQ_USER) {
		error = scxfs_qm_scall_trunc_qfile(mp, mp->m_sb.sb_uquotino);
		if (error)
			return error;
	}
	if (flags & SCXFS_DQ_GROUP) {
		error = scxfs_qm_scall_trunc_qfile(mp, mp->m_sb.sb_gquotino);
		if (error)
			return error;
	}
	if (flags & SCXFS_DQ_PROJ)
		error = scxfs_qm_scall_trunc_qfile(mp, mp->m_sb.sb_pquotino);

	return error;
}

/*
 * Switch on (a given) quota enforcement for a filesystem.  This takes
 * effect immediately.
 * (Switching on quota accounting must be done at mount time.)
 */
int
scxfs_qm_scall_quotaon(
	scxfs_mount_t	*mp,
	uint		flags)
{
	int		error;
	uint		qf;

	flags &= (SCXFS_ALL_QUOTA_ACCT | SCXFS_ALL_QUOTA_ENFD);
	/*
	 * Switching on quota accounting must be done at mount time.
	 */
	flags &= ~(SCXFS_ALL_QUOTA_ACCT);

	if (flags == 0) {
		scxfs_debug(mp, "%s: zero flags, m_qflags=%x",
			__func__, mp->m_qflags);
		return -EINVAL;
	}

	/*
	 * Can't enforce without accounting. We check the superblock
	 * qflags here instead of m_qflags because rootfs can have
	 * quota acct on ondisk without m_qflags' knowing.
	 */
	if (((mp->m_sb.sb_qflags & SCXFS_UQUOTA_ACCT) == 0 &&
	     (flags & SCXFS_UQUOTA_ENFD)) ||
	    ((mp->m_sb.sb_qflags & SCXFS_GQUOTA_ACCT) == 0 &&
	     (flags & SCXFS_GQUOTA_ENFD)) ||
	    ((mp->m_sb.sb_qflags & SCXFS_PQUOTA_ACCT) == 0 &&
	     (flags & SCXFS_PQUOTA_ENFD))) {
		scxfs_debug(mp,
			"%s: Can't enforce without acct, flags=%x sbflags=%x",
			__func__, flags, mp->m_sb.sb_qflags);
		return -EINVAL;
	}
	/*
	 * If everything's up to-date incore, then don't waste time.
	 */
	if ((mp->m_qflags & flags) == flags)
		return -EEXIST;

	/*
	 * Change sb_qflags on disk but not incore mp->qflags
	 * if this is the root filesystem.
	 */
	spin_lock(&mp->m_sb_lock);
	qf = mp->m_sb.sb_qflags;
	mp->m_sb.sb_qflags = qf | flags;
	spin_unlock(&mp->m_sb_lock);

	/*
	 * There's nothing to change if it's the same.
	 */
	if ((qf & flags) == flags)
		return -EEXIST;

	error = scxfs_sync_sb(mp, false);
	if (error)
		return error;
	/*
	 * If we aren't trying to switch on quota enforcement, we are done.
	 */
	if  (((mp->m_sb.sb_qflags & SCXFS_UQUOTA_ACCT) !=
	     (mp->m_qflags & SCXFS_UQUOTA_ACCT)) ||
	     ((mp->m_sb.sb_qflags & SCXFS_PQUOTA_ACCT) !=
	     (mp->m_qflags & SCXFS_PQUOTA_ACCT)) ||
	     ((mp->m_sb.sb_qflags & SCXFS_GQUOTA_ACCT) !=
	     (mp->m_qflags & SCXFS_GQUOTA_ACCT)))
		return 0;

	if (! SCXFS_IS_QUOTA_RUNNING(mp))
		return -ESRCH;

	/*
	 * Switch on quota enforcement in core.
	 */
	mutex_lock(&mp->m_quotainfo->qi_quotaofflock);
	mp->m_qflags |= (flags & SCXFS_ALL_QUOTA_ENFD);
	mutex_unlock(&mp->m_quotainfo->qi_quotaofflock);

	return 0;
}

#define SCXFS_QC_MASK \
	(QC_LIMIT_MASK | QC_TIMER_MASK | QC_WARNS_MASK)

/*
 * Adjust quota limits, and start/stop timers accordingly.
 */
int
scxfs_qm_scall_setqlim(
	struct scxfs_mount	*mp,
	scxfs_dqid_t		id,
	uint			type,
	struct qc_dqblk		*newlim)
{
	struct scxfs_quotainfo	*q = mp->m_quotainfo;
	struct scxfs_disk_dquot	*ddq;
	struct scxfs_dquot	*dqp;
	struct scxfs_trans	*tp;
	struct scxfs_def_quota	*defq;
	int			error;
	scxfs_qcnt_t		hard, soft;

	if (newlim->d_fieldmask & ~SCXFS_QC_MASK)
		return -EINVAL;
	if ((newlim->d_fieldmask & SCXFS_QC_MASK) == 0)
		return 0;

	/*
	 * We don't want to race with a quotaoff so take the quotaoff lock.
	 * We don't hold an inode lock, so there's nothing else to stop
	 * a quotaoff from happening.
	 */
	mutex_lock(&q->qi_quotaofflock);

	/*
	 * Get the dquot (locked) before we start, as we need to do a
	 * transaction to allocate it if it doesn't exist. Once we have the
	 * dquot, unlock it so we can start the next transaction safely. We hold
	 * a reference to the dquot, so it's safe to do this unlock/lock without
	 * it being reclaimed in the mean time.
	 */
	error = scxfs_qm_dqget(mp, id, type, true, &dqp);
	if (error) {
		ASSERT(error != -ENOENT);
		goto out_unlock;
	}

	defq = scxfs_get_defquota(dqp, q);
	scxfs_dqunlock(dqp);

	error = scxfs_trans_alloc(mp, &M_RES(mp)->tr_qm_setqlim, 0, 0, 0, &tp);
	if (error)
		goto out_rele;

	scxfs_dqlock(dqp);
	scxfs_trans_dqjoin(tp, dqp);
	ddq = &dqp->q_core;

	/*
	 * Make sure that hardlimits are >= soft limits before changing.
	 */
	hard = (newlim->d_fieldmask & QC_SPC_HARD) ?
		(scxfs_qcnt_t) SCXFS_B_TO_FSB(mp, newlim->d_spc_hardlimit) :
			be64_to_cpu(ddq->d_blk_hardlimit);
	soft = (newlim->d_fieldmask & QC_SPC_SOFT) ?
		(scxfs_qcnt_t) SCXFS_B_TO_FSB(mp, newlim->d_spc_softlimit) :
			be64_to_cpu(ddq->d_blk_softlimit);
	if (hard == 0 || hard >= soft) {
		ddq->d_blk_hardlimit = cpu_to_be64(hard);
		ddq->d_blk_softlimit = cpu_to_be64(soft);
		scxfs_dquot_set_prealloc_limits(dqp);
		if (id == 0) {
			defq->bhardlimit = hard;
			defq->bsoftlimit = soft;
		}
	} else {
		scxfs_debug(mp, "blkhard %Ld < blksoft %Ld", hard, soft);
	}
	hard = (newlim->d_fieldmask & QC_RT_SPC_HARD) ?
		(scxfs_qcnt_t) SCXFS_B_TO_FSB(mp, newlim->d_rt_spc_hardlimit) :
			be64_to_cpu(ddq->d_rtb_hardlimit);
	soft = (newlim->d_fieldmask & QC_RT_SPC_SOFT) ?
		(scxfs_qcnt_t) SCXFS_B_TO_FSB(mp, newlim->d_rt_spc_softlimit) :
			be64_to_cpu(ddq->d_rtb_softlimit);
	if (hard == 0 || hard >= soft) {
		ddq->d_rtb_hardlimit = cpu_to_be64(hard);
		ddq->d_rtb_softlimit = cpu_to_be64(soft);
		if (id == 0) {
			defq->rtbhardlimit = hard;
			defq->rtbsoftlimit = soft;
		}
	} else {
		scxfs_debug(mp, "rtbhard %Ld < rtbsoft %Ld", hard, soft);
	}

	hard = (newlim->d_fieldmask & QC_INO_HARD) ?
		(scxfs_qcnt_t) newlim->d_ino_hardlimit :
			be64_to_cpu(ddq->d_ino_hardlimit);
	soft = (newlim->d_fieldmask & QC_INO_SOFT) ?
		(scxfs_qcnt_t) newlim->d_ino_softlimit :
			be64_to_cpu(ddq->d_ino_softlimit);
	if (hard == 0 || hard >= soft) {
		ddq->d_ino_hardlimit = cpu_to_be64(hard);
		ddq->d_ino_softlimit = cpu_to_be64(soft);
		if (id == 0) {
			defq->ihardlimit = hard;
			defq->isoftlimit = soft;
		}
	} else {
		scxfs_debug(mp, "ihard %Ld < isoft %Ld", hard, soft);
	}

	/*
	 * Update warnings counter(s) if requested
	 */
	if (newlim->d_fieldmask & QC_SPC_WARNS)
		ddq->d_bwarns = cpu_to_be16(newlim->d_spc_warns);
	if (newlim->d_fieldmask & QC_INO_WARNS)
		ddq->d_iwarns = cpu_to_be16(newlim->d_ino_warns);
	if (newlim->d_fieldmask & QC_RT_SPC_WARNS)
		ddq->d_rtbwarns = cpu_to_be16(newlim->d_rt_spc_warns);

	if (id == 0) {
		/*
		 * Timelimits for the super user set the relative time
		 * the other users can be over quota for this file system.
		 * If it is zero a default is used.  Ditto for the default
		 * soft and hard limit values (already done, above), and
		 * for warnings.
		 */
		if (newlim->d_fieldmask & QC_SPC_TIMER) {
			q->qi_btimelimit = newlim->d_spc_timer;
			ddq->d_btimer = cpu_to_be32(newlim->d_spc_timer);
		}
		if (newlim->d_fieldmask & QC_INO_TIMER) {
			q->qi_itimelimit = newlim->d_ino_timer;
			ddq->d_itimer = cpu_to_be32(newlim->d_ino_timer);
		}
		if (newlim->d_fieldmask & QC_RT_SPC_TIMER) {
			q->qi_rtbtimelimit = newlim->d_rt_spc_timer;
			ddq->d_rtbtimer = cpu_to_be32(newlim->d_rt_spc_timer);
		}
		if (newlim->d_fieldmask & QC_SPC_WARNS)
			q->qi_bwarnlimit = newlim->d_spc_warns;
		if (newlim->d_fieldmask & QC_INO_WARNS)
			q->qi_iwarnlimit = newlim->d_ino_warns;
		if (newlim->d_fieldmask & QC_RT_SPC_WARNS)
			q->qi_rtbwarnlimit = newlim->d_rt_spc_warns;
	} else {
		/*
		 * If the user is now over quota, start the timelimit.
		 * The user will not be 'warned'.
		 * Note that we keep the timers ticking, whether enforcement
		 * is on or off. We don't really want to bother with iterating
		 * over all ondisk dquots and turning the timers on/off.
		 */
		scxfs_qm_adjust_dqtimers(mp, ddq);
	}
	dqp->dq_flags |= SCXFS_DQ_DIRTY;
	scxfs_trans_log_dquot(tp, dqp);

	error = scxfs_trans_commit(tp);

out_rele:
	scxfs_qm_dqrele(dqp);
out_unlock:
	mutex_unlock(&q->qi_quotaofflock);
	return error;
}

STATIC int
scxfs_qm_log_quotaoff_end(
	scxfs_mount_t		*mp,
	scxfs_qoff_logitem_t	*startqoff,
	uint			flags)
{
	scxfs_trans_t		*tp;
	int			error;
	scxfs_qoff_logitem_t	*qoffi;

	error = scxfs_trans_alloc(mp, &M_RES(mp)->tr_qm_equotaoff, 0, 0, 0, &tp);
	if (error)
		return error;

	qoffi = scxfs_trans_get_qoff_item(tp, startqoff,
					flags & SCXFS_ALL_QUOTA_ACCT);
	scxfs_trans_log_quotaoff_item(tp, qoffi);

	/*
	 * We have to make sure that the transaction is secure on disk before we
	 * return and actually stop quota accounting. So, make it synchronous.
	 * We don't care about quotoff's performance.
	 */
	scxfs_trans_set_sync(tp);
	return scxfs_trans_commit(tp);
}


STATIC int
scxfs_qm_log_quotaoff(
	scxfs_mount_t	       *mp,
	scxfs_qoff_logitem_t     **qoffstartp,
	uint		       flags)
{
	scxfs_trans_t	       *tp;
	int			error;
	scxfs_qoff_logitem_t     *qoffi;

	*qoffstartp = NULL;

	error = scxfs_trans_alloc(mp, &M_RES(mp)->tr_qm_quotaoff, 0, 0, 0, &tp);
	if (error)
		goto out;

	qoffi = scxfs_trans_get_qoff_item(tp, NULL, flags & SCXFS_ALL_QUOTA_ACCT);
	scxfs_trans_log_quotaoff_item(tp, qoffi);

	spin_lock(&mp->m_sb_lock);
	mp->m_sb.sb_qflags = (mp->m_qflags & ~(flags)) & SCXFS_MOUNT_QUOTA_ALL;
	spin_unlock(&mp->m_sb_lock);

	scxfs_log_sb(tp);

	/*
	 * We have to make sure that the transaction is secure on disk before we
	 * return and actually stop quota accounting. So, make it synchronous.
	 * We don't care about quotoff's performance.
	 */
	scxfs_trans_set_sync(tp);
	error = scxfs_trans_commit(tp);
	if (error)
		goto out;

	*qoffstartp = qoffi;
out:
	return error;
}

/* Fill out the quota context. */
static void
scxfs_qm_scall_getquota_fill_qc(
	struct scxfs_mount	*mp,
	uint			type,
	const struct scxfs_dquot	*dqp,
	struct qc_dqblk		*dst)
{
	memset(dst, 0, sizeof(*dst));
	dst->d_spc_hardlimit =
		SCXFS_FSB_TO_B(mp, be64_to_cpu(dqp->q_core.d_blk_hardlimit));
	dst->d_spc_softlimit =
		SCXFS_FSB_TO_B(mp, be64_to_cpu(dqp->q_core.d_blk_softlimit));
	dst->d_ino_hardlimit = be64_to_cpu(dqp->q_core.d_ino_hardlimit);
	dst->d_ino_softlimit = be64_to_cpu(dqp->q_core.d_ino_softlimit);
	dst->d_space = SCXFS_FSB_TO_B(mp, dqp->q_res_bcount);
	dst->d_ino_count = dqp->q_res_icount;
	dst->d_spc_timer = be32_to_cpu(dqp->q_core.d_btimer);
	dst->d_ino_timer = be32_to_cpu(dqp->q_core.d_itimer);
	dst->d_ino_warns = be16_to_cpu(dqp->q_core.d_iwarns);
	dst->d_spc_warns = be16_to_cpu(dqp->q_core.d_bwarns);
	dst->d_rt_spc_hardlimit =
		SCXFS_FSB_TO_B(mp, be64_to_cpu(dqp->q_core.d_rtb_hardlimit));
	dst->d_rt_spc_softlimit =
		SCXFS_FSB_TO_B(mp, be64_to_cpu(dqp->q_core.d_rtb_softlimit));
	dst->d_rt_space = SCXFS_FSB_TO_B(mp, dqp->q_res_rtbcount);
	dst->d_rt_spc_timer = be32_to_cpu(dqp->q_core.d_rtbtimer);
	dst->d_rt_spc_warns = be16_to_cpu(dqp->q_core.d_rtbwarns);

	/*
	 * Internally, we don't reset all the timers when quota enforcement
	 * gets turned off. No need to confuse the user level code,
	 * so return zeroes in that case.
	 */
	if ((!SCXFS_IS_UQUOTA_ENFORCED(mp) &&
	     dqp->q_core.d_flags == SCXFS_DQ_USER) ||
	    (!SCXFS_IS_GQUOTA_ENFORCED(mp) &&
	     dqp->q_core.d_flags == SCXFS_DQ_GROUP) ||
	    (!SCXFS_IS_PQUOTA_ENFORCED(mp) &&
	     dqp->q_core.d_flags == SCXFS_DQ_PROJ)) {
		dst->d_spc_timer = 0;
		dst->d_ino_timer = 0;
		dst->d_rt_spc_timer = 0;
	}

#ifdef DEBUG
	if (((SCXFS_IS_UQUOTA_ENFORCED(mp) && type == SCXFS_DQ_USER) ||
	     (SCXFS_IS_GQUOTA_ENFORCED(mp) && type == SCXFS_DQ_GROUP) ||
	     (SCXFS_IS_PQUOTA_ENFORCED(mp) && type == SCXFS_DQ_PROJ)) &&
	    dqp->q_core.d_id != 0) {
		if ((dst->d_space > dst->d_spc_softlimit) &&
		    (dst->d_spc_softlimit > 0)) {
			ASSERT(dst->d_spc_timer != 0);
		}
		if ((dst->d_ino_count > dst->d_ino_softlimit) &&
		    (dst->d_ino_softlimit > 0)) {
			ASSERT(dst->d_ino_timer != 0);
		}
	}
#endif
}

/* Return the quota information for the dquot matching id. */
int
scxfs_qm_scall_getquota(
	struct scxfs_mount	*mp,
	scxfs_dqid_t		id,
	uint			type,
	struct qc_dqblk		*dst)
{
	struct scxfs_dquot	*dqp;
	int			error;

	/*
	 * Try to get the dquot. We don't want it allocated on disk, so don't
	 * set doalloc. If it doesn't exist, we'll get ENOENT back.
	 */
	error = scxfs_qm_dqget(mp, id, type, false, &dqp);
	if (error)
		return error;

	/*
	 * If everything's NULL, this dquot doesn't quite exist as far as
	 * our utility programs are concerned.
	 */
	if (SCXFS_IS_DQUOT_UNINITIALIZED(dqp)) {
		error = -ENOENT;
		goto out_put;
	}

	scxfs_qm_scall_getquota_fill_qc(mp, type, dqp, dst);

out_put:
	scxfs_qm_dqput(dqp);
	return error;
}

/*
 * Return the quota information for the first initialized dquot whose id
 * is at least as high as id.
 */
int
scxfs_qm_scall_getquota_next(
	struct scxfs_mount	*mp,
	scxfs_dqid_t		*id,
	uint			type,
	struct qc_dqblk		*dst)
{
	struct scxfs_dquot	*dqp;
	int			error;

	error = scxfs_qm_dqget_next(mp, *id, type, &dqp);
	if (error)
		return error;

	/* Fill in the ID we actually read from disk */
	*id = be32_to_cpu(dqp->q_core.d_id);

	scxfs_qm_scall_getquota_fill_qc(mp, type, dqp, dst);

	scxfs_qm_dqput(dqp);
	return error;
}

STATIC int
scxfs_dqrele_inode(
	struct scxfs_inode	*ip,
	int			flags,
	void			*args)
{
	/* skip quota inodes */
	if (ip == ip->i_mount->m_quotainfo->qi_uquotaip ||
	    ip == ip->i_mount->m_quotainfo->qi_gquotaip ||
	    ip == ip->i_mount->m_quotainfo->qi_pquotaip) {
		ASSERT(ip->i_udquot == NULL);
		ASSERT(ip->i_gdquot == NULL);
		ASSERT(ip->i_pdquot == NULL);
		return 0;
	}

	scxfs_ilock(ip, SCXFS_ILOCK_EXCL);
	if ((flags & SCXFS_UQUOTA_ACCT) && ip->i_udquot) {
		scxfs_qm_dqrele(ip->i_udquot);
		ip->i_udquot = NULL;
	}
	if ((flags & SCXFS_GQUOTA_ACCT) && ip->i_gdquot) {
		scxfs_qm_dqrele(ip->i_gdquot);
		ip->i_gdquot = NULL;
	}
	if ((flags & SCXFS_PQUOTA_ACCT) && ip->i_pdquot) {
		scxfs_qm_dqrele(ip->i_pdquot);
		ip->i_pdquot = NULL;
	}
	scxfs_iunlock(ip, SCXFS_ILOCK_EXCL);
	return 0;
}


/*
 * Go thru all the inodes in the file system, releasing their dquots.
 *
 * Note that the mount structure gets modified to indicate that quotas are off
 * AFTER this, in the case of quotaoff.
 */
void
scxfs_qm_dqrele_all_inodes(
	struct scxfs_mount *mp,
	uint		 flags)
{
	ASSERT(mp->m_quotainfo);
	scxfs_inode_ag_iterator_flags(mp, scxfs_dqrele_inode, flags, NULL,
				    SCXFS_AGITER_INEW_WAIT);
}
