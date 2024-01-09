// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2002 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#include "scxfs.h"
#include "scxfs_fs.h"
#include "scxfs_shared.h"
#include "scxfs_format.h"
#include "scxfs_log_format.h"
#include "scxfs_trans_resv.h"
#include "scxfs_mount.h"
#include "scxfs_inode.h"
#include "scxfs_trans.h"
#include "scxfs_trans_priv.h"
#include "scxfs_quota.h"
#include "scxfs_qm.h"

STATIC void	scxfs_trans_alloc_dqinfo(scxfs_trans_t *);

/*
 * Add the locked dquot to the transaction.
 * The dquot must be locked, and it cannot be associated with any
 * transaction.
 */
void
scxfs_trans_dqjoin(
	scxfs_trans_t	*tp,
	scxfs_dquot_t	*dqp)
{
	ASSERT(SCXFS_DQ_IS_LOCKED(dqp));
	ASSERT(dqp->q_logitem.qli_dquot == dqp);

	/*
	 * Get a log_item_desc to point at the new item.
	 */
	scxfs_trans_add_item(tp, &dqp->q_logitem.qli_item);
}

/*
 * This is called to mark the dquot as needing
 * to be logged when the transaction is committed.  The dquot must
 * already be associated with the given transaction.
 * Note that it marks the entire transaction as dirty. In the ordinary
 * case, this gets called via scxfs_trans_commit, after the transaction
 * is already dirty. However, there's nothing stop this from getting
 * called directly, as done by scxfs_qm_scall_setqlim. Hence, the TRANS_DIRTY
 * flag.
 */
void
scxfs_trans_log_dquot(
	scxfs_trans_t	*tp,
	scxfs_dquot_t	*dqp)
{
	ASSERT(SCXFS_DQ_IS_LOCKED(dqp));

	tp->t_flags |= SCXFS_TRANS_DIRTY;
	set_bit(SCXFS_LI_DIRTY, &dqp->q_logitem.qli_item.li_flags);
}

/*
 * Carry forward whatever is left of the quota blk reservation to
 * the spanky new transaction
 */
void
scxfs_trans_dup_dqinfo(
	struct scxfs_trans	*otp,
	struct scxfs_trans	*ntp)
{
	struct scxfs_dqtrx	*oq, *nq;
	int			i, j;
	struct scxfs_dqtrx	*oqa, *nqa;
	uint64_t		blk_res_used;

	if (!otp->t_dqinfo)
		return;

	scxfs_trans_alloc_dqinfo(ntp);

	/*
	 * Because the quota blk reservation is carried forward,
	 * it is also necessary to carry forward the DQ_DIRTY flag.
	 */
	if (otp->t_flags & SCXFS_TRANS_DQ_DIRTY)
		ntp->t_flags |= SCXFS_TRANS_DQ_DIRTY;

	for (j = 0; j < SCXFS_QM_TRANS_DQTYPES; j++) {
		oqa = otp->t_dqinfo->dqs[j];
		nqa = ntp->t_dqinfo->dqs[j];
		for (i = 0; i < SCXFS_QM_TRANS_MAXDQS; i++) {
			blk_res_used = 0;

			if (oqa[i].qt_dquot == NULL)
				break;
			oq = &oqa[i];
			nq = &nqa[i];

			if (oq->qt_blk_res && oq->qt_bcount_delta > 0)
				blk_res_used = oq->qt_bcount_delta;

			nq->qt_dquot = oq->qt_dquot;
			nq->qt_bcount_delta = nq->qt_icount_delta = 0;
			nq->qt_rtbcount_delta = 0;

			/*
			 * Transfer whatever is left of the reservations.
			 */
			nq->qt_blk_res = oq->qt_blk_res - blk_res_used;
			oq->qt_blk_res = blk_res_used;

			nq->qt_rtblk_res = oq->qt_rtblk_res -
				oq->qt_rtblk_res_used;
			oq->qt_rtblk_res = oq->qt_rtblk_res_used;

			nq->qt_ino_res = oq->qt_ino_res - oq->qt_ino_res_used;
			oq->qt_ino_res = oq->qt_ino_res_used;

		}
	}
}

/*
 * Wrap around mod_dquot to account for both user and group quotas.
 */
void
scxfs_trans_mod_dquot_byino(
	scxfs_trans_t	*tp,
	scxfs_inode_t	*ip,
	uint		field,
	int64_t		delta)
{
	scxfs_mount_t	*mp = tp->t_mountp;

	if (!SCXFS_IS_QUOTA_RUNNING(mp) ||
	    !SCXFS_IS_QUOTA_ON(mp) ||
	    scxfs_is_quota_inode(&mp->m_sb, ip->i_ino))
		return;

	if (tp->t_dqinfo == NULL)
		scxfs_trans_alloc_dqinfo(tp);

	if (SCXFS_IS_UQUOTA_ON(mp) && ip->i_udquot)
		(void) scxfs_trans_mod_dquot(tp, ip->i_udquot, field, delta);
	if (SCXFS_IS_GQUOTA_ON(mp) && ip->i_gdquot)
		(void) scxfs_trans_mod_dquot(tp, ip->i_gdquot, field, delta);
	if (SCXFS_IS_PQUOTA_ON(mp) && ip->i_pdquot)
		(void) scxfs_trans_mod_dquot(tp, ip->i_pdquot, field, delta);
}

STATIC struct scxfs_dqtrx *
scxfs_trans_get_dqtrx(
	struct scxfs_trans	*tp,
	struct scxfs_dquot	*dqp)
{
	int			i;
	struct scxfs_dqtrx	*qa;

	if (SCXFS_QM_ISUDQ(dqp))
		qa = tp->t_dqinfo->dqs[SCXFS_QM_TRANS_USR];
	else if (SCXFS_QM_ISGDQ(dqp))
		qa = tp->t_dqinfo->dqs[SCXFS_QM_TRANS_GRP];
	else if (SCXFS_QM_ISPDQ(dqp))
		qa = tp->t_dqinfo->dqs[SCXFS_QM_TRANS_PRJ];
	else
		return NULL;

	for (i = 0; i < SCXFS_QM_TRANS_MAXDQS; i++) {
		if (qa[i].qt_dquot == NULL ||
		    qa[i].qt_dquot == dqp)
			return &qa[i];
	}

	return NULL;
}

/*
 * Make the changes in the transaction structure.
 * The moral equivalent to scxfs_trans_mod_sb().
 * We don't touch any fields in the dquot, so we don't care
 * if it's locked or not (most of the time it won't be).
 */
void
scxfs_trans_mod_dquot(
	struct scxfs_trans	*tp,
	struct scxfs_dquot	*dqp,
	uint			field,
	int64_t			delta)
{
	struct scxfs_dqtrx	*qtrx;

	ASSERT(tp);
	ASSERT(SCXFS_IS_QUOTA_RUNNING(tp->t_mountp));
	qtrx = NULL;

	if (tp->t_dqinfo == NULL)
		scxfs_trans_alloc_dqinfo(tp);
	/*
	 * Find either the first free slot or the slot that belongs
	 * to this dquot.
	 */
	qtrx = scxfs_trans_get_dqtrx(tp, dqp);
	ASSERT(qtrx);
	if (qtrx->qt_dquot == NULL)
		qtrx->qt_dquot = dqp;

	switch (field) {

		/*
		 * regular disk blk reservation
		 */
	      case SCXFS_TRANS_DQ_RES_BLKS:
		qtrx->qt_blk_res += delta;
		break;

		/*
		 * inode reservation
		 */
	      case SCXFS_TRANS_DQ_RES_INOS:
		qtrx->qt_ino_res += delta;
		break;

		/*
		 * disk blocks used.
		 */
	      case SCXFS_TRANS_DQ_BCOUNT:
		qtrx->qt_bcount_delta += delta;
		break;

	      case SCXFS_TRANS_DQ_DELBCOUNT:
		qtrx->qt_delbcnt_delta += delta;
		break;

		/*
		 * Inode Count
		 */
	      case SCXFS_TRANS_DQ_ICOUNT:
		if (qtrx->qt_ino_res && delta > 0) {
			qtrx->qt_ino_res_used += delta;
			ASSERT(qtrx->qt_ino_res >= qtrx->qt_ino_res_used);
		}
		qtrx->qt_icount_delta += delta;
		break;

		/*
		 * rtblk reservation
		 */
	      case SCXFS_TRANS_DQ_RES_RTBLKS:
		qtrx->qt_rtblk_res += delta;
		break;

		/*
		 * rtblk count
		 */
	      case SCXFS_TRANS_DQ_RTBCOUNT:
		if (qtrx->qt_rtblk_res && delta > 0) {
			qtrx->qt_rtblk_res_used += delta;
			ASSERT(qtrx->qt_rtblk_res >= qtrx->qt_rtblk_res_used);
		}
		qtrx->qt_rtbcount_delta += delta;
		break;

	      case SCXFS_TRANS_DQ_DELRTBCOUNT:
		qtrx->qt_delrtb_delta += delta;
		break;

	      default:
		ASSERT(0);
	}
	tp->t_flags |= SCXFS_TRANS_DQ_DIRTY;
}


/*
 * Given an array of dqtrx structures, lock all the dquots associated and join
 * them to the transaction, provided they have been modified.  We know that the
 * highest number of dquots of one type - usr, grp and prj - involved in a
 * transaction is 3 so we don't need to make this very generic.
 */
STATIC void
scxfs_trans_dqlockedjoin(
	struct scxfs_trans	*tp,
	struct scxfs_dqtrx	*q)
{
	ASSERT(q[0].qt_dquot != NULL);
	if (q[1].qt_dquot == NULL) {
		scxfs_dqlock(q[0].qt_dquot);
		scxfs_trans_dqjoin(tp, q[0].qt_dquot);
	} else {
		ASSERT(SCXFS_QM_TRANS_MAXDQS == 2);
		scxfs_dqlock2(q[0].qt_dquot, q[1].qt_dquot);
		scxfs_trans_dqjoin(tp, q[0].qt_dquot);
		scxfs_trans_dqjoin(tp, q[1].qt_dquot);
	}
}


/*
 * Called by scxfs_trans_commit() and similar in spirit to
 * scxfs_trans_apply_sb_deltas().
 * Go thru all the dquots belonging to this transaction and modify the
 * INCORE dquot to reflect the actual usages.
 * Unreserve just the reservations done by this transaction.
 * dquot is still left locked at exit.
 */
void
scxfs_trans_apply_dquot_deltas(
	struct scxfs_trans	*tp)
{
	int			i, j;
	struct scxfs_dquot	*dqp;
	struct scxfs_dqtrx	*qtrx, *qa;
	struct scxfs_disk_dquot	*d;
	int64_t			totalbdelta;
	int64_t			totalrtbdelta;

	if (!(tp->t_flags & SCXFS_TRANS_DQ_DIRTY))
		return;

	ASSERT(tp->t_dqinfo);
	for (j = 0; j < SCXFS_QM_TRANS_DQTYPES; j++) {
		qa = tp->t_dqinfo->dqs[j];
		if (qa[0].qt_dquot == NULL)
			continue;

		/*
		 * Lock all of the dquots and join them to the transaction.
		 */
		scxfs_trans_dqlockedjoin(tp, qa);

		for (i = 0; i < SCXFS_QM_TRANS_MAXDQS; i++) {
			qtrx = &qa[i];
			/*
			 * The array of dquots is filled
			 * sequentially, not sparsely.
			 */
			if ((dqp = qtrx->qt_dquot) == NULL)
				break;

			ASSERT(SCXFS_DQ_IS_LOCKED(dqp));

			/*
			 * adjust the actual number of blocks used
			 */
			d = &dqp->q_core;

			/*
			 * The issue here is - sometimes we don't make a blkquota
			 * reservation intentionally to be fair to users
			 * (when the amount is small). On the other hand,
			 * delayed allocs do make reservations, but that's
			 * outside of a transaction, so we have no
			 * idea how much was really reserved.
			 * So, here we've accumulated delayed allocation blks and
			 * non-delay blks. The assumption is that the
			 * delayed ones are always reserved (outside of a
			 * transaction), and the others may or may not have
			 * quota reservations.
			 */
			totalbdelta = qtrx->qt_bcount_delta +
				qtrx->qt_delbcnt_delta;
			totalrtbdelta = qtrx->qt_rtbcount_delta +
				qtrx->qt_delrtb_delta;
#ifdef DEBUG
			if (totalbdelta < 0)
				ASSERT(be64_to_cpu(d->d_bcount) >=
				       -totalbdelta);

			if (totalrtbdelta < 0)
				ASSERT(be64_to_cpu(d->d_rtbcount) >=
				       -totalrtbdelta);

			if (qtrx->qt_icount_delta < 0)
				ASSERT(be64_to_cpu(d->d_icount) >=
				       -qtrx->qt_icount_delta);
#endif
			if (totalbdelta)
				be64_add_cpu(&d->d_bcount, (scxfs_qcnt_t)totalbdelta);

			if (qtrx->qt_icount_delta)
				be64_add_cpu(&d->d_icount, (scxfs_qcnt_t)qtrx->qt_icount_delta);

			if (totalrtbdelta)
				be64_add_cpu(&d->d_rtbcount, (scxfs_qcnt_t)totalrtbdelta);

			/*
			 * Get any default limits in use.
			 * Start/reset the timer(s) if needed.
			 */
			if (d->d_id) {
				scxfs_qm_adjust_dqlimits(tp->t_mountp, dqp);
				scxfs_qm_adjust_dqtimers(tp->t_mountp, d);
			}

			dqp->dq_flags |= SCXFS_DQ_DIRTY;
			/*
			 * add this to the list of items to get logged
			 */
			scxfs_trans_log_dquot(tp, dqp);
			/*
			 * Take off what's left of the original reservation.
			 * In case of delayed allocations, there's no
			 * reservation that a transaction structure knows of.
			 */
			if (qtrx->qt_blk_res != 0) {
				uint64_t	blk_res_used = 0;

				if (qtrx->qt_bcount_delta > 0)
					blk_res_used = qtrx->qt_bcount_delta;

				if (qtrx->qt_blk_res != blk_res_used) {
					if (qtrx->qt_blk_res > blk_res_used)
						dqp->q_res_bcount -= (scxfs_qcnt_t)
							(qtrx->qt_blk_res -
							 blk_res_used);
					else
						dqp->q_res_bcount -= (scxfs_qcnt_t)
							(blk_res_used -
							 qtrx->qt_blk_res);
				}
			} else {
				/*
				 * These blks were never reserved, either inside
				 * a transaction or outside one (in a delayed
				 * allocation). Also, this isn't always a
				 * negative number since we sometimes
				 * deliberately skip quota reservations.
				 */
				if (qtrx->qt_bcount_delta) {
					dqp->q_res_bcount +=
					      (scxfs_qcnt_t)qtrx->qt_bcount_delta;
				}
			}
			/*
			 * Adjust the RT reservation.
			 */
			if (qtrx->qt_rtblk_res != 0) {
				if (qtrx->qt_rtblk_res != qtrx->qt_rtblk_res_used) {
					if (qtrx->qt_rtblk_res >
					    qtrx->qt_rtblk_res_used)
					       dqp->q_res_rtbcount -= (scxfs_qcnt_t)
						       (qtrx->qt_rtblk_res -
							qtrx->qt_rtblk_res_used);
					else
					       dqp->q_res_rtbcount -= (scxfs_qcnt_t)
						       (qtrx->qt_rtblk_res_used -
							qtrx->qt_rtblk_res);
				}
			} else {
				if (qtrx->qt_rtbcount_delta)
					dqp->q_res_rtbcount +=
					    (scxfs_qcnt_t)qtrx->qt_rtbcount_delta;
			}

			/*
			 * Adjust the inode reservation.
			 */
			if (qtrx->qt_ino_res != 0) {
				ASSERT(qtrx->qt_ino_res >=
				       qtrx->qt_ino_res_used);
				if (qtrx->qt_ino_res > qtrx->qt_ino_res_used)
					dqp->q_res_icount -= (scxfs_qcnt_t)
						(qtrx->qt_ino_res -
						 qtrx->qt_ino_res_used);
			} else {
				if (qtrx->qt_icount_delta)
					dqp->q_res_icount +=
					    (scxfs_qcnt_t)qtrx->qt_icount_delta;
			}

			ASSERT(dqp->q_res_bcount >=
				be64_to_cpu(dqp->q_core.d_bcount));
			ASSERT(dqp->q_res_icount >=
				be64_to_cpu(dqp->q_core.d_icount));
			ASSERT(dqp->q_res_rtbcount >=
				be64_to_cpu(dqp->q_core.d_rtbcount));
		}
	}
}

/*
 * Release the reservations, and adjust the dquots accordingly.
 * This is called only when the transaction is being aborted. If by
 * any chance we have done dquot modifications incore (ie. deltas) already,
 * we simply throw those away, since that's the expected behavior
 * when a transaction is curtailed without a commit.
 */
void
scxfs_trans_unreserve_and_mod_dquots(
	scxfs_trans_t		*tp)
{
	int			i, j;
	scxfs_dquot_t		*dqp;
	struct scxfs_dqtrx	*qtrx, *qa;
	bool                    locked;

	if (!tp->t_dqinfo || !(tp->t_flags & SCXFS_TRANS_DQ_DIRTY))
		return;

	for (j = 0; j < SCXFS_QM_TRANS_DQTYPES; j++) {
		qa = tp->t_dqinfo->dqs[j];

		for (i = 0; i < SCXFS_QM_TRANS_MAXDQS; i++) {
			qtrx = &qa[i];
			/*
			 * We assume that the array of dquots is filled
			 * sequentially, not sparsely.
			 */
			if ((dqp = qtrx->qt_dquot) == NULL)
				break;
			/*
			 * Unreserve the original reservation. We don't care
			 * about the number of blocks used field, or deltas.
			 * Also we don't bother to zero the fields.
			 */
			locked = false;
			if (qtrx->qt_blk_res) {
				scxfs_dqlock(dqp);
				locked = true;
				dqp->q_res_bcount -=
					(scxfs_qcnt_t)qtrx->qt_blk_res;
			}
			if (qtrx->qt_ino_res) {
				if (!locked) {
					scxfs_dqlock(dqp);
					locked = true;
				}
				dqp->q_res_icount -=
					(scxfs_qcnt_t)qtrx->qt_ino_res;
			}

			if (qtrx->qt_rtblk_res) {
				if (!locked) {
					scxfs_dqlock(dqp);
					locked = true;
				}
				dqp->q_res_rtbcount -=
					(scxfs_qcnt_t)qtrx->qt_rtblk_res;
			}
			if (locked)
				scxfs_dqunlock(dqp);

		}
	}
}

STATIC void
scxfs_quota_warn(
	struct scxfs_mount	*mp,
	struct scxfs_dquot	*dqp,
	int			type)
{
	enum quota_type qtype;

	if (dqp->dq_flags & SCXFS_DQ_PROJ)
		qtype = PRJQUOTA;
	else if (dqp->dq_flags & SCXFS_DQ_USER)
		qtype = USRQUOTA;
	else
		qtype = GRPQUOTA;

	quota_send_warning(make_kqid(&init_user_ns, qtype,
				     be32_to_cpu(dqp->q_core.d_id)),
			   mp->m_super->s_dev, type);
}

/*
 * This reserves disk blocks and inodes against a dquot.
 * Flags indicate if the dquot is to be locked here and also
 * if the blk reservation is for RT or regular blocks.
 * Sending in SCXFS_QMOPT_FORCE_RES flag skips the quota check.
 */
STATIC int
scxfs_trans_dqresv(
	scxfs_trans_t	*tp,
	scxfs_mount_t	*mp,
	scxfs_dquot_t	*dqp,
	int64_t		nblks,
	long		ninos,
	uint		flags)
{
	scxfs_qcnt_t	hardlimit;
	scxfs_qcnt_t	softlimit;
	time_t		timer;
	scxfs_qwarncnt_t	warns;
	scxfs_qwarncnt_t	warnlimit;
	scxfs_qcnt_t	total_count;
	scxfs_qcnt_t	*resbcountp;
	scxfs_quotainfo_t	*q = mp->m_quotainfo;
	struct scxfs_def_quota	*defq;


	scxfs_dqlock(dqp);

	defq = scxfs_get_defquota(dqp, q);

	if (flags & SCXFS_TRANS_DQ_RES_BLKS) {
		hardlimit = be64_to_cpu(dqp->q_core.d_blk_hardlimit);
		if (!hardlimit)
			hardlimit = defq->bhardlimit;
		softlimit = be64_to_cpu(dqp->q_core.d_blk_softlimit);
		if (!softlimit)
			softlimit = defq->bsoftlimit;
		timer = be32_to_cpu(dqp->q_core.d_btimer);
		warns = be16_to_cpu(dqp->q_core.d_bwarns);
		warnlimit = dqp->q_mount->m_quotainfo->qi_bwarnlimit;
		resbcountp = &dqp->q_res_bcount;
	} else {
		ASSERT(flags & SCXFS_TRANS_DQ_RES_RTBLKS);
		hardlimit = be64_to_cpu(dqp->q_core.d_rtb_hardlimit);
		if (!hardlimit)
			hardlimit = defq->rtbhardlimit;
		softlimit = be64_to_cpu(dqp->q_core.d_rtb_softlimit);
		if (!softlimit)
			softlimit = defq->rtbsoftlimit;
		timer = be32_to_cpu(dqp->q_core.d_rtbtimer);
		warns = be16_to_cpu(dqp->q_core.d_rtbwarns);
		warnlimit = dqp->q_mount->m_quotainfo->qi_rtbwarnlimit;
		resbcountp = &dqp->q_res_rtbcount;
	}

	if ((flags & SCXFS_QMOPT_FORCE_RES) == 0 &&
	    dqp->q_core.d_id &&
	    ((SCXFS_IS_UQUOTA_ENFORCED(dqp->q_mount) && SCXFS_QM_ISUDQ(dqp)) ||
	     (SCXFS_IS_GQUOTA_ENFORCED(dqp->q_mount) && SCXFS_QM_ISGDQ(dqp)) ||
	     (SCXFS_IS_PQUOTA_ENFORCED(dqp->q_mount) && SCXFS_QM_ISPDQ(dqp)))) {
		if (nblks > 0) {
			/*
			 * dquot is locked already. See if we'd go over the
			 * hardlimit or exceed the timelimit if we allocate
			 * nblks.
			 */
			total_count = *resbcountp + nblks;
			if (hardlimit && total_count > hardlimit) {
				scxfs_quota_warn(mp, dqp, QUOTA_NL_BHARDWARN);
				goto error_return;
			}
			if (softlimit && total_count > softlimit) {
				if ((timer != 0 && get_seconds() > timer) ||
				    (warns != 0 && warns >= warnlimit)) {
					scxfs_quota_warn(mp, dqp,
						       QUOTA_NL_BSOFTLONGWARN);
					goto error_return;
				}

				scxfs_quota_warn(mp, dqp, QUOTA_NL_BSOFTWARN);
			}
		}
		if (ninos > 0) {
			total_count = dqp->q_res_icount + ninos;
			timer = be32_to_cpu(dqp->q_core.d_itimer);
			warns = be16_to_cpu(dqp->q_core.d_iwarns);
			warnlimit = dqp->q_mount->m_quotainfo->qi_iwarnlimit;
			hardlimit = be64_to_cpu(dqp->q_core.d_ino_hardlimit);
			if (!hardlimit)
				hardlimit = defq->ihardlimit;
			softlimit = be64_to_cpu(dqp->q_core.d_ino_softlimit);
			if (!softlimit)
				softlimit = defq->isoftlimit;

			if (hardlimit && total_count > hardlimit) {
				scxfs_quota_warn(mp, dqp, QUOTA_NL_IHARDWARN);
				goto error_return;
			}
			if (softlimit && total_count > softlimit) {
				if  ((timer != 0 && get_seconds() > timer) ||
				     (warns != 0 && warns >= warnlimit)) {
					scxfs_quota_warn(mp, dqp,
						       QUOTA_NL_ISOFTLONGWARN);
					goto error_return;
				}
				scxfs_quota_warn(mp, dqp, QUOTA_NL_ISOFTWARN);
			}
		}
	}

	/*
	 * Change the reservation, but not the actual usage.
	 * Note that q_res_bcount = q_core.d_bcount + resv
	 */
	(*resbcountp) += (scxfs_qcnt_t)nblks;
	if (ninos != 0)
		dqp->q_res_icount += (scxfs_qcnt_t)ninos;

	/*
	 * note the reservation amt in the trans struct too,
	 * so that the transaction knows how much was reserved by
	 * it against this particular dquot.
	 * We don't do this when we are reserving for a delayed allocation,
	 * because we don't have the luxury of a transaction envelope then.
	 */
	if (tp) {
		ASSERT(tp->t_dqinfo);
		ASSERT(flags & SCXFS_QMOPT_RESBLK_MASK);
		if (nblks != 0)
			scxfs_trans_mod_dquot(tp, dqp,
					    flags & SCXFS_QMOPT_RESBLK_MASK,
					    nblks);
		if (ninos != 0)
			scxfs_trans_mod_dquot(tp, dqp,
					    SCXFS_TRANS_DQ_RES_INOS,
					    ninos);
	}
	ASSERT(dqp->q_res_bcount >= be64_to_cpu(dqp->q_core.d_bcount));
	ASSERT(dqp->q_res_rtbcount >= be64_to_cpu(dqp->q_core.d_rtbcount));
	ASSERT(dqp->q_res_icount >= be64_to_cpu(dqp->q_core.d_icount));

	scxfs_dqunlock(dqp);
	return 0;

error_return:
	scxfs_dqunlock(dqp);
	if (flags & SCXFS_QMOPT_ENOSPC)
		return -ENOSPC;
	return -EDQUOT;
}


/*
 * Given dquot(s), make disk block and/or inode reservations against them.
 * The fact that this does the reservation against user, group and
 * project quotas is important, because this follows a all-or-nothing
 * approach.
 *
 * flags = SCXFS_QMOPT_FORCE_RES evades limit enforcement. Used by chown.
 *	   SCXFS_QMOPT_ENOSPC returns ENOSPC not EDQUOT.  Used by pquota.
 *	   SCXFS_TRANS_DQ_RES_BLKS reserves regular disk blocks
 *	   SCXFS_TRANS_DQ_RES_RTBLKS reserves realtime disk blocks
 * dquots are unlocked on return, if they were not locked by caller.
 */
int
scxfs_trans_reserve_quota_bydquots(
	struct scxfs_trans	*tp,
	struct scxfs_mount	*mp,
	struct scxfs_dquot	*udqp,
	struct scxfs_dquot	*gdqp,
	struct scxfs_dquot	*pdqp,
	int64_t			nblks,
	long			ninos,
	uint			flags)
{
	int		error;

	if (!SCXFS_IS_QUOTA_RUNNING(mp) || !SCXFS_IS_QUOTA_ON(mp))
		return 0;

	if (tp && tp->t_dqinfo == NULL)
		scxfs_trans_alloc_dqinfo(tp);

	ASSERT(flags & SCXFS_QMOPT_RESBLK_MASK);

	if (udqp) {
		error = scxfs_trans_dqresv(tp, mp, udqp, nblks, ninos,
					(flags & ~SCXFS_QMOPT_ENOSPC));
		if (error)
			return error;
	}

	if (gdqp) {
		error = scxfs_trans_dqresv(tp, mp, gdqp, nblks, ninos, flags);
		if (error)
			goto unwind_usr;
	}

	if (pdqp) {
		error = scxfs_trans_dqresv(tp, mp, pdqp, nblks, ninos, flags);
		if (error)
			goto unwind_grp;
	}

	/*
	 * Didn't change anything critical, so, no need to log
	 */
	return 0;

unwind_grp:
	flags |= SCXFS_QMOPT_FORCE_RES;
	if (gdqp)
		scxfs_trans_dqresv(tp, mp, gdqp, -nblks, -ninos, flags);
unwind_usr:
	flags |= SCXFS_QMOPT_FORCE_RES;
	if (udqp)
		scxfs_trans_dqresv(tp, mp, udqp, -nblks, -ninos, flags);
	return error;
}


/*
 * Lock the dquot and change the reservation if we can.
 * This doesn't change the actual usage, just the reservation.
 * The inode sent in is locked.
 */
int
scxfs_trans_reserve_quota_nblks(
	struct scxfs_trans	*tp,
	struct scxfs_inode	*ip,
	int64_t			nblks,
	long			ninos,
	uint			flags)
{
	struct scxfs_mount	*mp = ip->i_mount;

	if (!SCXFS_IS_QUOTA_RUNNING(mp) || !SCXFS_IS_QUOTA_ON(mp))
		return 0;
	if (SCXFS_IS_PQUOTA_ON(mp))
		flags |= SCXFS_QMOPT_ENOSPC;

	ASSERT(!scxfs_is_quota_inode(&mp->m_sb, ip->i_ino));

	ASSERT(scxfs_isilocked(ip, SCXFS_ILOCK_EXCL));
	ASSERT((flags & ~(SCXFS_QMOPT_FORCE_RES | SCXFS_QMOPT_ENOSPC)) ==
				SCXFS_TRANS_DQ_RES_RTBLKS ||
	       (flags & ~(SCXFS_QMOPT_FORCE_RES | SCXFS_QMOPT_ENOSPC)) ==
				SCXFS_TRANS_DQ_RES_BLKS);

	/*
	 * Reserve nblks against these dquots, with trans as the mediator.
	 */
	return scxfs_trans_reserve_quota_bydquots(tp, mp,
						ip->i_udquot, ip->i_gdquot,
						ip->i_pdquot,
						nblks, ninos, flags);
}

/*
 * This routine is called to allocate a quotaoff log item.
 */
scxfs_qoff_logitem_t *
scxfs_trans_get_qoff_item(
	scxfs_trans_t		*tp,
	scxfs_qoff_logitem_t	*startqoff,
	uint			flags)
{
	scxfs_qoff_logitem_t	*q;

	ASSERT(tp != NULL);

	q = scxfs_qm_qoff_logitem_init(tp->t_mountp, startqoff, flags);
	ASSERT(q != NULL);

	/*
	 * Get a log_item_desc to point at the new item.
	 */
	scxfs_trans_add_item(tp, &q->qql_item);
	return q;
}


/*
 * This is called to mark the quotaoff logitem as needing
 * to be logged when the transaction is committed.  The logitem must
 * already be associated with the given transaction.
 */
void
scxfs_trans_log_quotaoff_item(
	scxfs_trans_t		*tp,
	scxfs_qoff_logitem_t	*qlp)
{
	tp->t_flags |= SCXFS_TRANS_DIRTY;
	set_bit(SCXFS_LI_DIRTY, &qlp->qql_item.li_flags);
}

STATIC void
scxfs_trans_alloc_dqinfo(
	scxfs_trans_t	*tp)
{
	tp->t_dqinfo = kmem_zone_zalloc(scxfs_qm_dqtrxzone, 0);
}

void
scxfs_trans_free_dqinfo(
	scxfs_trans_t	*tp)
{
	if (!tp->t_dqinfo)
		return;
	kmem_zone_free(scxfs_qm_dqtrxzone, tp->t_dqinfo);
	tp->t_dqinfo = NULL;
}
