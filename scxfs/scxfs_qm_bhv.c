// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2006 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#include "scxfs.h"
#include "scxfs_fs.h"
#include "scxfs_shared.h"
#include "scxfs_format.h"
#include "scxfs_log_format.h"
#include "scxfs_trans_resv.h"
#include "scxfs_quota.h"
#include "scxfs_mount.h"
#include "scxfs_inode.h"
#include "scxfs_trans.h"
#include "scxfs_qm.h"


STATIC void
scxfs_fill_statvfs_from_dquot(
	struct kstatfs		*statp,
	struct scxfs_dquot	*dqp)
{
	uint64_t		limit;

	limit = dqp->q_core.d_blk_softlimit ?
		be64_to_cpu(dqp->q_core.d_blk_softlimit) :
		be64_to_cpu(dqp->q_core.d_blk_hardlimit);
	if (limit && statp->f_blocks > limit) {
		statp->f_blocks = limit;
		statp->f_bfree = statp->f_bavail =
			(statp->f_blocks > dqp->q_res_bcount) ?
			 (statp->f_blocks - dqp->q_res_bcount) : 0;
	}

	limit = dqp->q_core.d_ino_softlimit ?
		be64_to_cpu(dqp->q_core.d_ino_softlimit) :
		be64_to_cpu(dqp->q_core.d_ino_hardlimit);
	if (limit && statp->f_files > limit) {
		statp->f_files = limit;
		statp->f_ffree =
			(statp->f_files > dqp->q_res_icount) ?
			 (statp->f_files - dqp->q_res_icount) : 0;
	}
}


/*
 * Directory tree accounting is implemented using project quotas, where
 * the project identifier is inherited from parent directories.
 * A statvfs (df, etc.) of a directory that is using project quota should
 * return a statvfs of the project, not the entire filesystem.
 * This makes such trees appear as if they are filesystems in themselves.
 */
void
scxfs_qm_statvfs(
	scxfs_inode_t		*ip,
	struct kstatfs		*statp)
{
	scxfs_mount_t		*mp = ip->i_mount;
	scxfs_dquot_t		*dqp;

	if (!scxfs_qm_dqget(mp, scxfs_get_projid(ip), SCXFS_DQ_PROJ, false, &dqp)) {
		scxfs_fill_statvfs_from_dquot(statp, dqp);
		scxfs_qm_dqput(dqp);
	}
}

int
scxfs_qm_newmount(
	scxfs_mount_t	*mp,
	uint		*needquotamount,
	uint		*quotaflags)
{
	uint		quotaondisk;
	uint		uquotaondisk = 0, gquotaondisk = 0, pquotaondisk = 0;

	quotaondisk = scxfs_sb_version_hasquota(&mp->m_sb) &&
				(mp->m_sb.sb_qflags & SCXFS_ALL_QUOTA_ACCT);

	if (quotaondisk) {
		uquotaondisk = mp->m_sb.sb_qflags & SCXFS_UQUOTA_ACCT;
		pquotaondisk = mp->m_sb.sb_qflags & SCXFS_PQUOTA_ACCT;
		gquotaondisk = mp->m_sb.sb_qflags & SCXFS_GQUOTA_ACCT;
	}

	/*
	 * If the device itself is read-only, we can't allow
	 * the user to change the state of quota on the mount -
	 * this would generate a transaction on the ro device,
	 * which would lead to an I/O error and shutdown
	 */

	if (((uquotaondisk && !SCXFS_IS_UQUOTA_ON(mp)) ||
	    (!uquotaondisk &&  SCXFS_IS_UQUOTA_ON(mp)) ||
	     (gquotaondisk && !SCXFS_IS_GQUOTA_ON(mp)) ||
	    (!gquotaondisk &&  SCXFS_IS_GQUOTA_ON(mp)) ||
	     (pquotaondisk && !SCXFS_IS_PQUOTA_ON(mp)) ||
	    (!pquotaondisk &&  SCXFS_IS_PQUOTA_ON(mp)))  &&
	    scxfs_dev_is_read_only(mp, "changing quota state")) {
		scxfs_warn(mp, "please mount with%s%s%s%s.",
			(!quotaondisk ? "out quota" : ""),
			(uquotaondisk ? " usrquota" : ""),
			(gquotaondisk ? " grpquota" : ""),
			(pquotaondisk ? " prjquota" : ""));
		return -EPERM;
	}

	if (SCXFS_IS_QUOTA_ON(mp) || quotaondisk) {
		/*
		 * Call mount_quotas at this point only if we won't have to do
		 * a quotacheck.
		 */
		if (quotaondisk && !SCXFS_QM_NEED_QUOTACHECK(mp)) {
			/*
			 * If an error occurred, qm_mount_quotas code
			 * has already disabled quotas. So, just finish
			 * mounting, and get on with the boring life
			 * without disk quotas.
			 */
			scxfs_qm_mount_quotas(mp);
		} else {
			/*
			 * Clear the quota flags, but remember them. This
			 * is so that the quota code doesn't get invoked
			 * before we're ready. This can happen when an
			 * inode goes inactive and wants to free blocks,
			 * or via scxfs_log_mount_finish.
			 */
			*needquotamount = true;
			*quotaflags = mp->m_qflags;
			mp->m_qflags = 0;
		}
	}

	return 0;
}
