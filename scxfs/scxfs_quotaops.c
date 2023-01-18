// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2008, Christoph Hellwig
 * All Rights Reserved.
 */
#include "scxfs.h"
#include "scxfs_shared.h"
#include "scxfs_format.h"
#include "scxfs_log_format.h"
#include "scxfs_trans_resv.h"
#include "scxfs_mount.h"
#include "scxfs_inode.h"
#include "scxfs_quota.h"
#include "scxfs_trans.h"
#include "scxfs_icache.h"
#include "scxfs_qm.h"


static void
scxfs_qm_fill_state(
	struct qc_type_state	*tstate,
	struct scxfs_mount	*mp,
	struct scxfs_inode	*ip,
	scxfs_ino_t		ino)
{
	struct scxfs_quotainfo *q = mp->m_quotainfo;
	bool tempqip = false;

	tstate->ino = ino;
	if (!ip && ino == NULLFSINO)
		return;
	if (!ip) {
		if (scxfs_iget(mp, NULL, ino, 0, 0, &ip))
			return;
		tempqip = true;
	}
	tstate->flags |= QCI_SYSFILE;
	tstate->blocks = ip->i_d.di_nblocks;
	tstate->nextents = ip->i_d.di_nextents;
	tstate->spc_timelimit = q->qi_btimelimit;
	tstate->ino_timelimit = q->qi_itimelimit;
	tstate->rt_spc_timelimit = q->qi_rtbtimelimit;
	tstate->spc_warnlimit = q->qi_bwarnlimit;
	tstate->ino_warnlimit = q->qi_iwarnlimit;
	tstate->rt_spc_warnlimit = q->qi_rtbwarnlimit;
	if (tempqip)
		scxfs_irele(ip);
}

/*
 * Return quota status information, such as enforcements, quota file inode
 * numbers etc.
 */
static int
scxfs_fs_get_quota_state(
	struct super_block	*sb,
	struct qc_state		*state)
{
	struct scxfs_mount *mp = SCXFS_M(sb);
	struct scxfs_quotainfo *q = mp->m_quotainfo;

	memset(state, 0, sizeof(*state));
	if (!SCXFS_IS_QUOTA_RUNNING(mp))
		return 0;
	state->s_incoredqs = q->qi_dquots;
	if (SCXFS_IS_UQUOTA_RUNNING(mp))
		state->s_state[USRQUOTA].flags |= QCI_ACCT_ENABLED;
	if (SCXFS_IS_UQUOTA_ENFORCED(mp))
		state->s_state[USRQUOTA].flags |= QCI_LIMITS_ENFORCED;
	if (SCXFS_IS_GQUOTA_RUNNING(mp))
		state->s_state[GRPQUOTA].flags |= QCI_ACCT_ENABLED;
	if (SCXFS_IS_GQUOTA_ENFORCED(mp))
		state->s_state[GRPQUOTA].flags |= QCI_LIMITS_ENFORCED;
	if (SCXFS_IS_PQUOTA_RUNNING(mp))
		state->s_state[PRJQUOTA].flags |= QCI_ACCT_ENABLED;
	if (SCXFS_IS_PQUOTA_ENFORCED(mp))
		state->s_state[PRJQUOTA].flags |= QCI_LIMITS_ENFORCED;

	scxfs_qm_fill_state(&state->s_state[USRQUOTA], mp, q->qi_uquotaip,
			  mp->m_sb.sb_uquotino);
	scxfs_qm_fill_state(&state->s_state[GRPQUOTA], mp, q->qi_gquotaip,
			  mp->m_sb.sb_gquotino);
	scxfs_qm_fill_state(&state->s_state[PRJQUOTA], mp, q->qi_pquotaip,
			  mp->m_sb.sb_pquotino);
	return 0;
}

STATIC int
scxfs_quota_type(int type)
{
	switch (type) {
	case USRQUOTA:
		return SCXFS_DQ_USER;
	case GRPQUOTA:
		return SCXFS_DQ_GROUP;
	default:
		return SCXFS_DQ_PROJ;
	}
}

#define SCXFS_QC_SETINFO_MASK (QC_TIMER_MASK | QC_WARNS_MASK)

/*
 * Adjust quota timers & warnings
 */
static int
scxfs_fs_set_info(
	struct super_block	*sb,
	int			type,
	struct qc_info		*info)
{
	struct scxfs_mount *mp = SCXFS_M(sb);
	struct qc_dqblk newlim;

	if (sb_rdonly(sb))
		return -EROFS;
	if (!SCXFS_IS_QUOTA_RUNNING(mp))
		return -ENOSYS;
	if (!SCXFS_IS_QUOTA_ON(mp))
		return -ESRCH;
	if (info->i_fieldmask & ~SCXFS_QC_SETINFO_MASK)
		return -EINVAL;
	if ((info->i_fieldmask & SCXFS_QC_SETINFO_MASK) == 0)
		return 0;

	newlim.d_fieldmask = info->i_fieldmask;
	newlim.d_spc_timer = info->i_spc_timelimit;
	newlim.d_ino_timer = info->i_ino_timelimit;
	newlim.d_rt_spc_timer = info->i_rt_spc_timelimit;
	newlim.d_ino_warns = info->i_ino_warnlimit;
	newlim.d_spc_warns = info->i_spc_warnlimit;
	newlim.d_rt_spc_warns = info->i_rt_spc_warnlimit;

	return scxfs_qm_scall_setqlim(mp, 0, scxfs_quota_type(type), &newlim);
}

static unsigned int
scxfs_quota_flags(unsigned int uflags)
{
	unsigned int flags = 0;

	if (uflags & FS_QUOTA_UDQ_ACCT)
		flags |= SCXFS_UQUOTA_ACCT;
	if (uflags & FS_QUOTA_PDQ_ACCT)
		flags |= SCXFS_PQUOTA_ACCT;
	if (uflags & FS_QUOTA_GDQ_ACCT)
		flags |= SCXFS_GQUOTA_ACCT;
	if (uflags & FS_QUOTA_UDQ_ENFD)
		flags |= SCXFS_UQUOTA_ENFD;
	if (uflags & FS_QUOTA_GDQ_ENFD)
		flags |= SCXFS_GQUOTA_ENFD;
	if (uflags & FS_QUOTA_PDQ_ENFD)
		flags |= SCXFS_PQUOTA_ENFD;

	return flags;
}

STATIC int
scxfs_quota_enable(
	struct super_block	*sb,
	unsigned int		uflags)
{
	struct scxfs_mount	*mp = SCXFS_M(sb);

	if (sb_rdonly(sb))
		return -EROFS;
	if (!SCXFS_IS_QUOTA_RUNNING(mp))
		return -ENOSYS;

	return scxfs_qm_scall_quotaon(mp, scxfs_quota_flags(uflags));
}

STATIC int
scxfs_quota_disable(
	struct super_block	*sb,
	unsigned int		uflags)
{
	struct scxfs_mount	*mp = SCXFS_M(sb);

	if (sb_rdonly(sb))
		return -EROFS;
	if (!SCXFS_IS_QUOTA_RUNNING(mp))
		return -ENOSYS;
	if (!SCXFS_IS_QUOTA_ON(mp))
		return -EINVAL;

	return scxfs_qm_scall_quotaoff(mp, scxfs_quota_flags(uflags));
}

STATIC int
scxfs_fs_rm_xquota(
	struct super_block	*sb,
	unsigned int		uflags)
{
	struct scxfs_mount	*mp = SCXFS_M(sb);
	unsigned int		flags = 0;

	if (sb_rdonly(sb))
		return -EROFS;

	if (SCXFS_IS_QUOTA_ON(mp))
		return -EINVAL;

	if (uflags & ~(FS_USER_QUOTA | FS_GROUP_QUOTA | FS_PROJ_QUOTA))
		return -EINVAL;

	if (uflags & FS_USER_QUOTA)
		flags |= SCXFS_DQ_USER;
	if (uflags & FS_GROUP_QUOTA)
		flags |= SCXFS_DQ_GROUP;
	if (uflags & FS_PROJ_QUOTA)
		flags |= SCXFS_DQ_PROJ;

	return scxfs_qm_scall_trunc_qfiles(mp, flags);
}

STATIC int
scxfs_fs_get_dqblk(
	struct super_block	*sb,
	struct kqid		qid,
	struct qc_dqblk		*qdq)
{
	struct scxfs_mount	*mp = SCXFS_M(sb);
	scxfs_dqid_t		id;

	if (!SCXFS_IS_QUOTA_RUNNING(mp))
		return -ENOSYS;
	if (!SCXFS_IS_QUOTA_ON(mp))
		return -ESRCH;

	id = from_kqid(&init_user_ns, qid);
	return scxfs_qm_scall_getquota(mp, id, scxfs_quota_type(qid.type), qdq);
}

/* Return quota info for active quota >= this qid */
STATIC int
scxfs_fs_get_nextdqblk(
	struct super_block	*sb,
	struct kqid		*qid,
	struct qc_dqblk		*qdq)
{
	int			ret;
	struct scxfs_mount	*mp = SCXFS_M(sb);
	scxfs_dqid_t		id;

	if (!SCXFS_IS_QUOTA_RUNNING(mp))
		return -ENOSYS;
	if (!SCXFS_IS_QUOTA_ON(mp))
		return -ESRCH;

	id = from_kqid(&init_user_ns, *qid);
	ret = scxfs_qm_scall_getquota_next(mp, &id, scxfs_quota_type(qid->type),
			qdq);
	if (ret)
		return ret;

	/* ID may be different, so convert back what we got */
	*qid = make_kqid(current_user_ns(), qid->type, id);
	return 0;
}

STATIC int
scxfs_fs_set_dqblk(
	struct super_block	*sb,
	struct kqid		qid,
	struct qc_dqblk		*qdq)
{
	struct scxfs_mount	*mp = SCXFS_M(sb);

	if (sb_rdonly(sb))
		return -EROFS;
	if (!SCXFS_IS_QUOTA_RUNNING(mp))
		return -ENOSYS;
	if (!SCXFS_IS_QUOTA_ON(mp))
		return -ESRCH;

	return scxfs_qm_scall_setqlim(mp, from_kqid(&init_user_ns, qid),
				     scxfs_quota_type(qid.type), qdq);
}

const struct quotactl_ops scxfs_quotactl_operations = {
	.get_state		= scxfs_fs_get_quota_state,
	.set_info		= scxfs_fs_set_info,
	.quota_enable		= scxfs_quota_enable,
	.quota_disable		= scxfs_quota_disable,
	.rm_xquota		= scxfs_fs_rm_xquota,
	.get_dqblk		= scxfs_fs_get_dqblk,
	.get_nextdqblk		= scxfs_fs_get_nextdqblk,
	.set_dqblk		= scxfs_fs_set_dqblk,
};
