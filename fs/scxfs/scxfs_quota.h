// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#ifndef __SCXFS_QUOTA_H__
#define __SCXFS_QUOTA_H__

#include "scxfs_quota_defs.h"

/*
 * Kernel only quota definitions and functions
 */

struct scxfs_trans;

/*
 * This check is done typically without holding the inode lock;
 * that may seem racy, but it is harmless in the context that it is used.
 * The inode cannot go inactive as long a reference is kept, and
 * therefore if dquot(s) were attached, they'll stay consistent.
 * If, for example, the ownership of the inode changes while
 * we didn't have the inode locked, the appropriate dquot(s) will be
 * attached atomically.
 */
#define SCXFS_NOT_DQATTACHED(mp, ip) \
	((SCXFS_IS_UQUOTA_ON(mp) && (ip)->i_udquot == NULL) || \
	 (SCXFS_IS_GQUOTA_ON(mp) && (ip)->i_gdquot == NULL) || \
	 (SCXFS_IS_PQUOTA_ON(mp) && (ip)->i_pdquot == NULL))

#define SCXFS_QM_NEED_QUOTACHECK(mp) \
	((SCXFS_IS_UQUOTA_ON(mp) && \
		(mp->m_sb.sb_qflags & SCXFS_UQUOTA_CHKD) == 0) || \
	 (SCXFS_IS_GQUOTA_ON(mp) && \
		(mp->m_sb.sb_qflags & SCXFS_GQUOTA_CHKD) == 0) || \
	 (SCXFS_IS_PQUOTA_ON(mp) && \
		(mp->m_sb.sb_qflags & SCXFS_PQUOTA_CHKD) == 0))

static inline uint
scxfs_quota_chkd_flag(
	uint		dqtype)
{
	switch (dqtype) {
	case SCXFS_DQ_USER:
		return SCXFS_UQUOTA_CHKD;
	case SCXFS_DQ_GROUP:
		return SCXFS_GQUOTA_CHKD;
	case SCXFS_DQ_PROJ:
		return SCXFS_PQUOTA_CHKD;
	default:
		return 0;
	}
}

/*
 * The structure kept inside the scxfs_trans_t keep track of dquot changes
 * within a transaction and apply them later.
 */
struct scxfs_dqtrx {
	struct scxfs_dquot *qt_dquot;	  /* the dquot this refers to */

	uint64_t	qt_blk_res;	  /* blks reserved on a dquot */
	int64_t		qt_bcount_delta;  /* dquot blk count changes */
	int64_t		qt_delbcnt_delta; /* delayed dquot blk count changes */

	uint64_t	qt_rtblk_res;	  /* # blks reserved on a dquot */
	uint64_t	qt_rtblk_res_used;/* # blks used from reservation */
	int64_t		qt_rtbcount_delta;/* dquot realtime blk changes */
	int64_t		qt_delrtb_delta;  /* delayed RT blk count changes */

	uint64_t	qt_ino_res;	  /* inode reserved on a dquot */
	uint64_t	qt_ino_res_used;  /* inodes used from the reservation */
	int64_t		qt_icount_delta;  /* dquot inode count changes */
};

#ifdef CONFIG_XFS_QUOTA
extern void scxfs_trans_dup_dqinfo(struct scxfs_trans *, struct scxfs_trans *);
extern void scxfs_trans_free_dqinfo(struct scxfs_trans *);
extern void scxfs_trans_mod_dquot_byino(struct scxfs_trans *, struct scxfs_inode *,
		uint, int64_t);
extern void scxfs_trans_apply_dquot_deltas(struct scxfs_trans *);
extern void scxfs_trans_unreserve_and_mod_dquots(struct scxfs_trans *);
extern int scxfs_trans_reserve_quota_nblks(struct scxfs_trans *,
		struct scxfs_inode *, int64_t, long, uint);
extern int scxfs_trans_reserve_quota_bydquots(struct scxfs_trans *,
		struct scxfs_mount *, struct scxfs_dquot *,
		struct scxfs_dquot *, struct scxfs_dquot *, int64_t, long, uint);

extern int scxfs_qm_vop_dqalloc(struct scxfs_inode *, scxfs_dqid_t, scxfs_dqid_t,
		prid_t, uint, struct scxfs_dquot **, struct scxfs_dquot **,
		struct scxfs_dquot **);
extern void scxfs_qm_vop_create_dqattach(struct scxfs_trans *, struct scxfs_inode *,
		struct scxfs_dquot *, struct scxfs_dquot *, struct scxfs_dquot *);
extern int scxfs_qm_vop_rename_dqattach(struct scxfs_inode **);
extern struct scxfs_dquot *scxfs_qm_vop_chown(struct scxfs_trans *,
		struct scxfs_inode *, struct scxfs_dquot **, struct scxfs_dquot *);
extern int scxfs_qm_vop_chown_reserve(struct scxfs_trans *, struct scxfs_inode *,
		struct scxfs_dquot *, struct scxfs_dquot *,
		struct scxfs_dquot *, uint);
extern int scxfs_qm_dqattach(struct scxfs_inode *);
extern int scxfs_qm_dqattach_locked(struct scxfs_inode *ip, bool doalloc);
extern void scxfs_qm_dqdetach(struct scxfs_inode *);
extern void scxfs_qm_dqrele(struct scxfs_dquot *);
extern void scxfs_qm_statvfs(struct scxfs_inode *, struct kstatfs *);
extern int scxfs_qm_newmount(struct scxfs_mount *, uint *, uint *);
extern void scxfs_qm_mount_quotas(struct scxfs_mount *);
extern void scxfs_qm_unmount(struct scxfs_mount *);
extern void scxfs_qm_unmount_quotas(struct scxfs_mount *);

#else
static inline int
scxfs_qm_vop_dqalloc(struct scxfs_inode *ip, scxfs_dqid_t uid, scxfs_dqid_t gid,
		prid_t prid, uint flags, struct scxfs_dquot **udqp,
		struct scxfs_dquot **gdqp, struct scxfs_dquot **pdqp)
{
	*udqp = NULL;
	*gdqp = NULL;
	*pdqp = NULL;
	return 0;
}
#define scxfs_trans_dup_dqinfo(tp, tp2)
#define scxfs_trans_free_dqinfo(tp)
#define scxfs_trans_mod_dquot_byino(tp, ip, fields, delta)
#define scxfs_trans_apply_dquot_deltas(tp)
#define scxfs_trans_unreserve_and_mod_dquots(tp)
static inline int scxfs_trans_reserve_quota_nblks(struct scxfs_trans *tp,
		struct scxfs_inode *ip, int64_t nblks, long ninos, uint flags)
{
	return 0;
}
static inline int scxfs_trans_reserve_quota_bydquots(struct scxfs_trans *tp,
		struct scxfs_mount *mp, struct scxfs_dquot *udqp,
		struct scxfs_dquot *gdqp, struct scxfs_dquot *pdqp,
		int64_t nblks, long nions, uint flags)
{
	return 0;
}
#define scxfs_qm_vop_create_dqattach(tp, ip, u, g, p)
#define scxfs_qm_vop_rename_dqattach(it)					(0)
#define scxfs_qm_vop_chown(tp, ip, old, new)				(NULL)
#define scxfs_qm_vop_chown_reserve(tp, ip, u, g, p, fl)			(0)
#define scxfs_qm_dqattach(ip)						(0)
#define scxfs_qm_dqattach_locked(ip, fl)					(0)
#define scxfs_qm_dqdetach(ip)
#define scxfs_qm_dqrele(d)
#define scxfs_qm_statvfs(ip, s)
#define scxfs_qm_newmount(mp, a, b)					(0)
#define scxfs_qm_mount_quotas(mp)
#define scxfs_qm_unmount(mp)
#define scxfs_qm_unmount_quotas(mp)
#endif /* CONFIG_XFS_QUOTA */

#define scxfs_trans_unreserve_quota_nblks(tp, ip, nblks, ninos, flags) \
	scxfs_trans_reserve_quota_nblks(tp, ip, -(nblks), -(ninos), flags)
#define scxfs_trans_reserve_quota(tp, mp, ud, gd, pd, nb, ni, f) \
	scxfs_trans_reserve_quota_bydquots(tp, mp, ud, gd, pd, nb, ni, \
				f | SCXFS_QMOPT_RES_REGBLKS)

extern int scxfs_mount_reset_sbqflags(struct scxfs_mount *);

#endif	/* __SCXFS_QUOTA_H__ */
