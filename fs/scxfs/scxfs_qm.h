// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#ifndef __SCXFS_QM_H__
#define __SCXFS_QM_H__

#include "scxfs_dquot_item.h"
#include "scxfs_dquot.h"

struct scxfs_inode;

extern struct kmem_zone	*scxfs_qm_dqtrxzone;

/*
 * Number of bmaps that we ask from bmapi when doing a quotacheck.
 * We make this restriction to keep the memory usage to a minimum.
 */
#define SCXFS_DQITER_MAP_SIZE	10

#define SCXFS_IS_DQUOT_UNINITIALIZED(dqp) ( \
	!dqp->q_core.d_blk_hardlimit && \
	!dqp->q_core.d_blk_softlimit && \
	!dqp->q_core.d_rtb_hardlimit && \
	!dqp->q_core.d_rtb_softlimit && \
	!dqp->q_core.d_ino_hardlimit && \
	!dqp->q_core.d_ino_softlimit && \
	!dqp->q_core.d_bcount && \
	!dqp->q_core.d_rtbcount && \
	!dqp->q_core.d_icount)

/*
 * This defines the unit of allocation of dquots.
 * Currently, it is just one file system block, and a 4K blk contains 30
 * (136 * 30 = 4080) dquots. It's probably not worth trying to make
 * this more dynamic.
 * XXXsup However, if this number is changed, we have to make sure that we don't
 * implicitly assume that we do allocations in chunks of a single filesystem
 * block in the dquot/xqm code.
 */
#define SCXFS_DQUOT_CLUSTER_SIZE_FSB	(scxfs_filblks_t)1

struct scxfs_def_quota {
	scxfs_qcnt_t       bhardlimit;     /* default data blk hard limit */
	scxfs_qcnt_t       bsoftlimit;	 /* default data blk soft limit */
	scxfs_qcnt_t       ihardlimit;	 /* default inode count hard limit */
	scxfs_qcnt_t       isoftlimit;	 /* default inode count soft limit */
	scxfs_qcnt_t	 rtbhardlimit;   /* default realtime blk hard limit */
	scxfs_qcnt_t	 rtbsoftlimit;   /* default realtime blk soft limit */
};

/*
 * Various quota information for individual filesystems.
 * The mount structure keeps a pointer to this.
 */
typedef struct scxfs_quotainfo {
	struct radix_tree_root qi_uquota_tree;
	struct radix_tree_root qi_gquota_tree;
	struct radix_tree_root qi_pquota_tree;
	struct mutex qi_tree_lock;
	struct scxfs_inode	*qi_uquotaip;	/* user quota inode */
	struct scxfs_inode	*qi_gquotaip;	/* group quota inode */
	struct scxfs_inode	*qi_pquotaip;	/* project quota inode */
	struct list_lru	 qi_lru;
	int		 qi_dquots;
	time_t		 qi_btimelimit;	 /* limit for blks timer */
	time_t		 qi_itimelimit;	 /* limit for inodes timer */
	time_t		 qi_rtbtimelimit;/* limit for rt blks timer */
	scxfs_qwarncnt_t	 qi_bwarnlimit;	 /* limit for blks warnings */
	scxfs_qwarncnt_t	 qi_iwarnlimit;	 /* limit for inodes warnings */
	scxfs_qwarncnt_t	 qi_rtbwarnlimit;/* limit for rt blks warnings */
	struct mutex	 qi_quotaofflock;/* to serialize quotaoff */
	scxfs_filblks_t	 qi_dqchunklen;	 /* # BBs in a chunk of dqs */
	uint		 qi_dqperchunk;	 /* # ondisk dqs in above chunk */
	struct scxfs_def_quota	qi_usr_default;
	struct scxfs_def_quota	qi_grp_default;
	struct scxfs_def_quota	qi_prj_default;
	struct shrinker  qi_shrinker;
} scxfs_quotainfo_t;

static inline struct radix_tree_root *
scxfs_dquot_tree(
	struct scxfs_quotainfo	*qi,
	int			type)
{
	switch (type) {
	case SCXFS_DQ_USER:
		return &qi->qi_uquota_tree;
	case SCXFS_DQ_GROUP:
		return &qi->qi_gquota_tree;
	case SCXFS_DQ_PROJ:
		return &qi->qi_pquota_tree;
	default:
		ASSERT(0);
	}
	return NULL;
}

static inline struct scxfs_inode *
scxfs_quota_inode(scxfs_mount_t *mp, uint dq_flags)
{
	switch (dq_flags & SCXFS_DQ_ALLTYPES) {
	case SCXFS_DQ_USER:
		return mp->m_quotainfo->qi_uquotaip;
	case SCXFS_DQ_GROUP:
		return mp->m_quotainfo->qi_gquotaip;
	case SCXFS_DQ_PROJ:
		return mp->m_quotainfo->qi_pquotaip;
	default:
		ASSERT(0);
	}
	return NULL;
}

extern void	scxfs_trans_mod_dquot(struct scxfs_trans *tp, struct scxfs_dquot *dqp,
				    uint field, int64_t delta);
extern void	scxfs_trans_dqjoin(struct scxfs_trans *, struct scxfs_dquot *);
extern void	scxfs_trans_log_dquot(struct scxfs_trans *, struct scxfs_dquot *);

/*
 * We keep the usr, grp, and prj dquots separately so that locking will be
 * easier to do at commit time. All transactions that we know of at this point
 * affect no more than two dquots of one type. Hence, the TRANS_MAXDQS value.
 */
enum {
	SCXFS_QM_TRANS_USR = 0,
	SCXFS_QM_TRANS_GRP,
	SCXFS_QM_TRANS_PRJ,
	SCXFS_QM_TRANS_DQTYPES
};
#define SCXFS_QM_TRANS_MAXDQS		2
struct scxfs_dquot_acct {
	struct scxfs_dqtrx	dqs[SCXFS_QM_TRANS_DQTYPES][SCXFS_QM_TRANS_MAXDQS];
};

/*
 * Users are allowed to have a usage exceeding their softlimit for
 * a period this long.
 */
#define SCXFS_QM_BTIMELIMIT	(7 * 24*60*60)          /* 1 week */
#define SCXFS_QM_RTBTIMELIMIT	(7 * 24*60*60)          /* 1 week */
#define SCXFS_QM_ITIMELIMIT	(7 * 24*60*60)          /* 1 week */

#define SCXFS_QM_BWARNLIMIT	5
#define SCXFS_QM_IWARNLIMIT	5
#define SCXFS_QM_RTBWARNLIMIT	5

extern void		scxfs_qm_destroy_quotainfo(struct scxfs_mount *);

/* dquot stuff */
extern void		scxfs_qm_dqpurge_all(struct scxfs_mount *, uint);
extern void		scxfs_qm_dqrele_all_inodes(struct scxfs_mount *, uint);

/* quota ops */
extern int		scxfs_qm_scall_trunc_qfiles(struct scxfs_mount *, uint);
extern int		scxfs_qm_scall_getquota(struct scxfs_mount *, scxfs_dqid_t,
					uint, struct qc_dqblk *);
extern int		scxfs_qm_scall_getquota_next(struct scxfs_mount *,
					scxfs_dqid_t *, uint, struct qc_dqblk *);
extern int		scxfs_qm_scall_setqlim(struct scxfs_mount *, scxfs_dqid_t, uint,
					struct qc_dqblk *);
extern int		scxfs_qm_scall_quotaon(struct scxfs_mount *, uint);
extern int		scxfs_qm_scall_quotaoff(struct scxfs_mount *, uint);

static inline struct scxfs_def_quota *
scxfs_get_defquota(struct scxfs_dquot *dqp, struct scxfs_quotainfo *qi)
{
	struct scxfs_def_quota *defq;

	if (SCXFS_QM_ISUDQ(dqp))
		defq = &qi->qi_usr_default;
	else if (SCXFS_QM_ISGDQ(dqp))
		defq = &qi->qi_grp_default;
	else {
		ASSERT(SCXFS_QM_ISPDQ(dqp));
		defq = &qi->qi_prj_default;
	}
	return defq;
}

#endif /* __SCXFS_QM_H__ */
