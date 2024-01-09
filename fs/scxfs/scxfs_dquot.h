// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#ifndef __SCXFS_DQUOT_H__
#define __SCXFS_DQUOT_H__

/*
 * Dquots are structures that hold quota information about a user or a group,
 * much like inodes are for files. In fact, dquots share many characteristics
 * with inodes. However, dquots can also be a centralized resource, relative
 * to a collection of inodes. In this respect, dquots share some characteristics
 * of the superblock.
 * SCXFS dquots exploit both those in its algorithms. They make every attempt
 * to not be a bottleneck when quotas are on and have minimal impact, if any,
 * when quotas are off.
 */

struct scxfs_mount;
struct scxfs_trans;

enum {
	SCXFS_QLOWSP_1_PCNT = 0,
	SCXFS_QLOWSP_3_PCNT,
	SCXFS_QLOWSP_5_PCNT,
	SCXFS_QLOWSP_MAX
};

/*
 * The incore dquot structure
 */
typedef struct scxfs_dquot {
	uint		 dq_flags;	/* various flags (SCXFS_DQ_*) */
	struct list_head q_lru;		/* global free list of dquots */
	struct scxfs_mount*q_mount;	/* filesystem this relates to */
	uint		 q_nrefs;	/* # active refs from inodes */
	scxfs_daddr_t	 q_blkno;	/* blkno of dquot buffer */
	int		 q_bufoffset;	/* off of dq in buffer (# dquots) */
	scxfs_fileoff_t	 q_fileoffset;	/* offset in quotas file */

	scxfs_disk_dquot_t q_core;	/* actual usage & quotas */
	scxfs_dq_logitem_t q_logitem;	/* dquot log item */
	scxfs_qcnt_t	 q_res_bcount;	/* total regular nblks used+reserved */
	scxfs_qcnt_t	 q_res_icount;	/* total inos allocd+reserved */
	scxfs_qcnt_t	 q_res_rtbcount;/* total realtime blks used+reserved */
	scxfs_qcnt_t	 q_prealloc_lo_wmark;/* prealloc throttle wmark */
	scxfs_qcnt_t	 q_prealloc_hi_wmark;/* prealloc disabled wmark */
	int64_t		 q_low_space[SCXFS_QLOWSP_MAX];
	struct mutex	 q_qlock;	/* quota lock */
	struct completion q_flush;	/* flush completion queue */
	atomic_t          q_pincount;	/* dquot pin count */
	wait_queue_head_t q_pinwait;	/* dquot pinning wait queue */
} scxfs_dquot_t;

/*
 * Lock hierarchy for q_qlock:
 *	SCXFS_QLOCK_NORMAL is the implicit default,
 * 	SCXFS_QLOCK_NESTED is the dquot with the higher id in scxfs_dqlock2
 */
enum {
	SCXFS_QLOCK_NORMAL = 0,
	SCXFS_QLOCK_NESTED,
};

/*
 * Manage the q_flush completion queue embedded in the dquot.  This completion
 * queue synchronizes processes attempting to flush the in-core dquot back to
 * disk.
 */
static inline void scxfs_dqflock(scxfs_dquot_t *dqp)
{
	wait_for_completion(&dqp->q_flush);
}

static inline bool scxfs_dqflock_nowait(scxfs_dquot_t *dqp)
{
	return try_wait_for_completion(&dqp->q_flush);
}

static inline void scxfs_dqfunlock(scxfs_dquot_t *dqp)
{
	complete(&dqp->q_flush);
}

static inline int scxfs_dqlock_nowait(struct scxfs_dquot *dqp)
{
	return mutex_trylock(&dqp->q_qlock);
}

static inline void scxfs_dqlock(struct scxfs_dquot *dqp)
{
	mutex_lock(&dqp->q_qlock);
}

static inline void scxfs_dqunlock(struct scxfs_dquot *dqp)
{
	mutex_unlock(&dqp->q_qlock);
}

static inline int scxfs_this_quota_on(struct scxfs_mount *mp, int type)
{
	switch (type & SCXFS_DQ_ALLTYPES) {
	case SCXFS_DQ_USER:
		return SCXFS_IS_UQUOTA_ON(mp);
	case SCXFS_DQ_GROUP:
		return SCXFS_IS_GQUOTA_ON(mp);
	case SCXFS_DQ_PROJ:
		return SCXFS_IS_PQUOTA_ON(mp);
	default:
		return 0;
	}
}

static inline scxfs_dquot_t *scxfs_inode_dquot(struct scxfs_inode *ip, int type)
{
	switch (type & SCXFS_DQ_ALLTYPES) {
	case SCXFS_DQ_USER:
		return ip->i_udquot;
	case SCXFS_DQ_GROUP:
		return ip->i_gdquot;
	case SCXFS_DQ_PROJ:
		return ip->i_pdquot;
	default:
		return NULL;
	}
}

/*
 * Check whether a dquot is under low free space conditions. We assume the quota
 * is enabled and enforced.
 */
static inline bool scxfs_dquot_lowsp(struct scxfs_dquot *dqp)
{
	int64_t freesp;

	freesp = be64_to_cpu(dqp->q_core.d_blk_hardlimit) - dqp->q_res_bcount;
	if (freesp < dqp->q_low_space[SCXFS_QLOWSP_1_PCNT])
		return true;

	return false;
}

#define SCXFS_DQ_IS_LOCKED(dqp)	(mutex_is_locked(&((dqp)->q_qlock)))
#define SCXFS_DQ_IS_DIRTY(dqp)	((dqp)->dq_flags & SCXFS_DQ_DIRTY)
#define SCXFS_QM_ISUDQ(dqp)	((dqp)->dq_flags & SCXFS_DQ_USER)
#define SCXFS_QM_ISPDQ(dqp)	((dqp)->dq_flags & SCXFS_DQ_PROJ)
#define SCXFS_QM_ISGDQ(dqp)	((dqp)->dq_flags & SCXFS_DQ_GROUP)

extern void		scxfs_qm_dqdestroy(scxfs_dquot_t *);
extern int		scxfs_qm_dqflush(struct scxfs_dquot *, struct scxfs_buf **);
extern void		scxfs_qm_dqunpin_wait(scxfs_dquot_t *);
extern void		scxfs_qm_adjust_dqtimers(scxfs_mount_t *,
					scxfs_disk_dquot_t *);
extern void		scxfs_qm_adjust_dqlimits(struct scxfs_mount *,
					       struct scxfs_dquot *);
extern scxfs_dqid_t	scxfs_qm_id_for_quotatype(struct scxfs_inode *ip,
					uint type);
extern int		scxfs_qm_dqget(struct scxfs_mount *mp, scxfs_dqid_t id,
					uint type, bool can_alloc,
					struct scxfs_dquot **dqpp);
extern int		scxfs_qm_dqget_inode(struct scxfs_inode *ip, uint type,
					bool can_alloc,
					struct scxfs_dquot **dqpp);
extern int		scxfs_qm_dqget_next(struct scxfs_mount *mp, scxfs_dqid_t id,
					uint type, struct scxfs_dquot **dqpp);
extern int		scxfs_qm_dqget_uncached(struct scxfs_mount *mp,
					scxfs_dqid_t id, uint type,
					struct scxfs_dquot **dqpp);
extern void		scxfs_qm_dqput(scxfs_dquot_t *);

extern void		scxfs_dqlock2(struct scxfs_dquot *, struct scxfs_dquot *);

extern void		scxfs_dquot_set_prealloc_limits(struct scxfs_dquot *);

static inline struct scxfs_dquot *scxfs_qm_dqhold(struct scxfs_dquot *dqp)
{
	scxfs_dqlock(dqp);
	dqp->q_nrefs++;
	scxfs_dqunlock(dqp);
	return dqp;
}

typedef int (*scxfs_qm_dqiterate_fn)(struct scxfs_dquot *dq, uint dqtype,
		void *priv);
int scxfs_qm_dqiterate(struct scxfs_mount *mp, uint dqtype,
		scxfs_qm_dqiterate_fn iter_fn, void *priv);

#endif /* __SCXFS_DQUOT_H__ */
