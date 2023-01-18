// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#ifndef __SCXFS_QUOTA_DEFS_H__
#define __SCXFS_QUOTA_DEFS_H__

/*
 * Quota definitions shared between user and kernel source trees.
 */

/*
 * Even though users may not have quota limits occupying all 64-bits,
 * they may need 64-bit accounting. Hence, 64-bit quota-counters,
 * and quota-limits. This is a waste in the common case, but hey ...
 */
typedef uint64_t	scxfs_qcnt_t;
typedef uint16_t	scxfs_qwarncnt_t;

/*
 * flags for q_flags field in the dquot.
 */
#define SCXFS_DQ_USER		0x0001		/* a user quota */
#define SCXFS_DQ_PROJ		0x0002		/* project quota */
#define SCXFS_DQ_GROUP		0x0004		/* a group quota */
#define SCXFS_DQ_DIRTY		0x0008		/* dquot is dirty */
#define SCXFS_DQ_FREEING		0x0010		/* dquot is being torn down */

#define SCXFS_DQ_ALLTYPES		(SCXFS_DQ_USER|SCXFS_DQ_PROJ|SCXFS_DQ_GROUP)

#define SCXFS_DQ_FLAGS \
	{ SCXFS_DQ_USER,		"USER" }, \
	{ SCXFS_DQ_PROJ,		"PROJ" }, \
	{ SCXFS_DQ_GROUP,		"GROUP" }, \
	{ SCXFS_DQ_DIRTY,		"DIRTY" }, \
	{ SCXFS_DQ_FREEING,	"FREEING" }

/*
 * We have the possibility of all three quota types being active at once, and
 * hence free space modification requires modification of all three current
 * dquots in a single transaction. For this case we need to have a reservation
 * of at least 3 dquots.
 *
 * However, a chmod operation can change both UID and GID in a single
 * transaction, resulting in requiring {old, new} x {uid, gid} dquots to be
 * modified. Hence for this case we need to reserve space for at least 4 dquots.
 *
 * And in the worst case, there's a rename operation that can be modifying up to
 * 4 inodes with dquots attached to them. In reality, the only inodes that can
 * have their dquots modified are the source and destination directory inodes
 * due to directory name creation and removal. That can require space allocation
 * and/or freeing on both directory inodes, and hence all three dquots on each
 * inode can be modified. And if the directories are world writeable, all the
 * dquots can be unique and so 6 dquots can be modified....
 *
 * And, of course, we also need to take into account the dquot log format item
 * used to describe each dquot.
 */
#define SCXFS_DQUOT_LOGRES(mp)	\
	((sizeof(struct scxfs_dq_logformat) + sizeof(struct scxfs_disk_dquot)) * 6)

#define SCXFS_IS_QUOTA_RUNNING(mp)	((mp)->m_qflags & SCXFS_ALL_QUOTA_ACCT)
#define SCXFS_IS_UQUOTA_RUNNING(mp)	((mp)->m_qflags & SCXFS_UQUOTA_ACCT)
#define SCXFS_IS_PQUOTA_RUNNING(mp)	((mp)->m_qflags & SCXFS_PQUOTA_ACCT)
#define SCXFS_IS_GQUOTA_RUNNING(mp)	((mp)->m_qflags & SCXFS_GQUOTA_ACCT)
#define SCXFS_IS_UQUOTA_ENFORCED(mp)	((mp)->m_qflags & SCXFS_UQUOTA_ENFD)
#define SCXFS_IS_GQUOTA_ENFORCED(mp)	((mp)->m_qflags & SCXFS_GQUOTA_ENFD)
#define SCXFS_IS_PQUOTA_ENFORCED(mp)	((mp)->m_qflags & SCXFS_PQUOTA_ENFD)

/*
 * Incore only flags for quotaoff - these bits get cleared when quota(s)
 * are in the process of getting turned off. These flags are in m_qflags but
 * never in sb_qflags.
 */
#define SCXFS_UQUOTA_ACTIVE	0x1000  /* uquotas are being turned off */
#define SCXFS_GQUOTA_ACTIVE	0x2000  /* gquotas are being turned off */
#define SCXFS_PQUOTA_ACTIVE	0x4000  /* pquotas are being turned off */
#define SCXFS_ALL_QUOTA_ACTIVE	\
	(SCXFS_UQUOTA_ACTIVE | SCXFS_GQUOTA_ACTIVE | SCXFS_PQUOTA_ACTIVE)

/*
 * Checking SCXFS_IS_*QUOTA_ON() while holding any inode lock guarantees
 * quota will be not be switched off as long as that inode lock is held.
 */
#define SCXFS_IS_QUOTA_ON(mp)	((mp)->m_qflags & (SCXFS_UQUOTA_ACTIVE | \
						   SCXFS_GQUOTA_ACTIVE | \
						   SCXFS_PQUOTA_ACTIVE))
#define SCXFS_IS_UQUOTA_ON(mp)	((mp)->m_qflags & SCXFS_UQUOTA_ACTIVE)
#define SCXFS_IS_GQUOTA_ON(mp)	((mp)->m_qflags & SCXFS_GQUOTA_ACTIVE)
#define SCXFS_IS_PQUOTA_ON(mp)	((mp)->m_qflags & SCXFS_PQUOTA_ACTIVE)

/*
 * Flags to tell various functions what to do. Not all of these are meaningful
 * to a single function. None of these SCXFS_QMOPT_* flags are meant to have
 * persistent values (ie. their values can and will change between versions)
 */
#define SCXFS_QMOPT_UQUOTA	0x0000004 /* user dquot requested */
#define SCXFS_QMOPT_PQUOTA	0x0000008 /* project dquot requested */
#define SCXFS_QMOPT_FORCE_RES	0x0000010 /* ignore quota limits */
#define SCXFS_QMOPT_SBVERSION	0x0000040 /* change superblock version num */
#define SCXFS_QMOPT_GQUOTA	0x0002000 /* group dquot requested */
#define SCXFS_QMOPT_ENOSPC	0x0004000 /* enospc instead of edquot (prj) */

/*
 * flags to scxfs_trans_mod_dquot to indicate which field needs to be
 * modified.
 */
#define SCXFS_QMOPT_RES_REGBLKS	0x0010000
#define SCXFS_QMOPT_RES_RTBLKS	0x0020000
#define SCXFS_QMOPT_BCOUNT	0x0040000
#define SCXFS_QMOPT_ICOUNT	0x0080000
#define SCXFS_QMOPT_RTBCOUNT	0x0100000
#define SCXFS_QMOPT_DELBCOUNT	0x0200000
#define SCXFS_QMOPT_DELRTBCOUNT	0x0400000
#define SCXFS_QMOPT_RES_INOS	0x0800000

/*
 * flags for dqalloc.
 */
#define SCXFS_QMOPT_INHERIT	0x1000000

/*
 * flags to scxfs_trans_mod_dquot.
 */
#define SCXFS_TRANS_DQ_RES_BLKS	SCXFS_QMOPT_RES_REGBLKS
#define SCXFS_TRANS_DQ_RES_RTBLKS	SCXFS_QMOPT_RES_RTBLKS
#define SCXFS_TRANS_DQ_RES_INOS	SCXFS_QMOPT_RES_INOS
#define SCXFS_TRANS_DQ_BCOUNT	SCXFS_QMOPT_BCOUNT
#define SCXFS_TRANS_DQ_DELBCOUNT	SCXFS_QMOPT_DELBCOUNT
#define SCXFS_TRANS_DQ_ICOUNT	SCXFS_QMOPT_ICOUNT
#define SCXFS_TRANS_DQ_RTBCOUNT	SCXFS_QMOPT_RTBCOUNT
#define SCXFS_TRANS_DQ_DELRTBCOUNT SCXFS_QMOPT_DELRTBCOUNT


#define SCXFS_QMOPT_QUOTALL	\
		(SCXFS_QMOPT_UQUOTA | SCXFS_QMOPT_PQUOTA | SCXFS_QMOPT_GQUOTA)
#define SCXFS_QMOPT_RESBLK_MASK	(SCXFS_QMOPT_RES_REGBLKS | SCXFS_QMOPT_RES_RTBLKS)

extern scxfs_failaddr_t scxfs_dquot_verify(struct scxfs_mount *mp,
		struct scxfs_disk_dquot *ddq, scxfs_dqid_t id, uint type);
extern scxfs_failaddr_t scxfs_dqblk_verify(struct scxfs_mount *mp,
		struct scxfs_dqblk *dqb, scxfs_dqid_t id, uint type);
extern int scxfs_calc_dquots_per_chunk(unsigned int nbblks);
extern void scxfs_dqblk_repair(struct scxfs_mount *mp, struct scxfs_dqblk *dqb,
		scxfs_dqid_t id, uint type);

#endif	/* __SCXFS_QUOTA_H__ */
