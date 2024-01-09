// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2002,2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#ifndef	__SCXFS_TRANS_RESV_H__
#define	__SCXFS_TRANS_RESV_H__

struct scxfs_mount;

/*
 * structure for maintaining pre-calculated transaction reservations.
 */
struct scxfs_trans_res {
	uint	tr_logres;	/* log space unit in bytes per log ticket */
	int	tr_logcount;	/* number of log operations per log ticket */
	int	tr_logflags;	/* log flags, currently only used for indicating
				 * a reservation request is permanent or not */
};

struct scxfs_trans_resv {
	struct scxfs_trans_res	tr_write;	/* extent alloc trans */
	struct scxfs_trans_res	tr_itruncate;	/* truncate trans */
	struct scxfs_trans_res	tr_rename;	/* rename trans */
	struct scxfs_trans_res	tr_link;	/* link trans */
	struct scxfs_trans_res	tr_remove;	/* unlink trans */
	struct scxfs_trans_res	tr_symlink;	/* symlink trans */
	struct scxfs_trans_res	tr_create;	/* create trans */
	struct scxfs_trans_res	tr_create_tmpfile; /* create O_TMPFILE trans */
	struct scxfs_trans_res	tr_mkdir;	/* mkdir trans */
	struct scxfs_trans_res	tr_ifree;	/* inode free trans */
	struct scxfs_trans_res	tr_ichange;	/* inode update trans */
	struct scxfs_trans_res	tr_growdata;	/* fs data section grow trans */
	struct scxfs_trans_res	tr_addafork;	/* add inode attr fork trans */
	struct scxfs_trans_res	tr_writeid;	/* write setuid/setgid file */
	struct scxfs_trans_res	tr_attrinval;	/* attr fork buffer
						 * invalidation */
	struct scxfs_trans_res	tr_attrsetm;	/* set/create an attribute at
						 * mount time */
	struct scxfs_trans_res	tr_attrsetrt;	/* set/create an attribute at
						 * runtime */
	struct scxfs_trans_res	tr_attrrm;	/* remove an attribute */
	struct scxfs_trans_res	tr_clearagi;	/* clear agi unlinked bucket */
	struct scxfs_trans_res	tr_growrtalloc;	/* grow realtime allocations */
	struct scxfs_trans_res	tr_growrtzero;	/* grow realtime zeroing */
	struct scxfs_trans_res	tr_growrtfree;	/* grow realtime freeing */
	struct scxfs_trans_res	tr_qm_setqlim;	/* adjust quota limits */
	struct scxfs_trans_res	tr_qm_dqalloc;	/* allocate quota on disk */
	struct scxfs_trans_res	tr_qm_quotaoff;	/* turn quota off */
	struct scxfs_trans_res	tr_qm_equotaoff;/* end of turn quota off */
	struct scxfs_trans_res	tr_sb;		/* modify superblock */
	struct scxfs_trans_res	tr_fsyncts;	/* update timestamps on fsync */
};

/* shorthand way of accessing reservation structure */
#define M_RES(mp)	(&(mp)->m_resv)

/*
 * Per-directory log reservation for any directory change.
 * dir blocks: (1 btree block per level + data block + free block) * dblock size
 * bmap btree: (levels + 2) * max depth * block size
 * v2 directory blocks can be fragmented below the dirblksize down to the fsb
 * size, so account for that in the DAENTER macros.
 */
#define	SCXFS_DIROP_LOG_RES(mp)	\
	(SCXFS_FSB_TO_B(mp, SCXFS_DAENTER_BLOCKS(mp, SCXFS_DATA_FORK)) + \
	 (SCXFS_FSB_TO_B(mp, SCXFS_DAENTER_BMAPS(mp, SCXFS_DATA_FORK) + 1)))
#define	SCXFS_DIROP_LOG_COUNT(mp)	\
	(SCXFS_DAENTER_BLOCKS(mp, SCXFS_DATA_FORK) + \
	 SCXFS_DAENTER_BMAPS(mp, SCXFS_DATA_FORK) + 1)

/*
 * Various log count values.
 */
#define	SCXFS_DEFAULT_LOG_COUNT		1
#define	SCXFS_DEFAULT_PERM_LOG_COUNT	2
#define	SCXFS_ITRUNCATE_LOG_COUNT		2
#define	SCXFS_ITRUNCATE_LOG_COUNT_REFLINK	8
#define SCXFS_INACTIVE_LOG_COUNT		2
#define	SCXFS_CREATE_LOG_COUNT		2
#define	SCXFS_CREATE_TMPFILE_LOG_COUNT	2
#define	SCXFS_MKDIR_LOG_COUNT		3
#define	SCXFS_SYMLINK_LOG_COUNT		3
#define	SCXFS_REMOVE_LOG_COUNT		2
#define	SCXFS_LINK_LOG_COUNT		2
#define	SCXFS_RENAME_LOG_COUNT		2
#define	SCXFS_WRITE_LOG_COUNT		2
#define	SCXFS_WRITE_LOG_COUNT_REFLINK	8
#define	SCXFS_ADDAFORK_LOG_COUNT		2
#define	SCXFS_ATTRINVAL_LOG_COUNT		1
#define	SCXFS_ATTRSET_LOG_COUNT		3
#define	SCXFS_ATTRRM_LOG_COUNT		3

void scxfs_trans_resv_calc(struct scxfs_mount *mp, struct scxfs_trans_resv *resp);
uint scxfs_allocfree_log_count(struct scxfs_mount *mp, uint num_ops);

#endif	/* __SCXFS_TRANS_RESV_H__ */
