// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2016 Oracle.  All Rights Reserved.
 * Author: Darrick J. Wong <darrick.wong@oracle.com>
 */
#ifndef __SCXFS_REFCOUNT_BTREE_H__
#define	__SCXFS_REFCOUNT_BTREE_H__

/*
 * Reference Count Btree on-disk structures
 */

struct scxfs_buf;
struct scxfs_btree_cur;
struct scxfs_mount;

/*
 * Btree block header size
 */
#define SCXFS_REFCOUNT_BLOCK_LEN	SCXFS_BTREE_SBLOCK_CRC_LEN

/*
 * Record, key, and pointer address macros for btree blocks.
 *
 * (note that some of these may appear unused, but they are used in userspace)
 */
#define SCXFS_REFCOUNT_REC_ADDR(block, index) \
	((struct scxfs_refcount_rec *) \
		((char *)(block) + \
		 SCXFS_REFCOUNT_BLOCK_LEN + \
		 (((index) - 1) * sizeof(struct scxfs_refcount_rec))))

#define SCXFS_REFCOUNT_KEY_ADDR(block, index) \
	((struct scxfs_refcount_key *) \
		((char *)(block) + \
		 SCXFS_REFCOUNT_BLOCK_LEN + \
		 ((index) - 1) * sizeof(struct scxfs_refcount_key)))

#define SCXFS_REFCOUNT_PTR_ADDR(block, index, maxrecs) \
	((scxfs_refcount_ptr_t *) \
		((char *)(block) + \
		 SCXFS_REFCOUNT_BLOCK_LEN + \
		 (maxrecs) * sizeof(struct scxfs_refcount_key) + \
		 ((index) - 1) * sizeof(scxfs_refcount_ptr_t)))

extern struct scxfs_btree_cur *scxfs_refcountbt_init_cursor(struct scxfs_mount *mp,
		struct scxfs_trans *tp, struct scxfs_buf *agbp,
		scxfs_agnumber_t agno);
extern int scxfs_refcountbt_maxrecs(int blocklen, bool leaf);
extern void scxfs_refcountbt_compute_maxlevels(struct scxfs_mount *mp);

extern scxfs_extlen_t scxfs_refcountbt_calc_size(struct scxfs_mount *mp,
		unsigned long long len);
extern scxfs_extlen_t scxfs_refcountbt_max_size(struct scxfs_mount *mp,
		scxfs_agblock_t agblocks);

extern int scxfs_refcountbt_calc_reserves(struct scxfs_mount *mp,
		struct scxfs_trans *tp, scxfs_agnumber_t agno, scxfs_extlen_t *ask,
		scxfs_extlen_t *used);

#endif	/* __SCXFS_REFCOUNT_BTREE_H__ */
