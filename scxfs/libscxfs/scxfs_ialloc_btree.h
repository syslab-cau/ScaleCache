// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000,2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#ifndef __SCXFS_IALLOC_BTREE_H__
#define	__SCXFS_IALLOC_BTREE_H__

/*
 * Inode map on-disk structures
 */

struct scxfs_buf;
struct scxfs_btree_cur;
struct scxfs_mount;

/*
 * Btree block header size depends on a superblock flag.
 */
#define SCXFS_INOBT_BLOCK_LEN(mp) \
	(scxfs_sb_version_hascrc(&((mp)->m_sb)) ? \
		SCXFS_BTREE_SBLOCK_CRC_LEN : SCXFS_BTREE_SBLOCK_LEN)

/*
 * Record, key, and pointer address macros for btree blocks.
 *
 * (note that some of these may appear unused, but they are used in userspace)
 */
#define SCXFS_INOBT_REC_ADDR(mp, block, index) \
	((scxfs_inobt_rec_t *) \
		((char *)(block) + \
		 SCXFS_INOBT_BLOCK_LEN(mp) + \
		 (((index) - 1) * sizeof(scxfs_inobt_rec_t))))

#define SCXFS_INOBT_KEY_ADDR(mp, block, index) \
	((scxfs_inobt_key_t *) \
		((char *)(block) + \
		 SCXFS_INOBT_BLOCK_LEN(mp) + \
		 ((index) - 1) * sizeof(scxfs_inobt_key_t)))

#define SCXFS_INOBT_PTR_ADDR(mp, block, index, maxrecs) \
	((scxfs_inobt_ptr_t *) \
		((char *)(block) + \
		 SCXFS_INOBT_BLOCK_LEN(mp) + \
		 (maxrecs) * sizeof(scxfs_inobt_key_t) + \
		 ((index) - 1) * sizeof(scxfs_inobt_ptr_t)))

extern struct scxfs_btree_cur *scxfs_inobt_init_cursor(struct scxfs_mount *,
		struct scxfs_trans *, struct scxfs_buf *, scxfs_agnumber_t,
		scxfs_btnum_t);
extern int scxfs_inobt_maxrecs(struct scxfs_mount *, int, int);

/* ir_holemask to inode allocation bitmap conversion */
uint64_t scxfs_inobt_irec_to_allocmask(struct scxfs_inobt_rec_incore *);

#if defined(DEBUG) || defined(SCXFS_WARN)
int scxfs_inobt_rec_check_count(struct scxfs_mount *,
			      struct scxfs_inobt_rec_incore *);
#else
#define scxfs_inobt_rec_check_count(mp, rec)	0
#endif	/* DEBUG */

int scxfs_finobt_calc_reserves(struct scxfs_mount *mp, struct scxfs_trans *tp,
		scxfs_agnumber_t agno, scxfs_extlen_t *ask, scxfs_extlen_t *used);
extern scxfs_extlen_t scxfs_iallocbt_calc_size(struct scxfs_mount *mp,
		unsigned long long len);
int scxfs_inobt_cur(struct scxfs_mount *mp, struct scxfs_trans *tp,
		scxfs_agnumber_t agno, scxfs_btnum_t btnum,
		struct scxfs_btree_cur **curpp, struct scxfs_buf **agi_bpp);

#endif	/* __SCXFS_IALLOC_BTREE_H__ */
