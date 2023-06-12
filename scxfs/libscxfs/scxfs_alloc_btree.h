// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000,2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#ifndef __SCXFS_ALLOC_BTREE_H__
#define	__SCXFS_ALLOC_BTREE_H__

/*
 * Freespace on-disk structures
 */

struct scxfs_buf;
struct scxfs_btree_cur;
struct scxfs_mount;

/*
 * Btree block header size depends on a superblock flag.
 */
#define SCXFS_ALLOC_BLOCK_LEN(mp) \
	(scxfs_sb_version_hascrc(&((mp)->m_sb)) ? \
		SCXFS_BTREE_SBLOCK_CRC_LEN : SCXFS_BTREE_SBLOCK_LEN)

/*
 * Record, key, and pointer address macros for btree blocks.
 *
 * (note that some of these may appear unused, but they are used in userspace)
 */
#define SCXFS_ALLOC_REC_ADDR(mp, block, index) \
	((scxfs_alloc_rec_t *) \
		((char *)(block) + \
		 SCXFS_ALLOC_BLOCK_LEN(mp) + \
		 (((index) - 1) * sizeof(scxfs_alloc_rec_t))))

#define SCXFS_ALLOC_KEY_ADDR(mp, block, index) \
	((scxfs_alloc_key_t *) \
		((char *)(block) + \
		 SCXFS_ALLOC_BLOCK_LEN(mp) + \
		 ((index) - 1) * sizeof(scxfs_alloc_key_t)))

#define SCXFS_ALLOC_PTR_ADDR(mp, block, index, maxrecs) \
	((scxfs_alloc_ptr_t *) \
		((char *)(block) + \
		 SCXFS_ALLOC_BLOCK_LEN(mp) + \
		 (maxrecs) * sizeof(scxfs_alloc_key_t) + \
		 ((index) - 1) * sizeof(scxfs_alloc_ptr_t)))

extern struct scxfs_btree_cur *scxfs_allocbt_init_cursor(struct scxfs_mount *,
		struct scxfs_trans *, struct scxfs_buf *,
		scxfs_agnumber_t, scxfs_btnum_t);
extern int scxfs_allocbt_maxrecs(struct scxfs_mount *, int, int);
extern scxfs_extlen_t scxfs_allocbt_calc_size(struct scxfs_mount *mp,
		unsigned long long len);

#endif	/* __SCXFS_ALLOC_BTREE_H__ */
