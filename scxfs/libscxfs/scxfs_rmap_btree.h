// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2014 Red Hat, Inc.
 * All Rights Reserved.
 */
#ifndef __SCXFS_RMAP_BTREE_H__
#define __SCXFS_RMAP_BTREE_H__

struct scxfs_buf;
struct scxfs_btree_cur;
struct scxfs_mount;

/* rmaps only exist on crc enabled filesystems */
#define SCXFS_RMAP_BLOCK_LEN	SCXFS_BTREE_SBLOCK_CRC_LEN

/*
 * Record, key, and pointer address macros for btree blocks.
 *
 * (note that some of these may appear unused, but they are used in userspace)
 */
#define SCXFS_RMAP_REC_ADDR(block, index) \
	((struct scxfs_rmap_rec *) \
		((char *)(block) + SCXFS_RMAP_BLOCK_LEN + \
		 (((index) - 1) * sizeof(struct scxfs_rmap_rec))))

#define SCXFS_RMAP_KEY_ADDR(block, index) \
	((struct scxfs_rmap_key *) \
		((char *)(block) + SCXFS_RMAP_BLOCK_LEN + \
		 ((index) - 1) * 2 * sizeof(struct scxfs_rmap_key)))

#define SCXFS_RMAP_HIGH_KEY_ADDR(block, index) \
	((struct scxfs_rmap_key *) \
		((char *)(block) + SCXFS_RMAP_BLOCK_LEN + \
		 sizeof(struct scxfs_rmap_key) + \
		 ((index) - 1) * 2 * sizeof(struct scxfs_rmap_key)))

#define SCXFS_RMAP_PTR_ADDR(block, index, maxrecs) \
	((scxfs_rmap_ptr_t *) \
		((char *)(block) + SCXFS_RMAP_BLOCK_LEN + \
		 (maxrecs) * 2 * sizeof(struct scxfs_rmap_key) + \
		 ((index) - 1) * sizeof(scxfs_rmap_ptr_t)))

struct scxfs_btree_cur *scxfs_rmapbt_init_cursor(struct scxfs_mount *mp,
				struct scxfs_trans *tp, struct scxfs_buf *bp,
				scxfs_agnumber_t agno);
int scxfs_rmapbt_maxrecs(int blocklen, int leaf);
extern void scxfs_rmapbt_compute_maxlevels(struct scxfs_mount *mp);

extern scxfs_extlen_t scxfs_rmapbt_calc_size(struct scxfs_mount *mp,
		unsigned long long len);
extern scxfs_extlen_t scxfs_rmapbt_max_size(struct scxfs_mount *mp,
		scxfs_agblock_t agblocks);

extern int scxfs_rmapbt_calc_reserves(struct scxfs_mount *mp, struct scxfs_trans *tp,
		scxfs_agnumber_t agno, scxfs_extlen_t *ask, scxfs_extlen_t *used);

#endif	/* __SCXFS_RMAP_BTREE_H__ */
