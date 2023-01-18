// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000,2002-2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#ifndef __SCXFS_BMAP_BTREE_H__
#define __SCXFS_BMAP_BTREE_H__

struct scxfs_btree_cur;
struct scxfs_btree_block;
struct scxfs_mount;
struct scxfs_inode;
struct scxfs_trans;

/*
 * Btree block header size depends on a superblock flag.
 */
#define SCXFS_BMBT_BLOCK_LEN(mp) \
	(scxfs_sb_version_hascrc(&((mp)->m_sb)) ? \
		SCXFS_BTREE_LBLOCK_CRC_LEN : SCXFS_BTREE_LBLOCK_LEN)

#define SCXFS_BMBT_REC_ADDR(mp, block, index) \
	((scxfs_bmbt_rec_t *) \
		((char *)(block) + \
		 SCXFS_BMBT_BLOCK_LEN(mp) + \
		 ((index) - 1) * sizeof(scxfs_bmbt_rec_t)))

#define SCXFS_BMBT_KEY_ADDR(mp, block, index) \
	((scxfs_bmbt_key_t *) \
		((char *)(block) + \
		 SCXFS_BMBT_BLOCK_LEN(mp) + \
		 ((index) - 1) * sizeof(scxfs_bmbt_key_t)))

#define SCXFS_BMBT_PTR_ADDR(mp, block, index, maxrecs) \
	((scxfs_bmbt_ptr_t *) \
		((char *)(block) + \
		 SCXFS_BMBT_BLOCK_LEN(mp) + \
		 (maxrecs) * sizeof(scxfs_bmbt_key_t) + \
		 ((index) - 1) * sizeof(scxfs_bmbt_ptr_t)))

#define SCXFS_BMDR_REC_ADDR(block, index) \
	((scxfs_bmdr_rec_t *) \
		((char *)(block) + \
		 sizeof(struct scxfs_bmdr_block) + \
	         ((index) - 1) * sizeof(scxfs_bmdr_rec_t)))

#define SCXFS_BMDR_KEY_ADDR(block, index) \
	((scxfs_bmdr_key_t *) \
		((char *)(block) + \
		 sizeof(struct scxfs_bmdr_block) + \
		 ((index) - 1) * sizeof(scxfs_bmdr_key_t)))

#define SCXFS_BMDR_PTR_ADDR(block, index, maxrecs) \
	((scxfs_bmdr_ptr_t *) \
		((char *)(block) + \
		 sizeof(struct scxfs_bmdr_block) + \
		 (maxrecs) * sizeof(scxfs_bmdr_key_t) + \
		 ((index) - 1) * sizeof(scxfs_bmdr_ptr_t)))

/*
 * These are to be used when we know the size of the block and
 * we don't have a cursor.
 */
#define SCXFS_BMAP_BROOT_PTR_ADDR(mp, bb, i, sz) \
	SCXFS_BMBT_PTR_ADDR(mp, bb, i, scxfs_bmbt_maxrecs(mp, sz, 0))

#define SCXFS_BMAP_BROOT_SPACE_CALC(mp, nrecs) \
	(int)(SCXFS_BMBT_BLOCK_LEN(mp) + \
	       ((nrecs) * (sizeof(scxfs_bmbt_key_t) + sizeof(scxfs_bmbt_ptr_t))))

#define SCXFS_BMAP_BROOT_SPACE(mp, bb) \
	(SCXFS_BMAP_BROOT_SPACE_CALC(mp, be16_to_cpu((bb)->bb_numrecs)))
#define SCXFS_BMDR_SPACE_CALC(nrecs) \
	(int)(sizeof(scxfs_bmdr_block_t) + \
	       ((nrecs) * (sizeof(scxfs_bmbt_key_t) + sizeof(scxfs_bmbt_ptr_t))))
#define SCXFS_BMAP_BMDR_SPACE(bb) \
	(SCXFS_BMDR_SPACE_CALC(be16_to_cpu((bb)->bb_numrecs)))

/*
 * Maximum number of bmap btree levels.
 */
#define SCXFS_BM_MAXLEVELS(mp,w)		((mp)->m_bm_maxlevels[(w)])

/*
 * Prototypes for scxfs_bmap.c to call.
 */
extern void scxfs_bmdr_to_bmbt(struct scxfs_inode *, scxfs_bmdr_block_t *, int,
			struct scxfs_btree_block *, int);

void scxfs_bmbt_disk_set_all(struct scxfs_bmbt_rec *r, struct scxfs_bmbt_irec *s);
extern scxfs_filblks_t scxfs_bmbt_disk_get_blockcount(scxfs_bmbt_rec_t *r);
extern scxfs_fileoff_t scxfs_bmbt_disk_get_startoff(scxfs_bmbt_rec_t *r);
extern void scxfs_bmbt_disk_get_all(scxfs_bmbt_rec_t *r, scxfs_bmbt_irec_t *s);

extern void scxfs_bmbt_to_bmdr(struct scxfs_mount *, struct scxfs_btree_block *, int,
			scxfs_bmdr_block_t *, int);

extern int scxfs_bmbt_get_maxrecs(struct scxfs_btree_cur *, int level);
extern int scxfs_bmdr_maxrecs(int blocklen, int leaf);
extern int scxfs_bmbt_maxrecs(struct scxfs_mount *, int blocklen, int leaf);

extern int scxfs_bmbt_change_owner(struct scxfs_trans *tp, struct scxfs_inode *ip,
				 int whichfork, scxfs_ino_t new_owner,
				 struct list_head *buffer_list);

extern struct scxfs_btree_cur *scxfs_bmbt_init_cursor(struct scxfs_mount *,
		struct scxfs_trans *, struct scxfs_inode *, int);

extern unsigned long long scxfs_bmbt_calc_size(struct scxfs_mount *mp,
		unsigned long long len);

#endif	/* __SCXFS_BMAP_BTREE_H__ */
