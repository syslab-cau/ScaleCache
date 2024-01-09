// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2001,2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#ifndef __SCXFS_DIR2_PRIV_H__
#define __SCXFS_DIR2_PRIV_H__

struct dir_context;

/* scxfs_dir2.c */
extern int scxfs_dir2_grow_inode(struct scxfs_da_args *args, int space,
				scxfs_dir2_db_t *dbp);
extern int scxfs_dir_cilookup_result(struct scxfs_da_args *args,
				const unsigned char *name, int len);


/* scxfs_dir2_block.c */
extern int scxfs_dir3_block_read(struct scxfs_trans *tp, struct scxfs_inode *dp,
			       struct scxfs_buf **bpp);
extern int scxfs_dir2_block_addname(struct scxfs_da_args *args);
extern int scxfs_dir2_block_lookup(struct scxfs_da_args *args);
extern int scxfs_dir2_block_removename(struct scxfs_da_args *args);
extern int scxfs_dir2_block_replace(struct scxfs_da_args *args);
extern int scxfs_dir2_leaf_to_block(struct scxfs_da_args *args,
		struct scxfs_buf *lbp, struct scxfs_buf *dbp);

/* scxfs_dir2_data.c */
#ifdef DEBUG
extern void scxfs_dir3_data_check(struct scxfs_inode *dp, struct scxfs_buf *bp);
#else
#define	scxfs_dir3_data_check(dp,bp)
#endif

extern scxfs_failaddr_t __scxfs_dir3_data_check(struct scxfs_inode *dp,
		struct scxfs_buf *bp);
extern int scxfs_dir3_data_read(struct scxfs_trans *tp, struct scxfs_inode *dp,
		scxfs_dablk_t bno, scxfs_daddr_t mapped_bno, struct scxfs_buf **bpp);
extern int scxfs_dir3_data_readahead(struct scxfs_inode *dp, scxfs_dablk_t bno,
		scxfs_daddr_t mapped_bno);

extern struct scxfs_dir2_data_free *
scxfs_dir2_data_freeinsert(struct scxfs_dir2_data_hdr *hdr,
		struct scxfs_dir2_data_free *bf, struct scxfs_dir2_data_unused *dup,
		int *loghead);
extern int scxfs_dir3_data_init(struct scxfs_da_args *args, scxfs_dir2_db_t blkno,
		struct scxfs_buf **bpp);

/* scxfs_dir2_leaf.c */
extern int scxfs_dir3_leaf_read(struct scxfs_trans *tp, struct scxfs_inode *dp,
		scxfs_dablk_t fbno, scxfs_daddr_t mappedbno, struct scxfs_buf **bpp);
extern int scxfs_dir3_leafn_read(struct scxfs_trans *tp, struct scxfs_inode *dp,
		scxfs_dablk_t fbno, scxfs_daddr_t mappedbno, struct scxfs_buf **bpp);
extern int scxfs_dir2_block_to_leaf(struct scxfs_da_args *args,
		struct scxfs_buf *dbp);
extern int scxfs_dir2_leaf_addname(struct scxfs_da_args *args);
extern void scxfs_dir3_leaf_compact(struct scxfs_da_args *args,
		struct scxfs_dir3_icleaf_hdr *leafhdr, struct scxfs_buf *bp);
extern void scxfs_dir3_leaf_compact_x1(struct scxfs_dir3_icleaf_hdr *leafhdr,
		struct scxfs_dir2_leaf_entry *ents, int *indexp,
		int *lowstalep, int *highstalep, int *lowlogp, int *highlogp);
extern int scxfs_dir3_leaf_get_buf(struct scxfs_da_args *args, scxfs_dir2_db_t bno,
		struct scxfs_buf **bpp, uint16_t magic);
extern void scxfs_dir3_leaf_log_ents(struct scxfs_da_args *args,
		struct scxfs_buf *bp, int first, int last);
extern void scxfs_dir3_leaf_log_header(struct scxfs_da_args *args,
		struct scxfs_buf *bp);
extern int scxfs_dir2_leaf_lookup(struct scxfs_da_args *args);
extern int scxfs_dir2_leaf_removename(struct scxfs_da_args *args);
extern int scxfs_dir2_leaf_replace(struct scxfs_da_args *args);
extern int scxfs_dir2_leaf_search_hash(struct scxfs_da_args *args,
		struct scxfs_buf *lbp);
extern int scxfs_dir2_leaf_trim_data(struct scxfs_da_args *args,
		struct scxfs_buf *lbp, scxfs_dir2_db_t db);
extern struct scxfs_dir2_leaf_entry *
scxfs_dir3_leaf_find_entry(struct scxfs_dir3_icleaf_hdr *leafhdr,
		struct scxfs_dir2_leaf_entry *ents, int index, int compact,
		int lowstale, int highstale, int *lfloglow, int *lfloghigh);
extern int scxfs_dir2_node_to_leaf(struct scxfs_da_state *state);

extern scxfs_failaddr_t scxfs_dir3_leaf_check_int(struct scxfs_mount *mp,
		struct scxfs_inode *dp, struct scxfs_dir3_icleaf_hdr *hdr,
		struct scxfs_dir2_leaf *leaf);

/* scxfs_dir2_node.c */
extern int scxfs_dir2_leaf_to_node(struct scxfs_da_args *args,
		struct scxfs_buf *lbp);
extern scxfs_dahash_t scxfs_dir2_leaf_lasthash(struct scxfs_inode *dp,
		struct scxfs_buf *bp, int *count);
extern int scxfs_dir2_leafn_lookup_int(struct scxfs_buf *bp,
		struct scxfs_da_args *args, int *indexp,
		struct scxfs_da_state *state);
extern int scxfs_dir2_leafn_order(struct scxfs_inode *dp, struct scxfs_buf *leaf1_bp,
		struct scxfs_buf *leaf2_bp);
extern int scxfs_dir2_leafn_split(struct scxfs_da_state *state,
	struct scxfs_da_state_blk *oldblk, struct scxfs_da_state_blk *newblk);
extern int scxfs_dir2_leafn_toosmall(struct scxfs_da_state *state, int *action);
extern void scxfs_dir2_leafn_unbalance(struct scxfs_da_state *state,
		struct scxfs_da_state_blk *drop_blk,
		struct scxfs_da_state_blk *save_blk);
extern int scxfs_dir2_node_addname(struct scxfs_da_args *args);
extern int scxfs_dir2_node_lookup(struct scxfs_da_args *args);
extern int scxfs_dir2_node_removename(struct scxfs_da_args *args);
extern int scxfs_dir2_node_replace(struct scxfs_da_args *args);
extern int scxfs_dir2_node_trim_free(struct scxfs_da_args *args, scxfs_fileoff_t fo,
		int *rvalp);
extern int scxfs_dir2_free_read(struct scxfs_trans *tp, struct scxfs_inode *dp,
		scxfs_dablk_t fbno, struct scxfs_buf **bpp);

/* scxfs_dir2_sf.c */
extern int scxfs_dir2_block_sfsize(struct scxfs_inode *dp,
		struct scxfs_dir2_data_hdr *block, struct scxfs_dir2_sf_hdr *sfhp);
extern int scxfs_dir2_block_to_sf(struct scxfs_da_args *args, struct scxfs_buf *bp,
		int size, scxfs_dir2_sf_hdr_t *sfhp);
extern int scxfs_dir2_sf_addname(struct scxfs_da_args *args);
extern int scxfs_dir2_sf_create(struct scxfs_da_args *args, scxfs_ino_t pino);
extern int scxfs_dir2_sf_lookup(struct scxfs_da_args *args);
extern int scxfs_dir2_sf_removename(struct scxfs_da_args *args);
extern int scxfs_dir2_sf_replace(struct scxfs_da_args *args);
extern scxfs_failaddr_t scxfs_dir2_sf_verify(struct scxfs_inode *ip);

/* scxfs_dir2_readdir.c */
extern int scxfs_readdir(struct scxfs_trans *tp, struct scxfs_inode *dp,
		       struct dir_context *ctx, size_t bufsize);

#endif /* __SCXFS_DIR2_PRIV_H__ */
