// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2001,2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#ifndef __SCXFS_DIR2_H__
#define __SCXFS_DIR2_H__

#include "scxfs_da_format.h"
#include "scxfs_da_btree.h"

struct scxfs_da_args;
struct scxfs_inode;
struct scxfs_mount;
struct scxfs_trans;
struct scxfs_dir2_sf_hdr;
struct scxfs_dir2_sf_entry;
struct scxfs_dir2_data_hdr;
struct scxfs_dir2_data_entry;
struct scxfs_dir2_data_unused;

extern struct scxfs_name	scxfs_name_dotdot;

/*
 * Convert inode mode to directory entry filetype
 */
extern unsigned char scxfs_mode_to_ftype(int mode);

/*
 * directory operations vector for encode/decode routines
 */
struct scxfs_dir_ops {
	int	(*sf_entsize)(struct scxfs_dir2_sf_hdr *hdr, int len);
	struct scxfs_dir2_sf_entry *
		(*sf_nextentry)(struct scxfs_dir2_sf_hdr *hdr,
				struct scxfs_dir2_sf_entry *sfep);
	uint8_t (*sf_get_ftype)(struct scxfs_dir2_sf_entry *sfep);
	void	(*sf_put_ftype)(struct scxfs_dir2_sf_entry *sfep,
				uint8_t ftype);
	scxfs_ino_t (*sf_get_ino)(struct scxfs_dir2_sf_hdr *hdr,
				struct scxfs_dir2_sf_entry *sfep);
	void	(*sf_put_ino)(struct scxfs_dir2_sf_hdr *hdr,
			      struct scxfs_dir2_sf_entry *sfep,
			      scxfs_ino_t ino);
	scxfs_ino_t (*sf_get_parent_ino)(struct scxfs_dir2_sf_hdr *hdr);
	void	(*sf_put_parent_ino)(struct scxfs_dir2_sf_hdr *hdr,
				     scxfs_ino_t ino);

	int	(*data_entsize)(int len);
	uint8_t (*data_get_ftype)(struct scxfs_dir2_data_entry *dep);
	void	(*data_put_ftype)(struct scxfs_dir2_data_entry *dep,
				uint8_t ftype);
	__be16 * (*data_entry_tag_p)(struct scxfs_dir2_data_entry *dep);
	struct scxfs_dir2_data_free *
		(*data_bestfree_p)(struct scxfs_dir2_data_hdr *hdr);

	scxfs_dir2_data_aoff_t data_dot_offset;
	scxfs_dir2_data_aoff_t data_dotdot_offset;
	scxfs_dir2_data_aoff_t data_first_offset;
	size_t	data_entry_offset;

	struct scxfs_dir2_data_entry *
		(*data_dot_entry_p)(struct scxfs_dir2_data_hdr *hdr);
	struct scxfs_dir2_data_entry *
		(*data_dotdot_entry_p)(struct scxfs_dir2_data_hdr *hdr);
	struct scxfs_dir2_data_entry *
		(*data_first_entry_p)(struct scxfs_dir2_data_hdr *hdr);
	struct scxfs_dir2_data_entry *
		(*data_entry_p)(struct scxfs_dir2_data_hdr *hdr);
	struct scxfs_dir2_data_unused *
		(*data_unused_p)(struct scxfs_dir2_data_hdr *hdr);

	int	leaf_hdr_size;
	void	(*leaf_hdr_to_disk)(struct scxfs_dir2_leaf *to,
				    struct scxfs_dir3_icleaf_hdr *from);
	void	(*leaf_hdr_from_disk)(struct scxfs_dir3_icleaf_hdr *to,
				      struct scxfs_dir2_leaf *from);
	int	(*leaf_max_ents)(struct scxfs_da_geometry *geo);
	struct scxfs_dir2_leaf_entry *
		(*leaf_ents_p)(struct scxfs_dir2_leaf *lp);

	int	node_hdr_size;
	void	(*node_hdr_to_disk)(struct scxfs_da_intnode *to,
				    struct scxfs_da3_icnode_hdr *from);
	void	(*node_hdr_from_disk)(struct scxfs_da3_icnode_hdr *to,
				      struct scxfs_da_intnode *from);
	struct scxfs_da_node_entry *
		(*node_tree_p)(struct scxfs_da_intnode *dap);

	int	free_hdr_size;
	void	(*free_hdr_to_disk)(struct scxfs_dir2_free *to,
				    struct scxfs_dir3_icfree_hdr *from);
	void	(*free_hdr_from_disk)(struct scxfs_dir3_icfree_hdr *to,
				      struct scxfs_dir2_free *from);
	int	(*free_max_bests)(struct scxfs_da_geometry *geo);
	__be16 * (*free_bests_p)(struct scxfs_dir2_free *free);
	scxfs_dir2_db_t (*db_to_fdb)(struct scxfs_da_geometry *geo,
				   scxfs_dir2_db_t db);
	int	(*db_to_fdindex)(struct scxfs_da_geometry *geo,
				 scxfs_dir2_db_t db);
};

extern const struct scxfs_dir_ops *
	scxfs_dir_get_ops(struct scxfs_mount *mp, struct scxfs_inode *dp);
extern const struct scxfs_dir_ops *
	scxfs_nondir_get_ops(struct scxfs_mount *mp, struct scxfs_inode *dp);

/*
 * Generic directory interface routines
 */
extern void scxfs_dir_startup(void);
extern int scxfs_da_mount(struct scxfs_mount *mp);
extern void scxfs_da_unmount(struct scxfs_mount *mp);

extern int scxfs_dir_isempty(struct scxfs_inode *dp);
extern int scxfs_dir_init(struct scxfs_trans *tp, struct scxfs_inode *dp,
				struct scxfs_inode *pdp);
extern int scxfs_dir_createname(struct scxfs_trans *tp, struct scxfs_inode *dp,
				struct scxfs_name *name, scxfs_ino_t inum,
				scxfs_extlen_t tot);
extern int scxfs_dir_lookup(struct scxfs_trans *tp, struct scxfs_inode *dp,
				struct scxfs_name *name, scxfs_ino_t *inum,
				struct scxfs_name *ci_name);
extern int scxfs_dir_removename(struct scxfs_trans *tp, struct scxfs_inode *dp,
				struct scxfs_name *name, scxfs_ino_t ino,
				scxfs_extlen_t tot);
extern int scxfs_dir_replace(struct scxfs_trans *tp, struct scxfs_inode *dp,
				struct scxfs_name *name, scxfs_ino_t inum,
				scxfs_extlen_t tot);
extern int scxfs_dir_canenter(struct scxfs_trans *tp, struct scxfs_inode *dp,
				struct scxfs_name *name);

/*
 * Direct call from the bmap code, bypassing the generic directory layer.
 */
extern int scxfs_dir2_sf_to_block(struct scxfs_da_args *args);

/*
 * Interface routines used by userspace utilities
 */
extern int scxfs_dir2_isblock(struct scxfs_da_args *args, int *r);
extern int scxfs_dir2_isleaf(struct scxfs_da_args *args, int *r);
extern int scxfs_dir2_shrink_inode(struct scxfs_da_args *args, scxfs_dir2_db_t db,
				struct scxfs_buf *bp);

extern void scxfs_dir2_data_freescan_int(struct scxfs_da_geometry *geo,
		const struct scxfs_dir_ops *ops,
		struct scxfs_dir2_data_hdr *hdr, int *loghead);
extern void scxfs_dir2_data_freescan(struct scxfs_inode *dp,
		struct scxfs_dir2_data_hdr *hdr, int *loghead);
extern void scxfs_dir2_data_log_entry(struct scxfs_da_args *args,
		struct scxfs_buf *bp, struct scxfs_dir2_data_entry *dep);
extern void scxfs_dir2_data_log_header(struct scxfs_da_args *args,
		struct scxfs_buf *bp);
extern void scxfs_dir2_data_log_unused(struct scxfs_da_args *args,
		struct scxfs_buf *bp, struct scxfs_dir2_data_unused *dup);
extern void scxfs_dir2_data_make_free(struct scxfs_da_args *args,
		struct scxfs_buf *bp, scxfs_dir2_data_aoff_t offset,
		scxfs_dir2_data_aoff_t len, int *needlogp, int *needscanp);
extern int scxfs_dir2_data_use_free(struct scxfs_da_args *args,
		struct scxfs_buf *bp, struct scxfs_dir2_data_unused *dup,
		scxfs_dir2_data_aoff_t offset, scxfs_dir2_data_aoff_t len,
		int *needlogp, int *needscanp);

extern struct scxfs_dir2_data_free *scxfs_dir2_data_freefind(
		struct scxfs_dir2_data_hdr *hdr, struct scxfs_dir2_data_free *bf,
		struct scxfs_dir2_data_unused *dup);

extern int scxfs_dir_ino_validate(struct scxfs_mount *mp, scxfs_ino_t ino);

extern const struct scxfs_buf_ops scxfs_dir3_block_buf_ops;
extern const struct scxfs_buf_ops scxfs_dir3_leafn_buf_ops;
extern const struct scxfs_buf_ops scxfs_dir3_leaf1_buf_ops;
extern const struct scxfs_buf_ops scxfs_dir3_free_buf_ops;
extern const struct scxfs_buf_ops scxfs_dir3_data_buf_ops;

/*
 * Directory offset/block conversion functions.
 *
 * DB blocks here are logical directory block numbers, not filesystem blocks.
 */

/*
 * Convert dataptr to byte in file space
 */
static inline scxfs_dir2_off_t
scxfs_dir2_dataptr_to_byte(scxfs_dir2_dataptr_t dp)
{
	return (scxfs_dir2_off_t)dp << SCXFS_DIR2_DATA_ALIGN_LOG;
}

/*
 * Convert byte in file space to dataptr.  It had better be aligned.
 */
static inline scxfs_dir2_dataptr_t
scxfs_dir2_byte_to_dataptr(scxfs_dir2_off_t by)
{
	return (scxfs_dir2_dataptr_t)(by >> SCXFS_DIR2_DATA_ALIGN_LOG);
}

/*
 * Convert byte in space to (DB) block
 */
static inline scxfs_dir2_db_t
scxfs_dir2_byte_to_db(struct scxfs_da_geometry *geo, scxfs_dir2_off_t by)
{
	return (scxfs_dir2_db_t)(by >> geo->blklog);
}

/*
 * Convert dataptr to a block number
 */
static inline scxfs_dir2_db_t
scxfs_dir2_dataptr_to_db(struct scxfs_da_geometry *geo, scxfs_dir2_dataptr_t dp)
{
	return scxfs_dir2_byte_to_db(geo, scxfs_dir2_dataptr_to_byte(dp));
}

/*
 * Convert byte in space to offset in a block
 */
static inline scxfs_dir2_data_aoff_t
scxfs_dir2_byte_to_off(struct scxfs_da_geometry *geo, scxfs_dir2_off_t by)
{
	return (scxfs_dir2_data_aoff_t)(by & (geo->blksize - 1));
}

/*
 * Convert dataptr to a byte offset in a block
 */
static inline scxfs_dir2_data_aoff_t
scxfs_dir2_dataptr_to_off(struct scxfs_da_geometry *geo, scxfs_dir2_dataptr_t dp)
{
	return scxfs_dir2_byte_to_off(geo, scxfs_dir2_dataptr_to_byte(dp));
}

/*
 * Convert block and offset to byte in space
 */
static inline scxfs_dir2_off_t
scxfs_dir2_db_off_to_byte(struct scxfs_da_geometry *geo, scxfs_dir2_db_t db,
			scxfs_dir2_data_aoff_t o)
{
	return ((scxfs_dir2_off_t)db << geo->blklog) + o;
}

/*
 * Convert block (DB) to block (dablk)
 */
static inline scxfs_dablk_t
scxfs_dir2_db_to_da(struct scxfs_da_geometry *geo, scxfs_dir2_db_t db)
{
	return (scxfs_dablk_t)(db << (geo->blklog - geo->fsblog));
}

/*
 * Convert byte in space to (DA) block
 */
static inline scxfs_dablk_t
scxfs_dir2_byte_to_da(struct scxfs_da_geometry *geo, scxfs_dir2_off_t by)
{
	return scxfs_dir2_db_to_da(geo, scxfs_dir2_byte_to_db(geo, by));
}

/*
 * Convert block and offset to dataptr
 */
static inline scxfs_dir2_dataptr_t
scxfs_dir2_db_off_to_dataptr(struct scxfs_da_geometry *geo, scxfs_dir2_db_t db,
			   scxfs_dir2_data_aoff_t o)
{
	return scxfs_dir2_byte_to_dataptr(scxfs_dir2_db_off_to_byte(geo, db, o));
}

/*
 * Convert block (dablk) to block (DB)
 */
static inline scxfs_dir2_db_t
scxfs_dir2_da_to_db(struct scxfs_da_geometry *geo, scxfs_dablk_t da)
{
	return (scxfs_dir2_db_t)(da >> (geo->blklog - geo->fsblog));
}

/*
 * Convert block (dablk) to byte offset in space
 */
static inline scxfs_dir2_off_t
scxfs_dir2_da_to_byte(struct scxfs_da_geometry *geo, scxfs_dablk_t da)
{
	return scxfs_dir2_db_off_to_byte(geo, scxfs_dir2_da_to_db(geo, da), 0);
}

/*
 * Directory tail pointer accessor functions. Based on block geometry.
 */
static inline struct scxfs_dir2_block_tail *
scxfs_dir2_block_tail_p(struct scxfs_da_geometry *geo, struct scxfs_dir2_data_hdr *hdr)
{
	return ((struct scxfs_dir2_block_tail *)
		((char *)hdr + geo->blksize)) - 1;
}

static inline struct scxfs_dir2_leaf_tail *
scxfs_dir2_leaf_tail_p(struct scxfs_da_geometry *geo, struct scxfs_dir2_leaf *lp)
{
	return (struct scxfs_dir2_leaf_tail *)
		((char *)lp + geo->blksize -
		  sizeof(struct scxfs_dir2_leaf_tail));
}

/*
 * The Linux API doesn't pass down the total size of the buffer
 * we read into down to the filesystem.  With the filldir concept
 * it's not needed for correct information, but the SCXFS dir2 leaf
 * code wants an estimate of the buffer size to calculate it's
 * readahead window and size the buffers used for mapping to
 * physical blocks.
 *
 * Try to give it an estimate that's good enough, maybe at some
 * point we can change the ->readdir prototype to include the
 * buffer size.  For now we use the current glibc buffer size.
 * musl libc hardcodes 2k and dietlibc uses PAGE_SIZE.
 */
#define SCXFS_READDIR_BUFSIZE	(32768)

unsigned char scxfs_dir3_get_dtype(struct scxfs_mount *mp, uint8_t filetype);
void *scxfs_dir3_data_endp(struct scxfs_da_geometry *geo,
		struct scxfs_dir2_data_hdr *hdr);
bool scxfs_dir2_namecheck(const void *name, size_t length);

#endif	/* __SCXFS_DIR2_H__ */
