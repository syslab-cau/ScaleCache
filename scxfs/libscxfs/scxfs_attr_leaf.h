// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000,2002-2003,2005 Silicon Graphics, Inc.
 * Copyright (c) 2013 Red Hat, Inc.
 * All Rights Reserved.
 */
#ifndef __SCXFS_ATTR_LEAF_H__
#define	__SCXFS_ATTR_LEAF_H__

struct attrlist;
struct attrlist_cursor_kern;
struct scxfs_attr_list_context;
struct scxfs_da_args;
struct scxfs_da_state;
struct scxfs_da_state_blk;
struct scxfs_inode;
struct scxfs_trans;

/*
 * Used to keep a list of "remote value" extents when unlinking an inode.
 */
typedef struct scxfs_attr_inactive_list {
	scxfs_dablk_t	valueblk;	/* block number of value bytes */
	int		valuelen;	/* number of bytes in value */
} scxfs_attr_inactive_list_t;


/*========================================================================
 * Function prototypes for the kernel.
 *========================================================================*/

/*
 * Internal routines when attribute fork size < SCXFS_LITINO(mp).
 */
void	scxfs_attr_shortform_create(struct scxfs_da_args *args);
void	scxfs_attr_shortform_add(struct scxfs_da_args *args, int forkoff);
int	scxfs_attr_shortform_lookup(struct scxfs_da_args *args);
int	scxfs_attr_shortform_getvalue(struct scxfs_da_args *args);
int	scxfs_attr_shortform_to_leaf(struct scxfs_da_args *args,
			struct scxfs_buf **leaf_bp);
int	scxfs_attr_shortform_remove(struct scxfs_da_args *args);
int	scxfs_attr_shortform_allfit(struct scxfs_buf *bp, struct scxfs_inode *dp);
int	scxfs_attr_shortform_bytesfit(struct scxfs_inode *dp, int bytes);
scxfs_failaddr_t scxfs_attr_shortform_verify(struct scxfs_inode *ip);
void	scxfs_attr_fork_remove(struct scxfs_inode *ip, struct scxfs_trans *tp);

/*
 * Internal routines when attribute fork size == SCXFS_LBSIZE(mp).
 */
int	scxfs_attr3_leaf_to_node(struct scxfs_da_args *args);
int	scxfs_attr3_leaf_to_shortform(struct scxfs_buf *bp,
				   struct scxfs_da_args *args, int forkoff);
int	scxfs_attr3_leaf_clearflag(struct scxfs_da_args *args);
int	scxfs_attr3_leaf_setflag(struct scxfs_da_args *args);
int	scxfs_attr3_leaf_flipflags(struct scxfs_da_args *args);

/*
 * Routines used for growing the Btree.
 */
int	scxfs_attr3_leaf_split(struct scxfs_da_state *state,
				   struct scxfs_da_state_blk *oldblk,
				   struct scxfs_da_state_blk *newblk);
int	scxfs_attr3_leaf_lookup_int(struct scxfs_buf *leaf,
					struct scxfs_da_args *args);
int	scxfs_attr3_leaf_getvalue(struct scxfs_buf *bp, struct scxfs_da_args *args);
int	scxfs_attr3_leaf_add(struct scxfs_buf *leaf_buffer,
				 struct scxfs_da_args *args);
int	scxfs_attr3_leaf_remove(struct scxfs_buf *leaf_buffer,
				    struct scxfs_da_args *args);
void	scxfs_attr3_leaf_list_int(struct scxfs_buf *bp,
				      struct scxfs_attr_list_context *context);

/*
 * Routines used for shrinking the Btree.
 */
int	scxfs_attr3_leaf_toosmall(struct scxfs_da_state *state, int *retval);
void	scxfs_attr3_leaf_unbalance(struct scxfs_da_state *state,
				       struct scxfs_da_state_blk *drop_blk,
				       struct scxfs_da_state_blk *save_blk);
/*
 * Utility routines.
 */
scxfs_dahash_t	scxfs_attr_leaf_lasthash(struct scxfs_buf *bp, int *count);
int	scxfs_attr_leaf_order(struct scxfs_buf *leaf1_bp,
				   struct scxfs_buf *leaf2_bp);
int	scxfs_attr_leaf_newentsize(struct scxfs_da_args *args, int *local);
int	scxfs_attr3_leaf_read(struct scxfs_trans *tp, struct scxfs_inode *dp,
			scxfs_dablk_t bno, scxfs_daddr_t mappedbno,
			struct scxfs_buf **bpp);
void	scxfs_attr3_leaf_hdr_from_disk(struct scxfs_da_geometry *geo,
				     struct scxfs_attr3_icleaf_hdr *to,
				     struct scxfs_attr_leafblock *from);
void	scxfs_attr3_leaf_hdr_to_disk(struct scxfs_da_geometry *geo,
				   struct scxfs_attr_leafblock *to,
				   struct scxfs_attr3_icleaf_hdr *from);

#endif	/* __SCXFS_ATTR_LEAF_H__ */
