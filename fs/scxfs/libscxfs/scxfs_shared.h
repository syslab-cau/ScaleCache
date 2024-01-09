// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2005 Silicon Graphics, Inc.
 * Copyright (c) 2013 Red Hat, Inc.
 * All Rights Reserved.
 */
#ifndef __SCXFS_SHARED_H__
#define __SCXFS_SHARED_H__

/*
 * Definitions shared between kernel and userspace that don't fit into any other
 * header file that is shared with userspace.
 */
struct scxfs_ifork;
struct scxfs_buf;
struct scxfs_buf_ops;
struct scxfs_mount;
struct scxfs_trans;
struct scxfs_inode;

/*
 * Buffer verifier operations are widely used, including userspace tools
 */
extern const struct scxfs_buf_ops scxfs_agf_buf_ops;
extern const struct scxfs_buf_ops scxfs_agi_buf_ops;
extern const struct scxfs_buf_ops scxfs_agf_buf_ops;
extern const struct scxfs_buf_ops scxfs_agfl_buf_ops;
extern const struct scxfs_buf_ops scxfs_bnobt_buf_ops;
extern const struct scxfs_buf_ops scxfs_cntbt_buf_ops;
extern const struct scxfs_buf_ops scxfs_rmapbt_buf_ops;
extern const struct scxfs_buf_ops scxfs_refcountbt_buf_ops;
extern const struct scxfs_buf_ops scxfs_attr3_leaf_buf_ops;
extern const struct scxfs_buf_ops scxfs_attr3_rmt_buf_ops;
extern const struct scxfs_buf_ops scxfs_bmbt_buf_ops;
extern const struct scxfs_buf_ops scxfs_da3_node_buf_ops;
extern const struct scxfs_buf_ops scxfs_dquot_buf_ops;
extern const struct scxfs_buf_ops scxfs_symlink_buf_ops;
extern const struct scxfs_buf_ops scxfs_agi_buf_ops;
extern const struct scxfs_buf_ops scxfs_inobt_buf_ops;
extern const struct scxfs_buf_ops scxfs_finobt_buf_ops;
extern const struct scxfs_buf_ops scxfs_inode_buf_ops;
extern const struct scxfs_buf_ops scxfs_inode_buf_ra_ops;
extern const struct scxfs_buf_ops scxfs_dquot_buf_ops;
extern const struct scxfs_buf_ops scxfs_dquot_buf_ra_ops;
extern const struct scxfs_buf_ops scxfs_sb_buf_ops;
extern const struct scxfs_buf_ops scxfs_sb_quiet_buf_ops;
extern const struct scxfs_buf_ops scxfs_symlink_buf_ops;
extern const struct scxfs_buf_ops scxfs_rtbuf_ops;

/* log size calculation functions */
int	scxfs_log_calc_unit_res(struct scxfs_mount *mp, int unit_bytes);
int	scxfs_log_calc_minimum_size(struct scxfs_mount *);

struct scxfs_trans_res;
void	scxfs_log_get_max_trans_res(struct scxfs_mount *mp,
				  struct scxfs_trans_res *max_resp);

/*
 * Values for t_flags.
 */
#define	SCXFS_TRANS_DIRTY		0x01	/* something needs to be logged */
#define	SCXFS_TRANS_SB_DIRTY	0x02	/* superblock is modified */
#define	SCXFS_TRANS_PERM_LOG_RES	0x04	/* xact took a permanent log res */
#define	SCXFS_TRANS_SYNC		0x08	/* make commit synchronous */
#define SCXFS_TRANS_DQ_DIRTY	0x10	/* at least one dquot in trx dirty */
#define SCXFS_TRANS_RESERVE	0x20    /* OK to use reserved data blocks */
#define SCXFS_TRANS_NO_WRITECOUNT 0x40	/* do not elevate SB writecount */
/*
 * LOWMODE is used by the allocator to activate the lowspace algorithm - when
 * free space is running low the extent allocator may choose to allocate an
 * extent from an AG without leaving sufficient space for a btree split when
 * inserting the new extent. In this case the allocator will enable the
 * lowspace algorithm which is supposed to allow further allocations (such as
 * btree splits and newroots) to allocate from sequential AGs. In order to
 * avoid locking AGs out of order the lowspace algorithm will start searching
 * for free space from AG 0. If the correct transaction reservations have been
 * made then this algorithm will eventually find all the space it needs.
 */
#define SCXFS_TRANS_LOWMODE	0x100	/* allocate in low space mode */

/*
 * Field values for scxfs_trans_mod_sb.
 */
#define	SCXFS_TRANS_SB_ICOUNT		0x00000001
#define	SCXFS_TRANS_SB_IFREE		0x00000002
#define	SCXFS_TRANS_SB_FDBLOCKS		0x00000004
#define	SCXFS_TRANS_SB_RES_FDBLOCKS	0x00000008
#define	SCXFS_TRANS_SB_FREXTENTS		0x00000010
#define	SCXFS_TRANS_SB_RES_FREXTENTS	0x00000020
#define	SCXFS_TRANS_SB_DBLOCKS		0x00000040
#define	SCXFS_TRANS_SB_AGCOUNT		0x00000080
#define	SCXFS_TRANS_SB_IMAXPCT		0x00000100
#define	SCXFS_TRANS_SB_REXTSIZE		0x00000200
#define	SCXFS_TRANS_SB_RBMBLOCKS		0x00000400
#define	SCXFS_TRANS_SB_RBLOCKS		0x00000800
#define	SCXFS_TRANS_SB_REXTENTS		0x00001000
#define	SCXFS_TRANS_SB_REXTSLOG		0x00002000

/*
 * Here we centralize the specification of SCXFS meta-data buffer reference count
 * values.  This determines how hard the buffer cache tries to hold onto the
 * buffer.
 */
#define	SCXFS_AGF_REF		4
#define	SCXFS_AGI_REF		4
#define	SCXFS_AGFL_REF		3
#define	SCXFS_INO_BTREE_REF	3
#define	SCXFS_ALLOC_BTREE_REF	2
#define	SCXFS_BMAP_BTREE_REF	2
#define	SCXFS_RMAP_BTREE_REF	2
#define	SCXFS_DIR_BTREE_REF	2
#define	SCXFS_INO_REF		2
#define	SCXFS_ATTR_BTREE_REF	1
#define	SCXFS_DQUOT_REF		1
#define	SCXFS_REFC_BTREE_REF	1
#define	SCXFS_SSB_REF		0

/*
 * Flags for scxfs_trans_ichgtime().
 */
#define	SCXFS_ICHGTIME_MOD	0x1	/* data fork modification timestamp */
#define	SCXFS_ICHGTIME_CHG	0x2	/* inode field change timestamp */
#define	SCXFS_ICHGTIME_CREATE	0x4	/* inode create timestamp */


/*
 * Symlink decoding/encoding functions
 */
int scxfs_symlink_blocks(struct scxfs_mount *mp, int pathlen);
int scxfs_symlink_hdr_set(struct scxfs_mount *mp, scxfs_ino_t ino, uint32_t offset,
			uint32_t size, struct scxfs_buf *bp);
bool scxfs_symlink_hdr_ok(scxfs_ino_t ino, uint32_t offset,
			uint32_t size, struct scxfs_buf *bp);
void scxfs_symlink_local_to_remote(struct scxfs_trans *tp, struct scxfs_buf *bp,
				 struct scxfs_inode *ip, struct scxfs_ifork *ifp);
scxfs_failaddr_t scxfs_symlink_shortform_verify(struct scxfs_inode *ip);

/* Computed inode geometry for the filesystem. */
struct scxfs_ino_geometry {
	/* Maximum inode count in this filesystem. */
	uint64_t	maxicount;

	/* Actual inode cluster buffer size, in bytes. */
	unsigned int	inode_cluster_size;

	/*
	 * Desired inode cluster buffer size, in bytes.  This value is not
	 * rounded up to at least one filesystem block, which is necessary for
	 * the sole purpose of validating sb_spino_align.  Runtime code must
	 * only ever use inode_cluster_size.
	 */
	unsigned int	inode_cluster_size_raw;

	/* Inode cluster sizes, adjusted to be at least 1 fsb. */
	unsigned int	inodes_per_cluster;
	unsigned int	blocks_per_cluster;

	/* Inode cluster alignment. */
	unsigned int	cluster_align;
	unsigned int	cluster_align_inodes;
	unsigned int	inoalign_mask;	/* mask sb_inoalignmt if used */

	unsigned int	inobt_mxr[2]; /* max inobt btree records */
	unsigned int	inobt_mnr[2]; /* min inobt btree records */
	unsigned int	inobt_maxlevels; /* max inobt btree levels. */

	/* Size of inode allocations under normal operation. */
	unsigned int	ialloc_inos;
	unsigned int	ialloc_blks;

	/* Minimum inode blocks for a sparse allocation. */
	unsigned int	ialloc_min_blks;

	/* stripe unit inode alignment */
	unsigned int	ialloc_align;

	unsigned int	agino_log;	/* #bits for agino in inum */
};

#endif /* __SCXFS_SHARED_H__ */
