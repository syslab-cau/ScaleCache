// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000,2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#ifndef __SCXFS_IALLOC_H__
#define	__SCXFS_IALLOC_H__

struct scxfs_buf;
struct scxfs_dinode;
struct scxfs_imap;
struct scxfs_mount;
struct scxfs_trans;
struct scxfs_btree_cur;

/* Move inodes in clusters of this size */
#define	SCXFS_INODE_BIG_CLUSTER_SIZE	8192

struct scxfs_icluster {
	bool		deleted;	/* record is deleted */
	scxfs_ino_t	first_ino;	/* first inode number */
	uint64_t	alloc;		/* inode phys. allocation bitmap for
					 * sparse chunks */
};

/*
 * Make an inode pointer out of the buffer/offset.
 */
static inline struct scxfs_dinode *
scxfs_make_iptr(struct scxfs_mount *mp, struct scxfs_buf *b, int o)
{
	return scxfs_buf_offset(b, o << (mp)->m_sb.sb_inodelog);
}

/*
 * Allocate an inode on disk.
 * Mode is used to tell whether the new inode will need space, and whether
 * it is a directory.
 *
 * To work within the constraint of one allocation per transaction,
 * scxfs_dialloc() is designed to be called twice if it has to do an
 * allocation to make more free inodes.  If an inode is
 * available without an allocation, agbp would be set to the current
 * agbp and alloc_done set to false.
 * If an allocation needed to be done, agbp would be set to the
 * inode header of the allocation group and alloc_done set to true.
 * The caller should then commit the current transaction and allocate a new
 * transaction.  scxfs_dialloc() should then be called again with
 * the agbp value returned from the previous call.
 *
 * Once we successfully pick an inode its number is returned and the
 * on-disk data structures are updated.  The inode itself is not read
 * in, since doing so would break ordering constraints with scxfs_reclaim.
 *
 * *agbp should be set to NULL on the first call, *alloc_done set to FALSE.
 */
int					/* error */
scxfs_dialloc(
	struct scxfs_trans *tp,		/* transaction pointer */
	scxfs_ino_t	parent,		/* parent inode (directory) */
	umode_t		mode,		/* mode bits for new inode */
	struct scxfs_buf	**agbp,		/* buf for a.g. inode header */
	scxfs_ino_t	*inop);		/* inode number allocated */

/*
 * Free disk inode.  Carefully avoids touching the incore inode, all
 * manipulations incore are the caller's responsibility.
 * The on-disk inode is not changed by this operation, only the
 * btree (free inode mask) is changed.
 */
int					/* error */
scxfs_difree(
	struct scxfs_trans *tp,		/* transaction pointer */
	scxfs_ino_t	inode,		/* inode to be freed */
	struct scxfs_icluster *ifree);	/* cluster info if deleted */

/*
 * Return the location of the inode in imap, for mapping it into a buffer.
 */
int
scxfs_imap(
	struct scxfs_mount *mp,		/* file system mount structure */
	struct scxfs_trans *tp,		/* transaction pointer */
	scxfs_ino_t	ino,		/* inode to locate */
	struct scxfs_imap	*imap,		/* location map structure */
	uint		flags);		/* flags for inode btree lookup */

/*
 * Log specified fields for the ag hdr (inode section)
 */
void
scxfs_ialloc_log_agi(
	struct scxfs_trans *tp,		/* transaction pointer */
	struct scxfs_buf	*bp,		/* allocation group header buffer */
	int		fields);	/* bitmask of fields to log */

/*
 * Read in the allocation group header (inode allocation section)
 */
int					/* error */
scxfs_ialloc_read_agi(
	struct scxfs_mount *mp,		/* file system mount structure */
	struct scxfs_trans *tp,		/* transaction pointer */
	scxfs_agnumber_t	agno,		/* allocation group number */
	struct scxfs_buf	**bpp);		/* allocation group hdr buf */

/*
 * Read in the allocation group header to initialise the per-ag data
 * in the mount structure
 */
int
scxfs_ialloc_pagi_init(
	struct scxfs_mount *mp,		/* file system mount structure */
	struct scxfs_trans *tp,		/* transaction pointer */
        scxfs_agnumber_t  agno);		/* allocation group number */

/*
 * Lookup a record by ino in the btree given by cur.
 */
int scxfs_inobt_lookup(struct scxfs_btree_cur *cur, scxfs_agino_t ino,
		scxfs_lookup_t dir, int *stat);

/*
 * Get the data from the pointed-to record.
 */
int scxfs_inobt_get_rec(struct scxfs_btree_cur *cur,
		scxfs_inobt_rec_incore_t *rec, int *stat);

/*
 * Inode chunk initialisation routine
 */
int scxfs_ialloc_inode_init(struct scxfs_mount *mp, struct scxfs_trans *tp,
			  struct list_head *buffer_list, int icount,
			  scxfs_agnumber_t agno, scxfs_agblock_t agbno,
			  scxfs_agblock_t length, unsigned int gen);

int scxfs_read_agi(struct scxfs_mount *mp, struct scxfs_trans *tp,
		scxfs_agnumber_t agno, struct scxfs_buf **bpp);

union scxfs_btree_rec;
void scxfs_inobt_btrec_to_irec(struct scxfs_mount *mp, union scxfs_btree_rec *rec,
		struct scxfs_inobt_rec_incore *irec);
int scxfs_ialloc_has_inodes_at_extent(struct scxfs_btree_cur *cur,
		scxfs_agblock_t bno, scxfs_extlen_t len, bool *exists);
int scxfs_ialloc_has_inode_record(struct scxfs_btree_cur *cur, scxfs_agino_t low,
		scxfs_agino_t high, bool *exists);
int scxfs_ialloc_count_inodes(struct scxfs_btree_cur *cur, scxfs_agino_t *count,
		scxfs_agino_t *freecount);
int scxfs_inobt_insert_rec(struct scxfs_btree_cur *cur, uint16_t holemask,
		uint8_t count, int32_t freecount, scxfs_inofree_t free,
		int *stat);

int scxfs_ialloc_cluster_alignment(struct scxfs_mount *mp);
void scxfs_ialloc_setup_geometry(struct scxfs_mount *mp);

#endif	/* __SCXFS_IALLOC_H__ */
