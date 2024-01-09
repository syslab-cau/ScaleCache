// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2017 Oracle.  All Rights Reserved.
 * Author: Darrick J. Wong <darrick.wong@oracle.com>
 */
#ifndef __SCXFS_SCRUB_SCRUB_H__
#define __SCXFS_SCRUB_SCRUB_H__

struct scxfs_scrub;

/* Type info and names for the scrub types. */
enum xchk_type {
	ST_NONE = 1,	/* disabled */
	ST_PERAG,	/* per-AG metadata */
	ST_FS,		/* per-FS metadata */
	ST_INODE,	/* per-inode metadata */
};

struct xchk_meta_ops {
	/* Acquire whatever resources are needed for the operation. */
	int		(*setup)(struct scxfs_scrub *,
				 struct scxfs_inode *);

	/* Examine metadata for errors. */
	int		(*scrub)(struct scxfs_scrub *);

	/* Repair or optimize the metadata. */
	int		(*repair)(struct scxfs_scrub *);

	/* Decide if we even have this piece of metadata. */
	bool		(*has)(struct scxfs_sb *);

	/* type describing required/allowed inputs */
	enum xchk_type	type;
};

/* Buffer pointers and btree cursors for an entire AG. */
struct xchk_ag {
	scxfs_agnumber_t		agno;
	struct scxfs_perag	*pag;

	/* AG btree roots */
	struct scxfs_buf		*agf_bp;
	struct scxfs_buf		*agfl_bp;
	struct scxfs_buf		*agi_bp;

	/* AG btrees */
	struct scxfs_btree_cur	*bno_cur;
	struct scxfs_btree_cur	*cnt_cur;
	struct scxfs_btree_cur	*ino_cur;
	struct scxfs_btree_cur	*fino_cur;
	struct scxfs_btree_cur	*rmap_cur;
	struct scxfs_btree_cur	*refc_cur;
};

struct scxfs_scrub {
	/* General scrub state. */
	struct scxfs_mount		*mp;
	struct scxfs_scrub_metadata	*sm;
	const struct xchk_meta_ops	*ops;
	struct scxfs_trans		*tp;
	struct scxfs_inode		*ip;
	void				*buf;
	uint				ilock_flags;

	/* See the XCHK/XREP state flags below. */
	unsigned int			flags;

	/*
	 * The SCXFS_SICK_* flags that correspond to the metadata being scrubbed
	 * or repaired.  We will use this mask to update the in-core fs health
	 * status with whatever we find.
	 */
	unsigned int			sick_mask;

	/* State tracking for single-AG operations. */
	struct xchk_ag			sa;
};

/* XCHK state flags grow up from zero, XREP state flags grown down from 2^31 */
#define XCHK_TRY_HARDER		(1 << 0)  /* can't get resources, try again */
#define XCHK_HAS_QUOTAOFFLOCK	(1 << 1)  /* we hold the quotaoff lock */
#define XCHK_REAPING_DISABLED	(1 << 2)  /* background block reaping paused */
#define XREP_ALREADY_FIXED	(1 << 31) /* checking our repair work */

/* Metadata scrubbers */
int xchk_tester(struct scxfs_scrub *sc);
int xchk_superblock(struct scxfs_scrub *sc);
int xchk_agf(struct scxfs_scrub *sc);
int xchk_agfl(struct scxfs_scrub *sc);
int xchk_agi(struct scxfs_scrub *sc);
int xchk_bnobt(struct scxfs_scrub *sc);
int xchk_cntbt(struct scxfs_scrub *sc);
int xchk_inobt(struct scxfs_scrub *sc);
int xchk_finobt(struct scxfs_scrub *sc);
int xchk_rmapbt(struct scxfs_scrub *sc);
int xchk_refcountbt(struct scxfs_scrub *sc);
int xchk_inode(struct scxfs_scrub *sc);
int xchk_bmap_data(struct scxfs_scrub *sc);
int xchk_bmap_attr(struct scxfs_scrub *sc);
int xchk_bmap_cow(struct scxfs_scrub *sc);
int xchk_directory(struct scxfs_scrub *sc);
int xchk_xattr(struct scxfs_scrub *sc);
int xchk_symlink(struct scxfs_scrub *sc);
int xchk_parent(struct scxfs_scrub *sc);
#ifdef CONFIG_XFS_RT
int xchk_rtbitmap(struct scxfs_scrub *sc);
int xchk_rtsummary(struct scxfs_scrub *sc);
#else
static inline int
xchk_rtbitmap(struct scxfs_scrub *sc)
{
	return -ENOENT;
}
static inline int
xchk_rtsummary(struct scxfs_scrub *sc)
{
	return -ENOENT;
}
#endif
#ifdef CONFIG_XFS_QUOTA
int xchk_quota(struct scxfs_scrub *sc);
#else
static inline int
xchk_quota(struct scxfs_scrub *sc)
{
	return -ENOENT;
}
#endif
int xchk_fscounters(struct scxfs_scrub *sc);

/* cross-referencing helpers */
void xchk_xref_is_used_space(struct scxfs_scrub *sc, scxfs_agblock_t agbno,
		scxfs_extlen_t len);
void xchk_xref_is_not_inode_chunk(struct scxfs_scrub *sc, scxfs_agblock_t agbno,
		scxfs_extlen_t len);
void xchk_xref_is_inode_chunk(struct scxfs_scrub *sc, scxfs_agblock_t agbno,
		scxfs_extlen_t len);
void xchk_xref_is_owned_by(struct scxfs_scrub *sc, scxfs_agblock_t agbno,
		scxfs_extlen_t len, const struct scxfs_owner_info *oinfo);
void xchk_xref_is_not_owned_by(struct scxfs_scrub *sc, scxfs_agblock_t agbno,
		scxfs_extlen_t len, const struct scxfs_owner_info *oinfo);
void xchk_xref_has_no_owner(struct scxfs_scrub *sc, scxfs_agblock_t agbno,
		scxfs_extlen_t len);
void xchk_xref_is_cow_staging(struct scxfs_scrub *sc, scxfs_agblock_t bno,
		scxfs_extlen_t len);
void xchk_xref_is_not_shared(struct scxfs_scrub *sc, scxfs_agblock_t bno,
		scxfs_extlen_t len);
#ifdef CONFIG_XFS_RT
void xchk_xref_is_used_rt_space(struct scxfs_scrub *sc, scxfs_rtblock_t rtbno,
		scxfs_extlen_t len);
#else
# define xchk_xref_is_used_rt_space(sc, rtbno, len) do { } while (0)
#endif

struct xchk_fscounters {
	uint64_t		icount;
	uint64_t		ifree;
	uint64_t		fdblocks;
	unsigned long long	icount_min;
	unsigned long long	icount_max;
};

#endif	/* __SCXFS_SCRUB_SCRUB_H__ */
