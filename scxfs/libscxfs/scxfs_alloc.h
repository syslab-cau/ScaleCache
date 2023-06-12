// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2002,2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#ifndef __SCXFS_ALLOC_H__
#define	__SCXFS_ALLOC_H__

struct scxfs_buf;
struct scxfs_btree_cur;
struct scxfs_mount;
struct scxfs_perag;
struct scxfs_trans;

extern struct workqueue_struct *scxfs_alloc_wq;

unsigned int scxfs_agfl_size(struct scxfs_mount *mp);

/*
 * Freespace allocation types.  Argument to scxfs_alloc_[v]extent.
 */
#define SCXFS_ALLOCTYPE_FIRST_AG	0x02	/* ... start at ag 0 */
#define SCXFS_ALLOCTYPE_THIS_AG	0x08	/* anywhere in this a.g. */
#define SCXFS_ALLOCTYPE_START_BNO	0x10	/* near this block else anywhere */
#define SCXFS_ALLOCTYPE_NEAR_BNO	0x20	/* in this a.g. and near this block */
#define SCXFS_ALLOCTYPE_THIS_BNO	0x40	/* at exactly this block */

/* this should become an enum again when the tracing code is fixed */
typedef unsigned int scxfs_alloctype_t;

#define SCXFS_ALLOC_TYPES \
	{ SCXFS_ALLOCTYPE_FIRST_AG,	"FIRST_AG" }, \
	{ SCXFS_ALLOCTYPE_THIS_AG,	"THIS_AG" }, \
	{ SCXFS_ALLOCTYPE_START_BNO,	"START_BNO" }, \
	{ SCXFS_ALLOCTYPE_NEAR_BNO,	"NEAR_BNO" }, \
	{ SCXFS_ALLOCTYPE_THIS_BNO,	"THIS_BNO" }

/*
 * Flags for scxfs_alloc_fix_freelist.
 */
#define	SCXFS_ALLOC_FLAG_TRYLOCK	0x00000001  /* use trylock for buffer locking */
#define	SCXFS_ALLOC_FLAG_FREEING	0x00000002  /* indicate caller is freeing extents*/
#define	SCXFS_ALLOC_FLAG_NORMAP	0x00000004  /* don't modify the rmapbt */
#define	SCXFS_ALLOC_FLAG_NOSHRINK	0x00000008  /* don't shrink the freelist */
#define	SCXFS_ALLOC_FLAG_CHECK	0x00000010  /* test only, don't modify args */

/*
 * Argument structure for scxfs_alloc routines.
 * This is turned into a structure to avoid having 20 arguments passed
 * down several levels of the stack.
 */
typedef struct scxfs_alloc_arg {
	struct scxfs_trans *tp;		/* transaction pointer */
	struct scxfs_mount *mp;		/* file system mount point */
	struct scxfs_buf	*agbp;		/* buffer for a.g. freelist header */
	struct scxfs_perag *pag;		/* per-ag struct for this agno */
	struct scxfs_inode *ip;		/* for userdata zeroing method */
	scxfs_fsblock_t	fsbno;		/* file system block number */
	scxfs_agnumber_t	agno;		/* allocation group number */
	scxfs_agblock_t	agbno;		/* allocation group-relative block # */
	scxfs_extlen_t	minlen;		/* minimum size of extent */
	scxfs_extlen_t	maxlen;		/* maximum size of extent */
	scxfs_extlen_t	mod;		/* mod value for extent size */
	scxfs_extlen_t	prod;		/* prod value for extent size */
	scxfs_extlen_t	minleft;	/* min blocks must be left after us */
	scxfs_extlen_t	total;		/* total blocks needed in xaction */
	scxfs_extlen_t	alignment;	/* align answer to multiple of this */
	scxfs_extlen_t	minalignslop;	/* slop for minlen+alignment calcs */
	scxfs_agblock_t	min_agbno;	/* set an agbno range for NEAR allocs */
	scxfs_agblock_t	max_agbno;	/* ... */
	scxfs_extlen_t	len;		/* output: actual size of extent */
	scxfs_alloctype_t	type;		/* allocation type SCXFS_ALLOCTYPE_... */
	scxfs_alloctype_t	otype;		/* original allocation type */
	int		datatype;	/* mask defining data type treatment */
	char		wasdel;		/* set if allocation was prev delayed */
	char		wasfromfl;	/* set if allocation is from freelist */
	struct scxfs_owner_info	oinfo;	/* owner of blocks being allocated */
	enum scxfs_ag_resv_type	resv;	/* block reservation to use */
} scxfs_alloc_arg_t;

/*
 * Defines for datatype
 */
#define SCXFS_ALLOC_USERDATA		(1 << 0)/* allocation is for user data*/
#define SCXFS_ALLOC_INITIAL_USER_DATA	(1 << 1)/* special case start of file */
#define SCXFS_ALLOC_USERDATA_ZERO		(1 << 2)/* zero extent on allocation */
#define SCXFS_ALLOC_NOBUSY		(1 << 3)/* Busy extents not allowed */

static inline bool
scxfs_alloc_is_userdata(int datatype)
{
	return (datatype & ~SCXFS_ALLOC_NOBUSY) != 0;
}

static inline bool
scxfs_alloc_allow_busy_reuse(int datatype)
{
	return (datatype & SCXFS_ALLOC_NOBUSY) == 0;
}

/* freespace limit calculations */
#define SCXFS_ALLOC_AGFL_RESERVE	4
unsigned int scxfs_alloc_set_aside(struct scxfs_mount *mp);
unsigned int scxfs_alloc_ag_max_usable(struct scxfs_mount *mp);

scxfs_extlen_t scxfs_alloc_longest_free_extent(struct scxfs_perag *pag,
		scxfs_extlen_t need, scxfs_extlen_t reserved);
unsigned int scxfs_alloc_min_freelist(struct scxfs_mount *mp,
		struct scxfs_perag *pag);

/*
 * Compute and fill in value of m_ag_maxlevels.
 */
void
scxfs_alloc_compute_maxlevels(
	struct scxfs_mount	*mp);	/* file system mount structure */

/*
 * Get a block from the freelist.
 * Returns with the buffer for the block gotten.
 */
int				/* error */
scxfs_alloc_get_freelist(
	struct scxfs_trans *tp,	/* transaction pointer */
	struct scxfs_buf	*agbp,	/* buffer containing the agf structure */
	scxfs_agblock_t	*bnop,	/* block address retrieved from freelist */
	int		btreeblk); /* destination is a AGF btree */

/*
 * Log the given fields from the agf structure.
 */
void
scxfs_alloc_log_agf(
	struct scxfs_trans *tp,	/* transaction pointer */
	struct scxfs_buf	*bp,	/* buffer for a.g. freelist header */
	int		fields);/* mask of fields to be logged (SCXFS_AGF_...) */

/*
 * Interface for inode allocation to force the pag data to be initialized.
 */
int				/* error */
scxfs_alloc_pagf_init(
	struct scxfs_mount *mp,	/* file system mount structure */
	struct scxfs_trans *tp,	/* transaction pointer */
	scxfs_agnumber_t	agno,	/* allocation group number */
	int		flags);	/* SCXFS_ALLOC_FLAGS_... */

/*
 * Put the block on the freelist for the allocation group.
 */
int				/* error */
scxfs_alloc_put_freelist(
	struct scxfs_trans *tp,	/* transaction pointer */
	struct scxfs_buf	*agbp,	/* buffer for a.g. freelist header */
	struct scxfs_buf	*agflbp,/* buffer for a.g. free block array */
	scxfs_agblock_t	bno,	/* block being freed */
	int		btreeblk); /* owner was a AGF btree */

/*
 * Read in the allocation group header (free/alloc section).
 */
int					/* error  */
scxfs_alloc_read_agf(
	struct scxfs_mount *mp,		/* mount point structure */
	struct scxfs_trans *tp,		/* transaction pointer */
	scxfs_agnumber_t	agno,		/* allocation group number */
	int		flags,		/* SCXFS_ALLOC_FLAG_... */
	struct scxfs_buf	**bpp);		/* buffer for the ag freelist header */

/*
 * Allocate an extent (variable-size).
 */
int				/* error */
scxfs_alloc_vextent(
	scxfs_alloc_arg_t	*args);	/* allocation argument structure */

/*
 * Free an extent.
 */
int				/* error */
__scxfs_free_extent(
	struct scxfs_trans	*tp,	/* transaction pointer */
	scxfs_fsblock_t		bno,	/* starting block number of extent */
	scxfs_extlen_t		len,	/* length of extent */
	const struct scxfs_owner_info	*oinfo,	/* extent owner */
	enum scxfs_ag_resv_type	type,	/* block reservation type */
	bool			skip_discard);

static inline int
scxfs_free_extent(
	struct scxfs_trans	*tp,
	scxfs_fsblock_t		bno,
	scxfs_extlen_t		len,
	const struct scxfs_owner_info	*oinfo,
	enum scxfs_ag_resv_type	type)
{
	return __scxfs_free_extent(tp, bno, len, oinfo, type, false);
}

int				/* error */
scxfs_alloc_lookup_le(
	struct scxfs_btree_cur	*cur,	/* btree cursor */
	scxfs_agblock_t		bno,	/* starting block of extent */
	scxfs_extlen_t		len,	/* length of extent */
	int			*stat);	/* success/failure */

int				/* error */
scxfs_alloc_lookup_ge(
	struct scxfs_btree_cur	*cur,	/* btree cursor */
	scxfs_agblock_t		bno,	/* starting block of extent */
	scxfs_extlen_t		len,	/* length of extent */
	int			*stat);	/* success/failure */

int					/* error */
scxfs_alloc_get_rec(
	struct scxfs_btree_cur	*cur,	/* btree cursor */
	scxfs_agblock_t		*bno,	/* output: starting block of extent */
	scxfs_extlen_t		*len,	/* output: length of extent */
	int			*stat);	/* output: success/failure */

int scxfs_read_agf(struct scxfs_mount *mp, struct scxfs_trans *tp,
			scxfs_agnumber_t agno, int flags, struct scxfs_buf **bpp);
int scxfs_alloc_read_agfl(struct scxfs_mount *mp, struct scxfs_trans *tp,
			scxfs_agnumber_t agno, struct scxfs_buf **bpp);
int scxfs_free_agfl_block(struct scxfs_trans *, scxfs_agnumber_t, scxfs_agblock_t,
			struct scxfs_buf *, struct scxfs_owner_info *);
int scxfs_alloc_fix_freelist(struct scxfs_alloc_arg *args, int flags);
int scxfs_free_extent_fix_freelist(struct scxfs_trans *tp, scxfs_agnumber_t agno,
		struct scxfs_buf **agbp);

scxfs_extlen_t scxfs_prealloc_blocks(struct scxfs_mount *mp);

typedef int (*scxfs_alloc_query_range_fn)(
	struct scxfs_btree_cur		*cur,
	struct scxfs_alloc_rec_incore	*rec,
	void				*priv);

int scxfs_alloc_query_range(struct scxfs_btree_cur *cur,
		struct scxfs_alloc_rec_incore *low_rec,
		struct scxfs_alloc_rec_incore *high_rec,
		scxfs_alloc_query_range_fn fn, void *priv);
int scxfs_alloc_query_all(struct scxfs_btree_cur *cur, scxfs_alloc_query_range_fn fn,
		void *priv);

int scxfs_alloc_has_record(struct scxfs_btree_cur *cur, scxfs_agblock_t bno,
		scxfs_extlen_t len, bool *exist);

typedef int (*scxfs_agfl_walk_fn)(struct scxfs_mount *mp, scxfs_agblock_t bno,
		void *priv);
int scxfs_agfl_walk(struct scxfs_mount *mp, struct scxfs_agf *agf,
		struct scxfs_buf *agflbp, scxfs_agfl_walk_fn walk_fn, void *priv);

#endif	/* __SCXFS_ALLOC_H__ */
