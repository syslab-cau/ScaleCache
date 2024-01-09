// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2001,2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#ifndef __SCXFS_BTREE_H__
#define	__SCXFS_BTREE_H__

struct scxfs_buf;
struct scxfs_inode;
struct scxfs_mount;
struct scxfs_trans;

extern kmem_zone_t	*scxfs_btree_cur_zone;

/*
 * Generic key, ptr and record wrapper structures.
 *
 * These are disk format structures, and are converted where necessary
 * by the btree specific code that needs to interpret them.
 */
union scxfs_btree_ptr {
	__be32			s;	/* short form ptr */
	__be64			l;	/* long form ptr */
};

/*
 * The in-core btree key.  Overlapping btrees actually store two keys
 * per pointer, so we reserve enough memory to hold both.  The __*bigkey
 * items should never be accessed directly.
 */
union scxfs_btree_key {
	struct scxfs_bmbt_key		bmbt;
	scxfs_bmdr_key_t			bmbr;	/* bmbt root block */
	scxfs_alloc_key_t			alloc;
	struct scxfs_inobt_key		inobt;
	struct scxfs_rmap_key		rmap;
	struct scxfs_rmap_key		__rmap_bigkey[2];
	struct scxfs_refcount_key		refc;
};

union scxfs_btree_rec {
	struct scxfs_bmbt_rec		bmbt;
	scxfs_bmdr_rec_t			bmbr;	/* bmbt root block */
	struct scxfs_alloc_rec		alloc;
	struct scxfs_inobt_rec		inobt;
	struct scxfs_rmap_rec		rmap;
	struct scxfs_refcount_rec		refc;
};

/*
 * This nonsense is to make -wlint happy.
 */
#define	SCXFS_LOOKUP_EQ	((scxfs_lookup_t)SCXFS_LOOKUP_EQi)
#define	SCXFS_LOOKUP_LE	((scxfs_lookup_t)SCXFS_LOOKUP_LEi)
#define	SCXFS_LOOKUP_GE	((scxfs_lookup_t)SCXFS_LOOKUP_GEi)

#define	SCXFS_BTNUM_BNO	((scxfs_btnum_t)SCXFS_BTNUM_BNOi)
#define	SCXFS_BTNUM_CNT	((scxfs_btnum_t)SCXFS_BTNUM_CNTi)
#define	SCXFS_BTNUM_BMAP	((scxfs_btnum_t)SCXFS_BTNUM_BMAPi)
#define	SCXFS_BTNUM_INO	((scxfs_btnum_t)SCXFS_BTNUM_INOi)
#define	SCXFS_BTNUM_FINO	((scxfs_btnum_t)SCXFS_BTNUM_FINOi)
#define	SCXFS_BTNUM_RMAP	((scxfs_btnum_t)SCXFS_BTNUM_RMAPi)
#define	SCXFS_BTNUM_REFC	((scxfs_btnum_t)SCXFS_BTNUM_REFCi)

uint32_t scxfs_btree_magic(int crc, scxfs_btnum_t btnum);

/*
 * For logging record fields.
 */
#define	SCXFS_BB_MAGIC		(1 << 0)
#define	SCXFS_BB_LEVEL		(1 << 1)
#define	SCXFS_BB_NUMRECS		(1 << 2)
#define	SCXFS_BB_LEFTSIB		(1 << 3)
#define	SCXFS_BB_RIGHTSIB		(1 << 4)
#define	SCXFS_BB_BLKNO		(1 << 5)
#define	SCXFS_BB_LSN		(1 << 6)
#define	SCXFS_BB_UUID		(1 << 7)
#define	SCXFS_BB_OWNER		(1 << 8)
#define	SCXFS_BB_NUM_BITS		5
#define	SCXFS_BB_ALL_BITS		((1 << SCXFS_BB_NUM_BITS) - 1)
#define	SCXFS_BB_NUM_BITS_CRC	9
#define	SCXFS_BB_ALL_BITS_CRC	((1 << SCXFS_BB_NUM_BITS_CRC) - 1)

/*
 * Generic stats interface
 */
#define SCXFS_BTREE_STATS_INC(cur, stat)	\
	SCXFS_STATS_INC_OFF((cur)->bc_mp, (cur)->bc_statoff + __XBTS_ ## stat)
#define SCXFS_BTREE_STATS_ADD(cur, stat, val)	\
	SCXFS_STATS_ADD_OFF((cur)->bc_mp, (cur)->bc_statoff + __XBTS_ ## stat, val)

#define	SCXFS_BTREE_MAXLEVELS	9	/* max of all btrees */

struct scxfs_btree_ops {
	/* size of the key and record structures */
	size_t	key_len;
	size_t	rec_len;

	/* cursor operations */
	struct scxfs_btree_cur *(*dup_cursor)(struct scxfs_btree_cur *);
	void	(*update_cursor)(struct scxfs_btree_cur *src,
				 struct scxfs_btree_cur *dst);

	/* update btree root pointer */
	void	(*set_root)(struct scxfs_btree_cur *cur,
			    union scxfs_btree_ptr *nptr, int level_change);

	/* block allocation / freeing */
	int	(*alloc_block)(struct scxfs_btree_cur *cur,
			       union scxfs_btree_ptr *start_bno,
			       union scxfs_btree_ptr *new_bno,
			       int *stat);
	int	(*free_block)(struct scxfs_btree_cur *cur, struct scxfs_buf *bp);

	/* update last record information */
	void	(*update_lastrec)(struct scxfs_btree_cur *cur,
				  struct scxfs_btree_block *block,
				  union scxfs_btree_rec *rec,
				  int ptr, int reason);

	/* records in block/level */
	int	(*get_minrecs)(struct scxfs_btree_cur *cur, int level);
	int	(*get_maxrecs)(struct scxfs_btree_cur *cur, int level);

	/* records on disk.  Matter for the root in inode case. */
	int	(*get_dmaxrecs)(struct scxfs_btree_cur *cur, int level);

	/* init values of btree structures */
	void	(*init_key_from_rec)(union scxfs_btree_key *key,
				     union scxfs_btree_rec *rec);
	void	(*init_rec_from_cur)(struct scxfs_btree_cur *cur,
				     union scxfs_btree_rec *rec);
	void	(*init_ptr_from_cur)(struct scxfs_btree_cur *cur,
				     union scxfs_btree_ptr *ptr);
	void	(*init_high_key_from_rec)(union scxfs_btree_key *key,
					  union scxfs_btree_rec *rec);

	/* difference between key value and cursor value */
	int64_t (*key_diff)(struct scxfs_btree_cur *cur,
			      union scxfs_btree_key *key);

	/*
	 * Difference between key2 and key1 -- positive if key1 > key2,
	 * negative if key1 < key2, and zero if equal.
	 */
	int64_t (*diff_two_keys)(struct scxfs_btree_cur *cur,
				   union scxfs_btree_key *key1,
				   union scxfs_btree_key *key2);

	const struct scxfs_buf_ops	*buf_ops;

	/* check that k1 is lower than k2 */
	int	(*keys_inorder)(struct scxfs_btree_cur *cur,
				union scxfs_btree_key *k1,
				union scxfs_btree_key *k2);

	/* check that r1 is lower than r2 */
	int	(*recs_inorder)(struct scxfs_btree_cur *cur,
				union scxfs_btree_rec *r1,
				union scxfs_btree_rec *r2);
};

/*
 * Reasons for the update_lastrec method to be called.
 */
#define LASTREC_UPDATE	0
#define LASTREC_INSREC	1
#define LASTREC_DELREC	2


union scxfs_btree_irec {
	struct scxfs_alloc_rec_incore	a;
	struct scxfs_bmbt_irec		b;
	struct scxfs_inobt_rec_incore	i;
	struct scxfs_rmap_irec		r;
	struct scxfs_refcount_irec	rc;
};

/* Per-AG btree private information. */
union scxfs_btree_cur_private {
	struct {
		unsigned long	nr_ops;		/* # record updates */
		int		shape_changes;	/* # of extent splits */
	} refc;
};

/*
 * Btree cursor structure.
 * This collects all information needed by the btree code in one place.
 */
typedef struct scxfs_btree_cur
{
	struct scxfs_trans	*bc_tp;	/* transaction we're in, if any */
	struct scxfs_mount	*bc_mp;	/* file system mount struct */
	const struct scxfs_btree_ops *bc_ops;
	uint			bc_flags; /* btree features - below */
	union scxfs_btree_irec	bc_rec;	/* current insert/search record value */
	struct scxfs_buf	*bc_bufs[SCXFS_BTREE_MAXLEVELS];	/* buf ptr per level */
	int		bc_ptrs[SCXFS_BTREE_MAXLEVELS];	/* key/record # */
	uint8_t		bc_ra[SCXFS_BTREE_MAXLEVELS];	/* readahead bits */
#define	SCXFS_BTCUR_LEFTRA	1	/* left sibling has been read-ahead */
#define	SCXFS_BTCUR_RIGHTRA	2	/* right sibling has been read-ahead */
	uint8_t		bc_nlevels;	/* number of levels in the tree */
	uint8_t		bc_blocklog;	/* log2(blocksize) of btree blocks */
	scxfs_btnum_t	bc_btnum;	/* identifies which btree type */
	int		bc_statoff;	/* offset of btre stats array */
	union {
		struct {			/* needed for BNO, CNT, INO */
			struct scxfs_buf	*agbp;	/* agf/agi buffer pointer */
			scxfs_agnumber_t	agno;	/* ag number */
			union scxfs_btree_cur_private	priv;
		} a;
		struct {			/* needed for BMAP */
			struct scxfs_inode *ip;	/* pointer to our inode */
			int		allocated;	/* count of alloced */
			short		forksize;	/* fork's inode space */
			char		whichfork;	/* data or attr fork */
			char		flags;		/* flags */
#define	SCXFS_BTCUR_BPRV_WASDEL		(1<<0)		/* was delayed */
#define	SCXFS_BTCUR_BPRV_INVALID_OWNER	(1<<1)		/* for ext swap */
		} b;
	}		bc_private;	/* per-btree type data */
} scxfs_btree_cur_t;

/* cursor flags */
#define SCXFS_BTREE_LONG_PTRS		(1<<0)	/* pointers are 64bits long */
#define SCXFS_BTREE_ROOT_IN_INODE		(1<<1)	/* root may be variable size */
#define SCXFS_BTREE_LASTREC_UPDATE	(1<<2)	/* track last rec externally */
#define SCXFS_BTREE_CRC_BLOCKS		(1<<3)	/* uses extended btree blocks */
#define SCXFS_BTREE_OVERLAPPING		(1<<4)	/* overlapping intervals */


#define	SCXFS_BTREE_NOERROR	0
#define	SCXFS_BTREE_ERROR		1

/*
 * Convert from buffer to btree block header.
 */
#define	SCXFS_BUF_TO_BLOCK(bp)	((struct scxfs_btree_block *)((bp)->b_addr))

/*
 * Internal long and short btree block checks.  They return NULL if the
 * block is ok or the address of the failed check otherwise.
 */
scxfs_failaddr_t __scxfs_btree_check_lblock(struct scxfs_btree_cur *cur,
		struct scxfs_btree_block *block, int level, struct scxfs_buf *bp);
scxfs_failaddr_t __scxfs_btree_check_sblock(struct scxfs_btree_cur *cur,
		struct scxfs_btree_block *block, int level, struct scxfs_buf *bp);

/*
 * Check that block header is ok.
 */
int
scxfs_btree_check_block(
	struct scxfs_btree_cur	*cur,	/* btree cursor */
	struct scxfs_btree_block	*block,	/* generic btree block pointer */
	int			level,	/* level of the btree block */
	struct scxfs_buf		*bp);	/* buffer containing block, if any */

/*
 * Check that (long) pointer is ok.
 */
bool					/* error (0 or EFSCORRUPTED) */
scxfs_btree_check_lptr(
	struct scxfs_btree_cur	*cur,	/* btree cursor */
	scxfs_fsblock_t		fsbno,	/* btree block disk address */
	int			level);	/* btree block level */

/*
 * Check that (short) pointer is ok.
 */
bool					/* error (0 or EFSCORRUPTED) */
scxfs_btree_check_sptr(
	struct scxfs_btree_cur	*cur,	/* btree cursor */
	scxfs_agblock_t		agbno,	/* btree block disk address */
	int			level);	/* btree block level */

/*
 * Delete the btree cursor.
 */
void
scxfs_btree_del_cursor(
	scxfs_btree_cur_t		*cur,	/* btree cursor */
	int			error);	/* del because of error */

/*
 * Duplicate the btree cursor.
 * Allocate a new one, copy the record, re-get the buffers.
 */
int					/* error */
scxfs_btree_dup_cursor(
	scxfs_btree_cur_t		*cur,	/* input cursor */
	scxfs_btree_cur_t		**ncur);/* output cursor */

/*
 * Get a buffer for the block, return it with no data read.
 * Long-form addressing.
 */
struct scxfs_buf *				/* buffer for fsbno */
scxfs_btree_get_bufl(
	struct scxfs_mount	*mp,	/* file system mount point */
	struct scxfs_trans	*tp,	/* transaction pointer */
	scxfs_fsblock_t		fsbno);	/* file system block number */

/*
 * Get a buffer for the block, return it with no data read.
 * Short-form addressing.
 */
struct scxfs_buf *				/* buffer for agno/agbno */
scxfs_btree_get_bufs(
	struct scxfs_mount	*mp,	/* file system mount point */
	struct scxfs_trans	*tp,	/* transaction pointer */
	scxfs_agnumber_t		agno,	/* allocation group number */
	scxfs_agblock_t		agbno);	/* allocation group block number */

/*
 * Check for the cursor referring to the last block at the given level.
 */
int					/* 1=is last block, 0=not last block */
scxfs_btree_islastblock(
	scxfs_btree_cur_t		*cur,	/* btree cursor */
	int			level);	/* level to check */

/*
 * Compute first and last byte offsets for the fields given.
 * Interprets the offsets table, which contains struct field offsets.
 */
void
scxfs_btree_offsets(
	int64_t			fields,	/* bitmask of fields */
	const short		*offsets,/* table of field offsets */
	int			nbits,	/* number of bits to inspect */
	int			*first,	/* output: first byte offset */
	int			*last);	/* output: last byte offset */

/*
 * Get a buffer for the block, return it read in.
 * Long-form addressing.
 */
int					/* error */
scxfs_btree_read_bufl(
	struct scxfs_mount	*mp,	/* file system mount point */
	struct scxfs_trans	*tp,	/* transaction pointer */
	scxfs_fsblock_t		fsbno,	/* file system block number */
	struct scxfs_buf		**bpp,	/* buffer for fsbno */
	int			refval,	/* ref count value for buffer */
	const struct scxfs_buf_ops *ops);

/*
 * Read-ahead the block, don't wait for it, don't return a buffer.
 * Long-form addressing.
 */
void					/* error */
scxfs_btree_reada_bufl(
	struct scxfs_mount	*mp,	/* file system mount point */
	scxfs_fsblock_t		fsbno,	/* file system block number */
	scxfs_extlen_t		count,	/* count of filesystem blocks */
	const struct scxfs_buf_ops *ops);

/*
 * Read-ahead the block, don't wait for it, don't return a buffer.
 * Short-form addressing.
 */
void					/* error */
scxfs_btree_reada_bufs(
	struct scxfs_mount	*mp,	/* file system mount point */
	scxfs_agnumber_t		agno,	/* allocation group number */
	scxfs_agblock_t		agbno,	/* allocation group block number */
	scxfs_extlen_t		count,	/* count of filesystem blocks */
	const struct scxfs_buf_ops *ops);

/*
 * Initialise a new btree block header
 */
void
scxfs_btree_init_block(
	struct scxfs_mount *mp,
	struct scxfs_buf	*bp,
	scxfs_btnum_t	btnum,
	__u16		level,
	__u16		numrecs,
	__u64		owner);

void
scxfs_btree_init_block_int(
	struct scxfs_mount	*mp,
	struct scxfs_btree_block	*buf,
	scxfs_daddr_t		blkno,
	scxfs_btnum_t		btnum,
	__u16			level,
	__u16			numrecs,
	__u64			owner,
	unsigned int		flags);

/*
 * Common btree core entry points.
 */
int scxfs_btree_increment(struct scxfs_btree_cur *, int, int *);
int scxfs_btree_decrement(struct scxfs_btree_cur *, int, int *);
int scxfs_btree_lookup(struct scxfs_btree_cur *, scxfs_lookup_t, int *);
int scxfs_btree_update(struct scxfs_btree_cur *, union scxfs_btree_rec *);
int scxfs_btree_new_iroot(struct scxfs_btree_cur *, int *, int *);
int scxfs_btree_insert(struct scxfs_btree_cur *, int *);
int scxfs_btree_delete(struct scxfs_btree_cur *, int *);
int scxfs_btree_get_rec(struct scxfs_btree_cur *, union scxfs_btree_rec **, int *);
int scxfs_btree_change_owner(struct scxfs_btree_cur *cur, uint64_t new_owner,
			   struct list_head *buffer_list);

/*
 * btree block CRC helpers
 */
void scxfs_btree_lblock_calc_crc(struct scxfs_buf *);
bool scxfs_btree_lblock_verify_crc(struct scxfs_buf *);
void scxfs_btree_sblock_calc_crc(struct scxfs_buf *);
bool scxfs_btree_sblock_verify_crc(struct scxfs_buf *);

/*
 * Internal btree helpers also used by scxfs_bmap.c.
 */
void scxfs_btree_log_block(struct scxfs_btree_cur *, struct scxfs_buf *, int);
void scxfs_btree_log_recs(struct scxfs_btree_cur *, struct scxfs_buf *, int, int);

/*
 * Helpers.
 */
static inline int scxfs_btree_get_numrecs(struct scxfs_btree_block *block)
{
	return be16_to_cpu(block->bb_numrecs);
}

static inline void scxfs_btree_set_numrecs(struct scxfs_btree_block *block,
		uint16_t numrecs)
{
	block->bb_numrecs = cpu_to_be16(numrecs);
}

static inline int scxfs_btree_get_level(struct scxfs_btree_block *block)
{
	return be16_to_cpu(block->bb_level);
}


/*
 * Min and max functions for extlen, agblock, fileoff, and filblks types.
 */
#define	SCXFS_EXTLEN_MIN(a,b)	min_t(scxfs_extlen_t, (a), (b))
#define	SCXFS_EXTLEN_MAX(a,b)	max_t(scxfs_extlen_t, (a), (b))
#define	SCXFS_AGBLOCK_MIN(a,b)	min_t(scxfs_agblock_t, (a), (b))
#define	SCXFS_AGBLOCK_MAX(a,b)	max_t(scxfs_agblock_t, (a), (b))
#define	SCXFS_FILEOFF_MIN(a,b)	min_t(scxfs_fileoff_t, (a), (b))
#define	SCXFS_FILEOFF_MAX(a,b)	max_t(scxfs_fileoff_t, (a), (b))
#define	SCXFS_FILBLKS_MIN(a,b)	min_t(scxfs_filblks_t, (a), (b))
#define	SCXFS_FILBLKS_MAX(a,b)	max_t(scxfs_filblks_t, (a), (b))

scxfs_failaddr_t scxfs_btree_sblock_v5hdr_verify(struct scxfs_buf *bp);
scxfs_failaddr_t scxfs_btree_sblock_verify(struct scxfs_buf *bp,
		unsigned int max_recs);
scxfs_failaddr_t scxfs_btree_lblock_v5hdr_verify(struct scxfs_buf *bp,
		uint64_t owner);
scxfs_failaddr_t scxfs_btree_lblock_verify(struct scxfs_buf *bp,
		unsigned int max_recs);

uint scxfs_btree_compute_maxlevels(uint *limits, unsigned long len);
unsigned long long scxfs_btree_calc_size(uint *limits, unsigned long long len);

/*
 * Return codes for the query range iterator function are 0 to continue
 * iterating, and non-zero to stop iterating.  Any non-zero value will be
 * passed up to the _query_range caller.  The special value -ECANCELED can be
 * used to stop iteration, because _query_range never generates that error
 * code on its own.
 */
typedef int (*scxfs_btree_query_range_fn)(struct scxfs_btree_cur *cur,
		union scxfs_btree_rec *rec, void *priv);

int scxfs_btree_query_range(struct scxfs_btree_cur *cur,
		union scxfs_btree_irec *low_rec, union scxfs_btree_irec *high_rec,
		scxfs_btree_query_range_fn fn, void *priv);
int scxfs_btree_query_all(struct scxfs_btree_cur *cur, scxfs_btree_query_range_fn fn,
		void *priv);

typedef int (*scxfs_btree_visit_blocks_fn)(struct scxfs_btree_cur *cur, int level,
		void *data);
int scxfs_btree_visit_blocks(struct scxfs_btree_cur *cur,
		scxfs_btree_visit_blocks_fn fn, void *data);

int scxfs_btree_count_blocks(struct scxfs_btree_cur *cur, scxfs_extlen_t *blocks);

union scxfs_btree_rec *scxfs_btree_rec_addr(struct scxfs_btree_cur *cur, int n,
		struct scxfs_btree_block *block);
union scxfs_btree_key *scxfs_btree_key_addr(struct scxfs_btree_cur *cur, int n,
		struct scxfs_btree_block *block);
union scxfs_btree_key *scxfs_btree_high_key_addr(struct scxfs_btree_cur *cur, int n,
		struct scxfs_btree_block *block);
union scxfs_btree_ptr *scxfs_btree_ptr_addr(struct scxfs_btree_cur *cur, int n,
		struct scxfs_btree_block *block);
int scxfs_btree_lookup_get_block(struct scxfs_btree_cur *cur, int level,
		union scxfs_btree_ptr *pp, struct scxfs_btree_block **blkp);
struct scxfs_btree_block *scxfs_btree_get_block(struct scxfs_btree_cur *cur,
		int level, struct scxfs_buf **bpp);
bool scxfs_btree_ptr_is_null(struct scxfs_btree_cur *cur, union scxfs_btree_ptr *ptr);
int64_t scxfs_btree_diff_two_ptrs(struct scxfs_btree_cur *cur,
				const union scxfs_btree_ptr *a,
				const union scxfs_btree_ptr *b);
void scxfs_btree_get_sibling(struct scxfs_btree_cur *cur,
			   struct scxfs_btree_block *block,
			   union scxfs_btree_ptr *ptr, int lr);
void scxfs_btree_get_keys(struct scxfs_btree_cur *cur,
		struct scxfs_btree_block *block, union scxfs_btree_key *key);
union scxfs_btree_key *scxfs_btree_high_key_from_key(struct scxfs_btree_cur *cur,
		union scxfs_btree_key *key);
int scxfs_btree_has_record(struct scxfs_btree_cur *cur, union scxfs_btree_irec *low,
		union scxfs_btree_irec *high, bool *exists);
bool scxfs_btree_has_more_records(struct scxfs_btree_cur *cur);

#endif	/* __SCXFS_BTREE_H__ */
