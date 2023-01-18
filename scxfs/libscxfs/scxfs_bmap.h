// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2006 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#ifndef __SCXFS_BMAP_H__
#define	__SCXFS_BMAP_H__

struct getbmap;
struct scxfs_bmbt_irec;
struct scxfs_ifork;
struct scxfs_inode;
struct scxfs_mount;
struct scxfs_trans;

extern kmem_zone_t	*scxfs_bmap_free_item_zone;

/*
 * Argument structure for scxfs_bmap_alloc.
 */
struct scxfs_bmalloca {
	struct scxfs_trans	*tp;	/* transaction pointer */
	struct scxfs_inode	*ip;	/* incore inode pointer */
	struct scxfs_bmbt_irec	prev;	/* extent before the new one */
	struct scxfs_bmbt_irec	got;	/* extent after, or delayed */

	scxfs_fileoff_t		offset;	/* offset in file filling in */
	scxfs_extlen_t		length;	/* i/o length asked/allocated */
	scxfs_fsblock_t		blkno;	/* starting block of new extent */

	struct scxfs_btree_cur	*cur;	/* btree cursor */
	struct scxfs_iext_cursor	icur;	/* incore extent cursor */
	int			nallocs;/* number of extents alloc'd */
	int			logflags;/* flags for transaction logging */

	scxfs_extlen_t		total;	/* total blocks needed for xaction */
	scxfs_extlen_t		minlen;	/* minimum allocation size (blocks) */
	scxfs_extlen_t		minleft; /* amount must be left after alloc */
	bool			eof;	/* set if allocating past last extent */
	bool			wasdel;	/* replacing a delayed allocation */
	bool			aeof;	/* allocated space at eof */
	bool			conv;	/* overwriting unwritten extents */
	int			datatype;/* data type being allocated */
	int			flags;
};

/*
 * List of extents to be free "later".
 * The list is kept sorted on xbf_startblock.
 */
struct scxfs_extent_free_item
{
	scxfs_fsblock_t		xefi_startblock;/* starting fs block number */
	scxfs_extlen_t		xefi_blockcount;/* number of blocks in extent */
	bool			xefi_skip_discard;
	struct list_head	xefi_list;
	struct scxfs_owner_info	xefi_oinfo;	/* extent owner */
};

#define	SCXFS_BMAP_MAX_NMAP	4

/*
 * Flags for scxfs_bmapi_*
 */
#define SCXFS_BMAPI_ENTIRE	0x001	/* return entire extent, not trimmed */
#define SCXFS_BMAPI_METADATA	0x002	/* mapping metadata not user data */
#define SCXFS_BMAPI_ATTRFORK	0x004	/* use attribute fork not data */
#define SCXFS_BMAPI_PREALLOC	0x008	/* preallocation op: unwritten space */
#define SCXFS_BMAPI_CONTIG	0x020	/* must allocate only one extent */
/*
 * unwritten extent conversion - this needs write cache flushing and no additional
 * allocation alignments. When specified with SCXFS_BMAPI_PREALLOC it converts
 * from written to unwritten, otherwise convert from unwritten to written.
 */
#define SCXFS_BMAPI_CONVERT	0x040

/*
 * allocate zeroed extents - this requires all newly allocated user data extents
 * to be initialised to zero. It will be ignored if SCXFS_BMAPI_METADATA is set.
 * Use in conjunction with SCXFS_BMAPI_CONVERT to convert unwritten extents found
 * during the allocation range to zeroed written extents.
 */
#define SCXFS_BMAPI_ZERO		0x080

/*
 * Map the inode offset to the block given in ap->firstblock.  Primarily
 * used for reflink.  The range must be in a hole, and this flag cannot be
 * turned on with PREALLOC or CONVERT, and cannot be used on the attr fork.
 *
 * For bunmapi, this flag unmaps the range without adjusting quota, reducing
 * refcount, or freeing the blocks.
 */
#define SCXFS_BMAPI_REMAP		0x100

/* Map something in the CoW fork. */
#define SCXFS_BMAPI_COWFORK	0x200

/* Skip online discard of freed extents */
#define SCXFS_BMAPI_NODISCARD	0x1000

/* Do not update the rmap btree.  Used for reconstructing bmbt from rmapbt. */
#define SCXFS_BMAPI_NORMAP	0x2000

#define SCXFS_BMAPI_FLAGS \
	{ SCXFS_BMAPI_ENTIRE,	"ENTIRE" }, \
	{ SCXFS_BMAPI_METADATA,	"METADATA" }, \
	{ SCXFS_BMAPI_ATTRFORK,	"ATTRFORK" }, \
	{ SCXFS_BMAPI_PREALLOC,	"PREALLOC" }, \
	{ SCXFS_BMAPI_CONTIG,	"CONTIG" }, \
	{ SCXFS_BMAPI_CONVERT,	"CONVERT" }, \
	{ SCXFS_BMAPI_ZERO,	"ZERO" }, \
	{ SCXFS_BMAPI_REMAP,	"REMAP" }, \
	{ SCXFS_BMAPI_COWFORK,	"COWFORK" }, \
	{ SCXFS_BMAPI_NODISCARD,	"NODISCARD" }, \
	{ SCXFS_BMAPI_NORMAP,	"NORMAP" }


static inline int scxfs_bmapi_aflag(int w)
{
	return (w == SCXFS_ATTR_FORK ? SCXFS_BMAPI_ATTRFORK :
	       (w == SCXFS_COW_FORK ? SCXFS_BMAPI_COWFORK : 0));
}

static inline int scxfs_bmapi_whichfork(int bmapi_flags)
{
	if (bmapi_flags & SCXFS_BMAPI_COWFORK)
		return SCXFS_COW_FORK;
	else if (bmapi_flags & SCXFS_BMAPI_ATTRFORK)
		return SCXFS_ATTR_FORK;
	return SCXFS_DATA_FORK;
}

/*
 * Special values for scxfs_bmbt_irec_t br_startblock field.
 */
#define	DELAYSTARTBLOCK		((scxfs_fsblock_t)-1LL)
#define	HOLESTARTBLOCK		((scxfs_fsblock_t)-2LL)

/*
 * Flags for scxfs_bmap_add_extent*.
 */
#define BMAP_LEFT_CONTIG	(1 << 0)
#define BMAP_RIGHT_CONTIG	(1 << 1)
#define BMAP_LEFT_FILLING	(1 << 2)
#define BMAP_RIGHT_FILLING	(1 << 3)
#define BMAP_LEFT_DELAY		(1 << 4)
#define BMAP_RIGHT_DELAY	(1 << 5)
#define BMAP_LEFT_VALID		(1 << 6)
#define BMAP_RIGHT_VALID	(1 << 7)
#define BMAP_ATTRFORK		(1 << 8)
#define BMAP_COWFORK		(1 << 9)

#define SCXFS_BMAP_EXT_FLAGS \
	{ BMAP_LEFT_CONTIG,	"LC" }, \
	{ BMAP_RIGHT_CONTIG,	"RC" }, \
	{ BMAP_LEFT_FILLING,	"LF" }, \
	{ BMAP_RIGHT_FILLING,	"RF" }, \
	{ BMAP_ATTRFORK,	"ATTR" }, \
	{ BMAP_COWFORK,		"COW" }


/*
 * Return true if the extent is a real, allocated extent, or false if it is  a
 * delayed allocation, and unwritten extent or a hole.
 */
static inline bool scxfs_bmap_is_real_extent(struct scxfs_bmbt_irec *irec)
{
	return irec->br_state != SCXFS_EXT_UNWRITTEN &&
		irec->br_startblock != HOLESTARTBLOCK &&
		irec->br_startblock != DELAYSTARTBLOCK &&
		!isnullstartblock(irec->br_startblock);
}

/*
 * Check the mapping for obviously garbage allocations that could trash the
 * filesystem immediately.
 */
#define scxfs_valid_startblock(ip, startblock) \
	((startblock) != 0 || SCXFS_IS_REALTIME_INODE(ip))

void	scxfs_trim_extent(struct scxfs_bmbt_irec *irec, scxfs_fileoff_t bno,
		scxfs_filblks_t len);
int	scxfs_bmap_add_attrfork(struct scxfs_inode *ip, int size, int rsvd);
int	scxfs_bmap_set_attrforkoff(struct scxfs_inode *ip, int size, int *version);
void	scxfs_bmap_local_to_extents_empty(struct scxfs_trans *tp,
		struct scxfs_inode *ip, int whichfork);
void	__scxfs_bmap_add_free(struct scxfs_trans *tp, scxfs_fsblock_t bno,
		scxfs_filblks_t len, const struct scxfs_owner_info *oinfo,
		bool skip_discard);
void	scxfs_bmap_compute_maxlevels(struct scxfs_mount *mp, int whichfork);
int	scxfs_bmap_first_unused(struct scxfs_trans *tp, struct scxfs_inode *ip,
		scxfs_extlen_t len, scxfs_fileoff_t *unused, int whichfork);
int	scxfs_bmap_last_before(struct scxfs_trans *tp, struct scxfs_inode *ip,
		scxfs_fileoff_t *last_block, int whichfork);
int	scxfs_bmap_last_offset(struct scxfs_inode *ip, scxfs_fileoff_t *unused,
		int whichfork);
int	scxfs_bmap_one_block(struct scxfs_inode *ip, int whichfork);
int	scxfs_bmapi_read(struct scxfs_inode *ip, scxfs_fileoff_t bno,
		scxfs_filblks_t len, struct scxfs_bmbt_irec *mval,
		int *nmap, int flags);
int	scxfs_bmapi_write(struct scxfs_trans *tp, struct scxfs_inode *ip,
		scxfs_fileoff_t bno, scxfs_filblks_t len, int flags,
		scxfs_extlen_t total, struct scxfs_bmbt_irec *mval, int *nmap);
int	__scxfs_bunmapi(struct scxfs_trans *tp, struct scxfs_inode *ip,
		scxfs_fileoff_t bno, scxfs_filblks_t *rlen, int flags,
		scxfs_extnum_t nexts);
int	scxfs_bunmapi(struct scxfs_trans *tp, struct scxfs_inode *ip,
		scxfs_fileoff_t bno, scxfs_filblks_t len, int flags,
		scxfs_extnum_t nexts, int *done);
int	scxfs_bmap_del_extent_delay(struct scxfs_inode *ip, int whichfork,
		struct scxfs_iext_cursor *cur, struct scxfs_bmbt_irec *got,
		struct scxfs_bmbt_irec *del);
void	scxfs_bmap_del_extent_cow(struct scxfs_inode *ip,
		struct scxfs_iext_cursor *cur, struct scxfs_bmbt_irec *got,
		struct scxfs_bmbt_irec *del);
uint	scxfs_default_attroffset(struct scxfs_inode *ip);
int	scxfs_bmap_collapse_extents(struct scxfs_trans *tp, struct scxfs_inode *ip,
		scxfs_fileoff_t *next_fsb, scxfs_fileoff_t offset_shift_fsb,
		bool *done);
int	scxfs_bmap_can_insert_extents(struct scxfs_inode *ip, scxfs_fileoff_t off,
		scxfs_fileoff_t shift);
int	scxfs_bmap_insert_extents(struct scxfs_trans *tp, struct scxfs_inode *ip,
		scxfs_fileoff_t *next_fsb, scxfs_fileoff_t offset_shift_fsb,
		bool *done, scxfs_fileoff_t stop_fsb);
int	scxfs_bmap_split_extent(struct scxfs_inode *ip, scxfs_fileoff_t split_offset);
int	scxfs_bmapi_reserve_delalloc(struct scxfs_inode *ip, int whichfork,
		scxfs_fileoff_t off, scxfs_filblks_t len, scxfs_filblks_t prealloc,
		struct scxfs_bmbt_irec *got, struct scxfs_iext_cursor *cur,
		int eof);
int	scxfs_bmapi_convert_delalloc(struct scxfs_inode *ip, int whichfork,
		scxfs_fileoff_t offset_fsb, struct scxfs_bmbt_irec *imap,
		unsigned int *seq);
int	scxfs_bmap_add_extent_unwritten_real(struct scxfs_trans *tp,
		struct scxfs_inode *ip, int whichfork,
		struct scxfs_iext_cursor *icur, struct scxfs_btree_cur **curp,
		struct scxfs_bmbt_irec *new, int *logflagsp);

static inline void
scxfs_bmap_add_free(
	struct scxfs_trans		*tp,
	scxfs_fsblock_t			bno,
	scxfs_filblks_t			len,
	const struct scxfs_owner_info	*oinfo)
{
	__scxfs_bmap_add_free(tp, bno, len, oinfo, false);
}

enum scxfs_bmap_intent_type {
	SCXFS_BMAP_MAP = 1,
	SCXFS_BMAP_UNMAP,
};

struct scxfs_bmap_intent {
	struct list_head			bi_list;
	enum scxfs_bmap_intent_type		bi_type;
	struct scxfs_inode			*bi_owner;
	int					bi_whichfork;
	struct scxfs_bmbt_irec			bi_bmap;
};

int	scxfs_bmap_finish_one(struct scxfs_trans *tp, struct scxfs_inode *ip,
		enum scxfs_bmap_intent_type type, int whichfork,
		scxfs_fileoff_t startoff, scxfs_fsblock_t startblock,
		scxfs_filblks_t *blockcount, scxfs_exntst_t state);
void	scxfs_bmap_map_extent(struct scxfs_trans *tp, struct scxfs_inode *ip,
		struct scxfs_bmbt_irec *imap);
void	scxfs_bmap_unmap_extent(struct scxfs_trans *tp, struct scxfs_inode *ip,
		struct scxfs_bmbt_irec *imap);

static inline int scxfs_bmap_fork_to_state(int whichfork)
{
	switch (whichfork) {
	case SCXFS_ATTR_FORK:
		return BMAP_ATTRFORK;
	case SCXFS_COW_FORK:
		return BMAP_COWFORK;
	default:
		return 0;
	}
}

scxfs_failaddr_t scxfs_bmap_validate_extent(struct scxfs_inode *ip, int whichfork,
		struct scxfs_bmbt_irec *irec);

int	scxfs_bmapi_remap(struct scxfs_trans *tp, struct scxfs_inode *ip,
		scxfs_fileoff_t bno, scxfs_filblks_t len, scxfs_fsblock_t startblock,
		int flags);

#endif	/* __SCXFS_BMAP_H__ */
