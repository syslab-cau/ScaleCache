// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2016 Oracle.  All Rights Reserved.
 * Author: Darrick J. Wong <darrick.wong@oracle.com>
 */
#ifndef __SCXFS_RMAP_H__
#define __SCXFS_RMAP_H__

static inline void
scxfs_rmap_ino_bmbt_owner(
	struct scxfs_owner_info	*oi,
	scxfs_ino_t		ino,
	int			whichfork)
{
	oi->oi_owner = ino;
	oi->oi_offset = 0;
	oi->oi_flags = SCXFS_OWNER_INFO_BMBT_BLOCK;
	if (whichfork == SCXFS_ATTR_FORK)
		oi->oi_flags |= SCXFS_OWNER_INFO_ATTR_FORK;
}

static inline void
scxfs_rmap_ino_owner(
	struct scxfs_owner_info	*oi,
	scxfs_ino_t		ino,
	int			whichfork,
	scxfs_fileoff_t		offset)
{
	oi->oi_owner = ino;
	oi->oi_offset = offset;
	oi->oi_flags = 0;
	if (whichfork == SCXFS_ATTR_FORK)
		oi->oi_flags |= SCXFS_OWNER_INFO_ATTR_FORK;
}

static inline bool
scxfs_rmap_should_skip_owner_update(
	const struct scxfs_owner_info	*oi)
{
	return oi->oi_owner == SCXFS_RMAP_OWN_NULL;
}

/* Reverse mapping functions. */

struct scxfs_buf;

static inline __u64
scxfs_rmap_irec_offset_pack(
	const struct scxfs_rmap_irec	*irec)
{
	__u64			x;

	x = SCXFS_RMAP_OFF(irec->rm_offset);
	if (irec->rm_flags & SCXFS_RMAP_ATTR_FORK)
		x |= SCXFS_RMAP_OFF_ATTR_FORK;
	if (irec->rm_flags & SCXFS_RMAP_BMBT_BLOCK)
		x |= SCXFS_RMAP_OFF_BMBT_BLOCK;
	if (irec->rm_flags & SCXFS_RMAP_UNWRITTEN)
		x |= SCXFS_RMAP_OFF_UNWRITTEN;
	return x;
}

static inline int
scxfs_rmap_irec_offset_unpack(
	__u64			offset,
	struct scxfs_rmap_irec	*irec)
{
	if (offset & ~(SCXFS_RMAP_OFF_MASK | SCXFS_RMAP_OFF_FLAGS))
		return -EFSCORRUPTED;
	irec->rm_offset = SCXFS_RMAP_OFF(offset);
	irec->rm_flags = 0;
	if (offset & SCXFS_RMAP_OFF_ATTR_FORK)
		irec->rm_flags |= SCXFS_RMAP_ATTR_FORK;
	if (offset & SCXFS_RMAP_OFF_BMBT_BLOCK)
		irec->rm_flags |= SCXFS_RMAP_BMBT_BLOCK;
	if (offset & SCXFS_RMAP_OFF_UNWRITTEN)
		irec->rm_flags |= SCXFS_RMAP_UNWRITTEN;
	return 0;
}

static inline void
scxfs_owner_info_unpack(
	const struct scxfs_owner_info	*oinfo,
	uint64_t			*owner,
	uint64_t			*offset,
	unsigned int			*flags)
{
	unsigned int			r = 0;

	*owner = oinfo->oi_owner;
	*offset = oinfo->oi_offset;
	if (oinfo->oi_flags & SCXFS_OWNER_INFO_ATTR_FORK)
		r |= SCXFS_RMAP_ATTR_FORK;
	if (oinfo->oi_flags & SCXFS_OWNER_INFO_BMBT_BLOCK)
		r |= SCXFS_RMAP_BMBT_BLOCK;
	*flags = r;
}

static inline void
scxfs_owner_info_pack(
	struct scxfs_owner_info	*oinfo,
	uint64_t		owner,
	uint64_t		offset,
	unsigned int		flags)
{
	oinfo->oi_owner = owner;
	oinfo->oi_offset = SCXFS_RMAP_OFF(offset);
	oinfo->oi_flags = 0;
	if (flags & SCXFS_RMAP_ATTR_FORK)
		oinfo->oi_flags |= SCXFS_OWNER_INFO_ATTR_FORK;
	if (flags & SCXFS_RMAP_BMBT_BLOCK)
		oinfo->oi_flags |= SCXFS_OWNER_INFO_BMBT_BLOCK;
}

int scxfs_rmap_alloc(struct scxfs_trans *tp, struct scxfs_buf *agbp,
		   scxfs_agnumber_t agno, scxfs_agblock_t bno, scxfs_extlen_t len,
		   const struct scxfs_owner_info *oinfo);
int scxfs_rmap_free(struct scxfs_trans *tp, struct scxfs_buf *agbp,
		  scxfs_agnumber_t agno, scxfs_agblock_t bno, scxfs_extlen_t len,
		  const struct scxfs_owner_info *oinfo);

int scxfs_rmap_lookup_le(struct scxfs_btree_cur *cur, scxfs_agblock_t bno,
		scxfs_extlen_t len, uint64_t owner, uint64_t offset,
		unsigned int flags, int *stat);
int scxfs_rmap_lookup_eq(struct scxfs_btree_cur *cur, scxfs_agblock_t bno,
		scxfs_extlen_t len, uint64_t owner, uint64_t offset,
		unsigned int flags, int *stat);
int scxfs_rmap_insert(struct scxfs_btree_cur *rcur, scxfs_agblock_t agbno,
		scxfs_extlen_t len, uint64_t owner, uint64_t offset,
		unsigned int flags);
int scxfs_rmap_get_rec(struct scxfs_btree_cur *cur, struct scxfs_rmap_irec *irec,
		int *stat);

typedef int (*scxfs_rmap_query_range_fn)(
	struct scxfs_btree_cur	*cur,
	struct scxfs_rmap_irec	*rec,
	void			*priv);

int scxfs_rmap_query_range(struct scxfs_btree_cur *cur,
		struct scxfs_rmap_irec *low_rec, struct scxfs_rmap_irec *high_rec,
		scxfs_rmap_query_range_fn fn, void *priv);
int scxfs_rmap_query_all(struct scxfs_btree_cur *cur, scxfs_rmap_query_range_fn fn,
		void *priv);

enum scxfs_rmap_intent_type {
	SCXFS_RMAP_MAP,
	SCXFS_RMAP_MAP_SHARED,
	SCXFS_RMAP_UNMAP,
	SCXFS_RMAP_UNMAP_SHARED,
	SCXFS_RMAP_CONVERT,
	SCXFS_RMAP_CONVERT_SHARED,
	SCXFS_RMAP_ALLOC,
	SCXFS_RMAP_FREE,
};

struct scxfs_rmap_intent {
	struct list_head			ri_list;
	enum scxfs_rmap_intent_type		ri_type;
	uint64_t				ri_owner;
	int					ri_whichfork;
	struct scxfs_bmbt_irec			ri_bmap;
};

/* functions for updating the rmapbt based on bmbt map/unmap operations */
void scxfs_rmap_map_extent(struct scxfs_trans *tp, struct scxfs_inode *ip,
		int whichfork, struct scxfs_bmbt_irec *imap);
void scxfs_rmap_unmap_extent(struct scxfs_trans *tp, struct scxfs_inode *ip,
		int whichfork, struct scxfs_bmbt_irec *imap);
void scxfs_rmap_convert_extent(struct scxfs_mount *mp, struct scxfs_trans *tp,
		struct scxfs_inode *ip, int whichfork,
		struct scxfs_bmbt_irec *imap);
void scxfs_rmap_alloc_extent(struct scxfs_trans *tp, scxfs_agnumber_t agno,
		scxfs_agblock_t bno, scxfs_extlen_t len, uint64_t owner);
void scxfs_rmap_free_extent(struct scxfs_trans *tp, scxfs_agnumber_t agno,
		scxfs_agblock_t bno, scxfs_extlen_t len, uint64_t owner);

void scxfs_rmap_finish_one_cleanup(struct scxfs_trans *tp,
		struct scxfs_btree_cur *rcur, int error);
int scxfs_rmap_finish_one(struct scxfs_trans *tp, enum scxfs_rmap_intent_type type,
		uint64_t owner, int whichfork, scxfs_fileoff_t startoff,
		scxfs_fsblock_t startblock, scxfs_filblks_t blockcount,
		scxfs_exntst_t state, struct scxfs_btree_cur **pcur);

int scxfs_rmap_find_left_neighbor(struct scxfs_btree_cur *cur, scxfs_agblock_t bno,
		uint64_t owner, uint64_t offset, unsigned int flags,
		struct scxfs_rmap_irec *irec, int	*stat);
int scxfs_rmap_lookup_le_range(struct scxfs_btree_cur *cur, scxfs_agblock_t bno,
		uint64_t owner, uint64_t offset, unsigned int flags,
		struct scxfs_rmap_irec *irec, int	*stat);
int scxfs_rmap_compare(const struct scxfs_rmap_irec *a,
		const struct scxfs_rmap_irec *b);
union scxfs_btree_rec;
int scxfs_rmap_btrec_to_irec(union scxfs_btree_rec *rec,
		struct scxfs_rmap_irec *irec);
int scxfs_rmap_has_record(struct scxfs_btree_cur *cur, scxfs_agblock_t bno,
		scxfs_extlen_t len, bool *exists);
int scxfs_rmap_record_exists(struct scxfs_btree_cur *cur, scxfs_agblock_t bno,
		scxfs_extlen_t len, const struct scxfs_owner_info *oinfo,
		bool *has_rmap);
int scxfs_rmap_has_other_keys(struct scxfs_btree_cur *cur, scxfs_agblock_t bno,
		scxfs_extlen_t len, const struct scxfs_owner_info *oinfo,
		bool *has_rmap);
int scxfs_rmap_map_raw(struct scxfs_btree_cur *cur, struct scxfs_rmap_irec *rmap);

extern const struct scxfs_owner_info SCXFS_RMAP_OINFO_SKIP_UPDATE;
extern const struct scxfs_owner_info SCXFS_RMAP_OINFO_ANY_OWNER;
extern const struct scxfs_owner_info SCXFS_RMAP_OINFO_FS;
extern const struct scxfs_owner_info SCXFS_RMAP_OINFO_LOG;
extern const struct scxfs_owner_info SCXFS_RMAP_OINFO_AG;
extern const struct scxfs_owner_info SCXFS_RMAP_OINFO_INOBT;
extern const struct scxfs_owner_info SCXFS_RMAP_OINFO_INODES;
extern const struct scxfs_owner_info SCXFS_RMAP_OINFO_REFC;
extern const struct scxfs_owner_info SCXFS_RMAP_OINFO_COW;

#endif	/* __SCXFS_RMAP_H__ */
