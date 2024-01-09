// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2016 Oracle.  All Rights Reserved.
 * Author: Darrick J. Wong <darrick.wong@oracle.com>
 */
#ifndef __SCXFS_REFCOUNT_H__
#define __SCXFS_REFCOUNT_H__

extern int scxfs_refcount_lookup_le(struct scxfs_btree_cur *cur,
		scxfs_agblock_t bno, int *stat);
extern int scxfs_refcount_lookup_ge(struct scxfs_btree_cur *cur,
		scxfs_agblock_t bno, int *stat);
extern int scxfs_refcount_lookup_eq(struct scxfs_btree_cur *cur,
		scxfs_agblock_t bno, int *stat);
extern int scxfs_refcount_get_rec(struct scxfs_btree_cur *cur,
		struct scxfs_refcount_irec *irec, int *stat);

enum scxfs_refcount_intent_type {
	SCXFS_REFCOUNT_INCREASE = 1,
	SCXFS_REFCOUNT_DECREASE,
	SCXFS_REFCOUNT_ALLOC_COW,
	SCXFS_REFCOUNT_FREE_COW,
};

struct scxfs_refcount_intent {
	struct list_head			ri_list;
	enum scxfs_refcount_intent_type		ri_type;
	scxfs_fsblock_t				ri_startblock;
	scxfs_extlen_t				ri_blockcount;
};

void scxfs_refcount_increase_extent(struct scxfs_trans *tp,
		struct scxfs_bmbt_irec *irec);
void scxfs_refcount_decrease_extent(struct scxfs_trans *tp,
		struct scxfs_bmbt_irec *irec);

extern void scxfs_refcount_finish_one_cleanup(struct scxfs_trans *tp,
		struct scxfs_btree_cur *rcur, int error);
extern int scxfs_refcount_finish_one(struct scxfs_trans *tp,
		enum scxfs_refcount_intent_type type, scxfs_fsblock_t startblock,
		scxfs_extlen_t blockcount, scxfs_fsblock_t *new_fsb,
		scxfs_extlen_t *new_len, struct scxfs_btree_cur **pcur);

extern int scxfs_refcount_find_shared(struct scxfs_btree_cur *cur,
		scxfs_agblock_t agbno, scxfs_extlen_t aglen, scxfs_agblock_t *fbno,
		scxfs_extlen_t *flen, bool find_end_of_shared);

void scxfs_refcount_alloc_cow_extent(struct scxfs_trans *tp, scxfs_fsblock_t fsb,
		scxfs_extlen_t len);
void scxfs_refcount_free_cow_extent(struct scxfs_trans *tp, scxfs_fsblock_t fsb,
		scxfs_extlen_t len);
extern int scxfs_refcount_recover_cow_leftovers(struct scxfs_mount *mp,
		scxfs_agnumber_t agno);

/*
 * While we're adjusting the refcounts records of an extent, we have
 * to keep an eye on the number of extents we're dirtying -- run too
 * many in a single transaction and we'll exceed the transaction's
 * reservation and crash the fs.  Each record adds 12 bytes to the
 * log (plus any key updates) so we'll conservatively assume 32 bytes
 * per record.  We must also leave space for btree splits on both ends
 * of the range and space for the CUD and a new CUI.
 */
#define SCXFS_REFCOUNT_ITEM_OVERHEAD	32

static inline scxfs_fileoff_t scxfs_refcount_max_unmap(int log_res)
{
	return (log_res * 3 / 4) / SCXFS_REFCOUNT_ITEM_OVERHEAD;
}

extern int scxfs_refcount_has_record(struct scxfs_btree_cur *cur,
		scxfs_agblock_t bno, scxfs_extlen_t len, bool *exists);
union scxfs_btree_rec;
extern void scxfs_refcount_btrec_to_irec(union scxfs_btree_rec *rec,
		struct scxfs_refcount_irec *irec);
extern int scxfs_refcount_insert(struct scxfs_btree_cur *cur,
		struct scxfs_refcount_irec *irec, int *stat);

#endif	/* __SCXFS_REFCOUNT_H__ */
