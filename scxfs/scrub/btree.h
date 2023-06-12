// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2017 Oracle.  All Rights Reserved.
 * Author: Darrick J. Wong <darrick.wong@oracle.com>
 */
#ifndef __SCXFS_SCRUB_BTREE_H__
#define __SCXFS_SCRUB_BTREE_H__

/* btree scrub */

/* Check for btree operation errors. */
bool xchk_btree_process_error(struct scxfs_scrub *sc,
		struct scxfs_btree_cur *cur, int level, int *error);

/* Check for btree xref operation errors. */
bool xchk_btree_xref_process_error(struct scxfs_scrub *sc,
		struct scxfs_btree_cur *cur, int level, int *error);

/* Check for btree corruption. */
void xchk_btree_set_corrupt(struct scxfs_scrub *sc,
		struct scxfs_btree_cur *cur, int level);

/* Check for btree xref discrepancies. */
void xchk_btree_xref_set_corrupt(struct scxfs_scrub *sc,
		struct scxfs_btree_cur *cur, int level);

struct xchk_btree;
typedef int (*xchk_btree_rec_fn)(
	struct xchk_btree	*bs,
	union scxfs_btree_rec	*rec);

struct xchk_btree {
	/* caller-provided scrub state */
	struct scxfs_scrub		*sc;
	struct scxfs_btree_cur		*cur;
	xchk_btree_rec_fn		scrub_rec;
	const struct scxfs_owner_info	*oinfo;
	void				*private;

	/* internal scrub state */
	union scxfs_btree_rec		lastrec;
	bool				firstrec;
	union scxfs_btree_key		lastkey[SCXFS_BTREE_MAXLEVELS];
	bool				firstkey[SCXFS_BTREE_MAXLEVELS];
	struct list_head		to_check;
};
int xchk_btree(struct scxfs_scrub *sc, struct scxfs_btree_cur *cur,
		xchk_btree_rec_fn scrub_fn, const struct scxfs_owner_info *oinfo,
		void *private);

#endif /* __SCXFS_SCRUB_BTREE_H__ */
