// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2018 Oracle.  All Rights Reserved.
 * Author: Darrick J. Wong <darrick.wong@oracle.com>
 */
#ifndef __SCXFS_SCRUB_BITMAP_H__
#define __SCXFS_SCRUB_BITMAP_H__

struct scxfs_bitmap_range {
	struct list_head	list;
	uint64_t		start;
	uint64_t		len;
};

struct scxfs_bitmap {
	struct list_head	list;
};

void scxfs_bitmap_init(struct scxfs_bitmap *bitmap);
void scxfs_bitmap_destroy(struct scxfs_bitmap *bitmap);

#define for_each_scxfs_bitmap_extent(bex, n, bitmap) \
	list_for_each_entry_safe((bex), (n), &(bitmap)->list, list)

#define for_each_scxfs_bitmap_block(b, bex, n, bitmap) \
	list_for_each_entry_safe((bex), (n), &(bitmap)->list, list) \
		for ((b) = bex->start; (b) < bex->start + bex->len; (b)++)

int scxfs_bitmap_set(struct scxfs_bitmap *bitmap, uint64_t start, uint64_t len);
int scxfs_bitmap_disunion(struct scxfs_bitmap *bitmap, struct scxfs_bitmap *sub);
int scxfs_bitmap_set_btcur_path(struct scxfs_bitmap *bitmap,
		struct scxfs_btree_cur *cur);
int scxfs_bitmap_set_btblocks(struct scxfs_bitmap *bitmap,
		struct scxfs_btree_cur *cur);

#endif	/* __SCXFS_SCRUB_BITMAP_H__ */
