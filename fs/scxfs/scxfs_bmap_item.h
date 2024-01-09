// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2016 Oracle.  All Rights Reserved.
 * Author: Darrick J. Wong <darrick.wong@oracle.com>
 */
#ifndef	__SCXFS_BMAP_ITEM_H__
#define	__SCXFS_BMAP_ITEM_H__

/*
 * There are (currently) two pairs of bmap btree redo item types: map & unmap.
 * The common abbreviations for these are BUI (bmap update intent) and BUD
 * (bmap update done).  The redo item type is encoded in the flags field of
 * each scxfs_map_extent.
 *
 * *I items should be recorded in the *first* of a series of rolled
 * transactions, and the *D items should be recorded in the same transaction
 * that records the associated bmbt updates.
 *
 * Should the system crash after the commit of the first transaction but
 * before the commit of the final transaction in a series, log recovery will
 * use the redo information recorded by the intent items to replay the
 * bmbt metadata updates in the non-first transaction.
 */

/* kernel only BUI/BUD definitions */

struct scxfs_mount;
struct kmem_zone;

/*
 * Max number of extents in fast allocation path.
 */
#define	SCXFS_BUI_MAX_FAST_EXTENTS	1

/*
 * Define BUI flag bits. Manipulated by set/clear/test_bit operators.
 */
#define	SCXFS_BUI_RECOVERED		1

/*
 * This is the "bmap update intent" log item.  It is used to log the fact that
 * some reverse mappings need to change.  It is used in conjunction with the
 * "bmap update done" log item described below.
 *
 * These log items follow the same rules as struct scxfs_efi_log_item; see the
 * comments about that structure (in scxfs_extfree_item.h) for more details.
 */
struct scxfs_bui_log_item {
	struct scxfs_log_item		bui_item;
	atomic_t			bui_refcount;
	atomic_t			bui_next_extent;
	unsigned long			bui_flags;	/* misc flags */
	struct scxfs_bui_log_format	bui_format;
};

static inline size_t
scxfs_bui_log_item_sizeof(
	unsigned int		nr)
{
	return offsetof(struct scxfs_bui_log_item, bui_format) +
			scxfs_bui_log_format_sizeof(nr);
}

/*
 * This is the "bmap update done" log item.  It is used to log the fact that
 * some bmbt updates mentioned in an earlier bui item have been performed.
 */
struct scxfs_bud_log_item {
	struct scxfs_log_item		bud_item;
	struct scxfs_bui_log_item		*bud_buip;
	struct scxfs_bud_log_format	bud_format;
};

extern struct kmem_zone	*scxfs_bui_zone;
extern struct kmem_zone	*scxfs_bud_zone;

struct scxfs_bui_log_item *scxfs_bui_init(struct scxfs_mount *);
void scxfs_bui_item_free(struct scxfs_bui_log_item *);
void scxfs_bui_release(struct scxfs_bui_log_item *);
int scxfs_bui_recover(struct scxfs_trans *parent_tp, struct scxfs_bui_log_item *buip);

#endif	/* __SCXFS_BMAP_ITEM_H__ */
