// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2017 Oracle.  All Rights Reserved.
 *
 * Author: Darrick J. Wong <darrick.wong@oracle.com>
 */
#include "scext4.h"
#include <linux/fsmap.h>
#include "fsmap.h"
#include "mballoc.h"
#include <linux/sort.h>
#include <linux/list_sort.h>
#include <trace/events/scext4.h>

/* Convert an scext4_fsmap to an fsmap. */
void scext4_fsmap_from_internal(struct super_block *sb, struct fsmap *dest,
			      struct scext4_fsmap *src)
{
	dest->fmr_device = src->fmr_device;
	dest->fmr_flags = src->fmr_flags;
	dest->fmr_physical = src->fmr_physical << sb->s_blocksize_bits;
	dest->fmr_owner = src->fmr_owner;
	dest->fmr_offset = 0;
	dest->fmr_length = src->fmr_length << sb->s_blocksize_bits;
	dest->fmr_reserved[0] = 0;
	dest->fmr_reserved[1] = 0;
	dest->fmr_reserved[2] = 0;
}

/* Convert an fsmap to an scext4_fsmap. */
void scext4_fsmap_to_internal(struct super_block *sb, struct scext4_fsmap *dest,
			    struct fsmap *src)
{
	dest->fmr_device = src->fmr_device;
	dest->fmr_flags = src->fmr_flags;
	dest->fmr_physical = src->fmr_physical >> sb->s_blocksize_bits;
	dest->fmr_owner = src->fmr_owner;
	dest->fmr_length = src->fmr_length >> sb->s_blocksize_bits;
}

/* getfsmap query state */
struct scext4_getfsmap_info {
	struct scext4_fsmap_head	*gfi_head;
	scext4_fsmap_format_t	gfi_formatter;	/* formatting fn */
	void			*gfi_format_arg;/* format buffer */
	scext4_fsblk_t		gfi_next_fsblk;	/* next fsblock we expect */
	u32			gfi_dev;	/* device id */
	scext4_group_t		gfi_agno;	/* bg number, if applicable */
	struct scext4_fsmap	gfi_low;	/* low rmap key */
	struct scext4_fsmap	gfi_high;	/* high rmap key */
	struct scext4_fsmap	gfi_lastfree;	/* free ext at end of last bg */
	struct list_head	gfi_meta_list;	/* fixed metadata list */
	bool			gfi_last;	/* last extent? */
};

/* Associate a device with a getfsmap handler. */
struct scext4_getfsmap_dev {
	int			(*gfd_fn)(struct super_block *sb,
				      struct scext4_fsmap *keys,
				      struct scext4_getfsmap_info *info);
	u32			gfd_dev;
};

/* Compare two getfsmap device handlers. */
static int scext4_getfsmap_dev_compare(const void *p1, const void *p2)
{
	const struct scext4_getfsmap_dev *d1 = p1;
	const struct scext4_getfsmap_dev *d2 = p2;

	return d1->gfd_dev - d2->gfd_dev;
}

/* Compare a record against our starting point */
static bool scext4_getfsmap_rec_before_low_key(struct scext4_getfsmap_info *info,
					     struct scext4_fsmap *rec)
{
	return rec->fmr_physical < info->gfi_low.fmr_physical;
}

/*
 * Format a reverse mapping for getfsmap, having translated rm_startblock
 * into the appropriate daddr units.
 */
static int scext4_getfsmap_helper(struct super_block *sb,
				struct scext4_getfsmap_info *info,
				struct scext4_fsmap *rec)
{
	struct scext4_fsmap fmr;
	struct scext4_sb_info *sbi = SCEXT4_SB(sb);
	scext4_fsblk_t rec_fsblk = rec->fmr_physical;
	scext4_group_t agno;
	scext4_grpblk_t cno;
	int error;

	if (fatal_signal_pending(current))
		return -EINTR;

	/*
	 * Filter out records that start before our startpoint, if the
	 * caller requested that.
	 */
	if (scext4_getfsmap_rec_before_low_key(info, rec)) {
		rec_fsblk += rec->fmr_length;
		if (info->gfi_next_fsblk < rec_fsblk)
			info->gfi_next_fsblk = rec_fsblk;
		return SCEXT4_QUERY_RANGE_CONTINUE;
	}

	/* Are we just counting mappings? */
	if (info->gfi_head->fmh_count == 0) {
		if (info->gfi_head->fmh_entries == UINT_MAX)
			return SCEXT4_QUERY_RANGE_ABORT;

		if (rec_fsblk > info->gfi_next_fsblk)
			info->gfi_head->fmh_entries++;

		if (info->gfi_last)
			return SCEXT4_QUERY_RANGE_CONTINUE;

		info->gfi_head->fmh_entries++;

		rec_fsblk += rec->fmr_length;
		if (info->gfi_next_fsblk < rec_fsblk)
			info->gfi_next_fsblk = rec_fsblk;
		return SCEXT4_QUERY_RANGE_CONTINUE;
	}

	/*
	 * If the record starts past the last physical block we saw,
	 * then we've found a gap.  Report the gap as being owned by
	 * whatever the caller specified is the missing owner.
	 */
	if (rec_fsblk > info->gfi_next_fsblk) {
		if (info->gfi_head->fmh_entries >= info->gfi_head->fmh_count)
			return SCEXT4_QUERY_RANGE_ABORT;

		scext4_get_group_no_and_offset(sb, info->gfi_next_fsblk,
				&agno, &cno);
		trace_scext4_fsmap_mapping(sb, info->gfi_dev, agno,
				SCEXT4_C2B(sbi, cno),
				rec_fsblk - info->gfi_next_fsblk,
				SCEXT4_FMR_OWN_UNKNOWN);

		fmr.fmr_device = info->gfi_dev;
		fmr.fmr_physical = info->gfi_next_fsblk;
		fmr.fmr_owner = SCEXT4_FMR_OWN_UNKNOWN;
		fmr.fmr_length = rec_fsblk - info->gfi_next_fsblk;
		fmr.fmr_flags = FMR_OF_SPECIAL_OWNER;
		error = info->gfi_formatter(&fmr, info->gfi_format_arg);
		if (error)
			return error;
		info->gfi_head->fmh_entries++;
	}

	if (info->gfi_last)
		goto out;

	/* Fill out the extent we found */
	if (info->gfi_head->fmh_entries >= info->gfi_head->fmh_count)
		return SCEXT4_QUERY_RANGE_ABORT;

	scext4_get_group_no_and_offset(sb, rec_fsblk, &agno, &cno);
	trace_scext4_fsmap_mapping(sb, info->gfi_dev, agno, SCEXT4_C2B(sbi, cno),
			rec->fmr_length, rec->fmr_owner);

	fmr.fmr_device = info->gfi_dev;
	fmr.fmr_physical = rec_fsblk;
	fmr.fmr_owner = rec->fmr_owner;
	fmr.fmr_flags = FMR_OF_SPECIAL_OWNER;
	fmr.fmr_length = rec->fmr_length;
	error = info->gfi_formatter(&fmr, info->gfi_format_arg);
	if (error)
		return error;
	info->gfi_head->fmh_entries++;

out:
	rec_fsblk += rec->fmr_length;
	if (info->gfi_next_fsblk < rec_fsblk)
		info->gfi_next_fsblk = rec_fsblk;
	return SCEXT4_QUERY_RANGE_CONTINUE;
}

static inline scext4_fsblk_t scext4_fsmap_next_pblk(struct scext4_fsmap *fmr)
{
	return fmr->fmr_physical + fmr->fmr_length;
}

/* Transform a blockgroup's free record into a fsmap */
static int scext4_getfsmap_datadev_helper(struct super_block *sb,
					scext4_group_t agno, scext4_grpblk_t start,
					scext4_grpblk_t len, void *priv)
{
	struct scext4_fsmap irec;
	struct scext4_getfsmap_info *info = priv;
	struct scext4_fsmap *p;
	struct scext4_fsmap *tmp;
	struct scext4_sb_info *sbi = SCEXT4_SB(sb);
	scext4_fsblk_t fsb;
	scext4_fsblk_t fslen;
	int error;

	fsb = (SCEXT4_C2B(sbi, start) + scext4_group_first_block_no(sb, agno));
	fslen = SCEXT4_C2B(sbi, len);

	/* If the retained free extent record is set... */
	if (info->gfi_lastfree.fmr_owner) {
		/* ...and abuts this one, lengthen it and return. */
		if (scext4_fsmap_next_pblk(&info->gfi_lastfree) == fsb) {
			info->gfi_lastfree.fmr_length += fslen;
			return 0;
		}

		/*
		 * There's a gap between the two free extents; emit the
		 * retained extent prior to merging the meta_list.
		 */
		error = scext4_getfsmap_helper(sb, info, &info->gfi_lastfree);
		if (error)
			return error;
		info->gfi_lastfree.fmr_owner = 0;
	}

	/* Merge in any relevant extents from the meta_list */
	list_for_each_entry_safe(p, tmp, &info->gfi_meta_list, fmr_list) {
		if (p->fmr_physical + p->fmr_length <= info->gfi_next_fsblk) {
			list_del(&p->fmr_list);
			kfree(p);
		} else if (p->fmr_physical < fsb) {
			error = scext4_getfsmap_helper(sb, info, p);
			if (error)
				return error;

			list_del(&p->fmr_list);
			kfree(p);
		}
	}

	irec.fmr_device = 0;
	irec.fmr_physical = fsb;
	irec.fmr_length = fslen;
	irec.fmr_owner = SCEXT4_FMR_OWN_FREE;
	irec.fmr_flags = 0;

	/* If this is a free extent at the end of a bg, buffer it. */
	if (scext4_fsmap_next_pblk(&irec) ==
			scext4_group_first_block_no(sb, agno + 1)) {
		info->gfi_lastfree = irec;
		return 0;
	}

	/* Otherwise, emit it */
	return scext4_getfsmap_helper(sb, info, &irec);
}

/* Execute a getfsmap query against the log device. */
static int scext4_getfsmap_logdev(struct super_block *sb, struct scext4_fsmap *keys,
				struct scext4_getfsmap_info *info)
{
	journal_t *journal = SCEXT4_SB(sb)->s_journal;
	struct scext4_fsmap irec;

	/* Set up search keys */
	info->gfi_low = keys[0];
	info->gfi_low.fmr_length = 0;

	memset(&info->gfi_high, 0xFF, sizeof(info->gfi_high));

	trace_scext4_fsmap_low_key(sb, info->gfi_dev, 0,
			info->gfi_low.fmr_physical,
			info->gfi_low.fmr_length,
			info->gfi_low.fmr_owner);

	trace_scext4_fsmap_high_key(sb, info->gfi_dev, 0,
			info->gfi_high.fmr_physical,
			info->gfi_high.fmr_length,
			info->gfi_high.fmr_owner);

	if (keys[0].fmr_physical > 0)
		return 0;

	/* Fabricate an rmap entry for the external log device. */
	irec.fmr_physical = journal->j_blk_offset;
	irec.fmr_length = journal->j_maxlen;
	irec.fmr_owner = SCEXT4_FMR_OWN_LOG;
	irec.fmr_flags = 0;

	return scext4_getfsmap_helper(sb, info, &irec);
}

/* Helper to fill out an scext4_fsmap. */
static inline int scext4_getfsmap_fill(struct list_head *meta_list,
				     scext4_fsblk_t fsb, scext4_fsblk_t len,
				     uint64_t owner)
{
	struct scext4_fsmap *fsm;

	fsm = kmalloc(sizeof(*fsm), GFP_NOFS);
	if (!fsm)
		return -ENOMEM;
	fsm->fmr_device = 0;
	fsm->fmr_flags = 0;
	fsm->fmr_physical = fsb;
	fsm->fmr_owner = owner;
	fsm->fmr_length = len;
	list_add_tail(&fsm->fmr_list, meta_list);

	return 0;
}

/*
 * This function returns the number of file system metadata blocks at
 * the beginning of a block group, including the reserved gdt blocks.
 */
static unsigned int scext4_getfsmap_find_sb(struct super_block *sb,
					  scext4_group_t agno,
					  struct list_head *meta_list)
{
	struct scext4_sb_info *sbi = SCEXT4_SB(sb);
	scext4_fsblk_t fsb = scext4_group_first_block_no(sb, agno);
	scext4_fsblk_t len;
	unsigned long first_meta_bg = le32_to_cpu(sbi->s_es->s_first_meta_bg);
	unsigned long metagroup = agno / SCEXT4_DESC_PER_BLOCK(sb);
	int error;

	/* Record the superblock. */
	if (scext4_bg_has_super(sb, agno)) {
		error = scext4_getfsmap_fill(meta_list, fsb, 1, SCEXT4_FMR_OWN_FS);
		if (error)
			return error;
		fsb++;
	}

	/* Record the group descriptors. */
	len = scext4_bg_num_gdb(sb, agno);
	if (!len)
		return 0;
	error = scext4_getfsmap_fill(meta_list, fsb, len,
				   SCEXT4_FMR_OWN_GDT);
	if (error)
		return error;
	fsb += len;

	/* Reserved GDT blocks */
	if (!scext4_has_feature_meta_bg(sb) || metagroup < first_meta_bg) {
		len = le16_to_cpu(sbi->s_es->s_reserved_gdt_blocks);
		error = scext4_getfsmap_fill(meta_list, fsb, len,
					   SCEXT4_FMR_OWN_RESV_GDT);
		if (error)
			return error;
	}

	return 0;
}

/* Compare two fsmap items. */
static int scext4_getfsmap_compare(void *priv,
				 struct list_head *a,
				 struct list_head *b)
{
	struct scext4_fsmap *fa;
	struct scext4_fsmap *fb;

	fa = container_of(a, struct scext4_fsmap, fmr_list);
	fb = container_of(b, struct scext4_fsmap, fmr_list);
	if (fa->fmr_physical < fb->fmr_physical)
		return -1;
	else if (fa->fmr_physical > fb->fmr_physical)
		return 1;
	return 0;
}

/* Merge adjacent extents of fixed metadata. */
static void scext4_getfsmap_merge_fixed_metadata(struct list_head *meta_list)
{
	struct scext4_fsmap *p;
	struct scext4_fsmap *prev = NULL;
	struct scext4_fsmap *tmp;

	list_for_each_entry_safe(p, tmp, meta_list, fmr_list) {
		if (!prev) {
			prev = p;
			continue;
		}

		if (prev->fmr_owner == p->fmr_owner &&
		    prev->fmr_physical + prev->fmr_length == p->fmr_physical) {
			prev->fmr_length += p->fmr_length;
			list_del(&p->fmr_list);
			kfree(p);
		} else
			prev = p;
	}
}

/* Free a list of fixed metadata. */
static void scext4_getfsmap_free_fixed_metadata(struct list_head *meta_list)
{
	struct scext4_fsmap *p;
	struct scext4_fsmap *tmp;

	list_for_each_entry_safe(p, tmp, meta_list, fmr_list) {
		list_del(&p->fmr_list);
		kfree(p);
	}
}

/* Find all the fixed metadata in the filesystem. */
static int scext4_getfsmap_find_fixed_metadata(struct super_block *sb,
					     struct list_head *meta_list)
{
	struct scext4_group_desc *gdp;
	scext4_group_t agno;
	int error;

	INIT_LIST_HEAD(meta_list);

	/* Collect everything. */
	for (agno = 0; agno < SCEXT4_SB(sb)->s_groups_count; agno++) {
		gdp = scext4_get_group_desc(sb, agno, NULL);
		if (!gdp) {
			error = -EFSCORRUPTED;
			goto err;
		}

		/* Superblock & GDT */
		error = scext4_getfsmap_find_sb(sb, agno, meta_list);
		if (error)
			goto err;

		/* Block bitmap */
		error = scext4_getfsmap_fill(meta_list,
					   scext4_block_bitmap(sb, gdp), 1,
					   SCEXT4_FMR_OWN_BLKBM);
		if (error)
			goto err;

		/* Inode bitmap */
		error = scext4_getfsmap_fill(meta_list,
					   scext4_inode_bitmap(sb, gdp), 1,
					   SCEXT4_FMR_OWN_INOBM);
		if (error)
			goto err;

		/* Inodes */
		error = scext4_getfsmap_fill(meta_list,
					   scext4_inode_table(sb, gdp),
					   SCEXT4_SB(sb)->s_itb_per_group,
					   SCEXT4_FMR_OWN_INODES);
		if (error)
			goto err;
	}

	/* Sort the list */
	list_sort(NULL, meta_list, scext4_getfsmap_compare);

	/* Merge adjacent extents */
	scext4_getfsmap_merge_fixed_metadata(meta_list);

	return 0;
err:
	scext4_getfsmap_free_fixed_metadata(meta_list);
	return error;
}

/* Execute a getfsmap query against the buddy bitmaps */
static int scext4_getfsmap_datadev(struct super_block *sb,
				 struct scext4_fsmap *keys,
				 struct scext4_getfsmap_info *info)
{
	struct scext4_sb_info *sbi = SCEXT4_SB(sb);
	scext4_fsblk_t start_fsb;
	scext4_fsblk_t end_fsb;
	scext4_fsblk_t bofs;
	scext4_fsblk_t eofs;
	scext4_group_t start_ag;
	scext4_group_t end_ag;
	scext4_grpblk_t first_cluster;
	scext4_grpblk_t last_cluster;
	int error = 0;

	bofs = le32_to_cpu(sbi->s_es->s_first_data_block);
	eofs = scext4_blocks_count(sbi->s_es);
	if (keys[0].fmr_physical >= eofs)
		return 0;
	else if (keys[0].fmr_physical < bofs)
		keys[0].fmr_physical = bofs;
	if (keys[1].fmr_physical >= eofs)
		keys[1].fmr_physical = eofs - 1;
	start_fsb = keys[0].fmr_physical;
	end_fsb = keys[1].fmr_physical;

	/* Determine first and last group to examine based on start and end */
	scext4_get_group_no_and_offset(sb, start_fsb, &start_ag, &first_cluster);
	scext4_get_group_no_and_offset(sb, end_fsb, &end_ag, &last_cluster);

	/*
	 * Convert the fsmap low/high keys to bg based keys.  Initialize
	 * low to the fsmap low key and max out the high key to the end
	 * of the bg.
	 */
	info->gfi_low = keys[0];
	info->gfi_low.fmr_physical = SCEXT4_C2B(sbi, first_cluster);
	info->gfi_low.fmr_length = 0;

	memset(&info->gfi_high, 0xFF, sizeof(info->gfi_high));

	/* Assemble a list of all the fixed-location metadata. */
	error = scext4_getfsmap_find_fixed_metadata(sb, &info->gfi_meta_list);
	if (error)
		goto err;

	/* Query each bg */
	for (info->gfi_agno = start_ag;
	     info->gfi_agno <= end_ag;
	     info->gfi_agno++) {
		/*
		 * Set the bg high key from the fsmap high key if this
		 * is the last bg that we're querying.
		 */
		if (info->gfi_agno == end_ag) {
			info->gfi_high = keys[1];
			info->gfi_high.fmr_physical = SCEXT4_C2B(sbi,
					last_cluster);
			info->gfi_high.fmr_length = 0;
		}

		trace_scext4_fsmap_low_key(sb, info->gfi_dev, info->gfi_agno,
				info->gfi_low.fmr_physical,
				info->gfi_low.fmr_length,
				info->gfi_low.fmr_owner);

		trace_scext4_fsmap_high_key(sb, info->gfi_dev, info->gfi_agno,
				info->gfi_high.fmr_physical,
				info->gfi_high.fmr_length,
				info->gfi_high.fmr_owner);

		error = scext4_mballoc_query_range(sb, info->gfi_agno,
				SCEXT4_B2C(sbi, info->gfi_low.fmr_physical),
				SCEXT4_B2C(sbi, info->gfi_high.fmr_physical),
				scext4_getfsmap_datadev_helper, info);
		if (error)
			goto err;

		/*
		 * Set the bg low key to the start of the bg prior to
		 * moving on to the next bg.
		 */
		if (info->gfi_agno == start_ag)
			memset(&info->gfi_low, 0, sizeof(info->gfi_low));
	}

	/* Do we have a retained free extent? */
	if (info->gfi_lastfree.fmr_owner) {
		error = scext4_getfsmap_helper(sb, info, &info->gfi_lastfree);
		if (error)
			goto err;
	}

	/* Report any gaps at the end of the bg */
	info->gfi_last = true;
	error = scext4_getfsmap_datadev_helper(sb, end_ag, last_cluster, 0, info);
	if (error)
		goto err;

err:
	scext4_getfsmap_free_fixed_metadata(&info->gfi_meta_list);
	return error;
}

/* Do we recognize the device? */
static bool scext4_getfsmap_is_valid_device(struct super_block *sb,
					  struct scext4_fsmap *fm)
{
	if (fm->fmr_device == 0 || fm->fmr_device == UINT_MAX ||
	    fm->fmr_device == new_encode_dev(sb->s_bdev->bd_dev))
		return true;
	if (SCEXT4_SB(sb)->journal_bdev &&
	    fm->fmr_device == new_encode_dev(SCEXT4_SB(sb)->journal_bdev->bd_dev))
		return true;
	return false;
}

/* Ensure that the low key is less than the high key. */
static bool scext4_getfsmap_check_keys(struct scext4_fsmap *low_key,
				     struct scext4_fsmap *high_key)
{
	if (low_key->fmr_device > high_key->fmr_device)
		return false;
	if (low_key->fmr_device < high_key->fmr_device)
		return true;

	if (low_key->fmr_physical > high_key->fmr_physical)
		return false;
	if (low_key->fmr_physical < high_key->fmr_physical)
		return true;

	if (low_key->fmr_owner > high_key->fmr_owner)
		return false;
	if (low_key->fmr_owner < high_key->fmr_owner)
		return true;

	return false;
}

#define SCEXT4_GETFSMAP_DEVS	2
/*
 * Get filesystem's extents as described in head, and format for
 * output.  Calls formatter to fill the user's buffer until all
 * extents are mapped, until the passed-in head->fmh_count slots have
 * been filled, or until the formatter short-circuits the loop, if it
 * is tracking filled-in extents on its own.
 *
 * Key to Confusion
 * ----------------
 * There are multiple levels of keys and counters at work here:
 * _fsmap_head.fmh_keys		-- low and high fsmap keys passed in;
 * 				   these reflect fs-wide block addrs.
 * dkeys			-- fmh_keys used to query each device;
 * 				   these are fmh_keys but w/ the low key
 * 				   bumped up by fmr_length.
 * _getfsmap_info.gfi_next_fsblk-- next fs block we expect to see; this
 *				   is how we detect gaps in the fsmap
 *				   records and report them.
 * _getfsmap_info.gfi_low/high	-- per-bg low/high keys computed from
 * 				   dkeys; used to query the free space.
 */
int scext4_getfsmap(struct super_block *sb, struct scext4_fsmap_head *head,
		  scext4_fsmap_format_t formatter, void *arg)
{
	struct scext4_fsmap dkeys[2];	/* per-dev keys */
	struct scext4_getfsmap_dev handlers[SCEXT4_GETFSMAP_DEVS];
	struct scext4_getfsmap_info info = { NULL };
	int i;
	int error = 0;

	if (head->fmh_iflags & ~FMH_IF_VALID)
		return -EINVAL;
	if (!scext4_getfsmap_is_valid_device(sb, &head->fmh_keys[0]) ||
	    !scext4_getfsmap_is_valid_device(sb, &head->fmh_keys[1]))
		return -EINVAL;

	head->fmh_entries = 0;

	/* Set up our device handlers. */
	memset(handlers, 0, sizeof(handlers));
	handlers[0].gfd_dev = new_encode_dev(sb->s_bdev->bd_dev);
	handlers[0].gfd_fn = scext4_getfsmap_datadev;
	if (SCEXT4_SB(sb)->journal_bdev) {
		handlers[1].gfd_dev = new_encode_dev(
				SCEXT4_SB(sb)->journal_bdev->bd_dev);
		handlers[1].gfd_fn = scext4_getfsmap_logdev;
	}

	sort(handlers, SCEXT4_GETFSMAP_DEVS, sizeof(struct scext4_getfsmap_dev),
			scext4_getfsmap_dev_compare, NULL);

	/*
	 * To continue where we left off, we allow userspace to use the
	 * last mapping from a previous call as the low key of the next.
	 * This is identified by a non-zero length in the low key. We
	 * have to increment the low key in this scenario to ensure we
	 * don't return the same mapping again, and instead return the
	 * very next mapping.
	 *
	 * Bump the physical offset as there can be no other mapping for
	 * the same physical block range.
	 */
	dkeys[0] = head->fmh_keys[0];
	dkeys[0].fmr_physical += dkeys[0].fmr_length;
	dkeys[0].fmr_owner = 0;
	dkeys[0].fmr_length = 0;
	memset(&dkeys[1], 0xFF, sizeof(struct scext4_fsmap));

	if (!scext4_getfsmap_check_keys(dkeys, &head->fmh_keys[1]))
		return -EINVAL;

	info.gfi_next_fsblk = head->fmh_keys[0].fmr_physical +
			  head->fmh_keys[0].fmr_length;
	info.gfi_formatter = formatter;
	info.gfi_format_arg = arg;
	info.gfi_head = head;

	/* For each device we support... */
	for (i = 0; i < SCEXT4_GETFSMAP_DEVS; i++) {
		/* Is this device within the range the user asked for? */
		if (!handlers[i].gfd_fn)
			continue;
		if (head->fmh_keys[0].fmr_device > handlers[i].gfd_dev)
			continue;
		if (head->fmh_keys[1].fmr_device < handlers[i].gfd_dev)
			break;

		/*
		 * If this device number matches the high key, we have
		 * to pass the high key to the handler to limit the
		 * query results.  If the device number exceeds the
		 * low key, zero out the low key so that we get
		 * everything from the beginning.
		 */
		if (handlers[i].gfd_dev == head->fmh_keys[1].fmr_device)
			dkeys[1] = head->fmh_keys[1];
		if (handlers[i].gfd_dev > head->fmh_keys[0].fmr_device)
			memset(&dkeys[0], 0, sizeof(struct scext4_fsmap));

		info.gfi_dev = handlers[i].gfd_dev;
		info.gfi_last = false;
		info.gfi_agno = -1;
		error = handlers[i].gfd_fn(sb, dkeys, &info);
		if (error)
			break;
		info.gfi_next_fsblk = 0;
	}

	head->fmh_oflags = FMH_OF_DEV_T;
	return error;
}
