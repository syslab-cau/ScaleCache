// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2003,2005 Silicon Graphics, Inc.
 * Copyright (c) 2013 Red Hat, Inc.
 * All Rights Reserved.
 */
#include "scxfs.h"
#include "scxfs_fs.h"
#include "scxfs_shared.h"
#include "scxfs_format.h"
#include "scxfs_log_format.h"
#include "scxfs_trans_resv.h"
#include "scxfs_mount.h"
#include "scxfs_inode.h"
#include "scxfs_trans.h"
#include "scxfs_bmap.h"
#include "scxfs_buf_item.h"
#include "scxfs_dir2.h"
#include "scxfs_dir2_priv.h"
#include "scxfs_error.h"
#include "scxfs_trace.h"
#include "scxfs_log.h"

/*
 * Local function prototypes.
 */
static void scxfs_dir2_block_log_leaf(scxfs_trans_t *tp, struct scxfs_buf *bp,
				    int first, int last);
static void scxfs_dir2_block_log_tail(scxfs_trans_t *tp, struct scxfs_buf *bp);
static int scxfs_dir2_block_lookup_int(scxfs_da_args_t *args, struct scxfs_buf **bpp,
				     int *entno);
static int scxfs_dir2_block_sort(const void *a, const void *b);

static scxfs_dahash_t scxfs_dir_hash_dot, scxfs_dir_hash_dotdot;

/*
 * One-time startup routine called from scxfs_init().
 */
void
scxfs_dir_startup(void)
{
	scxfs_dir_hash_dot = scxfs_da_hashname((unsigned char *)".", 1);
	scxfs_dir_hash_dotdot = scxfs_da_hashname((unsigned char *)"..", 2);
}

static scxfs_failaddr_t
scxfs_dir3_block_verify(
	struct scxfs_buf		*bp)
{
	struct scxfs_mount	*mp = bp->b_mount;
	struct scxfs_dir3_blk_hdr	*hdr3 = bp->b_addr;

	if (!scxfs_verify_magic(bp, hdr3->magic))
		return __this_address;

	if (scxfs_sb_version_hascrc(&mp->m_sb)) {
		if (!uuid_equal(&hdr3->uuid, &mp->m_sb.sb_meta_uuid))
			return __this_address;
		if (be64_to_cpu(hdr3->blkno) != bp->b_bn)
			return __this_address;
		if (!scxfs_log_check_lsn(mp, be64_to_cpu(hdr3->lsn)))
			return __this_address;
	}
	return __scxfs_dir3_data_check(NULL, bp);
}

static void
scxfs_dir3_block_read_verify(
	struct scxfs_buf	*bp)
{
	struct scxfs_mount	*mp = bp->b_mount;
	scxfs_failaddr_t		fa;

	if (scxfs_sb_version_hascrc(&mp->m_sb) &&
	     !scxfs_buf_verify_cksum(bp, SCXFS_DIR3_DATA_CRC_OFF))
		scxfs_verifier_error(bp, -EFSBADCRC, __this_address);
	else {
		fa = scxfs_dir3_block_verify(bp);
		if (fa)
			scxfs_verifier_error(bp, -EFSCORRUPTED, fa);
	}
}

static void
scxfs_dir3_block_write_verify(
	struct scxfs_buf	*bp)
{
	struct scxfs_mount	*mp = bp->b_mount;
	struct scxfs_buf_log_item	*bip = bp->b_log_item;
	struct scxfs_dir3_blk_hdr	*hdr3 = bp->b_addr;
	scxfs_failaddr_t		fa;

	fa = scxfs_dir3_block_verify(bp);
	if (fa) {
		scxfs_verifier_error(bp, -EFSCORRUPTED, fa);
		return;
	}

	if (!scxfs_sb_version_hascrc(&mp->m_sb))
		return;

	if (bip)
		hdr3->lsn = cpu_to_be64(bip->bli_item.li_lsn);

	scxfs_buf_update_cksum(bp, SCXFS_DIR3_DATA_CRC_OFF);
}

const struct scxfs_buf_ops scxfs_dir3_block_buf_ops = {
	.name = "scxfs_dir3_block",
	.magic = { cpu_to_be32(SCXFS_DIR2_BLOCK_MAGIC),
		   cpu_to_be32(SCXFS_DIR3_BLOCK_MAGIC) },
	.verify_read = scxfs_dir3_block_read_verify,
	.verify_write = scxfs_dir3_block_write_verify,
	.verify_struct = scxfs_dir3_block_verify,
};

int
scxfs_dir3_block_read(
	struct scxfs_trans	*tp,
	struct scxfs_inode	*dp,
	struct scxfs_buf		**bpp)
{
	struct scxfs_mount	*mp = dp->i_mount;
	int			err;

	err = scxfs_da_read_buf(tp, dp, mp->m_dir_geo->datablk, -1, bpp,
				SCXFS_DATA_FORK, &scxfs_dir3_block_buf_ops);
	if (!err && tp && *bpp)
		scxfs_trans_buf_set_type(tp, *bpp, SCXFS_BLFT_DIR_BLOCK_BUF);
	return err;
}

static void
scxfs_dir3_block_init(
	struct scxfs_mount	*mp,
	struct scxfs_trans	*tp,
	struct scxfs_buf		*bp,
	struct scxfs_inode	*dp)
{
	struct scxfs_dir3_blk_hdr *hdr3 = bp->b_addr;

	bp->b_ops = &scxfs_dir3_block_buf_ops;
	scxfs_trans_buf_set_type(tp, bp, SCXFS_BLFT_DIR_BLOCK_BUF);

	if (scxfs_sb_version_hascrc(&mp->m_sb)) {
		memset(hdr3, 0, sizeof(*hdr3));
		hdr3->magic = cpu_to_be32(SCXFS_DIR3_BLOCK_MAGIC);
		hdr3->blkno = cpu_to_be64(bp->b_bn);
		hdr3->owner = cpu_to_be64(dp->i_ino);
		uuid_copy(&hdr3->uuid, &mp->m_sb.sb_meta_uuid);
		return;

	}
	hdr3->magic = cpu_to_be32(SCXFS_DIR2_BLOCK_MAGIC);
}

static void
scxfs_dir2_block_need_space(
	struct scxfs_inode		*dp,
	struct scxfs_dir2_data_hdr	*hdr,
	struct scxfs_dir2_block_tail	*btp,
	struct scxfs_dir2_leaf_entry	*blp,
	__be16				**tagpp,
	struct scxfs_dir2_data_unused	**dupp,
	struct scxfs_dir2_data_unused	**enddupp,
	int				*compact,
	int				len)
{
	struct scxfs_dir2_data_free	*bf;
	__be16				*tagp = NULL;
	struct scxfs_dir2_data_unused	*dup = NULL;
	struct scxfs_dir2_data_unused	*enddup = NULL;

	*compact = 0;
	bf = dp->d_ops->data_bestfree_p(hdr);

	/*
	 * If there are stale entries we'll use one for the leaf.
	 */
	if (btp->stale) {
		if (be16_to_cpu(bf[0].length) >= len) {
			/*
			 * The biggest entry enough to avoid compaction.
			 */
			dup = (scxfs_dir2_data_unused_t *)
			      ((char *)hdr + be16_to_cpu(bf[0].offset));
			goto out;
		}

		/*
		 * Will need to compact to make this work.
		 * Tag just before the first leaf entry.
		 */
		*compact = 1;
		tagp = (__be16 *)blp - 1;

		/* Data object just before the first leaf entry.  */
		dup = (scxfs_dir2_data_unused_t *)((char *)hdr + be16_to_cpu(*tagp));

		/*
		 * If it's not free then the data will go where the
		 * leaf data starts now, if it works at all.
		 */
		if (be16_to_cpu(dup->freetag) == SCXFS_DIR2_DATA_FREE_TAG) {
			if (be16_to_cpu(dup->length) + (be32_to_cpu(btp->stale) - 1) *
			    (uint)sizeof(*blp) < len)
				dup = NULL;
		} else if ((be32_to_cpu(btp->stale) - 1) * (uint)sizeof(*blp) < len)
			dup = NULL;
		else
			dup = (scxfs_dir2_data_unused_t *)blp;
		goto out;
	}

	/*
	 * no stale entries, so just use free space.
	 * Tag just before the first leaf entry.
	 */
	tagp = (__be16 *)blp - 1;

	/* Data object just before the first leaf entry.  */
	enddup = (scxfs_dir2_data_unused_t *)((char *)hdr + be16_to_cpu(*tagp));

	/*
	 * If it's not free then can't do this add without cleaning up:
	 * the space before the first leaf entry needs to be free so it
	 * can be expanded to hold the pointer to the new entry.
	 */
	if (be16_to_cpu(enddup->freetag) == SCXFS_DIR2_DATA_FREE_TAG) {
		/*
		 * Check out the biggest freespace and see if it's the same one.
		 */
		dup = (scxfs_dir2_data_unused_t *)
		      ((char *)hdr + be16_to_cpu(bf[0].offset));
		if (dup != enddup) {
			/*
			 * Not the same free entry, just check its length.
			 */
			if (be16_to_cpu(dup->length) < len)
				dup = NULL;
			goto out;
		}

		/*
		 * It is the biggest freespace, can it hold the leaf too?
		 */
		if (be16_to_cpu(dup->length) < len + (uint)sizeof(*blp)) {
			/*
			 * Yes, use the second-largest entry instead if it works.
			 */
			if (be16_to_cpu(bf[1].length) >= len)
				dup = (scxfs_dir2_data_unused_t *)
				      ((char *)hdr + be16_to_cpu(bf[1].offset));
			else
				dup = NULL;
		}
	}
out:
	*tagpp = tagp;
	*dupp = dup;
	*enddupp = enddup;
}

/*
 * compact the leaf entries.
 * Leave the highest-numbered stale entry stale.
 * XXX should be the one closest to mid but mid is not yet computed.
 */
static void
scxfs_dir2_block_compact(
	struct scxfs_da_args		*args,
	struct scxfs_buf			*bp,
	struct scxfs_dir2_data_hdr	*hdr,
	struct scxfs_dir2_block_tail	*btp,
	struct scxfs_dir2_leaf_entry	*blp,
	int				*needlog,
	int				*lfloghigh,
	int				*lfloglow)
{
	int			fromidx;	/* source leaf index */
	int			toidx;		/* target leaf index */
	int			needscan = 0;
	int			highstale;	/* high stale index */

	fromidx = toidx = be32_to_cpu(btp->count) - 1;
	highstale = *lfloghigh = -1;
	for (; fromidx >= 0; fromidx--) {
		if (blp[fromidx].address == cpu_to_be32(SCXFS_DIR2_NULL_DATAPTR)) {
			if (highstale == -1)
				highstale = toidx;
			else {
				if (*lfloghigh == -1)
					*lfloghigh = toidx;
				continue;
			}
		}
		if (fromidx < toidx)
			blp[toidx] = blp[fromidx];
		toidx--;
	}
	*lfloglow = toidx + 1 - (be32_to_cpu(btp->stale) - 1);
	*lfloghigh -= be32_to_cpu(btp->stale) - 1;
	be32_add_cpu(&btp->count, -(be32_to_cpu(btp->stale) - 1));
	scxfs_dir2_data_make_free(args, bp,
		(scxfs_dir2_data_aoff_t)((char *)blp - (char *)hdr),
		(scxfs_dir2_data_aoff_t)((be32_to_cpu(btp->stale) - 1) * sizeof(*blp)),
		needlog, &needscan);
	btp->stale = cpu_to_be32(1);
	/*
	 * If we now need to rebuild the bestfree map, do so.
	 * This needs to happen before the next call to use_free.
	 */
	if (needscan)
		scxfs_dir2_data_freescan(args->dp, hdr, needlog);
}

/*
 * Add an entry to a block directory.
 */
int						/* error */
scxfs_dir2_block_addname(
	scxfs_da_args_t		*args)		/* directory op arguments */
{
	scxfs_dir2_data_hdr_t	*hdr;		/* block header */
	scxfs_dir2_leaf_entry_t	*blp;		/* block leaf entries */
	struct scxfs_buf		*bp;		/* buffer for block */
	scxfs_dir2_block_tail_t	*btp;		/* block tail */
	int			compact;	/* need to compact leaf ents */
	scxfs_dir2_data_entry_t	*dep;		/* block data entry */
	scxfs_inode_t		*dp;		/* directory inode */
	scxfs_dir2_data_unused_t	*dup;		/* block unused entry */
	int			error;		/* error return value */
	scxfs_dir2_data_unused_t	*enddup=NULL;	/* unused at end of data */
	scxfs_dahash_t		hash;		/* hash value of found entry */
	int			high;		/* high index for binary srch */
	int			highstale;	/* high stale index */
	int			lfloghigh=0;	/* last final leaf to log */
	int			lfloglow=0;	/* first final leaf to log */
	int			len;		/* length of the new entry */
	int			low;		/* low index for binary srch */
	int			lowstale;	/* low stale index */
	int			mid=0;		/* midpoint for binary srch */
	int			needlog;	/* need to log header */
	int			needscan;	/* need to rescan freespace */
	__be16			*tagp;		/* pointer to tag value */
	scxfs_trans_t		*tp;		/* transaction structure */

	trace_scxfs_dir2_block_addname(args);

	dp = args->dp;
	tp = args->trans;

	/* Read the (one and only) directory block into bp. */
	error = scxfs_dir3_block_read(tp, dp, &bp);
	if (error)
		return error;

	len = dp->d_ops->data_entsize(args->namelen);

	/*
	 * Set up pointers to parts of the block.
	 */
	hdr = bp->b_addr;
	btp = scxfs_dir2_block_tail_p(args->geo, hdr);
	blp = scxfs_dir2_block_leaf_p(btp);

	/*
	 * Find out if we can reuse stale entries or whether we need extra
	 * space for entry and new leaf.
	 */
	scxfs_dir2_block_need_space(dp, hdr, btp, blp, &tagp, &dup,
				  &enddup, &compact, len);

	/*
	 * Done everything we need for a space check now.
	 */
	if (args->op_flags & SCXFS_DA_OP_JUSTCHECK) {
		scxfs_trans_brelse(tp, bp);
		if (!dup)
			return -ENOSPC;
		return 0;
	}

	/*
	 * If we don't have space for the new entry & leaf ...
	 */
	if (!dup) {
		/* Don't have a space reservation: return no-space.  */
		if (args->total == 0)
			return -ENOSPC;
		/*
		 * Convert to the next larger format.
		 * Then add the new entry in that format.
		 */
		error = scxfs_dir2_block_to_leaf(args, bp);
		if (error)
			return error;
		return scxfs_dir2_leaf_addname(args);
	}

	needlog = needscan = 0;

	/*
	 * If need to compact the leaf entries, do it now.
	 */
	if (compact) {
		scxfs_dir2_block_compact(args, bp, hdr, btp, blp, &needlog,
				      &lfloghigh, &lfloglow);
		/* recalculate blp post-compaction */
		blp = scxfs_dir2_block_leaf_p(btp);
	} else if (btp->stale) {
		/*
		 * Set leaf logging boundaries to impossible state.
		 * For the no-stale case they're set explicitly.
		 */
		lfloglow = be32_to_cpu(btp->count);
		lfloghigh = -1;
	}

	/*
	 * Find the slot that's first lower than our hash value, -1 if none.
	 */
	for (low = 0, high = be32_to_cpu(btp->count) - 1; low <= high; ) {
		mid = (low + high) >> 1;
		if ((hash = be32_to_cpu(blp[mid].hashval)) == args->hashval)
			break;
		if (hash < args->hashval)
			low = mid + 1;
		else
			high = mid - 1;
	}
	while (mid >= 0 && be32_to_cpu(blp[mid].hashval) >= args->hashval) {
		mid--;
	}
	/*
	 * No stale entries, will use enddup space to hold new leaf.
	 */
	if (!btp->stale) {
		scxfs_dir2_data_aoff_t	aoff;

		/*
		 * Mark the space needed for the new leaf entry, now in use.
		 */
		aoff = (scxfs_dir2_data_aoff_t)((char *)enddup - (char *)hdr +
				be16_to_cpu(enddup->length) - sizeof(*blp));
		error = scxfs_dir2_data_use_free(args, bp, enddup, aoff,
				(scxfs_dir2_data_aoff_t)sizeof(*blp), &needlog,
				&needscan);
		if (error)
			return error;

		/*
		 * Update the tail (entry count).
		 */
		be32_add_cpu(&btp->count, 1);
		/*
		 * If we now need to rebuild the bestfree map, do so.
		 * This needs to happen before the next call to use_free.
		 */
		if (needscan) {
			scxfs_dir2_data_freescan(dp, hdr, &needlog);
			needscan = 0;
		}
		/*
		 * Adjust pointer to the first leaf entry, we're about to move
		 * the table up one to open up space for the new leaf entry.
		 * Then adjust our index to match.
		 */
		blp--;
		mid++;
		if (mid)
			memmove(blp, &blp[1], mid * sizeof(*blp));
		lfloglow = 0;
		lfloghigh = mid;
	}
	/*
	 * Use a stale leaf for our new entry.
	 */
	else {
		for (lowstale = mid;
		     lowstale >= 0 &&
			blp[lowstale].address !=
			cpu_to_be32(SCXFS_DIR2_NULL_DATAPTR);
		     lowstale--)
			continue;
		for (highstale = mid + 1;
		     highstale < be32_to_cpu(btp->count) &&
			blp[highstale].address !=
			cpu_to_be32(SCXFS_DIR2_NULL_DATAPTR) &&
			(lowstale < 0 || mid - lowstale > highstale - mid);
		     highstale++)
			continue;
		/*
		 * Move entries toward the low-numbered stale entry.
		 */
		if (lowstale >= 0 &&
		    (highstale == be32_to_cpu(btp->count) ||
		     mid - lowstale <= highstale - mid)) {
			if (mid - lowstale)
				memmove(&blp[lowstale], &blp[lowstale + 1],
					(mid - lowstale) * sizeof(*blp));
			lfloglow = min(lowstale, lfloglow);
			lfloghigh = max(mid, lfloghigh);
		}
		/*
		 * Move entries toward the high-numbered stale entry.
		 */
		else {
			ASSERT(highstale < be32_to_cpu(btp->count));
			mid++;
			if (highstale - mid)
				memmove(&blp[mid + 1], &blp[mid],
					(highstale - mid) * sizeof(*blp));
			lfloglow = min(mid, lfloglow);
			lfloghigh = max(highstale, lfloghigh);
		}
		be32_add_cpu(&btp->stale, -1);
	}
	/*
	 * Point to the new data entry.
	 */
	dep = (scxfs_dir2_data_entry_t *)dup;
	/*
	 * Fill in the leaf entry.
	 */
	blp[mid].hashval = cpu_to_be32(args->hashval);
	blp[mid].address = cpu_to_be32(scxfs_dir2_byte_to_dataptr(
				(char *)dep - (char *)hdr));
	scxfs_dir2_block_log_leaf(tp, bp, lfloglow, lfloghigh);
	/*
	 * Mark space for the data entry used.
	 */
	error = scxfs_dir2_data_use_free(args, bp, dup,
			(scxfs_dir2_data_aoff_t)((char *)dup - (char *)hdr),
			(scxfs_dir2_data_aoff_t)len, &needlog, &needscan);
	if (error)
		return error;
	/*
	 * Create the new data entry.
	 */
	dep->inumber = cpu_to_be64(args->inumber);
	dep->namelen = args->namelen;
	memcpy(dep->name, args->name, args->namelen);
	dp->d_ops->data_put_ftype(dep, args->filetype);
	tagp = dp->d_ops->data_entry_tag_p(dep);
	*tagp = cpu_to_be16((char *)dep - (char *)hdr);
	/*
	 * Clean up the bestfree array and log the header, tail, and entry.
	 */
	if (needscan)
		scxfs_dir2_data_freescan(dp, hdr, &needlog);
	if (needlog)
		scxfs_dir2_data_log_header(args, bp);
	scxfs_dir2_block_log_tail(tp, bp);
	scxfs_dir2_data_log_entry(args, bp, dep);
	scxfs_dir3_data_check(dp, bp);
	return 0;
}

/*
 * Log leaf entries from the block.
 */
static void
scxfs_dir2_block_log_leaf(
	scxfs_trans_t		*tp,		/* transaction structure */
	struct scxfs_buf		*bp,		/* block buffer */
	int			first,		/* index of first logged leaf */
	int			last)		/* index of last logged leaf */
{
	scxfs_dir2_data_hdr_t	*hdr = bp->b_addr;
	scxfs_dir2_leaf_entry_t	*blp;
	scxfs_dir2_block_tail_t	*btp;

	btp = scxfs_dir2_block_tail_p(tp->t_mountp->m_dir_geo, hdr);
	blp = scxfs_dir2_block_leaf_p(btp);
	scxfs_trans_log_buf(tp, bp, (uint)((char *)&blp[first] - (char *)hdr),
		(uint)((char *)&blp[last + 1] - (char *)hdr - 1));
}

/*
 * Log the block tail.
 */
static void
scxfs_dir2_block_log_tail(
	scxfs_trans_t		*tp,		/* transaction structure */
	struct scxfs_buf		*bp)		/* block buffer */
{
	scxfs_dir2_data_hdr_t	*hdr = bp->b_addr;
	scxfs_dir2_block_tail_t	*btp;

	btp = scxfs_dir2_block_tail_p(tp->t_mountp->m_dir_geo, hdr);
	scxfs_trans_log_buf(tp, bp, (uint)((char *)btp - (char *)hdr),
		(uint)((char *)(btp + 1) - (char *)hdr - 1));
}

/*
 * Look up an entry in the block.  This is the external routine,
 * scxfs_dir2_block_lookup_int does the real work.
 */
int						/* error */
scxfs_dir2_block_lookup(
	scxfs_da_args_t		*args)		/* dir lookup arguments */
{
	scxfs_dir2_data_hdr_t	*hdr;		/* block header */
	scxfs_dir2_leaf_entry_t	*blp;		/* block leaf entries */
	struct scxfs_buf		*bp;		/* block buffer */
	scxfs_dir2_block_tail_t	*btp;		/* block tail */
	scxfs_dir2_data_entry_t	*dep;		/* block data entry */
	scxfs_inode_t		*dp;		/* incore inode */
	int			ent;		/* entry index */
	int			error;		/* error return value */

	trace_scxfs_dir2_block_lookup(args);

	/*
	 * Get the buffer, look up the entry.
	 * If not found (ENOENT) then return, have no buffer.
	 */
	if ((error = scxfs_dir2_block_lookup_int(args, &bp, &ent)))
		return error;
	dp = args->dp;
	hdr = bp->b_addr;
	scxfs_dir3_data_check(dp, bp);
	btp = scxfs_dir2_block_tail_p(args->geo, hdr);
	blp = scxfs_dir2_block_leaf_p(btp);
	/*
	 * Get the offset from the leaf entry, to point to the data.
	 */
	dep = (scxfs_dir2_data_entry_t *)((char *)hdr +
			scxfs_dir2_dataptr_to_off(args->geo,
						be32_to_cpu(blp[ent].address)));
	/*
	 * Fill in inode number, CI name if appropriate, release the block.
	 */
	args->inumber = be64_to_cpu(dep->inumber);
	args->filetype = dp->d_ops->data_get_ftype(dep);
	error = scxfs_dir_cilookup_result(args, dep->name, dep->namelen);
	scxfs_trans_brelse(args->trans, bp);
	return error;
}

/*
 * Internal block lookup routine.
 */
static int					/* error */
scxfs_dir2_block_lookup_int(
	scxfs_da_args_t		*args,		/* dir lookup arguments */
	struct scxfs_buf		**bpp,		/* returned block buffer */
	int			*entno)		/* returned entry number */
{
	scxfs_dir2_dataptr_t	addr;		/* data entry address */
	scxfs_dir2_data_hdr_t	*hdr;		/* block header */
	scxfs_dir2_leaf_entry_t	*blp;		/* block leaf entries */
	struct scxfs_buf		*bp;		/* block buffer */
	scxfs_dir2_block_tail_t	*btp;		/* block tail */
	scxfs_dir2_data_entry_t	*dep;		/* block data entry */
	scxfs_inode_t		*dp;		/* incore inode */
	int			error;		/* error return value */
	scxfs_dahash_t		hash;		/* found hash value */
	int			high;		/* binary search high index */
	int			low;		/* binary search low index */
	int			mid;		/* binary search current idx */
	scxfs_mount_t		*mp;		/* filesystem mount point */
	scxfs_trans_t		*tp;		/* transaction pointer */
	enum scxfs_dacmp		cmp;		/* comparison result */

	dp = args->dp;
	tp = args->trans;
	mp = dp->i_mount;

	error = scxfs_dir3_block_read(tp, dp, &bp);
	if (error)
		return error;

	hdr = bp->b_addr;
	scxfs_dir3_data_check(dp, bp);
	btp = scxfs_dir2_block_tail_p(args->geo, hdr);
	blp = scxfs_dir2_block_leaf_p(btp);
	/*
	 * Loop doing a binary search for our hash value.
	 * Find our entry, ENOENT if it's not there.
	 */
	for (low = 0, high = be32_to_cpu(btp->count) - 1; ; ) {
		ASSERT(low <= high);
		mid = (low + high) >> 1;
		if ((hash = be32_to_cpu(blp[mid].hashval)) == args->hashval)
			break;
		if (hash < args->hashval)
			low = mid + 1;
		else
			high = mid - 1;
		if (low > high) {
			ASSERT(args->op_flags & SCXFS_DA_OP_OKNOENT);
			scxfs_trans_brelse(tp, bp);
			return -ENOENT;
		}
	}
	/*
	 * Back up to the first one with the right hash value.
	 */
	while (mid > 0 && be32_to_cpu(blp[mid - 1].hashval) == args->hashval) {
		mid--;
	}
	/*
	 * Now loop forward through all the entries with the
	 * right hash value looking for our name.
	 */
	do {
		if ((addr = be32_to_cpu(blp[mid].address)) == SCXFS_DIR2_NULL_DATAPTR)
			continue;
		/*
		 * Get pointer to the entry from the leaf.
		 */
		dep = (scxfs_dir2_data_entry_t *)
			((char *)hdr + scxfs_dir2_dataptr_to_off(args->geo, addr));
		/*
		 * Compare name and if it's an exact match, return the index
		 * and buffer. If it's the first case-insensitive match, store
		 * the index and buffer and continue looking for an exact match.
		 */
		cmp = mp->m_dirnameops->compname(args, dep->name, dep->namelen);
		if (cmp != SCXFS_CMP_DIFFERENT && cmp != args->cmpresult) {
			args->cmpresult = cmp;
			*bpp = bp;
			*entno = mid;
			if (cmp == SCXFS_CMP_EXACT)
				return 0;
		}
	} while (++mid < be32_to_cpu(btp->count) &&
			be32_to_cpu(blp[mid].hashval) == hash);

	ASSERT(args->op_flags & SCXFS_DA_OP_OKNOENT);
	/*
	 * Here, we can only be doing a lookup (not a rename or replace).
	 * If a case-insensitive match was found earlier, return success.
	 */
	if (args->cmpresult == SCXFS_CMP_CASE)
		return 0;
	/*
	 * No match, release the buffer and return ENOENT.
	 */
	scxfs_trans_brelse(tp, bp);
	return -ENOENT;
}

/*
 * Remove an entry from a block format directory.
 * If that makes the block small enough to fit in shortform, transform it.
 */
int						/* error */
scxfs_dir2_block_removename(
	scxfs_da_args_t		*args)		/* directory operation args */
{
	scxfs_dir2_data_hdr_t	*hdr;		/* block header */
	scxfs_dir2_leaf_entry_t	*blp;		/* block leaf pointer */
	struct scxfs_buf		*bp;		/* block buffer */
	scxfs_dir2_block_tail_t	*btp;		/* block tail */
	scxfs_dir2_data_entry_t	*dep;		/* block data entry */
	scxfs_inode_t		*dp;		/* incore inode */
	int			ent;		/* block leaf entry index */
	int			error;		/* error return value */
	int			needlog;	/* need to log block header */
	int			needscan;	/* need to fixup bestfree */
	scxfs_dir2_sf_hdr_t	sfh;		/* shortform header */
	int			size;		/* shortform size */
	scxfs_trans_t		*tp;		/* transaction pointer */

	trace_scxfs_dir2_block_removename(args);

	/*
	 * Look up the entry in the block.  Gets the buffer and entry index.
	 * It will always be there, the vnodeops level does a lookup first.
	 */
	if ((error = scxfs_dir2_block_lookup_int(args, &bp, &ent))) {
		return error;
	}
	dp = args->dp;
	tp = args->trans;
	hdr = bp->b_addr;
	btp = scxfs_dir2_block_tail_p(args->geo, hdr);
	blp = scxfs_dir2_block_leaf_p(btp);
	/*
	 * Point to the data entry using the leaf entry.
	 */
	dep = (scxfs_dir2_data_entry_t *)((char *)hdr +
			scxfs_dir2_dataptr_to_off(args->geo,
						be32_to_cpu(blp[ent].address)));
	/*
	 * Mark the data entry's space free.
	 */
	needlog = needscan = 0;
	scxfs_dir2_data_make_free(args, bp,
		(scxfs_dir2_data_aoff_t)((char *)dep - (char *)hdr),
		dp->d_ops->data_entsize(dep->namelen), &needlog, &needscan);
	/*
	 * Fix up the block tail.
	 */
	be32_add_cpu(&btp->stale, 1);
	scxfs_dir2_block_log_tail(tp, bp);
	/*
	 * Remove the leaf entry by marking it stale.
	 */
	blp[ent].address = cpu_to_be32(SCXFS_DIR2_NULL_DATAPTR);
	scxfs_dir2_block_log_leaf(tp, bp, ent, ent);
	/*
	 * Fix up bestfree, log the header if necessary.
	 */
	if (needscan)
		scxfs_dir2_data_freescan(dp, hdr, &needlog);
	if (needlog)
		scxfs_dir2_data_log_header(args, bp);
	scxfs_dir3_data_check(dp, bp);
	/*
	 * See if the size as a shortform is good enough.
	 */
	size = scxfs_dir2_block_sfsize(dp, hdr, &sfh);
	if (size > SCXFS_IFORK_DSIZE(dp))
		return 0;

	/*
	 * If it works, do the conversion.
	 */
	return scxfs_dir2_block_to_sf(args, bp, size, &sfh);
}

/*
 * Replace an entry in a V2 block directory.
 * Change the inode number to the new value.
 */
int						/* error */
scxfs_dir2_block_replace(
	scxfs_da_args_t		*args)		/* directory operation args */
{
	scxfs_dir2_data_hdr_t	*hdr;		/* block header */
	scxfs_dir2_leaf_entry_t	*blp;		/* block leaf entries */
	struct scxfs_buf		*bp;		/* block buffer */
	scxfs_dir2_block_tail_t	*btp;		/* block tail */
	scxfs_dir2_data_entry_t	*dep;		/* block data entry */
	scxfs_inode_t		*dp;		/* incore inode */
	int			ent;		/* leaf entry index */
	int			error;		/* error return value */

	trace_scxfs_dir2_block_replace(args);

	/*
	 * Lookup the entry in the directory.  Get buffer and entry index.
	 * This will always succeed since the caller has already done a lookup.
	 */
	if ((error = scxfs_dir2_block_lookup_int(args, &bp, &ent))) {
		return error;
	}
	dp = args->dp;
	hdr = bp->b_addr;
	btp = scxfs_dir2_block_tail_p(args->geo, hdr);
	blp = scxfs_dir2_block_leaf_p(btp);
	/*
	 * Point to the data entry we need to change.
	 */
	dep = (scxfs_dir2_data_entry_t *)((char *)hdr +
			scxfs_dir2_dataptr_to_off(args->geo,
						be32_to_cpu(blp[ent].address)));
	ASSERT(be64_to_cpu(dep->inumber) != args->inumber);
	/*
	 * Change the inode number to the new value.
	 */
	dep->inumber = cpu_to_be64(args->inumber);
	dp->d_ops->data_put_ftype(dep, args->filetype);
	scxfs_dir2_data_log_entry(args, bp, dep);
	scxfs_dir3_data_check(dp, bp);
	return 0;
}

/*
 * Qsort comparison routine for the block leaf entries.
 */
static int					/* sort order */
scxfs_dir2_block_sort(
	const void			*a,	/* first leaf entry */
	const void			*b)	/* second leaf entry */
{
	const scxfs_dir2_leaf_entry_t	*la;	/* first leaf entry */
	const scxfs_dir2_leaf_entry_t	*lb;	/* second leaf entry */

	la = a;
	lb = b;
	return be32_to_cpu(la->hashval) < be32_to_cpu(lb->hashval) ? -1 :
		(be32_to_cpu(la->hashval) > be32_to_cpu(lb->hashval) ? 1 : 0);
}

/*
 * Convert a V2 leaf directory to a V2 block directory if possible.
 */
int						/* error */
scxfs_dir2_leaf_to_block(
	scxfs_da_args_t		*args,		/* operation arguments */
	struct scxfs_buf		*lbp,		/* leaf buffer */
	struct scxfs_buf		*dbp)		/* data buffer */
{
	__be16			*bestsp;	/* leaf bests table */
	scxfs_dir2_data_hdr_t	*hdr;		/* block header */
	scxfs_dir2_block_tail_t	*btp;		/* block tail */
	scxfs_inode_t		*dp;		/* incore directory inode */
	scxfs_dir2_data_unused_t	*dup;		/* unused data entry */
	int			error;		/* error return value */
	int			from;		/* leaf from index */
	scxfs_dir2_leaf_t		*leaf;		/* leaf structure */
	scxfs_dir2_leaf_entry_t	*lep;		/* leaf entry */
	scxfs_dir2_leaf_tail_t	*ltp;		/* leaf tail structure */
	scxfs_mount_t		*mp;		/* file system mount point */
	int			needlog;	/* need to log data header */
	int			needscan;	/* need to scan for bestfree */
	scxfs_dir2_sf_hdr_t	sfh;		/* shortform header */
	int			size;		/* bytes used */
	__be16			*tagp;		/* end of entry (tag) */
	int			to;		/* block/leaf to index */
	scxfs_trans_t		*tp;		/* transaction pointer */
	struct scxfs_dir2_leaf_entry *ents;
	struct scxfs_dir3_icleaf_hdr leafhdr;

	trace_scxfs_dir2_leaf_to_block(args);

	dp = args->dp;
	tp = args->trans;
	mp = dp->i_mount;
	leaf = lbp->b_addr;
	dp->d_ops->leaf_hdr_from_disk(&leafhdr, leaf);
	ents = dp->d_ops->leaf_ents_p(leaf);
	ltp = scxfs_dir2_leaf_tail_p(args->geo, leaf);

	ASSERT(leafhdr.magic == SCXFS_DIR2_LEAF1_MAGIC ||
	       leafhdr.magic == SCXFS_DIR3_LEAF1_MAGIC);
	/*
	 * If there are data blocks other than the first one, take this
	 * opportunity to remove trailing empty data blocks that may have
	 * been left behind during no-space-reservation operations.
	 * These will show up in the leaf bests table.
	 */
	while (dp->i_d.di_size > args->geo->blksize) {
		int hdrsz;

		hdrsz = dp->d_ops->data_entry_offset;
		bestsp = scxfs_dir2_leaf_bests_p(ltp);
		if (be16_to_cpu(bestsp[be32_to_cpu(ltp->bestcount) - 1]) ==
					    args->geo->blksize - hdrsz) {
			if ((error =
			    scxfs_dir2_leaf_trim_data(args, lbp,
				    (scxfs_dir2_db_t)(be32_to_cpu(ltp->bestcount) - 1))))
				return error;
		} else
			return 0;
	}
	/*
	 * Read the data block if we don't already have it, give up if it fails.
	 */
	if (!dbp) {
		error = scxfs_dir3_data_read(tp, dp, args->geo->datablk, -1, &dbp);
		if (error)
			return error;
	}
	hdr = dbp->b_addr;
	ASSERT(hdr->magic == cpu_to_be32(SCXFS_DIR2_DATA_MAGIC) ||
	       hdr->magic == cpu_to_be32(SCXFS_DIR3_DATA_MAGIC));

	/*
	 * Size of the "leaf" area in the block.
	 */
	size = (uint)sizeof(scxfs_dir2_block_tail_t) +
	       (uint)sizeof(*lep) * (leafhdr.count - leafhdr.stale);
	/*
	 * Look at the last data entry.
	 */
	tagp = (__be16 *)((char *)hdr + args->geo->blksize) - 1;
	dup = (scxfs_dir2_data_unused_t *)((char *)hdr + be16_to_cpu(*tagp));
	/*
	 * If it's not free or is too short we can't do it.
	 */
	if (be16_to_cpu(dup->freetag) != SCXFS_DIR2_DATA_FREE_TAG ||
	    be16_to_cpu(dup->length) < size)
		return 0;

	/*
	 * Start converting it to block form.
	 */
	scxfs_dir3_block_init(mp, tp, dbp, dp);

	needlog = 1;
	needscan = 0;
	/*
	 * Use up the space at the end of the block (blp/btp).
	 */
	error = scxfs_dir2_data_use_free(args, dbp, dup,
			args->geo->blksize - size, size, &needlog, &needscan);
	if (error)
		return error;
	/*
	 * Initialize the block tail.
	 */
	btp = scxfs_dir2_block_tail_p(args->geo, hdr);
	btp->count = cpu_to_be32(leafhdr.count - leafhdr.stale);
	btp->stale = 0;
	scxfs_dir2_block_log_tail(tp, dbp);
	/*
	 * Initialize the block leaf area.  We compact out stale entries.
	 */
	lep = scxfs_dir2_block_leaf_p(btp);
	for (from = to = 0; from < leafhdr.count; from++) {
		if (ents[from].address == cpu_to_be32(SCXFS_DIR2_NULL_DATAPTR))
			continue;
		lep[to++] = ents[from];
	}
	ASSERT(to == be32_to_cpu(btp->count));
	scxfs_dir2_block_log_leaf(tp, dbp, 0, be32_to_cpu(btp->count) - 1);
	/*
	 * Scan the bestfree if we need it and log the data block header.
	 */
	if (needscan)
		scxfs_dir2_data_freescan(dp, hdr, &needlog);
	if (needlog)
		scxfs_dir2_data_log_header(args, dbp);
	/*
	 * Pitch the old leaf block.
	 */
	error = scxfs_da_shrink_inode(args, args->geo->leafblk, lbp);
	if (error)
		return error;

	/*
	 * Now see if the resulting block can be shrunken to shortform.
	 */
	size = scxfs_dir2_block_sfsize(dp, hdr, &sfh);
	if (size > SCXFS_IFORK_DSIZE(dp))
		return 0;

	return scxfs_dir2_block_to_sf(args, dbp, size, &sfh);
}

/*
 * Convert the shortform directory to block form.
 */
int						/* error */
scxfs_dir2_sf_to_block(
	scxfs_da_args_t		*args)		/* operation arguments */
{
	scxfs_dir2_db_t		blkno;		/* dir-relative block # (0) */
	scxfs_dir2_data_hdr_t	*hdr;		/* block header */
	scxfs_dir2_leaf_entry_t	*blp;		/* block leaf entries */
	struct scxfs_buf		*bp;		/* block buffer */
	scxfs_dir2_block_tail_t	*btp;		/* block tail pointer */
	scxfs_dir2_data_entry_t	*dep;		/* data entry pointer */
	scxfs_inode_t		*dp;		/* incore directory inode */
	int			dummy;		/* trash */
	scxfs_dir2_data_unused_t	*dup;		/* unused entry pointer */
	int			endoffset;	/* end of data objects */
	int			error;		/* error return value */
	int			i;		/* index */
	scxfs_mount_t		*mp;		/* filesystem mount point */
	int			needlog;	/* need to log block header */
	int			needscan;	/* need to scan block freespc */
	int			newoffset;	/* offset from current entry */
	int			offset;		/* target block offset */
	scxfs_dir2_sf_entry_t	*sfep;		/* sf entry pointer */
	scxfs_dir2_sf_hdr_t	*oldsfp;	/* old shortform header  */
	scxfs_dir2_sf_hdr_t	*sfp;		/* shortform header  */
	__be16			*tagp;		/* end of data entry */
	scxfs_trans_t		*tp;		/* transaction pointer */
	struct scxfs_name		name;
	struct scxfs_ifork	*ifp;

	trace_scxfs_dir2_sf_to_block(args);

	dp = args->dp;
	tp = args->trans;
	mp = dp->i_mount;
	ifp = SCXFS_IFORK_PTR(dp, SCXFS_DATA_FORK);
	ASSERT(ifp->if_flags & SCXFS_IFINLINE);
	/*
	 * Bomb out if the shortform directory is way too short.
	 */
	if (dp->i_d.di_size < offsetof(scxfs_dir2_sf_hdr_t, parent)) {
		ASSERT(SCXFS_FORCED_SHUTDOWN(mp));
		return -EIO;
	}

	oldsfp = (scxfs_dir2_sf_hdr_t *)ifp->if_u1.if_data;

	ASSERT(ifp->if_bytes == dp->i_d.di_size);
	ASSERT(ifp->if_u1.if_data != NULL);
	ASSERT(dp->i_d.di_size >= scxfs_dir2_sf_hdr_size(oldsfp->i8count));
	ASSERT(dp->i_d.di_nextents == 0);

	/*
	 * Copy the directory into a temporary buffer.
	 * Then pitch the incore inode data so we can make extents.
	 */
	sfp = kmem_alloc(ifp->if_bytes, 0);
	memcpy(sfp, oldsfp, ifp->if_bytes);

	scxfs_idata_realloc(dp, -ifp->if_bytes, SCXFS_DATA_FORK);
	scxfs_bmap_local_to_extents_empty(tp, dp, SCXFS_DATA_FORK);
	dp->i_d.di_size = 0;

	/*
	 * Add block 0 to the inode.
	 */
	error = scxfs_dir2_grow_inode(args, SCXFS_DIR2_DATA_SPACE, &blkno);
	if (error)
		goto out_free;
	/*
	 * Initialize the data block, then convert it to block format.
	 */
	error = scxfs_dir3_data_init(args, blkno, &bp);
	if (error)
		goto out_free;
	scxfs_dir3_block_init(mp, tp, bp, dp);
	hdr = bp->b_addr;

	/*
	 * Compute size of block "tail" area.
	 */
	i = (uint)sizeof(*btp) +
	    (sfp->count + 2) * (uint)sizeof(scxfs_dir2_leaf_entry_t);
	/*
	 * The whole thing is initialized to free by the init routine.
	 * Say we're using the leaf and tail area.
	 */
	dup = dp->d_ops->data_unused_p(hdr);
	needlog = needscan = 0;
	error = scxfs_dir2_data_use_free(args, bp, dup, args->geo->blksize - i,
			i, &needlog, &needscan);
	if (error)
		goto out_free;
	ASSERT(needscan == 0);
	/*
	 * Fill in the tail.
	 */
	btp = scxfs_dir2_block_tail_p(args->geo, hdr);
	btp->count = cpu_to_be32(sfp->count + 2);	/* ., .. */
	btp->stale = 0;
	blp = scxfs_dir2_block_leaf_p(btp);
	endoffset = (uint)((char *)blp - (char *)hdr);
	/*
	 * Remove the freespace, we'll manage it.
	 */
	error = scxfs_dir2_data_use_free(args, bp, dup,
			(scxfs_dir2_data_aoff_t)((char *)dup - (char *)hdr),
			be16_to_cpu(dup->length), &needlog, &needscan);
	if (error)
		goto out_free;
	/*
	 * Create entry for .
	 */
	dep = dp->d_ops->data_dot_entry_p(hdr);
	dep->inumber = cpu_to_be64(dp->i_ino);
	dep->namelen = 1;
	dep->name[0] = '.';
	dp->d_ops->data_put_ftype(dep, SCXFS_DIR3_FT_DIR);
	tagp = dp->d_ops->data_entry_tag_p(dep);
	*tagp = cpu_to_be16((char *)dep - (char *)hdr);
	scxfs_dir2_data_log_entry(args, bp, dep);
	blp[0].hashval = cpu_to_be32(scxfs_dir_hash_dot);
	blp[0].address = cpu_to_be32(scxfs_dir2_byte_to_dataptr(
				(char *)dep - (char *)hdr));
	/*
	 * Create entry for ..
	 */
	dep = dp->d_ops->data_dotdot_entry_p(hdr);
	dep->inumber = cpu_to_be64(dp->d_ops->sf_get_parent_ino(sfp));
	dep->namelen = 2;
	dep->name[0] = dep->name[1] = '.';
	dp->d_ops->data_put_ftype(dep, SCXFS_DIR3_FT_DIR);
	tagp = dp->d_ops->data_entry_tag_p(dep);
	*tagp = cpu_to_be16((char *)dep - (char *)hdr);
	scxfs_dir2_data_log_entry(args, bp, dep);
	blp[1].hashval = cpu_to_be32(scxfs_dir_hash_dotdot);
	blp[1].address = cpu_to_be32(scxfs_dir2_byte_to_dataptr(
				(char *)dep - (char *)hdr));
	offset = dp->d_ops->data_first_offset;
	/*
	 * Loop over existing entries, stuff them in.
	 */
	i = 0;
	if (!sfp->count)
		sfep = NULL;
	else
		sfep = scxfs_dir2_sf_firstentry(sfp);
	/*
	 * Need to preserve the existing offset values in the sf directory.
	 * Insert holes (unused entries) where necessary.
	 */
	while (offset < endoffset) {
		/*
		 * sfep is null when we reach the end of the list.
		 */
		if (sfep == NULL)
			newoffset = endoffset;
		else
			newoffset = scxfs_dir2_sf_get_offset(sfep);
		/*
		 * There should be a hole here, make one.
		 */
		if (offset < newoffset) {
			dup = (scxfs_dir2_data_unused_t *)((char *)hdr + offset);
			dup->freetag = cpu_to_be16(SCXFS_DIR2_DATA_FREE_TAG);
			dup->length = cpu_to_be16(newoffset - offset);
			*scxfs_dir2_data_unused_tag_p(dup) = cpu_to_be16(
				((char *)dup - (char *)hdr));
			scxfs_dir2_data_log_unused(args, bp, dup);
			scxfs_dir2_data_freeinsert(hdr,
						 dp->d_ops->data_bestfree_p(hdr),
						 dup, &dummy);
			offset += be16_to_cpu(dup->length);
			continue;
		}
		/*
		 * Copy a real entry.
		 */
		dep = (scxfs_dir2_data_entry_t *)((char *)hdr + newoffset);
		dep->inumber = cpu_to_be64(dp->d_ops->sf_get_ino(sfp, sfep));
		dep->namelen = sfep->namelen;
		dp->d_ops->data_put_ftype(dep, dp->d_ops->sf_get_ftype(sfep));
		memcpy(dep->name, sfep->name, dep->namelen);
		tagp = dp->d_ops->data_entry_tag_p(dep);
		*tagp = cpu_to_be16((char *)dep - (char *)hdr);
		scxfs_dir2_data_log_entry(args, bp, dep);
		name.name = sfep->name;
		name.len = sfep->namelen;
		blp[2 + i].hashval = cpu_to_be32(mp->m_dirnameops->
							hashname(&name));
		blp[2 + i].address = cpu_to_be32(scxfs_dir2_byte_to_dataptr(
						 (char *)dep - (char *)hdr));
		offset = (int)((char *)(tagp + 1) - (char *)hdr);
		if (++i == sfp->count)
			sfep = NULL;
		else
			sfep = dp->d_ops->sf_nextentry(sfp, sfep);
	}
	/* Done with the temporary buffer */
	kmem_free(sfp);
	/*
	 * Sort the leaf entries by hash value.
	 */
	scxfs_sort(blp, be32_to_cpu(btp->count), sizeof(*blp), scxfs_dir2_block_sort);
	/*
	 * Log the leaf entry area and tail.
	 * Already logged the header in data_init, ignore needlog.
	 */
	ASSERT(needscan == 0);
	scxfs_dir2_block_log_leaf(tp, bp, 0, be32_to_cpu(btp->count) - 1);
	scxfs_dir2_block_log_tail(tp, bp);
	scxfs_dir3_data_check(dp, bp);
	return 0;
out_free:
	kmem_free(sfp);
	return error;
}
