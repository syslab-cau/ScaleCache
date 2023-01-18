// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#include "scxfs.h"
#include "scxfs_fs.h"
#include "scxfs_shared.h"
#include "scxfs_format.h"
#include "scxfs_log_format.h"
#include "scxfs_trans_resv.h"
#include "scxfs_bit.h"
#include "scxfs_mount.h"
#include "scxfs_inode.h"
#include "scxfs_bmap.h"
#include "scxfs_trans.h"
#include "scxfs_rtalloc.h"


/*
 * Realtime allocator bitmap functions shared with userspace.
 */

/*
 * Real time buffers need verifiers to avoid runtime warnings during IO.
 * We don't have anything to verify, however, so these are just dummy
 * operations.
 */
static void
scxfs_rtbuf_verify_read(
	struct scxfs_buf	*bp)
{
	return;
}

static void
scxfs_rtbuf_verify_write(
	struct scxfs_buf	*bp)
{
	return;
}

const struct scxfs_buf_ops scxfs_rtbuf_ops = {
	.name = "rtbuf",
	.verify_read = scxfs_rtbuf_verify_read,
	.verify_write = scxfs_rtbuf_verify_write,
};

/*
 * Get a buffer for the bitmap or summary file block specified.
 * The buffer is returned read and locked.
 */
int
scxfs_rtbuf_get(
	scxfs_mount_t	*mp,		/* file system mount structure */
	scxfs_trans_t	*tp,		/* transaction pointer */
	scxfs_rtblock_t	block,		/* block number in bitmap or summary */
	int		issum,		/* is summary not bitmap */
	scxfs_buf_t	**bpp)		/* output: buffer for the block */
{
	scxfs_buf_t	*bp;		/* block buffer, result */
	scxfs_inode_t	*ip;		/* bitmap or summary inode */
	scxfs_bmbt_irec_t	map;
	int		nmap = 1;
	int		error;		/* error value */

	ip = issum ? mp->m_rsumip : mp->m_rbmip;

	error = scxfs_bmapi_read(ip, block, 1, &map, &nmap, SCXFS_DATA_FORK);
	if (error)
		return error;

	if (nmap == 0 || !scxfs_bmap_is_real_extent(&map))
		return -EFSCORRUPTED;

	ASSERT(map.br_startblock != NULLFSBLOCK);
	error = scxfs_trans_read_buf(mp, tp, mp->m_ddev_targp,
				   SCXFS_FSB_TO_DADDR(mp, map.br_startblock),
				   mp->m_bsize, 0, &bp, &scxfs_rtbuf_ops);
	if (error)
		return error;

	scxfs_trans_buf_set_type(tp, bp, issum ? SCXFS_BLFT_RTSUMMARY_BUF
					     : SCXFS_BLFT_RTBITMAP_BUF);
	*bpp = bp;
	return 0;
}

/*
 * Searching backward from start to limit, find the first block whose
 * allocated/free state is different from start's.
 */
int
scxfs_rtfind_back(
	scxfs_mount_t	*mp,		/* file system mount point */
	scxfs_trans_t	*tp,		/* transaction pointer */
	scxfs_rtblock_t	start,		/* starting block to look at */
	scxfs_rtblock_t	limit,		/* last block to look at */
	scxfs_rtblock_t	*rtblock)	/* out: start block found */
{
	scxfs_rtword_t	*b;		/* current word in buffer */
	int		bit;		/* bit number in the word */
	scxfs_rtblock_t	block;		/* bitmap block number */
	scxfs_buf_t	*bp;		/* buf for the block */
	scxfs_rtword_t	*bufp;		/* starting word in buffer */
	int		error;		/* error value */
	scxfs_rtblock_t	firstbit;	/* first useful bit in the word */
	scxfs_rtblock_t	i;		/* current bit number rel. to start */
	scxfs_rtblock_t	len;		/* length of inspected area */
	scxfs_rtword_t	mask;		/* mask of relevant bits for value */
	scxfs_rtword_t	want;		/* mask for "good" values */
	scxfs_rtword_t	wdiff;		/* difference from wanted value */
	int		word;		/* word number in the buffer */

	/*
	 * Compute and read in starting bitmap block for starting block.
	 */
	block = SCXFS_BITTOBLOCK(mp, start);
	error = scxfs_rtbuf_get(mp, tp, block, 0, &bp);
	if (error) {
		return error;
	}
	bufp = bp->b_addr;
	/*
	 * Get the first word's index & point to it.
	 */
	word = SCXFS_BITTOWORD(mp, start);
	b = &bufp[word];
	bit = (int)(start & (SCXFS_NBWORD - 1));
	len = start - limit + 1;
	/*
	 * Compute match value, based on the bit at start: if 1 (free)
	 * then all-ones, else all-zeroes.
	 */
	want = (*b & ((scxfs_rtword_t)1 << bit)) ? -1 : 0;
	/*
	 * If the starting position is not word-aligned, deal with the
	 * partial word.
	 */
	if (bit < SCXFS_NBWORD - 1) {
		/*
		 * Calculate first (leftmost) bit number to look at,
		 * and mask for all the relevant bits in this word.
		 */
		firstbit = SCXFS_RTMAX((scxfs_srtblock_t)(bit - len + 1), 0);
		mask = (((scxfs_rtword_t)1 << (bit - firstbit + 1)) - 1) <<
			firstbit;
		/*
		 * Calculate the difference between the value there
		 * and what we're looking for.
		 */
		if ((wdiff = (*b ^ want) & mask)) {
			/*
			 * Different.  Mark where we are and return.
			 */
			scxfs_trans_brelse(tp, bp);
			i = bit - SCXFS_RTHIBIT(wdiff);
			*rtblock = start - i + 1;
			return 0;
		}
		i = bit - firstbit + 1;
		/*
		 * Go on to previous block if that's where the previous word is
		 * and we need the previous word.
		 */
		if (--word == -1 && i < len) {
			/*
			 * If done with this block, get the previous one.
			 */
			scxfs_trans_brelse(tp, bp);
			error = scxfs_rtbuf_get(mp, tp, --block, 0, &bp);
			if (error) {
				return error;
			}
			bufp = bp->b_addr;
			word = SCXFS_BLOCKWMASK(mp);
			b = &bufp[word];
		} else {
			/*
			 * Go on to the previous word in the buffer.
			 */
			b--;
		}
	} else {
		/*
		 * Starting on a word boundary, no partial word.
		 */
		i = 0;
	}
	/*
	 * Loop over whole words in buffers.  When we use up one buffer
	 * we move on to the previous one.
	 */
	while (len - i >= SCXFS_NBWORD) {
		/*
		 * Compute difference between actual and desired value.
		 */
		if ((wdiff = *b ^ want)) {
			/*
			 * Different, mark where we are and return.
			 */
			scxfs_trans_brelse(tp, bp);
			i += SCXFS_NBWORD - 1 - SCXFS_RTHIBIT(wdiff);
			*rtblock = start - i + 1;
			return 0;
		}
		i += SCXFS_NBWORD;
		/*
		 * Go on to previous block if that's where the previous word is
		 * and we need the previous word.
		 */
		if (--word == -1 && i < len) {
			/*
			 * If done with this block, get the previous one.
			 */
			scxfs_trans_brelse(tp, bp);
			error = scxfs_rtbuf_get(mp, tp, --block, 0, &bp);
			if (error) {
				return error;
			}
			bufp = bp->b_addr;
			word = SCXFS_BLOCKWMASK(mp);
			b = &bufp[word];
		} else {
			/*
			 * Go on to the previous word in the buffer.
			 */
			b--;
		}
	}
	/*
	 * If not ending on a word boundary, deal with the last
	 * (partial) word.
	 */
	if (len - i) {
		/*
		 * Calculate first (leftmost) bit number to look at,
		 * and mask for all the relevant bits in this word.
		 */
		firstbit = SCXFS_NBWORD - (len - i);
		mask = (((scxfs_rtword_t)1 << (len - i)) - 1) << firstbit;
		/*
		 * Compute difference between actual and desired value.
		 */
		if ((wdiff = (*b ^ want) & mask)) {
			/*
			 * Different, mark where we are and return.
			 */
			scxfs_trans_brelse(tp, bp);
			i += SCXFS_NBWORD - 1 - SCXFS_RTHIBIT(wdiff);
			*rtblock = start - i + 1;
			return 0;
		} else
			i = len;
	}
	/*
	 * No match, return that we scanned the whole area.
	 */
	scxfs_trans_brelse(tp, bp);
	*rtblock = start - i + 1;
	return 0;
}

/*
 * Searching forward from start to limit, find the first block whose
 * allocated/free state is different from start's.
 */
int
scxfs_rtfind_forw(
	scxfs_mount_t	*mp,		/* file system mount point */
	scxfs_trans_t	*tp,		/* transaction pointer */
	scxfs_rtblock_t	start,		/* starting block to look at */
	scxfs_rtblock_t	limit,		/* last block to look at */
	scxfs_rtblock_t	*rtblock)	/* out: start block found */
{
	scxfs_rtword_t	*b;		/* current word in buffer */
	int		bit;		/* bit number in the word */
	scxfs_rtblock_t	block;		/* bitmap block number */
	scxfs_buf_t	*bp;		/* buf for the block */
	scxfs_rtword_t	*bufp;		/* starting word in buffer */
	int		error;		/* error value */
	scxfs_rtblock_t	i;		/* current bit number rel. to start */
	scxfs_rtblock_t	lastbit;	/* last useful bit in the word */
	scxfs_rtblock_t	len;		/* length of inspected area */
	scxfs_rtword_t	mask;		/* mask of relevant bits for value */
	scxfs_rtword_t	want;		/* mask for "good" values */
	scxfs_rtword_t	wdiff;		/* difference from wanted value */
	int		word;		/* word number in the buffer */

	/*
	 * Compute and read in starting bitmap block for starting block.
	 */
	block = SCXFS_BITTOBLOCK(mp, start);
	error = scxfs_rtbuf_get(mp, tp, block, 0, &bp);
	if (error) {
		return error;
	}
	bufp = bp->b_addr;
	/*
	 * Get the first word's index & point to it.
	 */
	word = SCXFS_BITTOWORD(mp, start);
	b = &bufp[word];
	bit = (int)(start & (SCXFS_NBWORD - 1));
	len = limit - start + 1;
	/*
	 * Compute match value, based on the bit at start: if 1 (free)
	 * then all-ones, else all-zeroes.
	 */
	want = (*b & ((scxfs_rtword_t)1 << bit)) ? -1 : 0;
	/*
	 * If the starting position is not word-aligned, deal with the
	 * partial word.
	 */
	if (bit) {
		/*
		 * Calculate last (rightmost) bit number to look at,
		 * and mask for all the relevant bits in this word.
		 */
		lastbit = SCXFS_RTMIN(bit + len, SCXFS_NBWORD);
		mask = (((scxfs_rtword_t)1 << (lastbit - bit)) - 1) << bit;
		/*
		 * Calculate the difference between the value there
		 * and what we're looking for.
		 */
		if ((wdiff = (*b ^ want) & mask)) {
			/*
			 * Different.  Mark where we are and return.
			 */
			scxfs_trans_brelse(tp, bp);
			i = SCXFS_RTLOBIT(wdiff) - bit;
			*rtblock = start + i - 1;
			return 0;
		}
		i = lastbit - bit;
		/*
		 * Go on to next block if that's where the next word is
		 * and we need the next word.
		 */
		if (++word == SCXFS_BLOCKWSIZE(mp) && i < len) {
			/*
			 * If done with this block, get the previous one.
			 */
			scxfs_trans_brelse(tp, bp);
			error = scxfs_rtbuf_get(mp, tp, ++block, 0, &bp);
			if (error) {
				return error;
			}
			b = bufp = bp->b_addr;
			word = 0;
		} else {
			/*
			 * Go on to the previous word in the buffer.
			 */
			b++;
		}
	} else {
		/*
		 * Starting on a word boundary, no partial word.
		 */
		i = 0;
	}
	/*
	 * Loop over whole words in buffers.  When we use up one buffer
	 * we move on to the next one.
	 */
	while (len - i >= SCXFS_NBWORD) {
		/*
		 * Compute difference between actual and desired value.
		 */
		if ((wdiff = *b ^ want)) {
			/*
			 * Different, mark where we are and return.
			 */
			scxfs_trans_brelse(tp, bp);
			i += SCXFS_RTLOBIT(wdiff);
			*rtblock = start + i - 1;
			return 0;
		}
		i += SCXFS_NBWORD;
		/*
		 * Go on to next block if that's where the next word is
		 * and we need the next word.
		 */
		if (++word == SCXFS_BLOCKWSIZE(mp) && i < len) {
			/*
			 * If done with this block, get the next one.
			 */
			scxfs_trans_brelse(tp, bp);
			error = scxfs_rtbuf_get(mp, tp, ++block, 0, &bp);
			if (error) {
				return error;
			}
			b = bufp = bp->b_addr;
			word = 0;
		} else {
			/*
			 * Go on to the next word in the buffer.
			 */
			b++;
		}
	}
	/*
	 * If not ending on a word boundary, deal with the last
	 * (partial) word.
	 */
	if ((lastbit = len - i)) {
		/*
		 * Calculate mask for all the relevant bits in this word.
		 */
		mask = ((scxfs_rtword_t)1 << lastbit) - 1;
		/*
		 * Compute difference between actual and desired value.
		 */
		if ((wdiff = (*b ^ want) & mask)) {
			/*
			 * Different, mark where we are and return.
			 */
			scxfs_trans_brelse(tp, bp);
			i += SCXFS_RTLOBIT(wdiff);
			*rtblock = start + i - 1;
			return 0;
		} else
			i = len;
	}
	/*
	 * No match, return that we scanned the whole area.
	 */
	scxfs_trans_brelse(tp, bp);
	*rtblock = start + i - 1;
	return 0;
}

/*
 * Read and/or modify the summary information for a given extent size,
 * bitmap block combination.
 * Keeps track of a current summary block, so we don't keep reading
 * it from the buffer cache.
 *
 * Summary information is returned in *sum if specified.
 * If no delta is specified, returns summary only.
 */
int
scxfs_rtmodify_summary_int(
	scxfs_mount_t	*mp,		/* file system mount structure */
	scxfs_trans_t	*tp,		/* transaction pointer */
	int		log,		/* log2 of extent size */
	scxfs_rtblock_t	bbno,		/* bitmap block number */
	int		delta,		/* change to make to summary info */
	scxfs_buf_t	**rbpp,		/* in/out: summary block buffer */
	scxfs_fsblock_t	*rsb,		/* in/out: summary block number */
	scxfs_suminfo_t	*sum)		/* out: summary info for this block */
{
	scxfs_buf_t	*bp;		/* buffer for the summary block */
	int		error;		/* error value */
	scxfs_fsblock_t	sb;		/* summary fsblock */
	int		so;		/* index into the summary file */
	scxfs_suminfo_t	*sp;		/* pointer to returned data */

	/*
	 * Compute entry number in the summary file.
	 */
	so = SCXFS_SUMOFFS(mp, log, bbno);
	/*
	 * Compute the block number in the summary file.
	 */
	sb = SCXFS_SUMOFFSTOBLOCK(mp, so);
	/*
	 * If we have an old buffer, and the block number matches, use that.
	 */
	if (*rbpp && *rsb == sb)
		bp = *rbpp;
	/*
	 * Otherwise we have to get the buffer.
	 */
	else {
		/*
		 * If there was an old one, get rid of it first.
		 */
		if (*rbpp)
			scxfs_trans_brelse(tp, *rbpp);
		error = scxfs_rtbuf_get(mp, tp, sb, 1, &bp);
		if (error) {
			return error;
		}
		/*
		 * Remember this buffer and block for the next call.
		 */
		*rbpp = bp;
		*rsb = sb;
	}
	/*
	 * Point to the summary information, modify/log it, and/or copy it out.
	 */
	sp = SCXFS_SUMPTR(mp, bp, so);
	if (delta) {
		uint first = (uint)((char *)sp - (char *)bp->b_addr);

		*sp += delta;
		if (mp->m_rsum_cache) {
			if (*sp == 0 && log == mp->m_rsum_cache[bbno])
				mp->m_rsum_cache[bbno]++;
			if (*sp != 0 && log < mp->m_rsum_cache[bbno])
				mp->m_rsum_cache[bbno] = log;
		}
		scxfs_trans_log_buf(tp, bp, first, first + sizeof(*sp) - 1);
	}
	if (sum)
		*sum = *sp;
	return 0;
}

int
scxfs_rtmodify_summary(
	scxfs_mount_t	*mp,		/* file system mount structure */
	scxfs_trans_t	*tp,		/* transaction pointer */
	int		log,		/* log2 of extent size */
	scxfs_rtblock_t	bbno,		/* bitmap block number */
	int		delta,		/* change to make to summary info */
	scxfs_buf_t	**rbpp,		/* in/out: summary block buffer */
	scxfs_fsblock_t	*rsb)		/* in/out: summary block number */
{
	return scxfs_rtmodify_summary_int(mp, tp, log, bbno,
					delta, rbpp, rsb, NULL);
}

/*
 * Set the given range of bitmap bits to the given value.
 * Do whatever I/O and logging is required.
 */
int
scxfs_rtmodify_range(
	scxfs_mount_t	*mp,		/* file system mount point */
	scxfs_trans_t	*tp,		/* transaction pointer */
	scxfs_rtblock_t	start,		/* starting block to modify */
	scxfs_extlen_t	len,		/* length of extent to modify */
	int		val)		/* 1 for free, 0 for allocated */
{
	scxfs_rtword_t	*b;		/* current word in buffer */
	int		bit;		/* bit number in the word */
	scxfs_rtblock_t	block;		/* bitmap block number */
	scxfs_buf_t	*bp;		/* buf for the block */
	scxfs_rtword_t	*bufp;		/* starting word in buffer */
	int		error;		/* error value */
	scxfs_rtword_t	*first;		/* first used word in the buffer */
	int		i;		/* current bit number rel. to start */
	int		lastbit;	/* last useful bit in word */
	scxfs_rtword_t	mask;		/* mask o frelevant bits for value */
	int		word;		/* word number in the buffer */

	/*
	 * Compute starting bitmap block number.
	 */
	block = SCXFS_BITTOBLOCK(mp, start);
	/*
	 * Read the bitmap block, and point to its data.
	 */
	error = scxfs_rtbuf_get(mp, tp, block, 0, &bp);
	if (error) {
		return error;
	}
	bufp = bp->b_addr;
	/*
	 * Compute the starting word's address, and starting bit.
	 */
	word = SCXFS_BITTOWORD(mp, start);
	first = b = &bufp[word];
	bit = (int)(start & (SCXFS_NBWORD - 1));
	/*
	 * 0 (allocated) => all zeroes; 1 (free) => all ones.
	 */
	val = -val;
	/*
	 * If not starting on a word boundary, deal with the first
	 * (partial) word.
	 */
	if (bit) {
		/*
		 * Compute first bit not changed and mask of relevant bits.
		 */
		lastbit = SCXFS_RTMIN(bit + len, SCXFS_NBWORD);
		mask = (((scxfs_rtword_t)1 << (lastbit - bit)) - 1) << bit;
		/*
		 * Set/clear the active bits.
		 */
		if (val)
			*b |= mask;
		else
			*b &= ~mask;
		i = lastbit - bit;
		/*
		 * Go on to the next block if that's where the next word is
		 * and we need the next word.
		 */
		if (++word == SCXFS_BLOCKWSIZE(mp) && i < len) {
			/*
			 * Log the changed part of this block.
			 * Get the next one.
			 */
			scxfs_trans_log_buf(tp, bp,
				(uint)((char *)first - (char *)bufp),
				(uint)((char *)b - (char *)bufp));
			error = scxfs_rtbuf_get(mp, tp, ++block, 0, &bp);
			if (error) {
				return error;
			}
			first = b = bufp = bp->b_addr;
			word = 0;
		} else {
			/*
			 * Go on to the next word in the buffer
			 */
			b++;
		}
	} else {
		/*
		 * Starting on a word boundary, no partial word.
		 */
		i = 0;
	}
	/*
	 * Loop over whole words in buffers.  When we use up one buffer
	 * we move on to the next one.
	 */
	while (len - i >= SCXFS_NBWORD) {
		/*
		 * Set the word value correctly.
		 */
		*b = val;
		i += SCXFS_NBWORD;
		/*
		 * Go on to the next block if that's where the next word is
		 * and we need the next word.
		 */
		if (++word == SCXFS_BLOCKWSIZE(mp) && i < len) {
			/*
			 * Log the changed part of this block.
			 * Get the next one.
			 */
			scxfs_trans_log_buf(tp, bp,
				(uint)((char *)first - (char *)bufp),
				(uint)((char *)b - (char *)bufp));
			error = scxfs_rtbuf_get(mp, tp, ++block, 0, &bp);
			if (error) {
				return error;
			}
			first = b = bufp = bp->b_addr;
			word = 0;
		} else {
			/*
			 * Go on to the next word in the buffer
			 */
			b++;
		}
	}
	/*
	 * If not ending on a word boundary, deal with the last
	 * (partial) word.
	 */
	if ((lastbit = len - i)) {
		/*
		 * Compute a mask of relevant bits.
		 */
		mask = ((scxfs_rtword_t)1 << lastbit) - 1;
		/*
		 * Set/clear the active bits.
		 */
		if (val)
			*b |= mask;
		else
			*b &= ~mask;
		b++;
	}
	/*
	 * Log any remaining changed bytes.
	 */
	if (b > first)
		scxfs_trans_log_buf(tp, bp, (uint)((char *)first - (char *)bufp),
			(uint)((char *)b - (char *)bufp - 1));
	return 0;
}

/*
 * Mark an extent specified by start and len freed.
 * Updates all the summary information as well as the bitmap.
 */
int
scxfs_rtfree_range(
	scxfs_mount_t	*mp,		/* file system mount point */
	scxfs_trans_t	*tp,		/* transaction pointer */
	scxfs_rtblock_t	start,		/* starting block to free */
	scxfs_extlen_t	len,		/* length to free */
	scxfs_buf_t	**rbpp,		/* in/out: summary block buffer */
	scxfs_fsblock_t	*rsb)		/* in/out: summary block number */
{
	scxfs_rtblock_t	end;		/* end of the freed extent */
	int		error;		/* error value */
	scxfs_rtblock_t	postblock;	/* first block freed > end */
	scxfs_rtblock_t	preblock;	/* first block freed < start */

	end = start + len - 1;
	/*
	 * Modify the bitmap to mark this extent freed.
	 */
	error = scxfs_rtmodify_range(mp, tp, start, len, 1);
	if (error) {
		return error;
	}
	/*
	 * Assume we're freeing out of the middle of an allocated extent.
	 * We need to find the beginning and end of the extent so we can
	 * properly update the summary.
	 */
	error = scxfs_rtfind_back(mp, tp, start, 0, &preblock);
	if (error) {
		return error;
	}
	/*
	 * Find the next allocated block (end of allocated extent).
	 */
	error = scxfs_rtfind_forw(mp, tp, end, mp->m_sb.sb_rextents - 1,
		&postblock);
	if (error)
		return error;
	/*
	 * If there are blocks not being freed at the front of the
	 * old extent, add summary data for them to be allocated.
	 */
	if (preblock < start) {
		error = scxfs_rtmodify_summary(mp, tp,
			SCXFS_RTBLOCKLOG(start - preblock),
			SCXFS_BITTOBLOCK(mp, preblock), -1, rbpp, rsb);
		if (error) {
			return error;
		}
	}
	/*
	 * If there are blocks not being freed at the end of the
	 * old extent, add summary data for them to be allocated.
	 */
	if (postblock > end) {
		error = scxfs_rtmodify_summary(mp, tp,
			SCXFS_RTBLOCKLOG(postblock - end),
			SCXFS_BITTOBLOCK(mp, end + 1), -1, rbpp, rsb);
		if (error) {
			return error;
		}
	}
	/*
	 * Increment the summary information corresponding to the entire
	 * (new) free extent.
	 */
	error = scxfs_rtmodify_summary(mp, tp,
		SCXFS_RTBLOCKLOG(postblock + 1 - preblock),
		SCXFS_BITTOBLOCK(mp, preblock), 1, rbpp, rsb);
	return error;
}

/*
 * Check that the given range is either all allocated (val = 0) or
 * all free (val = 1).
 */
int
scxfs_rtcheck_range(
	scxfs_mount_t	*mp,		/* file system mount point */
	scxfs_trans_t	*tp,		/* transaction pointer */
	scxfs_rtblock_t	start,		/* starting block number of extent */
	scxfs_extlen_t	len,		/* length of extent */
	int		val,		/* 1 for free, 0 for allocated */
	scxfs_rtblock_t	*new,		/* out: first block not matching */
	int		*stat)		/* out: 1 for matches, 0 for not */
{
	scxfs_rtword_t	*b;		/* current word in buffer */
	int		bit;		/* bit number in the word */
	scxfs_rtblock_t	block;		/* bitmap block number */
	scxfs_buf_t	*bp;		/* buf for the block */
	scxfs_rtword_t	*bufp;		/* starting word in buffer */
	int		error;		/* error value */
	scxfs_rtblock_t	i;		/* current bit number rel. to start */
	scxfs_rtblock_t	lastbit;	/* last useful bit in word */
	scxfs_rtword_t	mask;		/* mask of relevant bits for value */
	scxfs_rtword_t	wdiff;		/* difference from wanted value */
	int		word;		/* word number in the buffer */

	/*
	 * Compute starting bitmap block number
	 */
	block = SCXFS_BITTOBLOCK(mp, start);
	/*
	 * Read the bitmap block.
	 */
	error = scxfs_rtbuf_get(mp, tp, block, 0, &bp);
	if (error) {
		return error;
	}
	bufp = bp->b_addr;
	/*
	 * Compute the starting word's address, and starting bit.
	 */
	word = SCXFS_BITTOWORD(mp, start);
	b = &bufp[word];
	bit = (int)(start & (SCXFS_NBWORD - 1));
	/*
	 * 0 (allocated) => all zero's; 1 (free) => all one's.
	 */
	val = -val;
	/*
	 * If not starting on a word boundary, deal with the first
	 * (partial) word.
	 */
	if (bit) {
		/*
		 * Compute first bit not examined.
		 */
		lastbit = SCXFS_RTMIN(bit + len, SCXFS_NBWORD);
		/*
		 * Mask of relevant bits.
		 */
		mask = (((scxfs_rtword_t)1 << (lastbit - bit)) - 1) << bit;
		/*
		 * Compute difference between actual and desired value.
		 */
		if ((wdiff = (*b ^ val) & mask)) {
			/*
			 * Different, compute first wrong bit and return.
			 */
			scxfs_trans_brelse(tp, bp);
			i = SCXFS_RTLOBIT(wdiff) - bit;
			*new = start + i;
			*stat = 0;
			return 0;
		}
		i = lastbit - bit;
		/*
		 * Go on to next block if that's where the next word is
		 * and we need the next word.
		 */
		if (++word == SCXFS_BLOCKWSIZE(mp) && i < len) {
			/*
			 * If done with this block, get the next one.
			 */
			scxfs_trans_brelse(tp, bp);
			error = scxfs_rtbuf_get(mp, tp, ++block, 0, &bp);
			if (error) {
				return error;
			}
			b = bufp = bp->b_addr;
			word = 0;
		} else {
			/*
			 * Go on to the next word in the buffer.
			 */
			b++;
		}
	} else {
		/*
		 * Starting on a word boundary, no partial word.
		 */
		i = 0;
	}
	/*
	 * Loop over whole words in buffers.  When we use up one buffer
	 * we move on to the next one.
	 */
	while (len - i >= SCXFS_NBWORD) {
		/*
		 * Compute difference between actual and desired value.
		 */
		if ((wdiff = *b ^ val)) {
			/*
			 * Different, compute first wrong bit and return.
			 */
			scxfs_trans_brelse(tp, bp);
			i += SCXFS_RTLOBIT(wdiff);
			*new = start + i;
			*stat = 0;
			return 0;
		}
		i += SCXFS_NBWORD;
		/*
		 * Go on to next block if that's where the next word is
		 * and we need the next word.
		 */
		if (++word == SCXFS_BLOCKWSIZE(mp) && i < len) {
			/*
			 * If done with this block, get the next one.
			 */
			scxfs_trans_brelse(tp, bp);
			error = scxfs_rtbuf_get(mp, tp, ++block, 0, &bp);
			if (error) {
				return error;
			}
			b = bufp = bp->b_addr;
			word = 0;
		} else {
			/*
			 * Go on to the next word in the buffer.
			 */
			b++;
		}
	}
	/*
	 * If not ending on a word boundary, deal with the last
	 * (partial) word.
	 */
	if ((lastbit = len - i)) {
		/*
		 * Mask of relevant bits.
		 */
		mask = ((scxfs_rtword_t)1 << lastbit) - 1;
		/*
		 * Compute difference between actual and desired value.
		 */
		if ((wdiff = (*b ^ val) & mask)) {
			/*
			 * Different, compute first wrong bit and return.
			 */
			scxfs_trans_brelse(tp, bp);
			i += SCXFS_RTLOBIT(wdiff);
			*new = start + i;
			*stat = 0;
			return 0;
		} else
			i = len;
	}
	/*
	 * Successful, return.
	 */
	scxfs_trans_brelse(tp, bp);
	*new = start + i;
	*stat = 1;
	return 0;
}

#ifdef DEBUG
/*
 * Check that the given extent (block range) is allocated already.
 */
STATIC int				/* error */
scxfs_rtcheck_alloc_range(
	scxfs_mount_t	*mp,		/* file system mount point */
	scxfs_trans_t	*tp,		/* transaction pointer */
	scxfs_rtblock_t	bno,		/* starting block number of extent */
	scxfs_extlen_t	len)		/* length of extent */
{
	scxfs_rtblock_t	new;		/* dummy for scxfs_rtcheck_range */
	int		stat;
	int		error;

	error = scxfs_rtcheck_range(mp, tp, bno, len, 0, &new, &stat);
	if (error)
		return error;
	ASSERT(stat);
	return 0;
}
#else
#define scxfs_rtcheck_alloc_range(m,t,b,l)	(0)
#endif
/*
 * Free an extent in the realtime subvolume.  Length is expressed in
 * realtime extents, as is the block number.
 */
int					/* error */
scxfs_rtfree_extent(
	scxfs_trans_t	*tp,		/* transaction pointer */
	scxfs_rtblock_t	bno,		/* starting block number to free */
	scxfs_extlen_t	len)		/* length of extent freed */
{
	int		error;		/* error value */
	scxfs_mount_t	*mp;		/* file system mount structure */
	scxfs_fsblock_t	sb;		/* summary file block number */
	scxfs_buf_t	*sumbp = NULL;	/* summary file block buffer */

	mp = tp->t_mountp;

	ASSERT(mp->m_rbmip->i_itemp != NULL);
	ASSERT(scxfs_isilocked(mp->m_rbmip, SCXFS_ILOCK_EXCL));

	error = scxfs_rtcheck_alloc_range(mp, tp, bno, len);
	if (error)
		return error;

	/*
	 * Free the range of realtime blocks.
	 */
	error = scxfs_rtfree_range(mp, tp, bno, len, &sumbp, &sb);
	if (error) {
		return error;
	}
	/*
	 * Mark more blocks free in the superblock.
	 */
	scxfs_trans_mod_sb(tp, SCXFS_TRANS_SB_FREXTENTS, (long)len);
	/*
	 * If we've now freed all the blocks, reset the file sequence
	 * number to 0.
	 */
	if (tp->t_frextents_delta + mp->m_sb.sb_frextents ==
	    mp->m_sb.sb_rextents) {
		if (!(mp->m_rbmip->i_d.di_flags & SCXFS_DIFLAG_NEWRTBM))
			mp->m_rbmip->i_d.di_flags |= SCXFS_DIFLAG_NEWRTBM;
		*(uint64_t *)&VFS_I(mp->m_rbmip)->i_atime = 0;
		scxfs_trans_log_inode(tp, mp->m_rbmip, SCXFS_ILOG_CORE);
	}
	return 0;
}

/* Find all the free records within a given range. */
int
scxfs_rtalloc_query_range(
	struct scxfs_trans		*tp,
	struct scxfs_rtalloc_rec		*low_rec,
	struct scxfs_rtalloc_rec		*high_rec,
	scxfs_rtalloc_query_range_fn	fn,
	void				*priv)
{
	struct scxfs_rtalloc_rec		rec;
	struct scxfs_mount		*mp = tp->t_mountp;
	scxfs_rtblock_t			rtstart;
	scxfs_rtblock_t			rtend;
	int				is_free;
	int				error = 0;

	if (low_rec->ar_startext > high_rec->ar_startext)
		return -EINVAL;
	if (low_rec->ar_startext >= mp->m_sb.sb_rextents ||
	    low_rec->ar_startext == high_rec->ar_startext)
		return 0;
	high_rec->ar_startext = min(high_rec->ar_startext,
			mp->m_sb.sb_rextents - 1);

	/* Iterate the bitmap, looking for discrepancies. */
	rtstart = low_rec->ar_startext;
	while (rtstart <= high_rec->ar_startext) {
		/* Is the first block free? */
		error = scxfs_rtcheck_range(mp, tp, rtstart, 1, 1, &rtend,
				&is_free);
		if (error)
			break;

		/* How long does the extent go for? */
		error = scxfs_rtfind_forw(mp, tp, rtstart,
				high_rec->ar_startext, &rtend);
		if (error)
			break;

		if (is_free) {
			rec.ar_startext = rtstart;
			rec.ar_extcount = rtend - rtstart + 1;

			error = fn(tp, &rec, priv);
			if (error)
				break;
		}

		rtstart = rtend + 1;
	}

	return error;
}

/* Find all the free records. */
int
scxfs_rtalloc_query_all(
	struct scxfs_trans		*tp,
	scxfs_rtalloc_query_range_fn	fn,
	void				*priv)
{
	struct scxfs_rtalloc_rec		keys[2];

	keys[0].ar_startext = 0;
	keys[1].ar_startext = tp->t_mountp->m_sb.sb_rextents - 1;
	keys[0].ar_extcount = keys[1].ar_extcount = 0;

	return scxfs_rtalloc_query_range(tp, &keys[0], &keys[1], fn, priv);
}

/* Is the given extent all free? */
int
scxfs_rtalloc_extent_is_free(
	struct scxfs_mount		*mp,
	struct scxfs_trans		*tp,
	scxfs_rtblock_t			start,
	scxfs_extlen_t			len,
	bool				*is_free)
{
	scxfs_rtblock_t			end;
	int				matches;
	int				error;

	error = scxfs_rtcheck_range(mp, tp, start, len, 1, &end, &matches);
	if (error)
		return error;

	*is_free = matches;
	return 0;
}