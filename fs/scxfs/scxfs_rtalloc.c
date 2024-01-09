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
#include "scxfs_bmap_btree.h"
#include "scxfs_trans.h"
#include "scxfs_trans_space.h"
#include "scxfs_icache.h"
#include "scxfs_rtalloc.h"


/*
 * Read and return the summary information for a given extent size,
 * bitmap block combination.
 * Keeps track of a current summary block, so we don't keep reading
 * it from the buffer cache.
 */
static int
scxfs_rtget_summary(
	scxfs_mount_t	*mp,		/* file system mount structure */
	scxfs_trans_t	*tp,		/* transaction pointer */
	int		log,		/* log2 of extent size */
	scxfs_rtblock_t	bbno,		/* bitmap block number */
	scxfs_buf_t	**rbpp,		/* in/out: summary block buffer */
	scxfs_fsblock_t	*rsb,		/* in/out: summary block number */
	scxfs_suminfo_t	*sum)		/* out: summary info for this block */
{
	return scxfs_rtmodify_summary_int(mp, tp, log, bbno, 0, rbpp, rsb, sum);
}

/*
 * Return whether there are any free extents in the size range given
 * by low and high, for the bitmap block bbno.
 */
STATIC int				/* error */
scxfs_rtany_summary(
	scxfs_mount_t	*mp,		/* file system mount structure */
	scxfs_trans_t	*tp,		/* transaction pointer */
	int		low,		/* low log2 extent size */
	int		high,		/* high log2 extent size */
	scxfs_rtblock_t	bbno,		/* bitmap block number */
	scxfs_buf_t	**rbpp,		/* in/out: summary block buffer */
	scxfs_fsblock_t	*rsb,		/* in/out: summary block number */
	int		*stat)		/* out: any good extents here? */
{
	int		error;		/* error value */
	int		log;		/* loop counter, log2 of ext. size */
	scxfs_suminfo_t	sum;		/* summary data */

	/* There are no extents at levels < m_rsum_cache[bbno]. */
	if (mp->m_rsum_cache && low < mp->m_rsum_cache[bbno])
		low = mp->m_rsum_cache[bbno];

	/*
	 * Loop over logs of extent sizes.
	 */
	for (log = low; log <= high; log++) {
		/*
		 * Get one summary datum.
		 */
		error = scxfs_rtget_summary(mp, tp, log, bbno, rbpp, rsb, &sum);
		if (error) {
			return error;
		}
		/*
		 * If there are any, return success.
		 */
		if (sum) {
			*stat = 1;
			goto out;
		}
	}
	/*
	 * Found nothing, return failure.
	 */
	*stat = 0;
out:
	/* There were no extents at levels < log. */
	if (mp->m_rsum_cache && log > mp->m_rsum_cache[bbno])
		mp->m_rsum_cache[bbno] = log;
	return 0;
}


/*
 * Copy and transform the summary file, given the old and new
 * parameters in the mount structures.
 */
STATIC int				/* error */
scxfs_rtcopy_summary(
	scxfs_mount_t	*omp,		/* old file system mount point */
	scxfs_mount_t	*nmp,		/* new file system mount point */
	scxfs_trans_t	*tp)		/* transaction pointer */
{
	scxfs_rtblock_t	bbno;		/* bitmap block number */
	scxfs_buf_t	*bp;		/* summary buffer */
	int		error;		/* error return value */
	int		log;		/* summary level number (log length) */
	scxfs_suminfo_t	sum;		/* summary data */
	scxfs_fsblock_t	sumbno;		/* summary block number */

	bp = NULL;
	for (log = omp->m_rsumlevels - 1; log >= 0; log--) {
		for (bbno = omp->m_sb.sb_rbmblocks - 1;
		     (scxfs_srtblock_t)bbno >= 0;
		     bbno--) {
			error = scxfs_rtget_summary(omp, tp, log, bbno, &bp,
				&sumbno, &sum);
			if (error)
				return error;
			if (sum == 0)
				continue;
			error = scxfs_rtmodify_summary(omp, tp, log, bbno, -sum,
				&bp, &sumbno);
			if (error)
				return error;
			error = scxfs_rtmodify_summary(nmp, tp, log, bbno, sum,
				&bp, &sumbno);
			if (error)
				return error;
			ASSERT(sum > 0);
		}
	}
	return 0;
}
/*
 * Mark an extent specified by start and len allocated.
 * Updates all the summary information as well as the bitmap.
 */
STATIC int				/* error */
scxfs_rtallocate_range(
	scxfs_mount_t	*mp,		/* file system mount point */
	scxfs_trans_t	*tp,		/* transaction pointer */
	scxfs_rtblock_t	start,		/* start block to allocate */
	scxfs_extlen_t	len,		/* length to allocate */
	scxfs_buf_t	**rbpp,		/* in/out: summary block buffer */
	scxfs_fsblock_t	*rsb)		/* in/out: summary block number */
{
	scxfs_rtblock_t	end;		/* end of the allocated extent */
	int		error;		/* error value */
	scxfs_rtblock_t	postblock = 0;	/* first block allocated > end */
	scxfs_rtblock_t	preblock = 0;	/* first block allocated < start */

	end = start + len - 1;
	/*
	 * Assume we're allocating out of the middle of a free extent.
	 * We need to find the beginning and end of the extent so we can
	 * properly update the summary.
	 */
	error = scxfs_rtfind_back(mp, tp, start, 0, &preblock);
	if (error) {
		return error;
	}
	/*
	 * Find the next allocated block (end of free extent).
	 */
	error = scxfs_rtfind_forw(mp, tp, end, mp->m_sb.sb_rextents - 1,
		&postblock);
	if (error) {
		return error;
	}
	/*
	 * Decrement the summary information corresponding to the entire
	 * (old) free extent.
	 */
	error = scxfs_rtmodify_summary(mp, tp,
		SCXFS_RTBLOCKLOG(postblock + 1 - preblock),
		SCXFS_BITTOBLOCK(mp, preblock), -1, rbpp, rsb);
	if (error) {
		return error;
	}
	/*
	 * If there are blocks not being allocated at the front of the
	 * old extent, add summary data for them to be free.
	 */
	if (preblock < start) {
		error = scxfs_rtmodify_summary(mp, tp,
			SCXFS_RTBLOCKLOG(start - preblock),
			SCXFS_BITTOBLOCK(mp, preblock), 1, rbpp, rsb);
		if (error) {
			return error;
		}
	}
	/*
	 * If there are blocks not being allocated at the end of the
	 * old extent, add summary data for them to be free.
	 */
	if (postblock > end) {
		error = scxfs_rtmodify_summary(mp, tp,
			SCXFS_RTBLOCKLOG(postblock - end),
			SCXFS_BITTOBLOCK(mp, end + 1), 1, rbpp, rsb);
		if (error) {
			return error;
		}
	}
	/*
	 * Modify the bitmap to mark this extent allocated.
	 */
	error = scxfs_rtmodify_range(mp, tp, start, len, 0);
	return error;
}

/*
 * Attempt to allocate an extent minlen<=len<=maxlen starting from
 * bitmap block bbno.  If we don't get maxlen then use prod to trim
 * the length, if given.  Returns error; returns starting block in *rtblock.
 * The lengths are all in rtextents.
 */
STATIC int				/* error */
scxfs_rtallocate_extent_block(
	scxfs_mount_t	*mp,		/* file system mount point */
	scxfs_trans_t	*tp,		/* transaction pointer */
	scxfs_rtblock_t	bbno,		/* bitmap block number */
	scxfs_extlen_t	minlen,		/* minimum length to allocate */
	scxfs_extlen_t	maxlen,		/* maximum length to allocate */
	scxfs_extlen_t	*len,		/* out: actual length allocated */
	scxfs_rtblock_t	*nextp,		/* out: next block to try */
	scxfs_buf_t	**rbpp,		/* in/out: summary block buffer */
	scxfs_fsblock_t	*rsb,		/* in/out: summary block number */
	scxfs_extlen_t	prod,		/* extent product factor */
	scxfs_rtblock_t	*rtblock)	/* out: start block allocated */
{
	scxfs_rtblock_t	besti;		/* best rtblock found so far */
	scxfs_rtblock_t	bestlen;	/* best length found so far */
	scxfs_rtblock_t	end;		/* last rtblock in chunk */
	int		error;		/* error value */
	scxfs_rtblock_t	i;		/* current rtblock trying */
	scxfs_rtblock_t	next;		/* next rtblock to try */
	int		stat;		/* status from internal calls */

	/*
	 * Loop over all the extents starting in this bitmap block,
	 * looking for one that's long enough.
	 */
	for (i = SCXFS_BLOCKTOBIT(mp, bbno), besti = -1, bestlen = 0,
		end = SCXFS_BLOCKTOBIT(mp, bbno + 1) - 1;
	     i <= end;
	     i++) {
		/* Make sure we don't scan off the end of the rt volume. */
		maxlen = min(mp->m_sb.sb_rextents, i + maxlen) - i;

		/*
		 * See if there's a free extent of maxlen starting at i.
		 * If it's not so then next will contain the first non-free.
		 */
		error = scxfs_rtcheck_range(mp, tp, i, maxlen, 1, &next, &stat);
		if (error) {
			return error;
		}
		if (stat) {
			/*
			 * i for maxlen is all free, allocate and return that.
			 */
			error = scxfs_rtallocate_range(mp, tp, i, maxlen, rbpp,
				rsb);
			if (error) {
				return error;
			}
			*len = maxlen;
			*rtblock = i;
			return 0;
		}
		/*
		 * In the case where we have a variable-sized allocation
		 * request, figure out how big this free piece is,
		 * and if it's big enough for the minimum, and the best
		 * so far, remember it.
		 */
		if (minlen < maxlen) {
			scxfs_rtblock_t	thislen;	/* this extent size */

			thislen = next - i;
			if (thislen >= minlen && thislen > bestlen) {
				besti = i;
				bestlen = thislen;
			}
		}
		/*
		 * If not done yet, find the start of the next free space.
		 */
		if (next < end) {
			error = scxfs_rtfind_forw(mp, tp, next, end, &i);
			if (error) {
				return error;
			}
		} else
			break;
	}
	/*
	 * Searched the whole thing & didn't find a maxlen free extent.
	 */
	if (minlen < maxlen && besti != -1) {
		scxfs_extlen_t	p;	/* amount to trim length by */

		/*
		 * If size should be a multiple of prod, make that so.
		 */
		if (prod > 1) {
			div_u64_rem(bestlen, prod, &p);
			if (p)
				bestlen -= p;
		}

		/*
		 * Allocate besti for bestlen & return that.
		 */
		error = scxfs_rtallocate_range(mp, tp, besti, bestlen, rbpp, rsb);
		if (error) {
			return error;
		}
		*len = bestlen;
		*rtblock = besti;
		return 0;
	}
	/*
	 * Allocation failed.  Set *nextp to the next block to try.
	 */
	*nextp = next;
	*rtblock = NULLRTBLOCK;
	return 0;
}

/*
 * Allocate an extent of length minlen<=len<=maxlen, starting at block
 * bno.  If we don't get maxlen then use prod to trim the length, if given.
 * Returns error; returns starting block in *rtblock.
 * The lengths are all in rtextents.
 */
STATIC int				/* error */
scxfs_rtallocate_extent_exact(
	scxfs_mount_t	*mp,		/* file system mount point */
	scxfs_trans_t	*tp,		/* transaction pointer */
	scxfs_rtblock_t	bno,		/* starting block number to allocate */
	scxfs_extlen_t	minlen,		/* minimum length to allocate */
	scxfs_extlen_t	maxlen,		/* maximum length to allocate */
	scxfs_extlen_t	*len,		/* out: actual length allocated */
	scxfs_buf_t	**rbpp,		/* in/out: summary block buffer */
	scxfs_fsblock_t	*rsb,		/* in/out: summary block number */
	scxfs_extlen_t	prod,		/* extent product factor */
	scxfs_rtblock_t	*rtblock)	/* out: start block allocated */
{
	int		error;		/* error value */
	scxfs_extlen_t	i;		/* extent length trimmed due to prod */
	int		isfree;		/* extent is free */
	scxfs_rtblock_t	next;		/* next block to try (dummy) */

	ASSERT(minlen % prod == 0 && maxlen % prod == 0);
	/*
	 * Check if the range in question (for maxlen) is free.
	 */
	error = scxfs_rtcheck_range(mp, tp, bno, maxlen, 1, &next, &isfree);
	if (error) {
		return error;
	}
	if (isfree) {
		/*
		 * If it is, allocate it and return success.
		 */
		error = scxfs_rtallocate_range(mp, tp, bno, maxlen, rbpp, rsb);
		if (error) {
			return error;
		}
		*len = maxlen;
		*rtblock = bno;
		return 0;
	}
	/*
	 * If not, allocate what there is, if it's at least minlen.
	 */
	maxlen = next - bno;
	if (maxlen < minlen) {
		/*
		 * Failed, return failure status.
		 */
		*rtblock = NULLRTBLOCK;
		return 0;
	}
	/*
	 * Trim off tail of extent, if prod is specified.
	 */
	if (prod > 1 && (i = maxlen % prod)) {
		maxlen -= i;
		if (maxlen < minlen) {
			/*
			 * Now we can't do it, return failure status.
			 */
			*rtblock = NULLRTBLOCK;
			return 0;
		}
	}
	/*
	 * Allocate what we can and return it.
	 */
	error = scxfs_rtallocate_range(mp, tp, bno, maxlen, rbpp, rsb);
	if (error) {
		return error;
	}
	*len = maxlen;
	*rtblock = bno;
	return 0;
}

/*
 * Allocate an extent of length minlen<=len<=maxlen, starting as near
 * to bno as possible.  If we don't get maxlen then use prod to trim
 * the length, if given.  The lengths are all in rtextents.
 */
STATIC int				/* error */
scxfs_rtallocate_extent_near(
	scxfs_mount_t	*mp,		/* file system mount point */
	scxfs_trans_t	*tp,		/* transaction pointer */
	scxfs_rtblock_t	bno,		/* starting block number to allocate */
	scxfs_extlen_t	minlen,		/* minimum length to allocate */
	scxfs_extlen_t	maxlen,		/* maximum length to allocate */
	scxfs_extlen_t	*len,		/* out: actual length allocated */
	scxfs_buf_t	**rbpp,		/* in/out: summary block buffer */
	scxfs_fsblock_t	*rsb,		/* in/out: summary block number */
	scxfs_extlen_t	prod,		/* extent product factor */
	scxfs_rtblock_t	*rtblock)	/* out: start block allocated */
{
	int		any;		/* any useful extents from summary */
	scxfs_rtblock_t	bbno;		/* bitmap block number */
	int		error;		/* error value */
	int		i;		/* bitmap block offset (loop control) */
	int		j;		/* secondary loop control */
	int		log2len;	/* log2 of minlen */
	scxfs_rtblock_t	n;		/* next block to try */
	scxfs_rtblock_t	r;		/* result block */

	ASSERT(minlen % prod == 0 && maxlen % prod == 0);
	/*
	 * If the block number given is off the end, silently set it to
	 * the last block.
	 */
	if (bno >= mp->m_sb.sb_rextents)
		bno = mp->m_sb.sb_rextents - 1;

	/* Make sure we don't run off the end of the rt volume. */
	maxlen = min(mp->m_sb.sb_rextents, bno + maxlen) - bno;
	if (maxlen < minlen) {
		*rtblock = NULLRTBLOCK;
		return 0;
	}

	/*
	 * Try the exact allocation first.
	 */
	error = scxfs_rtallocate_extent_exact(mp, tp, bno, minlen, maxlen, len,
		rbpp, rsb, prod, &r);
	if (error) {
		return error;
	}
	/*
	 * If the exact allocation worked, return that.
	 */
	if (r != NULLRTBLOCK) {
		*rtblock = r;
		return 0;
	}
	bbno = SCXFS_BITTOBLOCK(mp, bno);
	i = 0;
	ASSERT(minlen != 0);
	log2len = scxfs_highbit32(minlen);
	/*
	 * Loop over all bitmap blocks (bbno + i is current block).
	 */
	for (;;) {
		/*
		 * Get summary information of extents of all useful levels
		 * starting in this bitmap block.
		 */
		error = scxfs_rtany_summary(mp, tp, log2len, mp->m_rsumlevels - 1,
			bbno + i, rbpp, rsb, &any);
		if (error) {
			return error;
		}
		/*
		 * If there are any useful extents starting here, try
		 * allocating one.
		 */
		if (any) {
			/*
			 * On the positive side of the starting location.
			 */
			if (i >= 0) {
				/*
				 * Try to allocate an extent starting in
				 * this block.
				 */
				error = scxfs_rtallocate_extent_block(mp, tp,
					bbno + i, minlen, maxlen, len, &n, rbpp,
					rsb, prod, &r);
				if (error) {
					return error;
				}
				/*
				 * If it worked, return it.
				 */
				if (r != NULLRTBLOCK) {
					*rtblock = r;
					return 0;
				}
			}
			/*
			 * On the negative side of the starting location.
			 */
			else {		/* i < 0 */
				/*
				 * Loop backwards through the bitmap blocks from
				 * the starting point-1 up to where we are now.
				 * There should be an extent which ends in this
				 * bitmap block and is long enough.
				 */
				for (j = -1; j > i; j--) {
					/*
					 * Grab the summary information for
					 * this bitmap block.
					 */
					error = scxfs_rtany_summary(mp, tp,
						log2len, mp->m_rsumlevels - 1,
						bbno + j, rbpp, rsb, &any);
					if (error) {
						return error;
					}
					/*
					 * If there's no extent given in the
					 * summary that means the extent we
					 * found must carry over from an
					 * earlier block.  If there is an
					 * extent given, we've already tried
					 * that allocation, don't do it again.
					 */
					if (any)
						continue;
					error = scxfs_rtallocate_extent_block(mp,
						tp, bbno + j, minlen, maxlen,
						len, &n, rbpp, rsb, prod, &r);
					if (error) {
						return error;
					}
					/*
					 * If it works, return the extent.
					 */
					if (r != NULLRTBLOCK) {
						*rtblock = r;
						return 0;
					}
				}
				/*
				 * There weren't intervening bitmap blocks
				 * with a long enough extent, or the
				 * allocation didn't work for some reason
				 * (i.e. it's a little * too short).
				 * Try to allocate from the summary block
				 * that we found.
				 */
				error = scxfs_rtallocate_extent_block(mp, tp,
					bbno + i, minlen, maxlen, len, &n, rbpp,
					rsb, prod, &r);
				if (error) {
					return error;
				}
				/*
				 * If it works, return the extent.
				 */
				if (r != NULLRTBLOCK) {
					*rtblock = r;
					return 0;
				}
			}
		}
		/*
		 * Loop control.  If we were on the positive side, and there's
		 * still more blocks on the negative side, go there.
		 */
		if (i > 0 && (int)bbno - i >= 0)
			i = -i;
		/*
		 * If positive, and no more negative, but there are more
		 * positive, go there.
		 */
		else if (i > 0 && (int)bbno + i < mp->m_sb.sb_rbmblocks - 1)
			i++;
		/*
		 * If negative or 0 (just started), and there are positive
		 * blocks to go, go there.  The 0 case moves to block 1.
		 */
		else if (i <= 0 && (int)bbno - i < mp->m_sb.sb_rbmblocks - 1)
			i = 1 - i;
		/*
		 * If negative or 0 and there are more negative blocks,
		 * go there.
		 */
		else if (i <= 0 && (int)bbno + i > 0)
			i--;
		/*
		 * Must be done.  Return failure.
		 */
		else
			break;
	}
	*rtblock = NULLRTBLOCK;
	return 0;
}

/*
 * Allocate an extent of length minlen<=len<=maxlen, with no position
 * specified.  If we don't get maxlen then use prod to trim
 * the length, if given.  The lengths are all in rtextents.
 */
STATIC int				/* error */
scxfs_rtallocate_extent_size(
	scxfs_mount_t	*mp,		/* file system mount point */
	scxfs_trans_t	*tp,		/* transaction pointer */
	scxfs_extlen_t	minlen,		/* minimum length to allocate */
	scxfs_extlen_t	maxlen,		/* maximum length to allocate */
	scxfs_extlen_t	*len,		/* out: actual length allocated */
	scxfs_buf_t	**rbpp,		/* in/out: summary block buffer */
	scxfs_fsblock_t	*rsb,		/* in/out: summary block number */
	scxfs_extlen_t	prod,		/* extent product factor */
	scxfs_rtblock_t	*rtblock)	/* out: start block allocated */
{
	int		error;		/* error value */
	int		i;		/* bitmap block number */
	int		l;		/* level number (loop control) */
	scxfs_rtblock_t	n;		/* next block to be tried */
	scxfs_rtblock_t	r;		/* result block number */
	scxfs_suminfo_t	sum;		/* summary information for extents */

	ASSERT(minlen % prod == 0 && maxlen % prod == 0);
	ASSERT(maxlen != 0);

	/*
	 * Loop over all the levels starting with maxlen.
	 * At each level, look at all the bitmap blocks, to see if there
	 * are extents starting there that are long enough (>= maxlen).
	 * Note, only on the initial level can the allocation fail if
	 * the summary says there's an extent.
	 */
	for (l = scxfs_highbit32(maxlen); l < mp->m_rsumlevels; l++) {
		/*
		 * Loop over all the bitmap blocks.
		 */
		for (i = 0; i < mp->m_sb.sb_rbmblocks; i++) {
			/*
			 * Get the summary for this level/block.
			 */
			error = scxfs_rtget_summary(mp, tp, l, i, rbpp, rsb,
				&sum);
			if (error) {
				return error;
			}
			/*
			 * Nothing there, on to the next block.
			 */
			if (!sum)
				continue;
			/*
			 * Try allocating the extent.
			 */
			error = scxfs_rtallocate_extent_block(mp, tp, i, maxlen,
				maxlen, len, &n, rbpp, rsb, prod, &r);
			if (error) {
				return error;
			}
			/*
			 * If it worked, return that.
			 */
			if (r != NULLRTBLOCK) {
				*rtblock = r;
				return 0;
			}
			/*
			 * If the "next block to try" returned from the
			 * allocator is beyond the next bitmap block,
			 * skip to that bitmap block.
			 */
			if (SCXFS_BITTOBLOCK(mp, n) > i + 1)
				i = SCXFS_BITTOBLOCK(mp, n) - 1;
		}
	}
	/*
	 * Didn't find any maxlen blocks.  Try smaller ones, unless
	 * we're asking for a fixed size extent.
	 */
	if (minlen > --maxlen) {
		*rtblock = NULLRTBLOCK;
		return 0;
	}
	ASSERT(minlen != 0);
	ASSERT(maxlen != 0);

	/*
	 * Loop over sizes, from maxlen down to minlen.
	 * This time, when we do the allocations, allow smaller ones
	 * to succeed.
	 */
	for (l = scxfs_highbit32(maxlen); l >= scxfs_highbit32(minlen); l--) {
		/*
		 * Loop over all the bitmap blocks, try an allocation
		 * starting in that block.
		 */
		for (i = 0; i < mp->m_sb.sb_rbmblocks; i++) {
			/*
			 * Get the summary information for this level/block.
			 */
			error =	scxfs_rtget_summary(mp, tp, l, i, rbpp, rsb,
						  &sum);
			if (error) {
				return error;
			}
			/*
			 * If nothing there, go on to next.
			 */
			if (!sum)
				continue;
			/*
			 * Try the allocation.  Make sure the specified
			 * minlen/maxlen are in the possible range for
			 * this summary level.
			 */
			error = scxfs_rtallocate_extent_block(mp, tp, i,
					SCXFS_RTMAX(minlen, 1 << l),
					SCXFS_RTMIN(maxlen, (1 << (l + 1)) - 1),
					len, &n, rbpp, rsb, prod, &r);
			if (error) {
				return error;
			}
			/*
			 * If it worked, return that extent.
			 */
			if (r != NULLRTBLOCK) {
				*rtblock = r;
				return 0;
			}
			/*
			 * If the "next block to try" returned from the
			 * allocator is beyond the next bitmap block,
			 * skip to that bitmap block.
			 */
			if (SCXFS_BITTOBLOCK(mp, n) > i + 1)
				i = SCXFS_BITTOBLOCK(mp, n) - 1;
		}
	}
	/*
	 * Got nothing, return failure.
	 */
	*rtblock = NULLRTBLOCK;
	return 0;
}

/*
 * Allocate space to the bitmap or summary file, and zero it, for growfs.
 */
STATIC int
scxfs_growfs_rt_alloc(
	struct scxfs_mount	*mp,		/* file system mount point */
	scxfs_extlen_t		oblocks,	/* old count of blocks */
	scxfs_extlen_t		nblocks,	/* new count of blocks */
	struct scxfs_inode	*ip)		/* inode (bitmap/summary) */
{
	scxfs_fileoff_t		bno;		/* block number in file */
	struct scxfs_buf		*bp;	/* temporary buffer for zeroing */
	scxfs_daddr_t		d;		/* disk block address */
	int			error;		/* error return value */
	scxfs_fsblock_t		fsbno;		/* filesystem block for bno */
	struct scxfs_bmbt_irec	map;		/* block map output */
	int			nmap;		/* number of block maps */
	int			resblks;	/* space reservation */
	struct scxfs_trans	*tp;

	/*
	 * Allocate space to the file, as necessary.
	 */
	while (oblocks < nblocks) {
		resblks = SCXFS_GROWFSRT_SPACE_RES(mp, nblocks - oblocks);
		/*
		 * Reserve space & log for one extent added to the file.
		 */
		error = scxfs_trans_alloc(mp, &M_RES(mp)->tr_growrtalloc, resblks,
				0, 0, &tp);
		if (error)
			return error;
		/*
		 * Lock the inode.
		 */
		scxfs_ilock(ip, SCXFS_ILOCK_EXCL);
		scxfs_trans_ijoin(tp, ip, SCXFS_ILOCK_EXCL);

		/*
		 * Allocate blocks to the bitmap file.
		 */
		nmap = 1;
		error = scxfs_bmapi_write(tp, ip, oblocks, nblocks - oblocks,
					SCXFS_BMAPI_METADATA, resblks, &map,
					&nmap);
		if (!error && nmap < 1)
			error = -ENOSPC;
		if (error)
			goto out_trans_cancel;
		/*
		 * Free any blocks freed up in the transaction, then commit.
		 */
		error = scxfs_trans_commit(tp);
		if (error)
			return error;
		/*
		 * Now we need to clear the allocated blocks.
		 * Do this one block per transaction, to keep it simple.
		 */
		for (bno = map.br_startoff, fsbno = map.br_startblock;
		     bno < map.br_startoff + map.br_blockcount;
		     bno++, fsbno++) {
			/*
			 * Reserve log for one block zeroing.
			 */
			error = scxfs_trans_alloc(mp, &M_RES(mp)->tr_growrtzero,
					0, 0, 0, &tp);
			if (error)
				return error;
			/*
			 * Lock the bitmap inode.
			 */
			scxfs_ilock(ip, SCXFS_ILOCK_EXCL);
			scxfs_trans_ijoin(tp, ip, SCXFS_ILOCK_EXCL);
			/*
			 * Get a buffer for the block.
			 */
			d = SCXFS_FSB_TO_DADDR(mp, fsbno);
			bp = scxfs_trans_get_buf(tp, mp->m_ddev_targp, d,
				mp->m_bsize, 0);
			if (bp == NULL) {
				error = -EIO;
				goto out_trans_cancel;
			}
			memset(bp->b_addr, 0, mp->m_sb.sb_blocksize);
			scxfs_trans_log_buf(tp, bp, 0, mp->m_sb.sb_blocksize - 1);
			/*
			 * Commit the transaction.
			 */
			error = scxfs_trans_commit(tp);
			if (error)
				return error;
		}
		/*
		 * Go on to the next extent, if any.
		 */
		oblocks = map.br_startoff + map.br_blockcount;
	}

	return 0;

out_trans_cancel:
	scxfs_trans_cancel(tp);
	return error;
}

static void
scxfs_alloc_rsum_cache(
	scxfs_mount_t	*mp,		/* file system mount structure */
	scxfs_extlen_t	rbmblocks)	/* number of rt bitmap blocks */
{
	/*
	 * The rsum cache is initialized to all zeroes, which is trivially a
	 * lower bound on the minimum level with any free extents. We can
	 * continue without the cache if it couldn't be allocated.
	 */
	mp->m_rsum_cache = kmem_zalloc_large(rbmblocks, 0);
	if (!mp->m_rsum_cache)
		scxfs_warn(mp, "could not allocate realtime summary cache");
}

/*
 * Visible (exported) functions.
 */

/*
 * Grow the realtime area of the filesystem.
 */
int
scxfs_growfs_rt(
	scxfs_mount_t	*mp,		/* mount point for filesystem */
	scxfs_growfs_rt_t	*in)		/* growfs rt input struct */
{
	scxfs_rtblock_t	bmbno;		/* bitmap block number */
	scxfs_buf_t	*bp;		/* temporary buffer */
	int		error;		/* error return value */
	scxfs_mount_t	*nmp;		/* new (fake) mount structure */
	scxfs_rfsblock_t	nrblocks;	/* new number of realtime blocks */
	scxfs_extlen_t	nrbmblocks;	/* new number of rt bitmap blocks */
	scxfs_rtblock_t	nrextents;	/* new number of realtime extents */
	uint8_t		nrextslog;	/* new log2 of sb_rextents */
	scxfs_extlen_t	nrsumblocks;	/* new number of summary blocks */
	uint		nrsumlevels;	/* new rt summary levels */
	uint		nrsumsize;	/* new size of rt summary, bytes */
	scxfs_sb_t	*nsbp;		/* new superblock */
	scxfs_extlen_t	rbmblocks;	/* current number of rt bitmap blocks */
	scxfs_extlen_t	rsumblocks;	/* current number of rt summary blks */
	scxfs_sb_t	*sbp;		/* old superblock */
	scxfs_fsblock_t	sumbno;		/* summary block number */
	uint8_t		*rsum_cache;	/* old summary cache */

	sbp = &mp->m_sb;
	/*
	 * Initial error checking.
	 */
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (mp->m_rtdev_targp == NULL || mp->m_rbmip == NULL ||
	    (nrblocks = in->newblocks) <= sbp->sb_rblocks ||
	    (sbp->sb_rblocks && (in->extsize != sbp->sb_rextsize)))
		return -EINVAL;
	if ((error = scxfs_sb_validate_fsb_count(sbp, nrblocks)))
		return error;
	/*
	 * Read in the last block of the device, make sure it exists.
	 */
	error = scxfs_buf_read_uncached(mp->m_rtdev_targp,
				SCXFS_FSB_TO_BB(mp, nrblocks - 1),
				SCXFS_FSB_TO_BB(mp, 1), 0, &bp, NULL);
	if (error)
		return error;
	scxfs_buf_relse(bp);

	/*
	 * Calculate new parameters.  These are the final values to be reached.
	 */
	nrextents = nrblocks;
	do_div(nrextents, in->extsize);
	nrbmblocks = howmany_64(nrextents, NBBY * sbp->sb_blocksize);
	nrextslog = scxfs_highbit32(nrextents);
	nrsumlevels = nrextslog + 1;
	nrsumsize = (uint)sizeof(scxfs_suminfo_t) * nrsumlevels * nrbmblocks;
	nrsumblocks = SCXFS_B_TO_FSB(mp, nrsumsize);
	nrsumsize = SCXFS_FSB_TO_B(mp, nrsumblocks);
	/*
	 * New summary size can't be more than half the size of
	 * the log.  This prevents us from getting a log overflow,
	 * since we'll log basically the whole summary file at once.
	 */
	if (nrsumblocks > (mp->m_sb.sb_logblocks >> 1))
		return -EINVAL;
	/*
	 * Get the old block counts for bitmap and summary inodes.
	 * These can't change since other growfs callers are locked out.
	 */
	rbmblocks = SCXFS_B_TO_FSB(mp, mp->m_rbmip->i_d.di_size);
	rsumblocks = SCXFS_B_TO_FSB(mp, mp->m_rsumip->i_d.di_size);
	/*
	 * Allocate space to the bitmap and summary files, as necessary.
	 */
	error = scxfs_growfs_rt_alloc(mp, rbmblocks, nrbmblocks, mp->m_rbmip);
	if (error)
		return error;
	error = scxfs_growfs_rt_alloc(mp, rsumblocks, nrsumblocks, mp->m_rsumip);
	if (error)
		return error;

	rsum_cache = mp->m_rsum_cache;
	if (nrbmblocks != sbp->sb_rbmblocks)
		scxfs_alloc_rsum_cache(mp, nrbmblocks);

	/*
	 * Allocate a new (fake) mount/sb.
	 */
	nmp = kmem_alloc(sizeof(*nmp), 0);
	/*
	 * Loop over the bitmap blocks.
	 * We will do everything one bitmap block at a time.
	 * Skip the current block if it is exactly full.
	 * This also deals with the case where there were no rtextents before.
	 */
	for (bmbno = sbp->sb_rbmblocks -
		     ((sbp->sb_rextents & ((1 << mp->m_blkbit_log) - 1)) != 0);
	     bmbno < nrbmblocks;
	     bmbno++) {
		scxfs_trans_t	*tp;

		*nmp = *mp;
		nsbp = &nmp->m_sb;
		/*
		 * Calculate new sb and mount fields for this round.
		 */
		nsbp->sb_rextsize = in->extsize;
		nsbp->sb_rbmblocks = bmbno + 1;
		nsbp->sb_rblocks =
			SCXFS_RTMIN(nrblocks,
				  nsbp->sb_rbmblocks * NBBY *
				  nsbp->sb_blocksize * nsbp->sb_rextsize);
		nsbp->sb_rextents = nsbp->sb_rblocks;
		do_div(nsbp->sb_rextents, nsbp->sb_rextsize);
		ASSERT(nsbp->sb_rextents != 0);
		nsbp->sb_rextslog = scxfs_highbit32(nsbp->sb_rextents);
		nrsumlevels = nmp->m_rsumlevels = nsbp->sb_rextslog + 1;
		nrsumsize =
			(uint)sizeof(scxfs_suminfo_t) * nrsumlevels *
			nsbp->sb_rbmblocks;
		nrsumblocks = SCXFS_B_TO_FSB(mp, nrsumsize);
		nmp->m_rsumsize = nrsumsize = SCXFS_FSB_TO_B(mp, nrsumblocks);
		/*
		 * Start a transaction, get the log reservation.
		 */
		error = scxfs_trans_alloc(mp, &M_RES(mp)->tr_growrtfree, 0, 0, 0,
				&tp);
		if (error)
			break;
		/*
		 * Lock out other callers by grabbing the bitmap inode lock.
		 */
		scxfs_ilock(mp->m_rbmip, SCXFS_ILOCK_EXCL);
		scxfs_trans_ijoin(tp, mp->m_rbmip, SCXFS_ILOCK_EXCL);
		/*
		 * Update the bitmap inode's size ondisk and incore.  We need
		 * to update the incore size so that inode inactivation won't
		 * punch what it thinks are "posteof" blocks.
		 */
		mp->m_rbmip->i_d.di_size =
			nsbp->sb_rbmblocks * nsbp->sb_blocksize;
		i_size_write(VFS_I(mp->m_rbmip), mp->m_rbmip->i_d.di_size);
		scxfs_trans_log_inode(tp, mp->m_rbmip, SCXFS_ILOG_CORE);
		/*
		 * Get the summary inode into the transaction.
		 */
		scxfs_ilock(mp->m_rsumip, SCXFS_ILOCK_EXCL);
		scxfs_trans_ijoin(tp, mp->m_rsumip, SCXFS_ILOCK_EXCL);
		/*
		 * Update the summary inode's size.  We need to update the
		 * incore size so that inode inactivation won't punch what it
		 * thinks are "posteof" blocks.
		 */
		mp->m_rsumip->i_d.di_size = nmp->m_rsumsize;
		i_size_write(VFS_I(mp->m_rsumip), mp->m_rsumip->i_d.di_size);
		scxfs_trans_log_inode(tp, mp->m_rsumip, SCXFS_ILOG_CORE);
		/*
		 * Copy summary data from old to new sizes.
		 * Do this when the real size (not block-aligned) changes.
		 */
		if (sbp->sb_rbmblocks != nsbp->sb_rbmblocks ||
		    mp->m_rsumlevels != nmp->m_rsumlevels) {
			error = scxfs_rtcopy_summary(mp, nmp, tp);
			if (error)
				goto error_cancel;
		}
		/*
		 * Update superblock fields.
		 */
		if (nsbp->sb_rextsize != sbp->sb_rextsize)
			scxfs_trans_mod_sb(tp, SCXFS_TRANS_SB_REXTSIZE,
				nsbp->sb_rextsize - sbp->sb_rextsize);
		if (nsbp->sb_rbmblocks != sbp->sb_rbmblocks)
			scxfs_trans_mod_sb(tp, SCXFS_TRANS_SB_RBMBLOCKS,
				nsbp->sb_rbmblocks - sbp->sb_rbmblocks);
		if (nsbp->sb_rblocks != sbp->sb_rblocks)
			scxfs_trans_mod_sb(tp, SCXFS_TRANS_SB_RBLOCKS,
				nsbp->sb_rblocks - sbp->sb_rblocks);
		if (nsbp->sb_rextents != sbp->sb_rextents)
			scxfs_trans_mod_sb(tp, SCXFS_TRANS_SB_REXTENTS,
				nsbp->sb_rextents - sbp->sb_rextents);
		if (nsbp->sb_rextslog != sbp->sb_rextslog)
			scxfs_trans_mod_sb(tp, SCXFS_TRANS_SB_REXTSLOG,
				nsbp->sb_rextslog - sbp->sb_rextslog);
		/*
		 * Free new extent.
		 */
		bp = NULL;
		error = scxfs_rtfree_range(nmp, tp, sbp->sb_rextents,
			nsbp->sb_rextents - sbp->sb_rextents, &bp, &sumbno);
		if (error) {
error_cancel:
			scxfs_trans_cancel(tp);
			break;
		}
		/*
		 * Mark more blocks free in the superblock.
		 */
		scxfs_trans_mod_sb(tp, SCXFS_TRANS_SB_FREXTENTS,
			nsbp->sb_rextents - sbp->sb_rextents);
		/*
		 * Update mp values into the real mp structure.
		 */
		mp->m_rsumlevels = nrsumlevels;
		mp->m_rsumsize = nrsumsize;

		error = scxfs_trans_commit(tp);
		if (error)
			break;
	}

	/*
	 * Free the fake mp structure.
	 */
	kmem_free(nmp);

	/*
	 * If we had to allocate a new rsum_cache, we either need to free the
	 * old one (if we succeeded) or free the new one and restore the old one
	 * (if there was an error).
	 */
	if (rsum_cache != mp->m_rsum_cache) {
		if (error) {
			kmem_free(mp->m_rsum_cache);
			mp->m_rsum_cache = rsum_cache;
		} else {
			kmem_free(rsum_cache);
		}
	}

	return error;
}

/*
 * Allocate an extent in the realtime subvolume, with the usual allocation
 * parameters.  The length units are all in realtime extents, as is the
 * result block number.
 */
int					/* error */
scxfs_rtallocate_extent(
	scxfs_trans_t	*tp,		/* transaction pointer */
	scxfs_rtblock_t	bno,		/* starting block number to allocate */
	scxfs_extlen_t	minlen,		/* minimum length to allocate */
	scxfs_extlen_t	maxlen,		/* maximum length to allocate */
	scxfs_extlen_t	*len,		/* out: actual length allocated */
	int		wasdel,		/* was a delayed allocation extent */
	scxfs_extlen_t	prod,		/* extent product factor */
	scxfs_rtblock_t	*rtblock)	/* out: start block allocated */
{
	scxfs_mount_t	*mp = tp->t_mountp;
	int		error;		/* error value */
	scxfs_rtblock_t	r;		/* result allocated block */
	scxfs_fsblock_t	sb;		/* summary file block number */
	scxfs_buf_t	*sumbp;		/* summary file block buffer */

	ASSERT(scxfs_isilocked(mp->m_rbmip, SCXFS_ILOCK_EXCL));
	ASSERT(minlen > 0 && minlen <= maxlen);

	/*
	 * If prod is set then figure out what to do to minlen and maxlen.
	 */
	if (prod > 1) {
		scxfs_extlen_t	i;

		if ((i = maxlen % prod))
			maxlen -= i;
		if ((i = minlen % prod))
			minlen += prod - i;
		if (maxlen < minlen) {
			*rtblock = NULLRTBLOCK;
			return 0;
		}
	}

retry:
	sumbp = NULL;
	if (bno == 0) {
		error = scxfs_rtallocate_extent_size(mp, tp, minlen, maxlen, len,
				&sumbp,	&sb, prod, &r);
	} else {
		error = scxfs_rtallocate_extent_near(mp, tp, bno, minlen, maxlen,
				len, &sumbp, &sb, prod, &r);
	}

	if (error)
		return error;

	/*
	 * If it worked, update the superblock.
	 */
	if (r != NULLRTBLOCK) {
		long	slen = (long)*len;

		ASSERT(*len >= minlen && *len <= maxlen);
		if (wasdel)
			scxfs_trans_mod_sb(tp, SCXFS_TRANS_SB_RES_FREXTENTS, -slen);
		else
			scxfs_trans_mod_sb(tp, SCXFS_TRANS_SB_FREXTENTS, -slen);
	} else if (prod > 1) {
		prod = 1;
		goto retry;
	}

	*rtblock = r;
	return 0;
}

/*
 * Initialize realtime fields in the mount structure.
 */
int				/* error */
scxfs_rtmount_init(
	struct scxfs_mount	*mp)	/* file system mount structure */
{
	struct scxfs_buf		*bp;	/* buffer for last block of subvolume */
	struct scxfs_sb		*sbp;	/* filesystem superblock copy in mount */
	scxfs_daddr_t		d;	/* address of last block of subvolume */
	int			error;

	sbp = &mp->m_sb;
	if (sbp->sb_rblocks == 0)
		return 0;
	if (mp->m_rtdev_targp == NULL) {
		scxfs_warn(mp,
	"Filesystem has a realtime volume, use rtdev=device option");
		return -ENODEV;
	}
	mp->m_rsumlevels = sbp->sb_rextslog + 1;
	mp->m_rsumsize =
		(uint)sizeof(scxfs_suminfo_t) * mp->m_rsumlevels *
		sbp->sb_rbmblocks;
	mp->m_rsumsize = roundup(mp->m_rsumsize, sbp->sb_blocksize);
	mp->m_rbmip = mp->m_rsumip = NULL;
	/*
	 * Check that the realtime section is an ok size.
	 */
	d = (scxfs_daddr_t)SCXFS_FSB_TO_BB(mp, mp->m_sb.sb_rblocks);
	if (SCXFS_BB_TO_FSB(mp, d) != mp->m_sb.sb_rblocks) {
		scxfs_warn(mp, "realtime mount -- %llu != %llu",
			(unsigned long long) SCXFS_BB_TO_FSB(mp, d),
			(unsigned long long) mp->m_sb.sb_rblocks);
		return -EFBIG;
	}
	error = scxfs_buf_read_uncached(mp->m_rtdev_targp,
					d - SCXFS_FSB_TO_BB(mp, 1),
					SCXFS_FSB_TO_BB(mp, 1), 0, &bp, NULL);
	if (error) {
		scxfs_warn(mp, "realtime device size check failed");
		return error;
	}
	scxfs_buf_relse(bp);
	return 0;
}

/*
 * Get the bitmap and summary inodes and the summary cache into the mount
 * structure at mount time.
 */
int					/* error */
scxfs_rtmount_inodes(
	scxfs_mount_t	*mp)		/* file system mount structure */
{
	int		error;		/* error return value */
	scxfs_sb_t	*sbp;

	sbp = &mp->m_sb;
	error = scxfs_iget(mp, NULL, sbp->sb_rbmino, 0, 0, &mp->m_rbmip);
	if (error)
		return error;
	ASSERT(mp->m_rbmip != NULL);

	error = scxfs_iget(mp, NULL, sbp->sb_rsumino, 0, 0, &mp->m_rsumip);
	if (error) {
		scxfs_irele(mp->m_rbmip);
		return error;
	}
	ASSERT(mp->m_rsumip != NULL);
	scxfs_alloc_rsum_cache(mp, sbp->sb_rbmblocks);
	return 0;
}

void
scxfs_rtunmount_inodes(
	struct scxfs_mount	*mp)
{
	kmem_free(mp->m_rsum_cache);
	if (mp->m_rbmip)
		scxfs_irele(mp->m_rbmip);
	if (mp->m_rsumip)
		scxfs_irele(mp->m_rsumip);
}

/*
 * Pick an extent for allocation at the start of a new realtime file.
 * Use the sequence number stored in the atime field of the bitmap inode.
 * Translate this to a fraction of the rtextents, and return the product
 * of rtextents and the fraction.
 * The fraction sequence is 0, 1/2, 1/4, 3/4, 1/8, ..., 7/8, 1/16, ...
 */
int					/* error */
scxfs_rtpick_extent(
	scxfs_mount_t	*mp,		/* file system mount point */
	scxfs_trans_t	*tp,		/* transaction pointer */
	scxfs_extlen_t	len,		/* allocation length (rtextents) */
	scxfs_rtblock_t	*pick)		/* result rt extent */
{
	scxfs_rtblock_t	b;		/* result block */
	int		log2;		/* log of sequence number */
	uint64_t	resid;		/* residual after log removed */
	uint64_t	seq;		/* sequence number of file creation */
	uint64_t	*seqp;		/* pointer to seqno in inode */

	ASSERT(scxfs_isilocked(mp->m_rbmip, SCXFS_ILOCK_EXCL));

	seqp = (uint64_t *)&VFS_I(mp->m_rbmip)->i_atime;
	if (!(mp->m_rbmip->i_d.di_flags & SCXFS_DIFLAG_NEWRTBM)) {
		mp->m_rbmip->i_d.di_flags |= SCXFS_DIFLAG_NEWRTBM;
		*seqp = 0;
	}
	seq = *seqp;
	if ((log2 = scxfs_highbit64(seq)) == -1)
		b = 0;
	else {
		resid = seq - (1ULL << log2);
		b = (mp->m_sb.sb_rextents * ((resid << 1) + 1ULL)) >>
		    (log2 + 1);
		if (b >= mp->m_sb.sb_rextents)
			div64_u64_rem(b, mp->m_sb.sb_rextents, &b);
		if (b + len > mp->m_sb.sb_rextents)
			b = mp->m_sb.sb_rextents - len;
	}
	*seqp = seq + 1;
	scxfs_trans_log_inode(tp, mp->m_rbmip, SCXFS_ILOG_CORE);
	*pick = b;
	return 0;
}
