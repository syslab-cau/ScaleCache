// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2019 Oracle.  All Rights Reserved.
 * Author: Darrick J. Wong <darrick.wong@oracle.com>
 */
#include "scxfs.h"
#include "scxfs_fs.h"
#include "scxfs_shared.h"
#include "scxfs_format.h"
#include "scxfs_log_format.h"
#include "scxfs_trans_resv.h"
#include "scxfs_mount.h"
#include "scxfs_inode.h"
#include "scxfs_btree.h"
#include "scxfs_ialloc.h"
#include "scxfs_ialloc_btree.h"
#include "scxfs_iwalk.h"
#include "scxfs_error.h"
#include "scxfs_trace.h"
#include "scxfs_icache.h"
#include "scxfs_health.h"
#include "scxfs_trans.h"
#include "scxfs_pwork.h"

/*
 * Walking Inodes in the Filesystem
 * ================================
 *
 * This iterator function walks a subset of filesystem inodes in increasing
 * order from @startino until there are no more inodes.  For each allocated
 * inode it finds, it calls a walk function with the relevant inode number and
 * a pointer to caller-provided data.  The walk function can return the usual
 * negative error code to stop the iteration; 0 to continue the iteration; or
 * -ECANCELED to stop the iteration.  This return value is returned to the
 * caller.
 *
 * Internally, we allow the walk function to do anything, which means that we
 * cannot maintain the inobt cursor or our lock on the AGI buffer.  We
 * therefore cache the inobt records in kernel memory and only call the walk
 * function when our memory buffer is full.  @nr_recs is the number of records
 * that we've cached, and @sz_recs is the size of our cache.
 *
 * It is the responsibility of the walk function to ensure it accesses
 * allocated inodes, as the inobt records may be stale by the time they are
 * acted upon.
 */

struct scxfs_iwalk_ag {
	/* parallel work control data; will be null if single threaded */
	struct scxfs_pwork		pwork;

	struct scxfs_mount		*mp;
	struct scxfs_trans		*tp;

	/* Where do we start the traversal? */
	scxfs_ino_t			startino;

	/* Array of inobt records we cache. */
	struct scxfs_inobt_rec_incore	*recs;

	/* Number of entries allocated for the @recs array. */
	unsigned int			sz_recs;

	/* Number of entries in the @recs array that are in use. */
	unsigned int			nr_recs;

	/* Inode walk function and data pointer. */
	scxfs_iwalk_fn			iwalk_fn;
	scxfs_inobt_walk_fn		inobt_walk_fn;
	void				*data;

	/*
	 * Make it look like the inodes up to startino are free so that
	 * bulkstat can start its inode iteration at the correct place without
	 * needing to special case everywhere.
	 */
	unsigned int			trim_start:1;

	/* Skip empty inobt records? */
	unsigned int			skip_empty:1;
};

/*
 * Loop over all clusters in a chunk for a given incore inode allocation btree
 * record.  Do a readahead if there are any allocated inodes in that cluster.
 */
STATIC void
scxfs_iwalk_ichunk_ra(
	struct scxfs_mount		*mp,
	scxfs_agnumber_t			agno,
	struct scxfs_inobt_rec_incore	*irec)
{
	struct scxfs_ino_geometry		*igeo = M_IGEO(mp);
	scxfs_agblock_t			agbno;
	struct blk_plug			plug;
	int				i;	/* inode chunk index */

	agbno = SCXFS_AGINO_TO_AGBNO(mp, irec->ir_startino);

	blk_start_plug(&plug);
	for (i = 0; i < SCXFS_INODES_PER_CHUNK; i += igeo->inodes_per_cluster) {
		scxfs_inofree_t	imask;

		imask = scxfs_inobt_maskn(i, igeo->inodes_per_cluster);
		if (imask & ~irec->ir_free) {
			scxfs_btree_reada_bufs(mp, agno, agbno,
					igeo->blocks_per_cluster,
					&scxfs_inode_buf_ops);
		}
		agbno += igeo->blocks_per_cluster;
	}
	blk_finish_plug(&plug);
}

/*
 * Set the bits in @irec's free mask that correspond to the inodes before
 * @agino so that we skip them.  This is how we restart an inode walk that was
 * interrupted in the middle of an inode record.
 */
STATIC void
scxfs_iwalk_adjust_start(
	scxfs_agino_t			agino,	/* starting inode of chunk */
	struct scxfs_inobt_rec_incore	*irec)	/* btree record */
{
	int				idx;	/* index into inode chunk */
	int				i;

	idx = agino - irec->ir_startino;

	/*
	 * We got a right chunk with some left inodes allocated at it.  Grab
	 * the chunk record.  Mark all the uninteresting inodes free because
	 * they're before our start point.
	 */
	for (i = 0; i < idx; i++) {
		if (SCXFS_INOBT_MASK(i) & ~irec->ir_free)
			irec->ir_freecount++;
	}

	irec->ir_free |= scxfs_inobt_maskn(0, idx);
}

/* Allocate memory for a walk. */
STATIC int
scxfs_iwalk_alloc(
	struct scxfs_iwalk_ag	*iwag)
{
	size_t			size;

	ASSERT(iwag->recs == NULL);
	iwag->nr_recs = 0;

	/* Allocate a prefetch buffer for inobt records. */
	size = iwag->sz_recs * sizeof(struct scxfs_inobt_rec_incore);
	iwag->recs = kmem_alloc(size, KM_MAYFAIL);
	if (iwag->recs == NULL)
		return -ENOMEM;

	return 0;
}

/* Free memory we allocated for a walk. */
STATIC void
scxfs_iwalk_free(
	struct scxfs_iwalk_ag	*iwag)
{
	kmem_free(iwag->recs);
	iwag->recs = NULL;
}

/* For each inuse inode in each cached inobt record, call our function. */
STATIC int
scxfs_iwalk_ag_recs(
	struct scxfs_iwalk_ag		*iwag)
{
	struct scxfs_mount		*mp = iwag->mp;
	struct scxfs_trans		*tp = iwag->tp;
	scxfs_ino_t			ino;
	unsigned int			i, j;
	scxfs_agnumber_t			agno;
	int				error;

	agno = SCXFS_INO_TO_AGNO(mp, iwag->startino);
	for (i = 0; i < iwag->nr_recs; i++) {
		struct scxfs_inobt_rec_incore	*irec = &iwag->recs[i];

		trace_scxfs_iwalk_ag_rec(mp, agno, irec);

		if (scxfs_pwork_want_abort(&iwag->pwork))
			return 0;

		if (iwag->inobt_walk_fn) {
			error = iwag->inobt_walk_fn(mp, tp, agno, irec,
					iwag->data);
			if (error)
				return error;
		}

		if (!iwag->iwalk_fn)
			continue;

		for (j = 0; j < SCXFS_INODES_PER_CHUNK; j++) {
			if (scxfs_pwork_want_abort(&iwag->pwork))
				return 0;

			/* Skip if this inode is free */
			if (SCXFS_INOBT_MASK(j) & irec->ir_free)
				continue;

			/* Otherwise call our function. */
			ino = SCXFS_AGINO_TO_INO(mp, agno, irec->ir_startino + j);
			error = iwag->iwalk_fn(mp, tp, ino, iwag->data);
			if (error)
				return error;
		}
	}

	return 0;
}

/* Delete cursor and let go of AGI. */
static inline void
scxfs_iwalk_del_inobt(
	struct scxfs_trans	*tp,
	struct scxfs_btree_cur	**curpp,
	struct scxfs_buf		**agi_bpp,
	int			error)
{
	if (*curpp) {
		scxfs_btree_del_cursor(*curpp, error);
		*curpp = NULL;
	}
	if (*agi_bpp) {
		scxfs_trans_brelse(tp, *agi_bpp);
		*agi_bpp = NULL;
	}
}

/*
 * Set ourselves up for walking inobt records starting from a given point in
 * the filesystem.
 *
 * If caller passed in a nonzero start inode number, load the record from the
 * inobt and make the record look like all the inodes before agino are free so
 * that we skip them, and then move the cursor to the next inobt record.  This
 * is how we support starting an iwalk in the middle of an inode chunk.
 *
 * If the caller passed in a start number of zero, move the cursor to the first
 * inobt record.
 *
 * The caller is responsible for cleaning up the cursor and buffer pointer
 * regardless of the error status.
 */
STATIC int
scxfs_iwalk_ag_start(
	struct scxfs_iwalk_ag	*iwag,
	scxfs_agnumber_t		agno,
	scxfs_agino_t		agino,
	struct scxfs_btree_cur	**curpp,
	struct scxfs_buf		**agi_bpp,
	int			*has_more)
{
	struct scxfs_mount	*mp = iwag->mp;
	struct scxfs_trans	*tp = iwag->tp;
	struct scxfs_inobt_rec_incore *irec;
	int			error;

	/* Set up a fresh cursor and empty the inobt cache. */
	iwag->nr_recs = 0;
	error = scxfs_inobt_cur(mp, tp, agno, SCXFS_BTNUM_INO, curpp, agi_bpp);
	if (error)
		return error;

	/* Starting at the beginning of the AG?  That's easy! */
	if (agino == 0)
		return scxfs_inobt_lookup(*curpp, 0, SCXFS_LOOKUP_GE, has_more);

	/*
	 * Otherwise, we have to grab the inobt record where we left off, stuff
	 * the record into our cache, and then see if there are more records.
	 * We require a lookup cache of at least two elements so that the
	 * caller doesn't have to deal with tearing down the cursor to walk the
	 * records.
	 */
	error = scxfs_inobt_lookup(*curpp, agino, SCXFS_LOOKUP_LE, has_more);
	if (error)
		return error;

	/*
	 * If the LE lookup at @agino yields no records, jump ahead to the
	 * inobt cursor increment to see if there are more records to process.
	 */
	if (!*has_more)
		goto out_advance;

	/* Get the record, should always work */
	irec = &iwag->recs[iwag->nr_recs];
	error = scxfs_inobt_get_rec(*curpp, irec, has_more);
	if (error)
		return error;
	SCXFS_WANT_CORRUPTED_RETURN(mp, *has_more == 1);

	/*
	 * If the LE lookup yielded an inobt record before the cursor position,
	 * skip it and see if there's another one after it.
	 */
	if (irec->ir_startino + SCXFS_INODES_PER_CHUNK <= agino)
		goto out_advance;

	/*
	 * If agino fell in the middle of the inode record, make it look like
	 * the inodes up to agino are free so that we don't return them again.
	 */
	if (iwag->trim_start)
		scxfs_iwalk_adjust_start(agino, irec);

	/*
	 * The prefetch calculation is supposed to give us a large enough inobt
	 * record cache that grab_ichunk can stage a partial first record and
	 * the loop body can cache a record without having to check for cache
	 * space until after it reads an inobt record.
	 */
	iwag->nr_recs++;
	ASSERT(iwag->nr_recs < iwag->sz_recs);

out_advance:
	return scxfs_btree_increment(*curpp, 0, has_more);
}

/*
 * The inobt record cache is full, so preserve the inobt cursor state and
 * run callbacks on the cached inobt records.  When we're done, restore the
 * cursor state to wherever the cursor would have been had the cache not been
 * full (and therefore we could've just incremented the cursor) if *@has_more
 * is true.  On exit, *@has_more will indicate whether or not the caller should
 * try for more inode records.
 */
STATIC int
scxfs_iwalk_run_callbacks(
	struct scxfs_iwalk_ag		*iwag,
	scxfs_agnumber_t			agno,
	struct scxfs_btree_cur		**curpp,
	struct scxfs_buf			**agi_bpp,
	int				*has_more)
{
	struct scxfs_mount		*mp = iwag->mp;
	struct scxfs_trans		*tp = iwag->tp;
	struct scxfs_inobt_rec_incore	*irec;
	scxfs_agino_t			restart;
	int				error;

	ASSERT(iwag->nr_recs > 0);

	/* Delete cursor but remember the last record we cached... */
	scxfs_iwalk_del_inobt(tp, curpp, agi_bpp, 0);
	irec = &iwag->recs[iwag->nr_recs - 1];
	restart = irec->ir_startino + SCXFS_INODES_PER_CHUNK - 1;

	error = scxfs_iwalk_ag_recs(iwag);
	if (error)
		return error;

	/* ...empty the cache... */
	iwag->nr_recs = 0;

	if (!has_more)
		return 0;

	/* ...and recreate the cursor just past where we left off. */
	error = scxfs_inobt_cur(mp, tp, agno, SCXFS_BTNUM_INO, curpp, agi_bpp);
	if (error)
		return error;

	return scxfs_inobt_lookup(*curpp, restart, SCXFS_LOOKUP_GE, has_more);
}

/* Walk all inodes in a single AG, from @iwag->startino to the end of the AG. */
STATIC int
scxfs_iwalk_ag(
	struct scxfs_iwalk_ag		*iwag)
{
	struct scxfs_mount		*mp = iwag->mp;
	struct scxfs_trans		*tp = iwag->tp;
	struct scxfs_buf			*agi_bp = NULL;
	struct scxfs_btree_cur		*cur = NULL;
	scxfs_agnumber_t			agno;
	scxfs_agino_t			agino;
	int				has_more;
	int				error = 0;

	/* Set up our cursor at the right place in the inode btree. */
	agno = SCXFS_INO_TO_AGNO(mp, iwag->startino);
	agino = SCXFS_INO_TO_AGINO(mp, iwag->startino);
	error = scxfs_iwalk_ag_start(iwag, agno, agino, &cur, &agi_bp, &has_more);

	while (!error && has_more) {
		struct scxfs_inobt_rec_incore	*irec;

		cond_resched();
		if (scxfs_pwork_want_abort(&iwag->pwork))
			goto out;

		/* Fetch the inobt record. */
		irec = &iwag->recs[iwag->nr_recs];
		error = scxfs_inobt_get_rec(cur, irec, &has_more);
		if (error || !has_more)
			break;

		/* No allocated inodes in this chunk; skip it. */
		if (iwag->skip_empty && irec->ir_freecount == irec->ir_count) {
			error = scxfs_btree_increment(cur, 0, &has_more);
			if (error)
				break;
			continue;
		}

		/*
		 * Start readahead for this inode chunk in anticipation of
		 * walking the inodes.
		 */
		if (iwag->iwalk_fn)
			scxfs_iwalk_ichunk_ra(mp, agno, irec);

		/*
		 * If there's space in the buffer for more records, increment
		 * the btree cursor and grab more.
		 */
		if (++iwag->nr_recs < iwag->sz_recs) {
			error = scxfs_btree_increment(cur, 0, &has_more);
			if (error || !has_more)
				break;
			continue;
		}

		/*
		 * Otherwise, we need to save cursor state and run the callback
		 * function on the cached records.  The run_callbacks function
		 * is supposed to return a cursor pointing to the record where
		 * we would be if we had been able to increment like above.
		 */
		ASSERT(has_more);
		error = scxfs_iwalk_run_callbacks(iwag, agno, &cur, &agi_bp,
				&has_more);
	}

	if (iwag->nr_recs == 0 || error)
		goto out;

	/* Walk the unprocessed records in the cache. */
	error = scxfs_iwalk_run_callbacks(iwag, agno, &cur, &agi_bp, &has_more);

out:
	scxfs_iwalk_del_inobt(tp, &cur, &agi_bp, error);
	return error;
}

/*
 * We experimentally determined that the reduction in ioctl call overhead
 * diminishes when userspace asks for more than 2048 inodes, so we'll cap
 * prefetch at this point.
 */
#define IWALK_MAX_INODE_PREFETCH	(2048U)

/*
 * Given the number of inodes to prefetch, set the number of inobt records that
 * we cache in memory, which controls the number of inodes we try to read
 * ahead.  Set the maximum if @inodes == 0.
 */
static inline unsigned int
scxfs_iwalk_prefetch(
	unsigned int		inodes)
{
	unsigned int		inobt_records;

	/*
	 * If the caller didn't tell us the number of inodes they wanted,
	 * assume the maximum prefetch possible for best performance.
	 * Otherwise, cap prefetch at that maximum so that we don't start an
	 * absurd amount of prefetch.
	 */
	if (inodes == 0)
		inodes = IWALK_MAX_INODE_PREFETCH;
	inodes = min(inodes, IWALK_MAX_INODE_PREFETCH);

	/* Round the inode count up to a full chunk. */
	inodes = round_up(inodes, SCXFS_INODES_PER_CHUNK);

	/*
	 * In order to convert the number of inodes to prefetch into an
	 * estimate of the number of inobt records to cache, we require a
	 * conversion factor that reflects our expectations of the average
	 * loading factor of an inode chunk.  Based on data gathered, most
	 * (but not all) filesystems manage to keep the inode chunks totally
	 * full, so we'll underestimate slightly so that our readahead will
	 * still deliver the performance we want on aging filesystems:
	 *
	 * inobt = inodes / (INODES_PER_CHUNK * (4 / 5));
	 *
	 * The funny math is to avoid integer division.
	 */
	inobt_records = (inodes * 5) / (4 * SCXFS_INODES_PER_CHUNK);

	/*
	 * Allocate enough space to prefetch at least two inobt records so that
	 * we can cache both the record where the iwalk started and the next
	 * record.  This simplifies the AG inode walk loop setup code.
	 */
	return max(inobt_records, 2U);
}

/*
 * Walk all inodes in the filesystem starting from @startino.  The @iwalk_fn
 * will be called for each allocated inode, being passed the inode's number and
 * @data.  @max_prefetch controls how many inobt records' worth of inodes we
 * try to readahead.
 */
int
scxfs_iwalk(
	struct scxfs_mount	*mp,
	struct scxfs_trans	*tp,
	scxfs_ino_t		startino,
	unsigned int		flags,
	scxfs_iwalk_fn		iwalk_fn,
	unsigned int		inode_records,
	void			*data)
{
	struct scxfs_iwalk_ag	iwag = {
		.mp		= mp,
		.tp		= tp,
		.iwalk_fn	= iwalk_fn,
		.data		= data,
		.startino	= startino,
		.sz_recs	= scxfs_iwalk_prefetch(inode_records),
		.trim_start	= 1,
		.skip_empty	= 1,
		.pwork		= SCXFS_PWORK_SINGLE_THREADED,
	};
	scxfs_agnumber_t		agno = SCXFS_INO_TO_AGNO(mp, startino);
	int			error;

	ASSERT(agno < mp->m_sb.sb_agcount);
	ASSERT(!(flags & ~SCXFS_IWALK_FLAGS_ALL));

	error = scxfs_iwalk_alloc(&iwag);
	if (error)
		return error;

	for (; agno < mp->m_sb.sb_agcount; agno++) {
		error = scxfs_iwalk_ag(&iwag);
		if (error)
			break;
		iwag.startino = SCXFS_AGINO_TO_INO(mp, agno + 1, 0);
		if (flags & SCXFS_INOBT_WALK_SAME_AG)
			break;
	}

	scxfs_iwalk_free(&iwag);
	return error;
}

/* Run per-thread iwalk work. */
static int
scxfs_iwalk_ag_work(
	struct scxfs_mount	*mp,
	struct scxfs_pwork	*pwork)
{
	struct scxfs_iwalk_ag	*iwag;
	int			error = 0;

	iwag = container_of(pwork, struct scxfs_iwalk_ag, pwork);
	if (scxfs_pwork_want_abort(pwork))
		goto out;

	error = scxfs_iwalk_alloc(iwag);
	if (error)
		goto out;

	error = scxfs_iwalk_ag(iwag);
	scxfs_iwalk_free(iwag);
out:
	kmem_free(iwag);
	return error;
}

/*
 * Walk all the inodes in the filesystem using multiple threads to process each
 * AG.
 */
int
scxfs_iwalk_threaded(
	struct scxfs_mount	*mp,
	scxfs_ino_t		startino,
	unsigned int		flags,
	scxfs_iwalk_fn		iwalk_fn,
	unsigned int		inode_records,
	bool			polled,
	void			*data)
{
	struct scxfs_pwork_ctl	pctl;
	scxfs_agnumber_t		agno = SCXFS_INO_TO_AGNO(mp, startino);
	unsigned int		nr_threads;
	int			error;

	ASSERT(agno < mp->m_sb.sb_agcount);
	ASSERT(!(flags & ~SCXFS_IWALK_FLAGS_ALL));

	nr_threads = scxfs_pwork_guess_datadev_parallelism(mp);
	error = scxfs_pwork_init(mp, &pctl, scxfs_iwalk_ag_work, "scxfs_iwalk",
			nr_threads);
	if (error)
		return error;

	for (; agno < mp->m_sb.sb_agcount; agno++) {
		struct scxfs_iwalk_ag	*iwag;

		if (scxfs_pwork_ctl_want_abort(&pctl))
			break;

		iwag = kmem_zalloc(sizeof(struct scxfs_iwalk_ag), 0);
		iwag->mp = mp;
		iwag->iwalk_fn = iwalk_fn;
		iwag->data = data;
		iwag->startino = startino;
		iwag->sz_recs = scxfs_iwalk_prefetch(inode_records);
		scxfs_pwork_queue(&pctl, &iwag->pwork);
		startino = SCXFS_AGINO_TO_INO(mp, agno + 1, 0);
		if (flags & SCXFS_INOBT_WALK_SAME_AG)
			break;
	}

	if (polled)
		scxfs_pwork_poll(&pctl);
	return scxfs_pwork_destroy(&pctl);
}

/*
 * Allow callers to cache up to a page's worth of inobt records.  This reflects
 * the existing inumbers prefetching behavior.  Since the inobt walk does not
 * itself do anything with the inobt records, we can set a fairly high limit
 * here.
 */
#define MAX_INOBT_WALK_PREFETCH	\
	(PAGE_SIZE / sizeof(struct scxfs_inobt_rec_incore))

/*
 * Given the number of records that the user wanted, set the number of inobt
 * records that we buffer in memory.  Set the maximum if @inobt_records == 0.
 */
static inline unsigned int
scxfs_inobt_walk_prefetch(
	unsigned int		inobt_records)
{
	/*
	 * If the caller didn't tell us the number of inobt records they
	 * wanted, assume the maximum prefetch possible for best performance.
	 */
	if (inobt_records == 0)
		inobt_records = MAX_INOBT_WALK_PREFETCH;

	/*
	 * Allocate enough space to prefetch at least two inobt records so that
	 * we can cache both the record where the iwalk started and the next
	 * record.  This simplifies the AG inode walk loop setup code.
	 */
	inobt_records = max(inobt_records, 2U);

	/*
	 * Cap prefetch at that maximum so that we don't use an absurd amount
	 * of memory.
	 */
	return min_t(unsigned int, inobt_records, MAX_INOBT_WALK_PREFETCH);
}

/*
 * Walk all inode btree records in the filesystem starting from @startino.  The
 * @inobt_walk_fn will be called for each btree record, being passed the incore
 * record and @data.  @max_prefetch controls how many inobt records we try to
 * cache ahead of time.
 */
int
scxfs_inobt_walk(
	struct scxfs_mount	*mp,
	struct scxfs_trans	*tp,
	scxfs_ino_t		startino,
	unsigned int		flags,
	scxfs_inobt_walk_fn	inobt_walk_fn,
	unsigned int		inobt_records,
	void			*data)
{
	struct scxfs_iwalk_ag	iwag = {
		.mp		= mp,
		.tp		= tp,
		.inobt_walk_fn	= inobt_walk_fn,
		.data		= data,
		.startino	= startino,
		.sz_recs	= scxfs_inobt_walk_prefetch(inobt_records),
		.pwork		= SCXFS_PWORK_SINGLE_THREADED,
	};
	scxfs_agnumber_t		agno = SCXFS_INO_TO_AGNO(mp, startino);
	int			error;

	ASSERT(agno < mp->m_sb.sb_agcount);
	ASSERT(!(flags & ~SCXFS_INOBT_WALK_FLAGS_ALL));

	error = scxfs_iwalk_alloc(&iwag);
	if (error)
		return error;

	for (; agno < mp->m_sb.sb_agcount; agno++) {
		error = scxfs_iwalk_ag(&iwag);
		if (error)
			break;
		iwag.startino = SCXFS_AGINO_TO_INO(mp, agno + 1, 0);
		if (flags & SCXFS_INOBT_WALK_SAME_AG)
			break;
	}

	scxfs_iwalk_free(&iwag);
	return error;
}
