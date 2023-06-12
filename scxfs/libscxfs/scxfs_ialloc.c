// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2002,2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#include "scxfs.h"
#include "scxfs_fs.h"
#include "scxfs_shared.h"
#include "scxfs_format.h"
#include "scxfs_log_format.h"
#include "scxfs_trans_resv.h"
#include "scxfs_bit.h"
#include "scxfs_sb.h"
#include "scxfs_mount.h"
#include "scxfs_inode.h"
#include "scxfs_btree.h"
#include "scxfs_ialloc.h"
#include "scxfs_ialloc_btree.h"
#include "scxfs_alloc.h"
#include "scxfs_errortag.h"
#include "scxfs_error.h"
#include "scxfs_bmap.h"
#include "scxfs_trans.h"
#include "scxfs_buf_item.h"
#include "scxfs_icreate_item.h"
#include "scxfs_icache.h"
#include "scxfs_trace.h"
#include "scxfs_log.h"
#include "scxfs_rmap.h"

/*
 * Lookup a record by ino in the btree given by cur.
 */
int					/* error */
scxfs_inobt_lookup(
	struct scxfs_btree_cur	*cur,	/* btree cursor */
	scxfs_agino_t		ino,	/* starting inode of chunk */
	scxfs_lookup_t		dir,	/* <=, >=, == */
	int			*stat)	/* success/failure */
{
	cur->bc_rec.i.ir_startino = ino;
	cur->bc_rec.i.ir_holemask = 0;
	cur->bc_rec.i.ir_count = 0;
	cur->bc_rec.i.ir_freecount = 0;
	cur->bc_rec.i.ir_free = 0;
	return scxfs_btree_lookup(cur, dir, stat);
}

/*
 * Update the record referred to by cur to the value given.
 * This either works (return 0) or gets an EFSCORRUPTED error.
 */
STATIC int				/* error */
scxfs_inobt_update(
	struct scxfs_btree_cur	*cur,	/* btree cursor */
	scxfs_inobt_rec_incore_t	*irec)	/* btree record */
{
	union scxfs_btree_rec	rec;

	rec.inobt.ir_startino = cpu_to_be32(irec->ir_startino);
	if (scxfs_sb_version_hassparseinodes(&cur->bc_mp->m_sb)) {
		rec.inobt.ir_u.sp.ir_holemask = cpu_to_be16(irec->ir_holemask);
		rec.inobt.ir_u.sp.ir_count = irec->ir_count;
		rec.inobt.ir_u.sp.ir_freecount = irec->ir_freecount;
	} else {
		/* ir_holemask/ir_count not supported on-disk */
		rec.inobt.ir_u.f.ir_freecount = cpu_to_be32(irec->ir_freecount);
	}
	rec.inobt.ir_free = cpu_to_be64(irec->ir_free);
	return scxfs_btree_update(cur, &rec);
}

/* Convert on-disk btree record to incore inobt record. */
void
scxfs_inobt_btrec_to_irec(
	struct scxfs_mount		*mp,
	union scxfs_btree_rec		*rec,
	struct scxfs_inobt_rec_incore	*irec)
{
	irec->ir_startino = be32_to_cpu(rec->inobt.ir_startino);
	if (scxfs_sb_version_hassparseinodes(&mp->m_sb)) {
		irec->ir_holemask = be16_to_cpu(rec->inobt.ir_u.sp.ir_holemask);
		irec->ir_count = rec->inobt.ir_u.sp.ir_count;
		irec->ir_freecount = rec->inobt.ir_u.sp.ir_freecount;
	} else {
		/*
		 * ir_holemask/ir_count not supported on-disk. Fill in hardcoded
		 * values for full inode chunks.
		 */
		irec->ir_holemask = SCXFS_INOBT_HOLEMASK_FULL;
		irec->ir_count = SCXFS_INODES_PER_CHUNK;
		irec->ir_freecount =
				be32_to_cpu(rec->inobt.ir_u.f.ir_freecount);
	}
	irec->ir_free = be64_to_cpu(rec->inobt.ir_free);
}

/*
 * Get the data from the pointed-to record.
 */
int
scxfs_inobt_get_rec(
	struct scxfs_btree_cur		*cur,
	struct scxfs_inobt_rec_incore	*irec,
	int				*stat)
{
	struct scxfs_mount		*mp = cur->bc_mp;
	scxfs_agnumber_t			agno = cur->bc_private.a.agno;
	union scxfs_btree_rec		*rec;
	int				error;
	uint64_t			realfree;

	error = scxfs_btree_get_rec(cur, &rec, stat);
	if (error || *stat == 0)
		return error;

	scxfs_inobt_btrec_to_irec(mp, rec, irec);

	if (!scxfs_verify_agino(mp, agno, irec->ir_startino))
		goto out_bad_rec;
	if (irec->ir_count < SCXFS_INODES_PER_HOLEMASK_BIT ||
	    irec->ir_count > SCXFS_INODES_PER_CHUNK)
		goto out_bad_rec;
	if (irec->ir_freecount > SCXFS_INODES_PER_CHUNK)
		goto out_bad_rec;

	/* if there are no holes, return the first available offset */
	if (!scxfs_inobt_issparse(irec->ir_holemask))
		realfree = irec->ir_free;
	else
		realfree = irec->ir_free & scxfs_inobt_irec_to_allocmask(irec);
	if (hweight64(realfree) != irec->ir_freecount)
		goto out_bad_rec;

	return 0;

out_bad_rec:
	scxfs_warn(mp,
		"%s Inode BTree record corruption in AG %d detected!",
		cur->bc_btnum == SCXFS_BTNUM_INO ? "Used" : "Free", agno);
	scxfs_warn(mp,
"start inode 0x%x, count 0x%x, free 0x%x freemask 0x%llx, holemask 0x%x",
		irec->ir_startino, irec->ir_count, irec->ir_freecount,
		irec->ir_free, irec->ir_holemask);
	return -EFSCORRUPTED;
}

/*
 * Insert a single inobt record. Cursor must already point to desired location.
 */
int
scxfs_inobt_insert_rec(
	struct scxfs_btree_cur	*cur,
	uint16_t		holemask,
	uint8_t			count,
	int32_t			freecount,
	scxfs_inofree_t		free,
	int			*stat)
{
	cur->bc_rec.i.ir_holemask = holemask;
	cur->bc_rec.i.ir_count = count;
	cur->bc_rec.i.ir_freecount = freecount;
	cur->bc_rec.i.ir_free = free;
	return scxfs_btree_insert(cur, stat);
}

/*
 * Insert records describing a newly allocated inode chunk into the inobt.
 */
STATIC int
scxfs_inobt_insert(
	struct scxfs_mount	*mp,
	struct scxfs_trans	*tp,
	struct scxfs_buf		*agbp,
	scxfs_agino_t		newino,
	scxfs_agino_t		newlen,
	scxfs_btnum_t		btnum)
{
	struct scxfs_btree_cur	*cur;
	struct scxfs_agi		*agi = SCXFS_BUF_TO_AGI(agbp);
	scxfs_agnumber_t		agno = be32_to_cpu(agi->agi_seqno);
	scxfs_agino_t		thisino;
	int			i;
	int			error;

	cur = scxfs_inobt_init_cursor(mp, tp, agbp, agno, btnum);

	for (thisino = newino;
	     thisino < newino + newlen;
	     thisino += SCXFS_INODES_PER_CHUNK) {
		error = scxfs_inobt_lookup(cur, thisino, SCXFS_LOOKUP_EQ, &i);
		if (error) {
			scxfs_btree_del_cursor(cur, SCXFS_BTREE_ERROR);
			return error;
		}
		ASSERT(i == 0);

		error = scxfs_inobt_insert_rec(cur, SCXFS_INOBT_HOLEMASK_FULL,
					     SCXFS_INODES_PER_CHUNK,
					     SCXFS_INODES_PER_CHUNK,
					     SCXFS_INOBT_ALL_FREE, &i);
		if (error) {
			scxfs_btree_del_cursor(cur, SCXFS_BTREE_ERROR);
			return error;
		}
		ASSERT(i == 1);
	}

	scxfs_btree_del_cursor(cur, SCXFS_BTREE_NOERROR);

	return 0;
}

/*
 * Verify that the number of free inodes in the AGI is correct.
 */
#ifdef DEBUG
STATIC int
scxfs_check_agi_freecount(
	struct scxfs_btree_cur	*cur,
	struct scxfs_agi		*agi)
{
	if (cur->bc_nlevels == 1) {
		scxfs_inobt_rec_incore_t rec;
		int		freecount = 0;
		int		error;
		int		i;

		error = scxfs_inobt_lookup(cur, 0, SCXFS_LOOKUP_GE, &i);
		if (error)
			return error;

		do {
			error = scxfs_inobt_get_rec(cur, &rec, &i);
			if (error)
				return error;

			if (i) {
				freecount += rec.ir_freecount;
				error = scxfs_btree_increment(cur, 0, &i);
				if (error)
					return error;
			}
		} while (i == 1);

		if (!SCXFS_FORCED_SHUTDOWN(cur->bc_mp))
			ASSERT(freecount == be32_to_cpu(agi->agi_freecount));
	}
	return 0;
}
#else
#define scxfs_check_agi_freecount(cur, agi)	0
#endif

/*
 * Initialise a new set of inodes. When called without a transaction context
 * (e.g. from recovery) we initiate a delayed write of the inode buffers rather
 * than logging them (which in a transaction context puts them into the AIL
 * for writeback rather than the xfsbufd queue).
 */
int
scxfs_ialloc_inode_init(
	struct scxfs_mount	*mp,
	struct scxfs_trans	*tp,
	struct list_head	*buffer_list,
	int			icount,
	scxfs_agnumber_t		agno,
	scxfs_agblock_t		agbno,
	scxfs_agblock_t		length,
	unsigned int		gen)
{
	struct scxfs_buf		*fbuf;
	struct scxfs_dinode	*free;
	int			nbufs;
	int			version;
	int			i, j;
	scxfs_daddr_t		d;
	scxfs_ino_t		ino = 0;

	/*
	 * Loop over the new block(s), filling in the inodes.  For small block
	 * sizes, manipulate the inodes in buffers  which are multiples of the
	 * blocks size.
	 */
	nbufs = length / M_IGEO(mp)->blocks_per_cluster;

	/*
	 * Figure out what version number to use in the inodes we create.  If
	 * the superblock version has caught up to the one that supports the new
	 * inode format, then use the new inode version.  Otherwise use the old
	 * version so that old kernels will continue to be able to use the file
	 * system.
	 *
	 * For v3 inodes, we also need to write the inode number into the inode,
	 * so calculate the first inode number of the chunk here as
	 * SCXFS_AGB_TO_AGINO() only works within a filesystem block, not
	 * across multiple filesystem blocks (such as a cluster) and so cannot
	 * be used in the cluster buffer loop below.
	 *
	 * Further, because we are writing the inode directly into the buffer
	 * and calculating a CRC on the entire inode, we have ot log the entire
	 * inode so that the entire range the CRC covers is present in the log.
	 * That means for v3 inode we log the entire buffer rather than just the
	 * inode cores.
	 */
	if (scxfs_sb_version_hascrc(&mp->m_sb)) {
		version = 3;
		ino = SCXFS_AGINO_TO_INO(mp, agno, SCXFS_AGB_TO_AGINO(mp, agbno));

		/*
		 * log the initialisation that is about to take place as an
		 * logical operation. This means the transaction does not
		 * need to log the physical changes to the inode buffers as log
		 * recovery will know what initialisation is actually needed.
		 * Hence we only need to log the buffers as "ordered" buffers so
		 * they track in the AIL as if they were physically logged.
		 */
		if (tp)
			scxfs_icreate_log(tp, agno, agbno, icount,
					mp->m_sb.sb_inodesize, length, gen);
	} else
		version = 2;

	for (j = 0; j < nbufs; j++) {
		/*
		 * Get the block.
		 */
		d = SCXFS_AGB_TO_DADDR(mp, agno, agbno +
				(j * M_IGEO(mp)->blocks_per_cluster));
		fbuf = scxfs_trans_get_buf(tp, mp->m_ddev_targp, d,
					 mp->m_bsize *
					 M_IGEO(mp)->blocks_per_cluster,
					 XBF_UNMAPPED);
		if (!fbuf)
			return -ENOMEM;

		/* Initialize the inode buffers and log them appropriately. */
		fbuf->b_ops = &scxfs_inode_buf_ops;
		scxfs_buf_zero(fbuf, 0, BBTOB(fbuf->b_length));
		for (i = 0; i < M_IGEO(mp)->inodes_per_cluster; i++) {
			int	ioffset = i << mp->m_sb.sb_inodelog;
			uint	isize = scxfs_dinode_size(version);

			free = scxfs_make_iptr(mp, fbuf, i);
			free->di_magic = cpu_to_be16(SCXFS_DINODE_MAGIC);
			free->di_version = version;
			free->di_gen = cpu_to_be32(gen);
			free->di_next_unlinked = cpu_to_be32(NULLAGINO);

			if (version == 3) {
				free->di_ino = cpu_to_be64(ino);
				ino++;
				uuid_copy(&free->di_uuid,
					  &mp->m_sb.sb_meta_uuid);
				scxfs_dinode_calc_crc(mp, free);
			} else if (tp) {
				/* just log the inode core */
				scxfs_trans_log_buf(tp, fbuf, ioffset,
						  ioffset + isize - 1);
			}
		}

		if (tp) {
			/*
			 * Mark the buffer as an inode allocation buffer so it
			 * sticks in AIL at the point of this allocation
			 * transaction. This ensures the they are on disk before
			 * the tail of the log can be moved past this
			 * transaction (i.e. by preventing relogging from moving
			 * it forward in the log).
			 */
			scxfs_trans_inode_alloc_buf(tp, fbuf);
			if (version == 3) {
				/*
				 * Mark the buffer as ordered so that they are
				 * not physically logged in the transaction but
				 * still tracked in the AIL as part of the
				 * transaction and pin the log appropriately.
				 */
				scxfs_trans_ordered_buf(tp, fbuf);
			}
		} else {
			fbuf->b_flags |= XBF_DONE;
			scxfs_buf_delwri_queue(fbuf, buffer_list);
			scxfs_buf_relse(fbuf);
		}
	}
	return 0;
}

/*
 * Align startino and allocmask for a recently allocated sparse chunk such that
 * they are fit for insertion (or merge) into the on-disk inode btrees.
 *
 * Background:
 *
 * When enabled, sparse inode support increases the inode alignment from cluster
 * size to inode chunk size. This means that the minimum range between two
 * non-adjacent inode records in the inobt is large enough for a full inode
 * record. This allows for cluster sized, cluster aligned block allocation
 * without need to worry about whether the resulting inode record overlaps with
 * another record in the tree. Without this basic rule, we would have to deal
 * with the consequences of overlap by potentially undoing recent allocations in
 * the inode allocation codepath.
 *
 * Because of this alignment rule (which is enforced on mount), there are two
 * inobt possibilities for newly allocated sparse chunks. One is that the
 * aligned inode record for the chunk covers a range of inodes not already
 * covered in the inobt (i.e., it is safe to insert a new sparse record). The
 * other is that a record already exists at the aligned startino that considers
 * the newly allocated range as sparse. In the latter case, record content is
 * merged in hope that sparse inode chunks fill to full chunks over time.
 */
STATIC void
scxfs_align_sparse_ino(
	struct scxfs_mount		*mp,
	scxfs_agino_t			*startino,
	uint16_t			*allocmask)
{
	scxfs_agblock_t			agbno;
	scxfs_agblock_t			mod;
	int				offset;

	agbno = SCXFS_AGINO_TO_AGBNO(mp, *startino);
	mod = agbno % mp->m_sb.sb_inoalignmt;
	if (!mod)
		return;

	/* calculate the inode offset and align startino */
	offset = SCXFS_AGB_TO_AGINO(mp, mod);
	*startino -= offset;

	/*
	 * Since startino has been aligned down, left shift allocmask such that
	 * it continues to represent the same physical inodes relative to the
	 * new startino.
	 */
	*allocmask <<= offset / SCXFS_INODES_PER_HOLEMASK_BIT;
}

/*
 * Determine whether the source inode record can merge into the target. Both
 * records must be sparse, the inode ranges must match and there must be no
 * allocation overlap between the records.
 */
STATIC bool
__scxfs_inobt_can_merge(
	struct scxfs_inobt_rec_incore	*trec,	/* tgt record */
	struct scxfs_inobt_rec_incore	*srec)	/* src record */
{
	uint64_t			talloc;
	uint64_t			salloc;

	/* records must cover the same inode range */
	if (trec->ir_startino != srec->ir_startino)
		return false;

	/* both records must be sparse */
	if (!scxfs_inobt_issparse(trec->ir_holemask) ||
	    !scxfs_inobt_issparse(srec->ir_holemask))
		return false;

	/* both records must track some inodes */
	if (!trec->ir_count || !srec->ir_count)
		return false;

	/* can't exceed capacity of a full record */
	if (trec->ir_count + srec->ir_count > SCXFS_INODES_PER_CHUNK)
		return false;

	/* verify there is no allocation overlap */
	talloc = scxfs_inobt_irec_to_allocmask(trec);
	salloc = scxfs_inobt_irec_to_allocmask(srec);
	if (talloc & salloc)
		return false;

	return true;
}

/*
 * Merge the source inode record into the target. The caller must call
 * __scxfs_inobt_can_merge() to ensure the merge is valid.
 */
STATIC void
__scxfs_inobt_rec_merge(
	struct scxfs_inobt_rec_incore	*trec,	/* target */
	struct scxfs_inobt_rec_incore	*srec)	/* src */
{
	ASSERT(trec->ir_startino == srec->ir_startino);

	/* combine the counts */
	trec->ir_count += srec->ir_count;
	trec->ir_freecount += srec->ir_freecount;

	/*
	 * Merge the holemask and free mask. For both fields, 0 bits refer to
	 * allocated inodes. We combine the allocated ranges with bitwise AND.
	 */
	trec->ir_holemask &= srec->ir_holemask;
	trec->ir_free &= srec->ir_free;
}

/*
 * Insert a new sparse inode chunk into the associated inode btree. The inode
 * record for the sparse chunk is pre-aligned to a startino that should match
 * any pre-existing sparse inode record in the tree. This allows sparse chunks
 * to fill over time.
 *
 * This function supports two modes of handling preexisting records depending on
 * the merge flag. If merge is true, the provided record is merged with the
 * existing record and updated in place. The merged record is returned in nrec.
 * If merge is false, an existing record is replaced with the provided record.
 * If no preexisting record exists, the provided record is always inserted.
 *
 * It is considered corruption if a merge is requested and not possible. Given
 * the sparse inode alignment constraints, this should never happen.
 */
STATIC int
scxfs_inobt_insert_sprec(
	struct scxfs_mount		*mp,
	struct scxfs_trans		*tp,
	struct scxfs_buf			*agbp,
	int				btnum,
	struct scxfs_inobt_rec_incore	*nrec,	/* in/out: new/merged rec. */
	bool				merge)	/* merge or replace */
{
	struct scxfs_btree_cur		*cur;
	struct scxfs_agi			*agi = SCXFS_BUF_TO_AGI(agbp);
	scxfs_agnumber_t			agno = be32_to_cpu(agi->agi_seqno);
	int				error;
	int				i;
	struct scxfs_inobt_rec_incore	rec;

	cur = scxfs_inobt_init_cursor(mp, tp, agbp, agno, btnum);

	/* the new record is pre-aligned so we know where to look */
	error = scxfs_inobt_lookup(cur, nrec->ir_startino, SCXFS_LOOKUP_EQ, &i);
	if (error)
		goto error;
	/* if nothing there, insert a new record and return */
	if (i == 0) {
		error = scxfs_inobt_insert_rec(cur, nrec->ir_holemask,
					     nrec->ir_count, nrec->ir_freecount,
					     nrec->ir_free, &i);
		if (error)
			goto error;
		SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, error);

		goto out;
	}

	/*
	 * A record exists at this startino. Merge or replace the record
	 * depending on what we've been asked to do.
	 */
	if (merge) {
		error = scxfs_inobt_get_rec(cur, &rec, &i);
		if (error)
			goto error;
		SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, error);
		SCXFS_WANT_CORRUPTED_GOTO(mp,
					rec.ir_startino == nrec->ir_startino,
					error);

		/*
		 * This should never fail. If we have coexisting records that
		 * cannot merge, something is seriously wrong.
		 */
		SCXFS_WANT_CORRUPTED_GOTO(mp, __scxfs_inobt_can_merge(nrec, &rec),
					error);

		trace_scxfs_irec_merge_pre(mp, agno, rec.ir_startino,
					 rec.ir_holemask, nrec->ir_startino,
					 nrec->ir_holemask);

		/* merge to nrec to output the updated record */
		__scxfs_inobt_rec_merge(nrec, &rec);

		trace_scxfs_irec_merge_post(mp, agno, nrec->ir_startino,
					  nrec->ir_holemask);

		error = scxfs_inobt_rec_check_count(mp, nrec);
		if (error)
			goto error;
	}

	error = scxfs_inobt_update(cur, nrec);
	if (error)
		goto error;

out:
	scxfs_btree_del_cursor(cur, SCXFS_BTREE_NOERROR);
	return 0;
error:
	scxfs_btree_del_cursor(cur, SCXFS_BTREE_ERROR);
	return error;
}

/*
 * Allocate new inodes in the allocation group specified by agbp.
 * Return 0 for success, else error code.
 */
STATIC int
scxfs_ialloc_ag_alloc(
	struct scxfs_trans	*tp,
	struct scxfs_buf		*agbp,
	int			*alloc)
{
	struct scxfs_agi		*agi;
	struct scxfs_alloc_arg	args;
	scxfs_agnumber_t		agno;
	int			error;
	scxfs_agino_t		newino;		/* new first inode's number */
	scxfs_agino_t		newlen;		/* new number of inodes */
	int			isaligned = 0;	/* inode allocation at stripe */
						/* unit boundary */
	/* init. to full chunk */
	uint16_t		allocmask = (uint16_t) -1;
	struct scxfs_inobt_rec_incore rec;
	struct scxfs_perag	*pag;
	struct scxfs_ino_geometry	*igeo = M_IGEO(tp->t_mountp);
	int			do_sparse = 0;

	memset(&args, 0, sizeof(args));
	args.tp = tp;
	args.mp = tp->t_mountp;
	args.fsbno = NULLFSBLOCK;
	args.oinfo = SCXFS_RMAP_OINFO_INODES;

#ifdef DEBUG
	/* randomly do sparse inode allocations */
	if (scxfs_sb_version_hassparseinodes(&tp->t_mountp->m_sb) &&
	    igeo->ialloc_min_blks < igeo->ialloc_blks)
		do_sparse = prandom_u32() & 1;
#endif

	/*
	 * Locking will ensure that we don't have two callers in here
	 * at one time.
	 */
	newlen = igeo->ialloc_inos;
	if (igeo->maxicount &&
	    percpu_counter_read_positive(&args.mp->m_icount) + newlen >
							igeo->maxicount)
		return -ENOSPC;
	args.minlen = args.maxlen = igeo->ialloc_blks;
	/*
	 * First try to allocate inodes contiguous with the last-allocated
	 * chunk of inodes.  If the filesystem is striped, this will fill
	 * an entire stripe unit with inodes.
	 */
	agi = SCXFS_BUF_TO_AGI(agbp);
	newino = be32_to_cpu(agi->agi_newino);
	agno = be32_to_cpu(agi->agi_seqno);
	args.agbno = SCXFS_AGINO_TO_AGBNO(args.mp, newino) +
		     igeo->ialloc_blks;
	if (do_sparse)
		goto sparse_alloc;
	if (likely(newino != NULLAGINO &&
		  (args.agbno < be32_to_cpu(agi->agi_length)))) {
		args.fsbno = SCXFS_AGB_TO_FSB(args.mp, agno, args.agbno);
		args.type = SCXFS_ALLOCTYPE_THIS_BNO;
		args.prod = 1;

		/*
		 * We need to take into account alignment here to ensure that
		 * we don't modify the free list if we fail to have an exact
		 * block. If we don't have an exact match, and every oher
		 * attempt allocation attempt fails, we'll end up cancelling
		 * a dirty transaction and shutting down.
		 *
		 * For an exact allocation, alignment must be 1,
		 * however we need to take cluster alignment into account when
		 * fixing up the freelist. Use the minalignslop field to
		 * indicate that extra blocks might be required for alignment,
		 * but not to use them in the actual exact allocation.
		 */
		args.alignment = 1;
		args.minalignslop = igeo->cluster_align - 1;

		/* Allow space for the inode btree to split. */
		args.minleft = igeo->inobt_maxlevels;
		if ((error = scxfs_alloc_vextent(&args)))
			return error;

		/*
		 * This request might have dirtied the transaction if the AG can
		 * satisfy the request, but the exact block was not available.
		 * If the allocation did fail, subsequent requests will relax
		 * the exact agbno requirement and increase the alignment
		 * instead. It is critical that the total size of the request
		 * (len + alignment + slop) does not increase from this point
		 * on, so reset minalignslop to ensure it is not included in
		 * subsequent requests.
		 */
		args.minalignslop = 0;
	}

	if (unlikely(args.fsbno == NULLFSBLOCK)) {
		/*
		 * Set the alignment for the allocation.
		 * If stripe alignment is turned on then align at stripe unit
		 * boundary.
		 * If the cluster size is smaller than a filesystem block
		 * then we're doing I/O for inodes in filesystem block size
		 * pieces, so don't need alignment anyway.
		 */
		isaligned = 0;
		if (igeo->ialloc_align) {
			ASSERT(!(args.mp->m_flags & SCXFS_MOUNT_NOALIGN));
			args.alignment = args.mp->m_dalign;
			isaligned = 1;
		} else
			args.alignment = igeo->cluster_align;
		/*
		 * Need to figure out where to allocate the inode blocks.
		 * Ideally they should be spaced out through the a.g.
		 * For now, just allocate blocks up front.
		 */
		args.agbno = be32_to_cpu(agi->agi_root);
		args.fsbno = SCXFS_AGB_TO_FSB(args.mp, agno, args.agbno);
		/*
		 * Allocate a fixed-size extent of inodes.
		 */
		args.type = SCXFS_ALLOCTYPE_NEAR_BNO;
		args.prod = 1;
		/*
		 * Allow space for the inode btree to split.
		 */
		args.minleft = igeo->inobt_maxlevels;
		if ((error = scxfs_alloc_vextent(&args)))
			return error;
	}

	/*
	 * If stripe alignment is turned on, then try again with cluster
	 * alignment.
	 */
	if (isaligned && args.fsbno == NULLFSBLOCK) {
		args.type = SCXFS_ALLOCTYPE_NEAR_BNO;
		args.agbno = be32_to_cpu(agi->agi_root);
		args.fsbno = SCXFS_AGB_TO_FSB(args.mp, agno, args.agbno);
		args.alignment = igeo->cluster_align;
		if ((error = scxfs_alloc_vextent(&args)))
			return error;
	}

	/*
	 * Finally, try a sparse allocation if the filesystem supports it and
	 * the sparse allocation length is smaller than a full chunk.
	 */
	if (scxfs_sb_version_hassparseinodes(&args.mp->m_sb) &&
	    igeo->ialloc_min_blks < igeo->ialloc_blks &&
	    args.fsbno == NULLFSBLOCK) {
sparse_alloc:
		args.type = SCXFS_ALLOCTYPE_NEAR_BNO;
		args.agbno = be32_to_cpu(agi->agi_root);
		args.fsbno = SCXFS_AGB_TO_FSB(args.mp, agno, args.agbno);
		args.alignment = args.mp->m_sb.sb_spino_align;
		args.prod = 1;

		args.minlen = igeo->ialloc_min_blks;
		args.maxlen = args.minlen;

		/*
		 * The inode record will be aligned to full chunk size. We must
		 * prevent sparse allocation from AG boundaries that result in
		 * invalid inode records, such as records that start at agbno 0
		 * or extend beyond the AG.
		 *
		 * Set min agbno to the first aligned, non-zero agbno and max to
		 * the last aligned agbno that is at least one full chunk from
		 * the end of the AG.
		 */
		args.min_agbno = args.mp->m_sb.sb_inoalignmt;
		args.max_agbno = round_down(args.mp->m_sb.sb_agblocks,
					    args.mp->m_sb.sb_inoalignmt) -
				 igeo->ialloc_blks;

		error = scxfs_alloc_vextent(&args);
		if (error)
			return error;

		newlen = SCXFS_AGB_TO_AGINO(args.mp, args.len);
		ASSERT(newlen <= SCXFS_INODES_PER_CHUNK);
		allocmask = (1 << (newlen / SCXFS_INODES_PER_HOLEMASK_BIT)) - 1;
	}

	if (args.fsbno == NULLFSBLOCK) {
		*alloc = 0;
		return 0;
	}
	ASSERT(args.len == args.minlen);

	/*
	 * Stamp and write the inode buffers.
	 *
	 * Seed the new inode cluster with a random generation number. This
	 * prevents short-term reuse of generation numbers if a chunk is
	 * freed and then immediately reallocated. We use random numbers
	 * rather than a linear progression to prevent the next generation
	 * number from being easily guessable.
	 */
	error = scxfs_ialloc_inode_init(args.mp, tp, NULL, newlen, agno,
			args.agbno, args.len, prandom_u32());

	if (error)
		return error;
	/*
	 * Convert the results.
	 */
	newino = SCXFS_AGB_TO_AGINO(args.mp, args.agbno);

	if (scxfs_inobt_issparse(~allocmask)) {
		/*
		 * We've allocated a sparse chunk. Align the startino and mask.
		 */
		scxfs_align_sparse_ino(args.mp, &newino, &allocmask);

		rec.ir_startino = newino;
		rec.ir_holemask = ~allocmask;
		rec.ir_count = newlen;
		rec.ir_freecount = newlen;
		rec.ir_free = SCXFS_INOBT_ALL_FREE;

		/*
		 * Insert the sparse record into the inobt and allow for a merge
		 * if necessary. If a merge does occur, rec is updated to the
		 * merged record.
		 */
		error = scxfs_inobt_insert_sprec(args.mp, tp, agbp, SCXFS_BTNUM_INO,
					       &rec, true);
		if (error == -EFSCORRUPTED) {
			scxfs_alert(args.mp,
	"invalid sparse inode record: ino 0x%llx holemask 0x%x count %u",
				  SCXFS_AGINO_TO_INO(args.mp, agno,
						   rec.ir_startino),
				  rec.ir_holemask, rec.ir_count);
			scxfs_force_shutdown(args.mp, SHUTDOWN_CORRUPT_INCORE);
		}
		if (error)
			return error;

		/*
		 * We can't merge the part we've just allocated as for the inobt
		 * due to finobt semantics. The original record may or may not
		 * exist independent of whether physical inodes exist in this
		 * sparse chunk.
		 *
		 * We must update the finobt record based on the inobt record.
		 * rec contains the fully merged and up to date inobt record
		 * from the previous call. Set merge false to replace any
		 * existing record with this one.
		 */
		if (scxfs_sb_version_hasfinobt(&args.mp->m_sb)) {
			error = scxfs_inobt_insert_sprec(args.mp, tp, agbp,
						       SCXFS_BTNUM_FINO, &rec,
						       false);
			if (error)
				return error;
		}
	} else {
		/* full chunk - insert new records to both btrees */
		error = scxfs_inobt_insert(args.mp, tp, agbp, newino, newlen,
					 SCXFS_BTNUM_INO);
		if (error)
			return error;

		if (scxfs_sb_version_hasfinobt(&args.mp->m_sb)) {
			error = scxfs_inobt_insert(args.mp, tp, agbp, newino,
						 newlen, SCXFS_BTNUM_FINO);
			if (error)
				return error;
		}
	}

	/*
	 * Update AGI counts and newino.
	 */
	be32_add_cpu(&agi->agi_count, newlen);
	be32_add_cpu(&agi->agi_freecount, newlen);
	pag = scxfs_perag_get(args.mp, agno);
	pag->pagi_freecount += newlen;
	pag->pagi_count += newlen;
	scxfs_perag_put(pag);
	agi->agi_newino = cpu_to_be32(newino);

	/*
	 * Log allocation group header fields
	 */
	scxfs_ialloc_log_agi(tp, agbp,
		SCXFS_AGI_COUNT | SCXFS_AGI_FREECOUNT | SCXFS_AGI_NEWINO);
	/*
	 * Modify/log superblock values for inode count and inode free count.
	 */
	scxfs_trans_mod_sb(tp, SCXFS_TRANS_SB_ICOUNT, (long)newlen);
	scxfs_trans_mod_sb(tp, SCXFS_TRANS_SB_IFREE, (long)newlen);
	*alloc = 1;
	return 0;
}

STATIC scxfs_agnumber_t
scxfs_ialloc_next_ag(
	scxfs_mount_t	*mp)
{
	scxfs_agnumber_t	agno;

	spin_lock(&mp->m_agirotor_lock);
	agno = mp->m_agirotor;
	if (++mp->m_agirotor >= mp->m_maxagi)
		mp->m_agirotor = 0;
	spin_unlock(&mp->m_agirotor_lock);

	return agno;
}

/*
 * Select an allocation group to look for a free inode in, based on the parent
 * inode and the mode.  Return the allocation group buffer.
 */
STATIC scxfs_agnumber_t
scxfs_ialloc_ag_select(
	scxfs_trans_t	*tp,		/* transaction pointer */
	scxfs_ino_t	parent,		/* parent directory inode number */
	umode_t		mode)		/* bits set to indicate file type */
{
	scxfs_agnumber_t	agcount;	/* number of ag's in the filesystem */
	scxfs_agnumber_t	agno;		/* current ag number */
	int		flags;		/* alloc buffer locking flags */
	scxfs_extlen_t	ineed;		/* blocks needed for inode allocation */
	scxfs_extlen_t	longest = 0;	/* longest extent available */
	scxfs_mount_t	*mp;		/* mount point structure */
	int		needspace;	/* file mode implies space allocated */
	scxfs_perag_t	*pag;		/* per allocation group data */
	scxfs_agnumber_t	pagno;		/* parent (starting) ag number */
	int		error;

	/*
	 * Files of these types need at least one block if length > 0
	 * (and they won't fit in the inode, but that's hard to figure out).
	 */
	needspace = S_ISDIR(mode) || S_ISREG(mode) || S_ISLNK(mode);
	mp = tp->t_mountp;
	agcount = mp->m_maxagi;
	if (S_ISDIR(mode))
		pagno = scxfs_ialloc_next_ag(mp);
	else {
		pagno = SCXFS_INO_TO_AGNO(mp, parent);
		if (pagno >= agcount)
			pagno = 0;
	}

	ASSERT(pagno < agcount);

	/*
	 * Loop through allocation groups, looking for one with a little
	 * free space in it.  Note we don't look for free inodes, exactly.
	 * Instead, we include whether there is a need to allocate inodes
	 * to mean that blocks must be allocated for them,
	 * if none are currently free.
	 */
	agno = pagno;
	flags = SCXFS_ALLOC_FLAG_TRYLOCK;
	for (;;) {
		pag = scxfs_perag_get(mp, agno);
		if (!pag->pagi_inodeok) {
			scxfs_ialloc_next_ag(mp);
			goto nextag;
		}

		if (!pag->pagi_init) {
			error = scxfs_ialloc_pagi_init(mp, tp, agno);
			if (error)
				goto nextag;
		}

		if (pag->pagi_freecount) {
			scxfs_perag_put(pag);
			return agno;
		}

		if (!pag->pagf_init) {
			error = scxfs_alloc_pagf_init(mp, tp, agno, flags);
			if (error)
				goto nextag;
		}

		/*
		 * Check that there is enough free space for the file plus a
		 * chunk of inodes if we need to allocate some. If this is the
		 * first pass across the AGs, take into account the potential
		 * space needed for alignment of inode chunks when checking the
		 * longest contiguous free space in the AG - this prevents us
		 * from getting ENOSPC because we have free space larger than
		 * ialloc_blks but alignment constraints prevent us from using
		 * it.
		 *
		 * If we can't find an AG with space for full alignment slack to
		 * be taken into account, we must be near ENOSPC in all AGs.
		 * Hence we don't include alignment for the second pass and so
		 * if we fail allocation due to alignment issues then it is most
		 * likely a real ENOSPC condition.
		 */
		ineed = M_IGEO(mp)->ialloc_min_blks;
		if (flags && ineed > 1)
			ineed += M_IGEO(mp)->cluster_align;
		longest = pag->pagf_longest;
		if (!longest)
			longest = pag->pagf_flcount > 0;

		if (pag->pagf_freeblks >= needspace + ineed &&
		    longest >= ineed) {
			scxfs_perag_put(pag);
			return agno;
		}
nextag:
		scxfs_perag_put(pag);
		/*
		 * No point in iterating over the rest, if we're shutting
		 * down.
		 */
		if (SCXFS_FORCED_SHUTDOWN(mp))
			return NULLAGNUMBER;
		agno++;
		if (agno >= agcount)
			agno = 0;
		if (agno == pagno) {
			if (flags == 0)
				return NULLAGNUMBER;
			flags = 0;
		}
	}
}

/*
 * Try to retrieve the next record to the left/right from the current one.
 */
STATIC int
scxfs_ialloc_next_rec(
	struct scxfs_btree_cur	*cur,
	scxfs_inobt_rec_incore_t	*rec,
	int			*done,
	int			left)
{
	int                     error;
	int			i;

	if (left)
		error = scxfs_btree_decrement(cur, 0, &i);
	else
		error = scxfs_btree_increment(cur, 0, &i);

	if (error)
		return error;
	*done = !i;
	if (i) {
		error = scxfs_inobt_get_rec(cur, rec, &i);
		if (error)
			return error;
		SCXFS_WANT_CORRUPTED_RETURN(cur->bc_mp, i == 1);
	}

	return 0;
}

STATIC int
scxfs_ialloc_get_rec(
	struct scxfs_btree_cur	*cur,
	scxfs_agino_t		agino,
	scxfs_inobt_rec_incore_t	*rec,
	int			*done)
{
	int                     error;
	int			i;

	error = scxfs_inobt_lookup(cur, agino, SCXFS_LOOKUP_EQ, &i);
	if (error)
		return error;
	*done = !i;
	if (i) {
		error = scxfs_inobt_get_rec(cur, rec, &i);
		if (error)
			return error;
		SCXFS_WANT_CORRUPTED_RETURN(cur->bc_mp, i == 1);
	}

	return 0;
}

/*
 * Return the offset of the first free inode in the record. If the inode chunk
 * is sparsely allocated, we convert the record holemask to inode granularity
 * and mask off the unallocated regions from the inode free mask.
 */
STATIC int
scxfs_inobt_first_free_inode(
	struct scxfs_inobt_rec_incore	*rec)
{
	scxfs_inofree_t			realfree;

	/* if there are no holes, return the first available offset */
	if (!scxfs_inobt_issparse(rec->ir_holemask))
		return scxfs_lowbit64(rec->ir_free);

	realfree = scxfs_inobt_irec_to_allocmask(rec);
	realfree &= rec->ir_free;

	return scxfs_lowbit64(realfree);
}

/*
 * Allocate an inode using the inobt-only algorithm.
 */
STATIC int
scxfs_dialloc_ag_inobt(
	struct scxfs_trans	*tp,
	struct scxfs_buf		*agbp,
	scxfs_ino_t		parent,
	scxfs_ino_t		*inop)
{
	struct scxfs_mount	*mp = tp->t_mountp;
	struct scxfs_agi		*agi = SCXFS_BUF_TO_AGI(agbp);
	scxfs_agnumber_t		agno = be32_to_cpu(agi->agi_seqno);
	scxfs_agnumber_t		pagno = SCXFS_INO_TO_AGNO(mp, parent);
	scxfs_agino_t		pagino = SCXFS_INO_TO_AGINO(mp, parent);
	struct scxfs_perag	*pag;
	struct scxfs_btree_cur	*cur, *tcur;
	struct scxfs_inobt_rec_incore rec, trec;
	scxfs_ino_t		ino;
	int			error;
	int			offset;
	int			i, j;
	int			searchdistance = 10;

	pag = scxfs_perag_get(mp, agno);

	ASSERT(pag->pagi_init);
	ASSERT(pag->pagi_inodeok);
	ASSERT(pag->pagi_freecount > 0);

 restart_pagno:
	cur = scxfs_inobt_init_cursor(mp, tp, agbp, agno, SCXFS_BTNUM_INO);
	/*
	 * If pagino is 0 (this is the root inode allocation) use newino.
	 * This must work because we've just allocated some.
	 */
	if (!pagino)
		pagino = be32_to_cpu(agi->agi_newino);

	error = scxfs_check_agi_freecount(cur, agi);
	if (error)
		goto error0;

	/*
	 * If in the same AG as the parent, try to get near the parent.
	 */
	if (pagno == agno) {
		int		doneleft;	/* done, to the left */
		int		doneright;	/* done, to the right */

		error = scxfs_inobt_lookup(cur, pagino, SCXFS_LOOKUP_LE, &i);
		if (error)
			goto error0;
		SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, error0);

		error = scxfs_inobt_get_rec(cur, &rec, &j);
		if (error)
			goto error0;
		SCXFS_WANT_CORRUPTED_GOTO(mp, j == 1, error0);

		if (rec.ir_freecount > 0) {
			/*
			 * Found a free inode in the same chunk
			 * as the parent, done.
			 */
			goto alloc_inode;
		}


		/*
		 * In the same AG as parent, but parent's chunk is full.
		 */

		/* duplicate the cursor, search left & right simultaneously */
		error = scxfs_btree_dup_cursor(cur, &tcur);
		if (error)
			goto error0;

		/*
		 * Skip to last blocks looked up if same parent inode.
		 */
		if (pagino != NULLAGINO &&
		    pag->pagl_pagino == pagino &&
		    pag->pagl_leftrec != NULLAGINO &&
		    pag->pagl_rightrec != NULLAGINO) {
			error = scxfs_ialloc_get_rec(tcur, pag->pagl_leftrec,
						   &trec, &doneleft);
			if (error)
				goto error1;

			error = scxfs_ialloc_get_rec(cur, pag->pagl_rightrec,
						   &rec, &doneright);
			if (error)
				goto error1;
		} else {
			/* search left with tcur, back up 1 record */
			error = scxfs_ialloc_next_rec(tcur, &trec, &doneleft, 1);
			if (error)
				goto error1;

			/* search right with cur, go forward 1 record. */
			error = scxfs_ialloc_next_rec(cur, &rec, &doneright, 0);
			if (error)
				goto error1;
		}

		/*
		 * Loop until we find an inode chunk with a free inode.
		 */
		while (--searchdistance > 0 && (!doneleft || !doneright)) {
			int	useleft;  /* using left inode chunk this time */

			/* figure out the closer block if both are valid. */
			if (!doneleft && !doneright) {
				useleft = pagino -
				 (trec.ir_startino + SCXFS_INODES_PER_CHUNK - 1) <
				  rec.ir_startino - pagino;
			} else {
				useleft = !doneleft;
			}

			/* free inodes to the left? */
			if (useleft && trec.ir_freecount) {
				scxfs_btree_del_cursor(cur, SCXFS_BTREE_NOERROR);
				cur = tcur;

				pag->pagl_leftrec = trec.ir_startino;
				pag->pagl_rightrec = rec.ir_startino;
				pag->pagl_pagino = pagino;
				rec = trec;
				goto alloc_inode;
			}

			/* free inodes to the right? */
			if (!useleft && rec.ir_freecount) {
				scxfs_btree_del_cursor(tcur, SCXFS_BTREE_NOERROR);

				pag->pagl_leftrec = trec.ir_startino;
				pag->pagl_rightrec = rec.ir_startino;
				pag->pagl_pagino = pagino;
				goto alloc_inode;
			}

			/* get next record to check */
			if (useleft) {
				error = scxfs_ialloc_next_rec(tcur, &trec,
								 &doneleft, 1);
			} else {
				error = scxfs_ialloc_next_rec(cur, &rec,
								 &doneright, 0);
			}
			if (error)
				goto error1;
		}

		if (searchdistance <= 0) {
			/*
			 * Not in range - save last search
			 * location and allocate a new inode
			 */
			scxfs_btree_del_cursor(tcur, SCXFS_BTREE_NOERROR);
			pag->pagl_leftrec = trec.ir_startino;
			pag->pagl_rightrec = rec.ir_startino;
			pag->pagl_pagino = pagino;

		} else {
			/*
			 * We've reached the end of the btree. because
			 * we are only searching a small chunk of the
			 * btree each search, there is obviously free
			 * inodes closer to the parent inode than we
			 * are now. restart the search again.
			 */
			pag->pagl_pagino = NULLAGINO;
			pag->pagl_leftrec = NULLAGINO;
			pag->pagl_rightrec = NULLAGINO;
			scxfs_btree_del_cursor(tcur, SCXFS_BTREE_NOERROR);
			scxfs_btree_del_cursor(cur, SCXFS_BTREE_NOERROR);
			goto restart_pagno;
		}
	}

	/*
	 * In a different AG from the parent.
	 * See if the most recently allocated block has any free.
	 */
	if (agi->agi_newino != cpu_to_be32(NULLAGINO)) {
		error = scxfs_inobt_lookup(cur, be32_to_cpu(agi->agi_newino),
					 SCXFS_LOOKUP_EQ, &i);
		if (error)
			goto error0;

		if (i == 1) {
			error = scxfs_inobt_get_rec(cur, &rec, &j);
			if (error)
				goto error0;

			if (j == 1 && rec.ir_freecount > 0) {
				/*
				 * The last chunk allocated in the group
				 * still has a free inode.
				 */
				goto alloc_inode;
			}
		}
	}

	/*
	 * None left in the last group, search the whole AG
	 */
	error = scxfs_inobt_lookup(cur, 0, SCXFS_LOOKUP_GE, &i);
	if (error)
		goto error0;
	SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, error0);

	for (;;) {
		error = scxfs_inobt_get_rec(cur, &rec, &i);
		if (error)
			goto error0;
		SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, error0);
		if (rec.ir_freecount > 0)
			break;
		error = scxfs_btree_increment(cur, 0, &i);
		if (error)
			goto error0;
		SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, error0);
	}

alloc_inode:
	offset = scxfs_inobt_first_free_inode(&rec);
	ASSERT(offset >= 0);
	ASSERT(offset < SCXFS_INODES_PER_CHUNK);
	ASSERT((SCXFS_AGINO_TO_OFFSET(mp, rec.ir_startino) %
				   SCXFS_INODES_PER_CHUNK) == 0);
	ino = SCXFS_AGINO_TO_INO(mp, agno, rec.ir_startino + offset);
	rec.ir_free &= ~SCXFS_INOBT_MASK(offset);
	rec.ir_freecount--;
	error = scxfs_inobt_update(cur, &rec);
	if (error)
		goto error0;
	be32_add_cpu(&agi->agi_freecount, -1);
	scxfs_ialloc_log_agi(tp, agbp, SCXFS_AGI_FREECOUNT);
	pag->pagi_freecount--;

	error = scxfs_check_agi_freecount(cur, agi);
	if (error)
		goto error0;

	scxfs_btree_del_cursor(cur, SCXFS_BTREE_NOERROR);
	scxfs_trans_mod_sb(tp, SCXFS_TRANS_SB_IFREE, -1);
	scxfs_perag_put(pag);
	*inop = ino;
	return 0;
error1:
	scxfs_btree_del_cursor(tcur, SCXFS_BTREE_ERROR);
error0:
	scxfs_btree_del_cursor(cur, SCXFS_BTREE_ERROR);
	scxfs_perag_put(pag);
	return error;
}

/*
 * Use the free inode btree to allocate an inode based on distance from the
 * parent. Note that the provided cursor may be deleted and replaced.
 */
STATIC int
scxfs_dialloc_ag_finobt_near(
	scxfs_agino_t			pagino,
	struct scxfs_btree_cur		**ocur,
	struct scxfs_inobt_rec_incore	*rec)
{
	struct scxfs_btree_cur		*lcur = *ocur;	/* left search cursor */
	struct scxfs_btree_cur		*rcur;	/* right search cursor */
	struct scxfs_inobt_rec_incore	rrec;
	int				error;
	int				i, j;

	error = scxfs_inobt_lookup(lcur, pagino, SCXFS_LOOKUP_LE, &i);
	if (error)
		return error;

	if (i == 1) {
		error = scxfs_inobt_get_rec(lcur, rec, &i);
		if (error)
			return error;
		SCXFS_WANT_CORRUPTED_RETURN(lcur->bc_mp, i == 1);

		/*
		 * See if we've landed in the parent inode record. The finobt
		 * only tracks chunks with at least one free inode, so record
		 * existence is enough.
		 */
		if (pagino >= rec->ir_startino &&
		    pagino < (rec->ir_startino + SCXFS_INODES_PER_CHUNK))
			return 0;
	}

	error = scxfs_btree_dup_cursor(lcur, &rcur);
	if (error)
		return error;

	error = scxfs_inobt_lookup(rcur, pagino, SCXFS_LOOKUP_GE, &j);
	if (error)
		goto error_rcur;
	if (j == 1) {
		error = scxfs_inobt_get_rec(rcur, &rrec, &j);
		if (error)
			goto error_rcur;
		SCXFS_WANT_CORRUPTED_GOTO(lcur->bc_mp, j == 1, error_rcur);
	}

	SCXFS_WANT_CORRUPTED_GOTO(lcur->bc_mp, i == 1 || j == 1, error_rcur);
	if (i == 1 && j == 1) {
		/*
		 * Both the left and right records are valid. Choose the closer
		 * inode chunk to the target.
		 */
		if ((pagino - rec->ir_startino + SCXFS_INODES_PER_CHUNK - 1) >
		    (rrec.ir_startino - pagino)) {
			*rec = rrec;
			scxfs_btree_del_cursor(lcur, SCXFS_BTREE_NOERROR);
			*ocur = rcur;
		} else {
			scxfs_btree_del_cursor(rcur, SCXFS_BTREE_NOERROR);
		}
	} else if (j == 1) {
		/* only the right record is valid */
		*rec = rrec;
		scxfs_btree_del_cursor(lcur, SCXFS_BTREE_NOERROR);
		*ocur = rcur;
	} else if (i == 1) {
		/* only the left record is valid */
		scxfs_btree_del_cursor(rcur, SCXFS_BTREE_NOERROR);
	}

	return 0;

error_rcur:
	scxfs_btree_del_cursor(rcur, SCXFS_BTREE_ERROR);
	return error;
}

/*
 * Use the free inode btree to find a free inode based on a newino hint. If
 * the hint is NULL, find the first free inode in the AG.
 */
STATIC int
scxfs_dialloc_ag_finobt_newino(
	struct scxfs_agi			*agi,
	struct scxfs_btree_cur		*cur,
	struct scxfs_inobt_rec_incore	*rec)
{
	int error;
	int i;

	if (agi->agi_newino != cpu_to_be32(NULLAGINO)) {
		error = scxfs_inobt_lookup(cur, be32_to_cpu(agi->agi_newino),
					 SCXFS_LOOKUP_EQ, &i);
		if (error)
			return error;
		if (i == 1) {
			error = scxfs_inobt_get_rec(cur, rec, &i);
			if (error)
				return error;
			SCXFS_WANT_CORRUPTED_RETURN(cur->bc_mp, i == 1);
			return 0;
		}
	}

	/*
	 * Find the first inode available in the AG.
	 */
	error = scxfs_inobt_lookup(cur, 0, SCXFS_LOOKUP_GE, &i);
	if (error)
		return error;
	SCXFS_WANT_CORRUPTED_RETURN(cur->bc_mp, i == 1);

	error = scxfs_inobt_get_rec(cur, rec, &i);
	if (error)
		return error;
	SCXFS_WANT_CORRUPTED_RETURN(cur->bc_mp, i == 1);

	return 0;
}

/*
 * Update the inobt based on a modification made to the finobt. Also ensure that
 * the records from both trees are equivalent post-modification.
 */
STATIC int
scxfs_dialloc_ag_update_inobt(
	struct scxfs_btree_cur		*cur,	/* inobt cursor */
	struct scxfs_inobt_rec_incore	*frec,	/* finobt record */
	int				offset) /* inode offset */
{
	struct scxfs_inobt_rec_incore	rec;
	int				error;
	int				i;

	error = scxfs_inobt_lookup(cur, frec->ir_startino, SCXFS_LOOKUP_EQ, &i);
	if (error)
		return error;
	SCXFS_WANT_CORRUPTED_RETURN(cur->bc_mp, i == 1);

	error = scxfs_inobt_get_rec(cur, &rec, &i);
	if (error)
		return error;
	SCXFS_WANT_CORRUPTED_RETURN(cur->bc_mp, i == 1);
	ASSERT((SCXFS_AGINO_TO_OFFSET(cur->bc_mp, rec.ir_startino) %
				   SCXFS_INODES_PER_CHUNK) == 0);

	rec.ir_free &= ~SCXFS_INOBT_MASK(offset);
	rec.ir_freecount--;

	SCXFS_WANT_CORRUPTED_RETURN(cur->bc_mp, (rec.ir_free == frec->ir_free) &&
				  (rec.ir_freecount == frec->ir_freecount));

	return scxfs_inobt_update(cur, &rec);
}

/*
 * Allocate an inode using the free inode btree, if available. Otherwise, fall
 * back to the inobt search algorithm.
 *
 * The caller selected an AG for us, and made sure that free inodes are
 * available.
 */
STATIC int
scxfs_dialloc_ag(
	struct scxfs_trans	*tp,
	struct scxfs_buf		*agbp,
	scxfs_ino_t		parent,
	scxfs_ino_t		*inop)
{
	struct scxfs_mount		*mp = tp->t_mountp;
	struct scxfs_agi			*agi = SCXFS_BUF_TO_AGI(agbp);
	scxfs_agnumber_t			agno = be32_to_cpu(agi->agi_seqno);
	scxfs_agnumber_t			pagno = SCXFS_INO_TO_AGNO(mp, parent);
	scxfs_agino_t			pagino = SCXFS_INO_TO_AGINO(mp, parent);
	struct scxfs_perag		*pag;
	struct scxfs_btree_cur		*cur;	/* finobt cursor */
	struct scxfs_btree_cur		*icur;	/* inobt cursor */
	struct scxfs_inobt_rec_incore	rec;
	scxfs_ino_t			ino;
	int				error;
	int				offset;
	int				i;

	if (!scxfs_sb_version_hasfinobt(&mp->m_sb))
		return scxfs_dialloc_ag_inobt(tp, agbp, parent, inop);

	pag = scxfs_perag_get(mp, agno);

	/*
	 * If pagino is 0 (this is the root inode allocation) use newino.
	 * This must work because we've just allocated some.
	 */
	if (!pagino)
		pagino = be32_to_cpu(agi->agi_newino);

	cur = scxfs_inobt_init_cursor(mp, tp, agbp, agno, SCXFS_BTNUM_FINO);

	error = scxfs_check_agi_freecount(cur, agi);
	if (error)
		goto error_cur;

	/*
	 * The search algorithm depends on whether we're in the same AG as the
	 * parent. If so, find the closest available inode to the parent. If
	 * not, consider the agi hint or find the first free inode in the AG.
	 */
	if (agno == pagno)
		error = scxfs_dialloc_ag_finobt_near(pagino, &cur, &rec);
	else
		error = scxfs_dialloc_ag_finobt_newino(agi, cur, &rec);
	if (error)
		goto error_cur;

	offset = scxfs_inobt_first_free_inode(&rec);
	ASSERT(offset >= 0);
	ASSERT(offset < SCXFS_INODES_PER_CHUNK);
	ASSERT((SCXFS_AGINO_TO_OFFSET(mp, rec.ir_startino) %
				   SCXFS_INODES_PER_CHUNK) == 0);
	ino = SCXFS_AGINO_TO_INO(mp, agno, rec.ir_startino + offset);

	/*
	 * Modify or remove the finobt record.
	 */
	rec.ir_free &= ~SCXFS_INOBT_MASK(offset);
	rec.ir_freecount--;
	if (rec.ir_freecount)
		error = scxfs_inobt_update(cur, &rec);
	else
		error = scxfs_btree_delete(cur, &i);
	if (error)
		goto error_cur;

	/*
	 * The finobt has now been updated appropriately. We haven't updated the
	 * agi and superblock yet, so we can create an inobt cursor and validate
	 * the original freecount. If all is well, make the equivalent update to
	 * the inobt using the finobt record and offset information.
	 */
	icur = scxfs_inobt_init_cursor(mp, tp, agbp, agno, SCXFS_BTNUM_INO);

	error = scxfs_check_agi_freecount(icur, agi);
	if (error)
		goto error_icur;

	error = scxfs_dialloc_ag_update_inobt(icur, &rec, offset);
	if (error)
		goto error_icur;

	/*
	 * Both trees have now been updated. We must update the perag and
	 * superblock before we can check the freecount for each btree.
	 */
	be32_add_cpu(&agi->agi_freecount, -1);
	scxfs_ialloc_log_agi(tp, agbp, SCXFS_AGI_FREECOUNT);
	pag->pagi_freecount--;

	scxfs_trans_mod_sb(tp, SCXFS_TRANS_SB_IFREE, -1);

	error = scxfs_check_agi_freecount(icur, agi);
	if (error)
		goto error_icur;
	error = scxfs_check_agi_freecount(cur, agi);
	if (error)
		goto error_icur;

	scxfs_btree_del_cursor(icur, SCXFS_BTREE_NOERROR);
	scxfs_btree_del_cursor(cur, SCXFS_BTREE_NOERROR);
	scxfs_perag_put(pag);
	*inop = ino;
	return 0;

error_icur:
	scxfs_btree_del_cursor(icur, SCXFS_BTREE_ERROR);
error_cur:
	scxfs_btree_del_cursor(cur, SCXFS_BTREE_ERROR);
	scxfs_perag_put(pag);
	return error;
}

/*
 * Allocate an inode on disk.
 *
 * Mode is used to tell whether the new inode will need space, and whether it
 * is a directory.
 *
 * This function is designed to be called twice if it has to do an allocation
 * to make more free inodes.  On the first call, *IO_agbp should be set to NULL.
 * If an inode is available without having to performn an allocation, an inode
 * number is returned.  In this case, *IO_agbp is set to NULL.  If an allocation
 * needs to be done, scxfs_dialloc returns the current AGI buffer in *IO_agbp.
 * The caller should then commit the current transaction, allocate a
 * new transaction, and call scxfs_dialloc() again, passing in the previous value
 * of *IO_agbp.  IO_agbp should be held across the transactions. Since the AGI
 * buffer is locked across the two calls, the second call is guaranteed to have
 * a free inode available.
 *
 * Once we successfully pick an inode its number is returned and the on-disk
 * data structures are updated.  The inode itself is not read in, since doing so
 * would break ordering constraints with scxfs_reclaim.
 */
int
scxfs_dialloc(
	struct scxfs_trans	*tp,
	scxfs_ino_t		parent,
	umode_t			mode,
	struct scxfs_buf		**IO_agbp,
	scxfs_ino_t		*inop)
{
	struct scxfs_mount	*mp = tp->t_mountp;
	struct scxfs_buf		*agbp;
	scxfs_agnumber_t		agno;
	int			error;
	int			ialloced;
	int			noroom = 0;
	scxfs_agnumber_t		start_agno;
	struct scxfs_perag	*pag;
	struct scxfs_ino_geometry	*igeo = M_IGEO(mp);
	int			okalloc = 1;

	if (*IO_agbp) {
		/*
		 * If the caller passes in a pointer to the AGI buffer,
		 * continue where we left off before.  In this case, we
		 * know that the allocation group has free inodes.
		 */
		agbp = *IO_agbp;
		goto out_alloc;
	}

	/*
	 * We do not have an agbp, so select an initial allocation
	 * group for inode allocation.
	 */
	start_agno = scxfs_ialloc_ag_select(tp, parent, mode);
	if (start_agno == NULLAGNUMBER) {
		*inop = NULLFSINO;
		return 0;
	}

	/*
	 * If we have already hit the ceiling of inode blocks then clear
	 * okalloc so we scan all available agi structures for a free
	 * inode.
	 *
	 * Read rough value of mp->m_icount by percpu_counter_read_positive,
	 * which will sacrifice the preciseness but improve the performance.
	 */
	if (igeo->maxicount &&
	    percpu_counter_read_positive(&mp->m_icount) + igeo->ialloc_inos
							> igeo->maxicount) {
		noroom = 1;
		okalloc = 0;
	}

	/*
	 * Loop until we find an allocation group that either has free inodes
	 * or in which we can allocate some inodes.  Iterate through the
	 * allocation groups upward, wrapping at the end.
	 */
	agno = start_agno;
	for (;;) {
		pag = scxfs_perag_get(mp, agno);
		if (!pag->pagi_inodeok) {
			scxfs_ialloc_next_ag(mp);
			goto nextag;
		}

		if (!pag->pagi_init) {
			error = scxfs_ialloc_pagi_init(mp, tp, agno);
			if (error)
				goto out_error;
		}

		/*
		 * Do a first racy fast path check if this AG is usable.
		 */
		if (!pag->pagi_freecount && !okalloc)
			goto nextag;

		/*
		 * Then read in the AGI buffer and recheck with the AGI buffer
		 * lock held.
		 */
		error = scxfs_ialloc_read_agi(mp, tp, agno, &agbp);
		if (error)
			goto out_error;

		if (pag->pagi_freecount) {
			scxfs_perag_put(pag);
			goto out_alloc;
		}

		if (!okalloc)
			goto nextag_relse_buffer;


		error = scxfs_ialloc_ag_alloc(tp, agbp, &ialloced);
		if (error) {
			scxfs_trans_brelse(tp, agbp);

			if (error != -ENOSPC)
				goto out_error;

			scxfs_perag_put(pag);
			*inop = NULLFSINO;
			return 0;
		}

		if (ialloced) {
			/*
			 * We successfully allocated some inodes, return
			 * the current context to the caller so that it
			 * can commit the current transaction and call
			 * us again where we left off.
			 */
			ASSERT(pag->pagi_freecount > 0);
			scxfs_perag_put(pag);

			*IO_agbp = agbp;
			*inop = NULLFSINO;
			return 0;
		}

nextag_relse_buffer:
		scxfs_trans_brelse(tp, agbp);
nextag:
		scxfs_perag_put(pag);
		if (++agno == mp->m_sb.sb_agcount)
			agno = 0;
		if (agno == start_agno) {
			*inop = NULLFSINO;
			return noroom ? -ENOSPC : 0;
		}
	}

out_alloc:
	*IO_agbp = NULL;
	return scxfs_dialloc_ag(tp, agbp, parent, inop);
out_error:
	scxfs_perag_put(pag);
	return error;
}

/*
 * Free the blocks of an inode chunk. We must consider that the inode chunk
 * might be sparse and only free the regions that are allocated as part of the
 * chunk.
 */
STATIC void
scxfs_difree_inode_chunk(
	struct scxfs_trans		*tp,
	scxfs_agnumber_t			agno,
	struct scxfs_inobt_rec_incore	*rec)
{
	struct scxfs_mount		*mp = tp->t_mountp;
	scxfs_agblock_t			sagbno = SCXFS_AGINO_TO_AGBNO(mp,
							rec->ir_startino);
	int				startidx, endidx;
	int				nextbit;
	scxfs_agblock_t			agbno;
	int				contigblk;
	DECLARE_BITMAP(holemask, SCXFS_INOBT_HOLEMASK_BITS);

	if (!scxfs_inobt_issparse(rec->ir_holemask)) {
		/* not sparse, calculate extent info directly */
		scxfs_bmap_add_free(tp, SCXFS_AGB_TO_FSB(mp, agno, sagbno),
				  M_IGEO(mp)->ialloc_blks,
				  &SCXFS_RMAP_OINFO_INODES);
		return;
	}

	/* holemask is only 16-bits (fits in an unsigned long) */
	ASSERT(sizeof(rec->ir_holemask) <= sizeof(holemask[0]));
	holemask[0] = rec->ir_holemask;

	/*
	 * Find contiguous ranges of zeroes (i.e., allocated regions) in the
	 * holemask and convert the start/end index of each range to an extent.
	 * We start with the start and end index both pointing at the first 0 in
	 * the mask.
	 */
	startidx = endidx = find_first_zero_bit(holemask,
						SCXFS_INOBT_HOLEMASK_BITS);
	nextbit = startidx + 1;
	while (startidx < SCXFS_INOBT_HOLEMASK_BITS) {
		nextbit = find_next_zero_bit(holemask, SCXFS_INOBT_HOLEMASK_BITS,
					     nextbit);
		/*
		 * If the next zero bit is contiguous, update the end index of
		 * the current range and continue.
		 */
		if (nextbit != SCXFS_INOBT_HOLEMASK_BITS &&
		    nextbit == endidx + 1) {
			endidx = nextbit;
			goto next;
		}

		/*
		 * nextbit is not contiguous with the current end index. Convert
		 * the current start/end to an extent and add it to the free
		 * list.
		 */
		agbno = sagbno + (startidx * SCXFS_INODES_PER_HOLEMASK_BIT) /
				  mp->m_sb.sb_inopblock;
		contigblk = ((endidx - startidx + 1) *
			     SCXFS_INODES_PER_HOLEMASK_BIT) /
			    mp->m_sb.sb_inopblock;

		ASSERT(agbno % mp->m_sb.sb_spino_align == 0);
		ASSERT(contigblk % mp->m_sb.sb_spino_align == 0);
		scxfs_bmap_add_free(tp, SCXFS_AGB_TO_FSB(mp, agno, agbno),
				  contigblk, &SCXFS_RMAP_OINFO_INODES);

		/* reset range to current bit and carry on... */
		startidx = endidx = nextbit;

next:
		nextbit++;
	}
}

STATIC int
scxfs_difree_inobt(
	struct scxfs_mount		*mp,
	struct scxfs_trans		*tp,
	struct scxfs_buf			*agbp,
	scxfs_agino_t			agino,
	struct scxfs_icluster		*xic,
	struct scxfs_inobt_rec_incore	*orec)
{
	struct scxfs_agi			*agi = SCXFS_BUF_TO_AGI(agbp);
	scxfs_agnumber_t			agno = be32_to_cpu(agi->agi_seqno);
	struct scxfs_perag		*pag;
	struct scxfs_btree_cur		*cur;
	struct scxfs_inobt_rec_incore	rec;
	int				ilen;
	int				error;
	int				i;
	int				off;

	ASSERT(agi->agi_magicnum == cpu_to_be32(SCXFS_AGI_MAGIC));
	ASSERT(SCXFS_AGINO_TO_AGBNO(mp, agino) < be32_to_cpu(agi->agi_length));

	/*
	 * Initialize the cursor.
	 */
	cur = scxfs_inobt_init_cursor(mp, tp, agbp, agno, SCXFS_BTNUM_INO);

	error = scxfs_check_agi_freecount(cur, agi);
	if (error)
		goto error0;

	/*
	 * Look for the entry describing this inode.
	 */
	if ((error = scxfs_inobt_lookup(cur, agino, SCXFS_LOOKUP_LE, &i))) {
		scxfs_warn(mp, "%s: scxfs_inobt_lookup() returned error %d.",
			__func__, error);
		goto error0;
	}
	SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, error0);
	error = scxfs_inobt_get_rec(cur, &rec, &i);
	if (error) {
		scxfs_warn(mp, "%s: scxfs_inobt_get_rec() returned error %d.",
			__func__, error);
		goto error0;
	}
	SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, error0);
	/*
	 * Get the offset in the inode chunk.
	 */
	off = agino - rec.ir_startino;
	ASSERT(off >= 0 && off < SCXFS_INODES_PER_CHUNK);
	ASSERT(!(rec.ir_free & SCXFS_INOBT_MASK(off)));
	/*
	 * Mark the inode free & increment the count.
	 */
	rec.ir_free |= SCXFS_INOBT_MASK(off);
	rec.ir_freecount++;

	/*
	 * When an inode chunk is free, it becomes eligible for removal. Don't
	 * remove the chunk if the block size is large enough for multiple inode
	 * chunks (that might not be free).
	 */
	if (!(mp->m_flags & SCXFS_MOUNT_IKEEP) &&
	    rec.ir_free == SCXFS_INOBT_ALL_FREE &&
	    mp->m_sb.sb_inopblock <= SCXFS_INODES_PER_CHUNK) {
		xic->deleted = true;
		xic->first_ino = SCXFS_AGINO_TO_INO(mp, agno, rec.ir_startino);
		xic->alloc = scxfs_inobt_irec_to_allocmask(&rec);

		/*
		 * Remove the inode cluster from the AGI B+Tree, adjust the
		 * AGI and Superblock inode counts, and mark the disk space
		 * to be freed when the transaction is committed.
		 */
		ilen = rec.ir_freecount;
		be32_add_cpu(&agi->agi_count, -ilen);
		be32_add_cpu(&agi->agi_freecount, -(ilen - 1));
		scxfs_ialloc_log_agi(tp, agbp, SCXFS_AGI_COUNT | SCXFS_AGI_FREECOUNT);
		pag = scxfs_perag_get(mp, agno);
		pag->pagi_freecount -= ilen - 1;
		pag->pagi_count -= ilen;
		scxfs_perag_put(pag);
		scxfs_trans_mod_sb(tp, SCXFS_TRANS_SB_ICOUNT, -ilen);
		scxfs_trans_mod_sb(tp, SCXFS_TRANS_SB_IFREE, -(ilen - 1));

		if ((error = scxfs_btree_delete(cur, &i))) {
			scxfs_warn(mp, "%s: scxfs_btree_delete returned error %d.",
				__func__, error);
			goto error0;
		}

		scxfs_difree_inode_chunk(tp, agno, &rec);
	} else {
		xic->deleted = false;

		error = scxfs_inobt_update(cur, &rec);
		if (error) {
			scxfs_warn(mp, "%s: scxfs_inobt_update returned error %d.",
				__func__, error);
			goto error0;
		}

		/* 
		 * Change the inode free counts and log the ag/sb changes.
		 */
		be32_add_cpu(&agi->agi_freecount, 1);
		scxfs_ialloc_log_agi(tp, agbp, SCXFS_AGI_FREECOUNT);
		pag = scxfs_perag_get(mp, agno);
		pag->pagi_freecount++;
		scxfs_perag_put(pag);
		scxfs_trans_mod_sb(tp, SCXFS_TRANS_SB_IFREE, 1);
	}

	error = scxfs_check_agi_freecount(cur, agi);
	if (error)
		goto error0;

	*orec = rec;
	scxfs_btree_del_cursor(cur, SCXFS_BTREE_NOERROR);
	return 0;

error0:
	scxfs_btree_del_cursor(cur, SCXFS_BTREE_ERROR);
	return error;
}

/*
 * Free an inode in the free inode btree.
 */
STATIC int
scxfs_difree_finobt(
	struct scxfs_mount		*mp,
	struct scxfs_trans		*tp,
	struct scxfs_buf			*agbp,
	scxfs_agino_t			agino,
	struct scxfs_inobt_rec_incore	*ibtrec) /* inobt record */
{
	struct scxfs_agi			*agi = SCXFS_BUF_TO_AGI(agbp);
	scxfs_agnumber_t			agno = be32_to_cpu(agi->agi_seqno);
	struct scxfs_btree_cur		*cur;
	struct scxfs_inobt_rec_incore	rec;
	int				offset = agino - ibtrec->ir_startino;
	int				error;
	int				i;

	cur = scxfs_inobt_init_cursor(mp, tp, agbp, agno, SCXFS_BTNUM_FINO);

	error = scxfs_inobt_lookup(cur, ibtrec->ir_startino, SCXFS_LOOKUP_EQ, &i);
	if (error)
		goto error;
	if (i == 0) {
		/*
		 * If the record does not exist in the finobt, we must have just
		 * freed an inode in a previously fully allocated chunk. If not,
		 * something is out of sync.
		 */
		SCXFS_WANT_CORRUPTED_GOTO(mp, ibtrec->ir_freecount == 1, error);

		error = scxfs_inobt_insert_rec(cur, ibtrec->ir_holemask,
					     ibtrec->ir_count,
					     ibtrec->ir_freecount,
					     ibtrec->ir_free, &i);
		if (error)
			goto error;
		ASSERT(i == 1);

		goto out;
	}

	/*
	 * Read and update the existing record. We could just copy the ibtrec
	 * across here, but that would defeat the purpose of having redundant
	 * metadata. By making the modifications independently, we can catch
	 * corruptions that we wouldn't see if we just copied from one record
	 * to another.
	 */
	error = scxfs_inobt_get_rec(cur, &rec, &i);
	if (error)
		goto error;
	SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, error);

	rec.ir_free |= SCXFS_INOBT_MASK(offset);
	rec.ir_freecount++;

	SCXFS_WANT_CORRUPTED_GOTO(mp, (rec.ir_free == ibtrec->ir_free) &&
				(rec.ir_freecount == ibtrec->ir_freecount),
				error);

	/*
	 * The content of inobt records should always match between the inobt
	 * and finobt. The lifecycle of records in the finobt is different from
	 * the inobt in that the finobt only tracks records with at least one
	 * free inode. Hence, if all of the inodes are free and we aren't
	 * keeping inode chunks permanently on disk, remove the record.
	 * Otherwise, update the record with the new information.
	 *
	 * Note that we currently can't free chunks when the block size is large
	 * enough for multiple chunks. Leave the finobt record to remain in sync
	 * with the inobt.
	 */
	if (rec.ir_free == SCXFS_INOBT_ALL_FREE &&
	    mp->m_sb.sb_inopblock <= SCXFS_INODES_PER_CHUNK &&
	    !(mp->m_flags & SCXFS_MOUNT_IKEEP)) {
		error = scxfs_btree_delete(cur, &i);
		if (error)
			goto error;
		ASSERT(i == 1);
	} else {
		error = scxfs_inobt_update(cur, &rec);
		if (error)
			goto error;
	}

out:
	error = scxfs_check_agi_freecount(cur, agi);
	if (error)
		goto error;

	scxfs_btree_del_cursor(cur, SCXFS_BTREE_NOERROR);
	return 0;

error:
	scxfs_btree_del_cursor(cur, SCXFS_BTREE_ERROR);
	return error;
}

/*
 * Free disk inode.  Carefully avoids touching the incore inode, all
 * manipulations incore are the caller's responsibility.
 * The on-disk inode is not changed by this operation, only the
 * btree (free inode mask) is changed.
 */
int
scxfs_difree(
	struct scxfs_trans	*tp,		/* transaction pointer */
	scxfs_ino_t		inode,		/* inode to be freed */
	struct scxfs_icluster	*xic)	/* cluster info if deleted */
{
	/* REFERENCED */
	scxfs_agblock_t		agbno;	/* block number containing inode */
	struct scxfs_buf		*agbp;	/* buffer for allocation group header */
	scxfs_agino_t		agino;	/* allocation group inode number */
	scxfs_agnumber_t		agno;	/* allocation group number */
	int			error;	/* error return value */
	struct scxfs_mount	*mp;	/* mount structure for filesystem */
	struct scxfs_inobt_rec_incore rec;/* btree record */

	mp = tp->t_mountp;

	/*
	 * Break up inode number into its components.
	 */
	agno = SCXFS_INO_TO_AGNO(mp, inode);
	if (agno >= mp->m_sb.sb_agcount)  {
		scxfs_warn(mp, "%s: agno >= mp->m_sb.sb_agcount (%d >= %d).",
			__func__, agno, mp->m_sb.sb_agcount);
		ASSERT(0);
		return -EINVAL;
	}
	agino = SCXFS_INO_TO_AGINO(mp, inode);
	if (inode != SCXFS_AGINO_TO_INO(mp, agno, agino))  {
		scxfs_warn(mp, "%s: inode != SCXFS_AGINO_TO_INO() (%llu != %llu).",
			__func__, (unsigned long long)inode,
			(unsigned long long)SCXFS_AGINO_TO_INO(mp, agno, agino));
		ASSERT(0);
		return -EINVAL;
	}
	agbno = SCXFS_AGINO_TO_AGBNO(mp, agino);
	if (agbno >= mp->m_sb.sb_agblocks)  {
		scxfs_warn(mp, "%s: agbno >= mp->m_sb.sb_agblocks (%d >= %d).",
			__func__, agbno, mp->m_sb.sb_agblocks);
		ASSERT(0);
		return -EINVAL;
	}
	/*
	 * Get the allocation group header.
	 */
	error = scxfs_ialloc_read_agi(mp, tp, agno, &agbp);
	if (error) {
		scxfs_warn(mp, "%s: scxfs_ialloc_read_agi() returned error %d.",
			__func__, error);
		return error;
	}

	/*
	 * Fix up the inode allocation btree.
	 */
	error = scxfs_difree_inobt(mp, tp, agbp, agino, xic, &rec);
	if (error)
		goto error0;

	/*
	 * Fix up the free inode btree.
	 */
	if (scxfs_sb_version_hasfinobt(&mp->m_sb)) {
		error = scxfs_difree_finobt(mp, tp, agbp, agino, &rec);
		if (error)
			goto error0;
	}

	return 0;

error0:
	return error;
}

STATIC int
scxfs_imap_lookup(
	struct scxfs_mount	*mp,
	struct scxfs_trans	*tp,
	scxfs_agnumber_t		agno,
	scxfs_agino_t		agino,
	scxfs_agblock_t		agbno,
	scxfs_agblock_t		*chunk_agbno,
	scxfs_agblock_t		*offset_agbno,
	int			flags)
{
	struct scxfs_inobt_rec_incore rec;
	struct scxfs_btree_cur	*cur;
	struct scxfs_buf		*agbp;
	int			error;
	int			i;

	error = scxfs_ialloc_read_agi(mp, tp, agno, &agbp);
	if (error) {
		scxfs_alert(mp,
			"%s: scxfs_ialloc_read_agi() returned error %d, agno %d",
			__func__, error, agno);
		return error;
	}

	/*
	 * Lookup the inode record for the given agino. If the record cannot be
	 * found, then it's an invalid inode number and we should abort. Once
	 * we have a record, we need to ensure it contains the inode number
	 * we are looking up.
	 */
	cur = scxfs_inobt_init_cursor(mp, tp, agbp, agno, SCXFS_BTNUM_INO);
	error = scxfs_inobt_lookup(cur, agino, SCXFS_LOOKUP_LE, &i);
	if (!error) {
		if (i)
			error = scxfs_inobt_get_rec(cur, &rec, &i);
		if (!error && i == 0)
			error = -EINVAL;
	}

	scxfs_trans_brelse(tp, agbp);
	scxfs_btree_del_cursor(cur, error);
	if (error)
		return error;

	/* check that the returned record contains the required inode */
	if (rec.ir_startino > agino ||
	    rec.ir_startino + M_IGEO(mp)->ialloc_inos <= agino)
		return -EINVAL;

	/* for untrusted inodes check it is allocated first */
	if ((flags & SCXFS_IGET_UNTRUSTED) &&
	    (rec.ir_free & SCXFS_INOBT_MASK(agino - rec.ir_startino)))
		return -EINVAL;

	*chunk_agbno = SCXFS_AGINO_TO_AGBNO(mp, rec.ir_startino);
	*offset_agbno = agbno - *chunk_agbno;
	return 0;
}

/*
 * Return the location of the inode in imap, for mapping it into a buffer.
 */
int
scxfs_imap(
	scxfs_mount_t	 *mp,	/* file system mount structure */
	scxfs_trans_t	 *tp,	/* transaction pointer */
	scxfs_ino_t	ino,	/* inode to locate */
	struct scxfs_imap	*imap,	/* location map structure */
	uint		flags)	/* flags for inode btree lookup */
{
	scxfs_agblock_t	agbno;	/* block number of inode in the alloc group */
	scxfs_agino_t	agino;	/* inode number within alloc group */
	scxfs_agnumber_t	agno;	/* allocation group number */
	scxfs_agblock_t	chunk_agbno;	/* first block in inode chunk */
	scxfs_agblock_t	cluster_agbno;	/* first block in inode cluster */
	int		error;	/* error code */
	int		offset;	/* index of inode in its buffer */
	scxfs_agblock_t	offset_agbno;	/* blks from chunk start to inode */

	ASSERT(ino != NULLFSINO);

	/*
	 * Split up the inode number into its parts.
	 */
	agno = SCXFS_INO_TO_AGNO(mp, ino);
	agino = SCXFS_INO_TO_AGINO(mp, ino);
	agbno = SCXFS_AGINO_TO_AGBNO(mp, agino);
	if (agno >= mp->m_sb.sb_agcount || agbno >= mp->m_sb.sb_agblocks ||
	    ino != SCXFS_AGINO_TO_INO(mp, agno, agino)) {
#ifdef DEBUG
		/*
		 * Don't output diagnostic information for untrusted inodes
		 * as they can be invalid without implying corruption.
		 */
		if (flags & SCXFS_IGET_UNTRUSTED)
			return -EINVAL;
		if (agno >= mp->m_sb.sb_agcount) {
			scxfs_alert(mp,
				"%s: agno (%d) >= mp->m_sb.sb_agcount (%d)",
				__func__, agno, mp->m_sb.sb_agcount);
		}
		if (agbno >= mp->m_sb.sb_agblocks) {
			scxfs_alert(mp,
		"%s: agbno (0x%llx) >= mp->m_sb.sb_agblocks (0x%lx)",
				__func__, (unsigned long long)agbno,
				(unsigned long)mp->m_sb.sb_agblocks);
		}
		if (ino != SCXFS_AGINO_TO_INO(mp, agno, agino)) {
			scxfs_alert(mp,
		"%s: ino (0x%llx) != SCXFS_AGINO_TO_INO() (0x%llx)",
				__func__, ino,
				SCXFS_AGINO_TO_INO(mp, agno, agino));
		}
		scxfs_stack_trace();
#endif /* DEBUG */
		return -EINVAL;
	}

	/*
	 * For bulkstat and handle lookups, we have an untrusted inode number
	 * that we have to verify is valid. We cannot do this just by reading
	 * the inode buffer as it may have been unlinked and removed leaving
	 * inodes in stale state on disk. Hence we have to do a btree lookup
	 * in all cases where an untrusted inode number is passed.
	 */
	if (flags & SCXFS_IGET_UNTRUSTED) {
		error = scxfs_imap_lookup(mp, tp, agno, agino, agbno,
					&chunk_agbno, &offset_agbno, flags);
		if (error)
			return error;
		goto out_map;
	}

	/*
	 * If the inode cluster size is the same as the blocksize or
	 * smaller we get to the buffer by simple arithmetics.
	 */
	if (M_IGEO(mp)->blocks_per_cluster == 1) {
		offset = SCXFS_INO_TO_OFFSET(mp, ino);
		ASSERT(offset < mp->m_sb.sb_inopblock);

		imap->im_blkno = SCXFS_AGB_TO_DADDR(mp, agno, agbno);
		imap->im_len = SCXFS_FSB_TO_BB(mp, 1);
		imap->im_boffset = (unsigned short)(offset <<
							mp->m_sb.sb_inodelog);
		return 0;
	}

	/*
	 * If the inode chunks are aligned then use simple maths to
	 * find the location. Otherwise we have to do a btree
	 * lookup to find the location.
	 */
	if (M_IGEO(mp)->inoalign_mask) {
		offset_agbno = agbno & M_IGEO(mp)->inoalign_mask;
		chunk_agbno = agbno - offset_agbno;
	} else {
		error = scxfs_imap_lookup(mp, tp, agno, agino, agbno,
					&chunk_agbno, &offset_agbno, flags);
		if (error)
			return error;
	}

out_map:
	ASSERT(agbno >= chunk_agbno);
	cluster_agbno = chunk_agbno +
		((offset_agbno / M_IGEO(mp)->blocks_per_cluster) *
		 M_IGEO(mp)->blocks_per_cluster);
	offset = ((agbno - cluster_agbno) * mp->m_sb.sb_inopblock) +
		SCXFS_INO_TO_OFFSET(mp, ino);

	imap->im_blkno = SCXFS_AGB_TO_DADDR(mp, agno, cluster_agbno);
	imap->im_len = SCXFS_FSB_TO_BB(mp, M_IGEO(mp)->blocks_per_cluster);
	imap->im_boffset = (unsigned short)(offset << mp->m_sb.sb_inodelog);

	/*
	 * If the inode number maps to a block outside the bounds
	 * of the file system then return NULL rather than calling
	 * read_buf and panicing when we get an error from the
	 * driver.
	 */
	if ((imap->im_blkno + imap->im_len) >
	    SCXFS_FSB_TO_BB(mp, mp->m_sb.sb_dblocks)) {
		scxfs_alert(mp,
	"%s: (im_blkno (0x%llx) + im_len (0x%llx)) > sb_dblocks (0x%llx)",
			__func__, (unsigned long long) imap->im_blkno,
			(unsigned long long) imap->im_len,
			SCXFS_FSB_TO_BB(mp, mp->m_sb.sb_dblocks));
		return -EINVAL;
	}
	return 0;
}

/*
 * Log specified fields for the ag hdr (inode section). The growth of the agi
 * structure over time requires that we interpret the buffer as two logical
 * regions delineated by the end of the unlinked list. This is due to the size
 * of the hash table and its location in the middle of the agi.
 *
 * For example, a request to log a field before agi_unlinked and a field after
 * agi_unlinked could cause us to log the entire hash table and use an excessive
 * amount of log space. To avoid this behavior, log the region up through
 * agi_unlinked in one call and the region after agi_unlinked through the end of
 * the structure in another.
 */
void
scxfs_ialloc_log_agi(
	scxfs_trans_t	*tp,		/* transaction pointer */
	scxfs_buf_t	*bp,		/* allocation group header buffer */
	int		fields)		/* bitmask of fields to log */
{
	int			first;		/* first byte number */
	int			last;		/* last byte number */
	static const short	offsets[] = {	/* field starting offsets */
					/* keep in sync with bit definitions */
		offsetof(scxfs_agi_t, agi_magicnum),
		offsetof(scxfs_agi_t, agi_versionnum),
		offsetof(scxfs_agi_t, agi_seqno),
		offsetof(scxfs_agi_t, agi_length),
		offsetof(scxfs_agi_t, agi_count),
		offsetof(scxfs_agi_t, agi_root),
		offsetof(scxfs_agi_t, agi_level),
		offsetof(scxfs_agi_t, agi_freecount),
		offsetof(scxfs_agi_t, agi_newino),
		offsetof(scxfs_agi_t, agi_dirino),
		offsetof(scxfs_agi_t, agi_unlinked),
		offsetof(scxfs_agi_t, agi_free_root),
		offsetof(scxfs_agi_t, agi_free_level),
		sizeof(scxfs_agi_t)
	};
#ifdef DEBUG
	scxfs_agi_t		*agi;	/* allocation group header */

	agi = SCXFS_BUF_TO_AGI(bp);
	ASSERT(agi->agi_magicnum == cpu_to_be32(SCXFS_AGI_MAGIC));
#endif

	/*
	 * Compute byte offsets for the first and last fields in the first
	 * region and log the agi buffer. This only logs up through
	 * agi_unlinked.
	 */
	if (fields & SCXFS_AGI_ALL_BITS_R1) {
		scxfs_btree_offsets(fields, offsets, SCXFS_AGI_NUM_BITS_R1,
				  &first, &last);
		scxfs_trans_log_buf(tp, bp, first, last);
	}

	/*
	 * Mask off the bits in the first region and calculate the first and
	 * last field offsets for any bits in the second region.
	 */
	fields &= ~SCXFS_AGI_ALL_BITS_R1;
	if (fields) {
		scxfs_btree_offsets(fields, offsets, SCXFS_AGI_NUM_BITS_R2,
				  &first, &last);
		scxfs_trans_log_buf(tp, bp, first, last);
	}
}

static scxfs_failaddr_t
scxfs_agi_verify(
	struct scxfs_buf	*bp)
{
	struct scxfs_mount *mp = bp->b_mount;
	struct scxfs_agi	*agi = SCXFS_BUF_TO_AGI(bp);
	int		i;

	if (scxfs_sb_version_hascrc(&mp->m_sb)) {
		if (!uuid_equal(&agi->agi_uuid, &mp->m_sb.sb_meta_uuid))
			return __this_address;
		if (!scxfs_log_check_lsn(mp,
				be64_to_cpu(SCXFS_BUF_TO_AGI(bp)->agi_lsn)))
			return __this_address;
	}

	/*
	 * Validate the magic number of the agi block.
	 */
	if (!scxfs_verify_magic(bp, agi->agi_magicnum))
		return __this_address;
	if (!SCXFS_AGI_GOOD_VERSION(be32_to_cpu(agi->agi_versionnum)))
		return __this_address;

	if (be32_to_cpu(agi->agi_level) < 1 ||
	    be32_to_cpu(agi->agi_level) > SCXFS_BTREE_MAXLEVELS)
		return __this_address;

	if (scxfs_sb_version_hasfinobt(&mp->m_sb) &&
	    (be32_to_cpu(agi->agi_free_level) < 1 ||
	     be32_to_cpu(agi->agi_free_level) > SCXFS_BTREE_MAXLEVELS))
		return __this_address;

	/*
	 * during growfs operations, the perag is not fully initialised,
	 * so we can't use it for any useful checking. growfs ensures we can't
	 * use it by using uncached buffers that don't have the perag attached
	 * so we can detect and avoid this problem.
	 */
	if (bp->b_pag && be32_to_cpu(agi->agi_seqno) != bp->b_pag->pag_agno)
		return __this_address;

	for (i = 0; i < SCXFS_AGI_UNLINKED_BUCKETS; i++) {
		if (agi->agi_unlinked[i] == cpu_to_be32(NULLAGINO))
			continue;
		if (!scxfs_verify_ino(mp, be32_to_cpu(agi->agi_unlinked[i])))
			return __this_address;
	}

	return NULL;
}

static void
scxfs_agi_read_verify(
	struct scxfs_buf	*bp)
{
	struct scxfs_mount *mp = bp->b_mount;
	scxfs_failaddr_t	fa;

	if (scxfs_sb_version_hascrc(&mp->m_sb) &&
	    !scxfs_buf_verify_cksum(bp, SCXFS_AGI_CRC_OFF))
		scxfs_verifier_error(bp, -EFSBADCRC, __this_address);
	else {
		fa = scxfs_agi_verify(bp);
		if (SCXFS_TEST_ERROR(fa, mp, SCXFS_ERRTAG_IALLOC_READ_AGI))
			scxfs_verifier_error(bp, -EFSCORRUPTED, fa);
	}
}

static void
scxfs_agi_write_verify(
	struct scxfs_buf	*bp)
{
	struct scxfs_mount	*mp = bp->b_mount;
	struct scxfs_buf_log_item	*bip = bp->b_log_item;
	scxfs_failaddr_t		fa;

	fa = scxfs_agi_verify(bp);
	if (fa) {
		scxfs_verifier_error(bp, -EFSCORRUPTED, fa);
		return;
	}

	if (!scxfs_sb_version_hascrc(&mp->m_sb))
		return;

	if (bip)
		SCXFS_BUF_TO_AGI(bp)->agi_lsn = cpu_to_be64(bip->bli_item.li_lsn);
	scxfs_buf_update_cksum(bp, SCXFS_AGI_CRC_OFF);
}

const struct scxfs_buf_ops scxfs_agi_buf_ops = {
	.name = "scxfs_agi",
	.magic = { cpu_to_be32(SCXFS_AGI_MAGIC), cpu_to_be32(SCXFS_AGI_MAGIC) },
	.verify_read = scxfs_agi_read_verify,
	.verify_write = scxfs_agi_write_verify,
	.verify_struct = scxfs_agi_verify,
};

/*
 * Read in the allocation group header (inode allocation section)
 */
int
scxfs_read_agi(
	struct scxfs_mount	*mp,	/* file system mount structure */
	struct scxfs_trans	*tp,	/* transaction pointer */
	scxfs_agnumber_t		agno,	/* allocation group number */
	struct scxfs_buf		**bpp)	/* allocation group hdr buf */
{
	int			error;

	trace_scxfs_read_agi(mp, agno);

	ASSERT(agno != NULLAGNUMBER);
	error = scxfs_trans_read_buf(mp, tp, mp->m_ddev_targp,
			SCXFS_AG_DADDR(mp, agno, SCXFS_AGI_DADDR(mp)),
			SCXFS_FSS_TO_BB(mp, 1), 0, bpp, &scxfs_agi_buf_ops);
	if (error)
		return error;
	if (tp)
		scxfs_trans_buf_set_type(tp, *bpp, SCXFS_BLFT_AGI_BUF);

	scxfs_buf_set_ref(*bpp, SCXFS_AGI_REF);
	return 0;
}

int
scxfs_ialloc_read_agi(
	struct scxfs_mount	*mp,	/* file system mount structure */
	struct scxfs_trans	*tp,	/* transaction pointer */
	scxfs_agnumber_t		agno,	/* allocation group number */
	struct scxfs_buf		**bpp)	/* allocation group hdr buf */
{
	struct scxfs_agi		*agi;	/* allocation group header */
	struct scxfs_perag	*pag;	/* per allocation group data */
	int			error;

	trace_scxfs_ialloc_read_agi(mp, agno);

	error = scxfs_read_agi(mp, tp, agno, bpp);
	if (error)
		return error;

	agi = SCXFS_BUF_TO_AGI(*bpp);
	pag = scxfs_perag_get(mp, agno);
	if (!pag->pagi_init) {
		pag->pagi_freecount = be32_to_cpu(agi->agi_freecount);
		pag->pagi_count = be32_to_cpu(agi->agi_count);
		pag->pagi_init = 1;
	}

	/*
	 * It's possible for these to be out of sync if
	 * we are in the middle of a forced shutdown.
	 */
	ASSERT(pag->pagi_freecount == be32_to_cpu(agi->agi_freecount) ||
		SCXFS_FORCED_SHUTDOWN(mp));
	scxfs_perag_put(pag);
	return 0;
}

/*
 * Read in the agi to initialise the per-ag data in the mount structure
 */
int
scxfs_ialloc_pagi_init(
	scxfs_mount_t	*mp,		/* file system mount structure */
	scxfs_trans_t	*tp,		/* transaction pointer */
	scxfs_agnumber_t	agno)		/* allocation group number */
{
	scxfs_buf_t	*bp = NULL;
	int		error;

	error = scxfs_ialloc_read_agi(mp, tp, agno, &bp);
	if (error)
		return error;
	if (bp)
		scxfs_trans_brelse(tp, bp);
	return 0;
}

/* Is there an inode record covering a given range of inode numbers? */
int
scxfs_ialloc_has_inode_record(
	struct scxfs_btree_cur	*cur,
	scxfs_agino_t		low,
	scxfs_agino_t		high,
	bool			*exists)
{
	struct scxfs_inobt_rec_incore	irec;
	scxfs_agino_t		agino;
	uint16_t		holemask;
	int			has_record;
	int			i;
	int			error;

	*exists = false;
	error = scxfs_inobt_lookup(cur, low, SCXFS_LOOKUP_LE, &has_record);
	while (error == 0 && has_record) {
		error = scxfs_inobt_get_rec(cur, &irec, &has_record);
		if (error || irec.ir_startino > high)
			break;

		agino = irec.ir_startino;
		holemask = irec.ir_holemask;
		for (i = 0; i < SCXFS_INOBT_HOLEMASK_BITS; holemask >>= 1,
				i++, agino += SCXFS_INODES_PER_HOLEMASK_BIT) {
			if (holemask & 1)
				continue;
			if (agino + SCXFS_INODES_PER_HOLEMASK_BIT > low &&
					agino <= high) {
				*exists = true;
				return 0;
			}
		}

		error = scxfs_btree_increment(cur, 0, &has_record);
	}
	return error;
}

/* Is there an inode record covering a given extent? */
int
scxfs_ialloc_has_inodes_at_extent(
	struct scxfs_btree_cur	*cur,
	scxfs_agblock_t		bno,
	scxfs_extlen_t		len,
	bool			*exists)
{
	scxfs_agino_t		low;
	scxfs_agino_t		high;

	low = SCXFS_AGB_TO_AGINO(cur->bc_mp, bno);
	high = SCXFS_AGB_TO_AGINO(cur->bc_mp, bno + len) - 1;

	return scxfs_ialloc_has_inode_record(cur, low, high, exists);
}

struct scxfs_ialloc_count_inodes {
	scxfs_agino_t			count;
	scxfs_agino_t			freecount;
};

/* Record inode counts across all inobt records. */
STATIC int
scxfs_ialloc_count_inodes_rec(
	struct scxfs_btree_cur		*cur,
	union scxfs_btree_rec		*rec,
	void				*priv)
{
	struct scxfs_inobt_rec_incore	irec;
	struct scxfs_ialloc_count_inodes	*ci = priv;

	scxfs_inobt_btrec_to_irec(cur->bc_mp, rec, &irec);
	ci->count += irec.ir_count;
	ci->freecount += irec.ir_freecount;

	return 0;
}

/* Count allocated and free inodes under an inobt. */
int
scxfs_ialloc_count_inodes(
	struct scxfs_btree_cur		*cur,
	scxfs_agino_t			*count,
	scxfs_agino_t			*freecount)
{
	struct scxfs_ialloc_count_inodes	ci = {0};
	int				error;

	ASSERT(cur->bc_btnum == SCXFS_BTNUM_INO);
	error = scxfs_btree_query_all(cur, scxfs_ialloc_count_inodes_rec, &ci);
	if (error)
		return error;

	*count = ci.count;
	*freecount = ci.freecount;
	return 0;
}

/*
 * Initialize inode-related geometry information.
 *
 * Compute the inode btree min and max levels and set maxicount.
 *
 * Set the inode cluster size.  This may still be overridden by the file
 * system block size if it is larger than the chosen cluster size.
 *
 * For v5 filesystems, scale the cluster size with the inode size to keep a
 * constant ratio of inode per cluster buffer, but only if mkfs has set the
 * inode alignment value appropriately for larger cluster sizes.
 *
 * Then compute the inode cluster alignment information.
 */
void
scxfs_ialloc_setup_geometry(
	struct scxfs_mount	*mp)
{
	struct scxfs_sb		*sbp = &mp->m_sb;
	struct scxfs_ino_geometry	*igeo = M_IGEO(mp);
	uint64_t		icount;
	uint			inodes;

	/* Compute inode btree geometry. */
	igeo->agino_log = sbp->sb_inopblog + sbp->sb_agblklog;
	igeo->inobt_mxr[0] = scxfs_inobt_maxrecs(mp, sbp->sb_blocksize, 1);
	igeo->inobt_mxr[1] = scxfs_inobt_maxrecs(mp, sbp->sb_blocksize, 0);
	igeo->inobt_mnr[0] = igeo->inobt_mxr[0] / 2;
	igeo->inobt_mnr[1] = igeo->inobt_mxr[1] / 2;

	igeo->ialloc_inos = max_t(uint16_t, SCXFS_INODES_PER_CHUNK,
			sbp->sb_inopblock);
	igeo->ialloc_blks = igeo->ialloc_inos >> sbp->sb_inopblog;

	if (sbp->sb_spino_align)
		igeo->ialloc_min_blks = sbp->sb_spino_align;
	else
		igeo->ialloc_min_blks = igeo->ialloc_blks;

	/* Compute and fill in value of m_ino_geo.inobt_maxlevels. */
	inodes = (1LL << SCXFS_INO_AGINO_BITS(mp)) >> SCXFS_INODES_PER_CHUNK_LOG;
	igeo->inobt_maxlevels = scxfs_btree_compute_maxlevels(igeo->inobt_mnr,
			inodes);

	/*
	 * Set the maximum inode count for this filesystem, being careful not
	 * to use obviously garbage sb_inopblog/sb_inopblock values.  Regular
	 * users should never get here due to failing sb verification, but
	 * certain users (scxfs_db) need to be usable even with corrupt metadata.
	 */
	if (sbp->sb_imax_pct && igeo->ialloc_blks) {
		/*
		 * Make sure the maximum inode count is a multiple
		 * of the units we allocate inodes in.
		 */
		icount = sbp->sb_dblocks * sbp->sb_imax_pct;
		do_div(icount, 100);
		do_div(icount, igeo->ialloc_blks);
		igeo->maxicount = SCXFS_FSB_TO_INO(mp,
				icount * igeo->ialloc_blks);
	} else {
		igeo->maxicount = 0;
	}

	/*
	 * Compute the desired size of an inode cluster buffer size, which
	 * starts at 8K and (on v5 filesystems) scales up with larger inode
	 * sizes.
	 *
	 * Preserve the desired inode cluster size because the sparse inodes
	 * feature uses that desired size (not the actual size) to compute the
	 * sparse inode alignment.  The mount code validates this value, so we
	 * cannot change the behavior.
	 */
	igeo->inode_cluster_size_raw = SCXFS_INODE_BIG_CLUSTER_SIZE;
	if (scxfs_sb_version_hascrc(&mp->m_sb)) {
		int	new_size = igeo->inode_cluster_size_raw;

		new_size *= mp->m_sb.sb_inodesize / SCXFS_DINODE_MIN_SIZE;
		if (mp->m_sb.sb_inoalignmt >= SCXFS_B_TO_FSBT(mp, new_size))
			igeo->inode_cluster_size_raw = new_size;
	}

	/* Calculate inode cluster ratios. */
	if (igeo->inode_cluster_size_raw > mp->m_sb.sb_blocksize)
		igeo->blocks_per_cluster = SCXFS_B_TO_FSBT(mp,
				igeo->inode_cluster_size_raw);
	else
		igeo->blocks_per_cluster = 1;
	igeo->inode_cluster_size = SCXFS_FSB_TO_B(mp, igeo->blocks_per_cluster);
	igeo->inodes_per_cluster = SCXFS_FSB_TO_INO(mp, igeo->blocks_per_cluster);

	/* Calculate inode cluster alignment. */
	if (scxfs_sb_version_hasalign(&mp->m_sb) &&
	    mp->m_sb.sb_inoalignmt >= igeo->blocks_per_cluster)
		igeo->cluster_align = mp->m_sb.sb_inoalignmt;
	else
		igeo->cluster_align = 1;
	igeo->inoalign_mask = igeo->cluster_align - 1;
	igeo->cluster_align_inodes = SCXFS_FSB_TO_INO(mp, igeo->cluster_align);

	/*
	 * If we are using stripe alignment, check whether
	 * the stripe unit is a multiple of the inode alignment
	 */
	if (mp->m_dalign && igeo->inoalign_mask &&
	    !(mp->m_dalign & igeo->inoalign_mask))
		igeo->ialloc_align = mp->m_dalign;
	else
		igeo->ialloc_align = 0;
}
