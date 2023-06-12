// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2014 Red Hat, Inc.
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
#include "scxfs_defer.h"
#include "scxfs_btree.h"
#include "scxfs_trans.h"
#include "scxfs_alloc.h"
#include "scxfs_rmap.h"
#include "scxfs_rmap_btree.h"
#include "scxfs_trace.h"
#include "scxfs_errortag.h"
#include "scxfs_error.h"
#include "scxfs_inode.h"

/*
 * Lookup the first record less than or equal to [bno, len, owner, offset]
 * in the btree given by cur.
 */
int
scxfs_rmap_lookup_le(
	struct scxfs_btree_cur	*cur,
	scxfs_agblock_t		bno,
	scxfs_extlen_t		len,
	uint64_t		owner,
	uint64_t		offset,
	unsigned int		flags,
	int			*stat)
{
	cur->bc_rec.r.rm_startblock = bno;
	cur->bc_rec.r.rm_blockcount = len;
	cur->bc_rec.r.rm_owner = owner;
	cur->bc_rec.r.rm_offset = offset;
	cur->bc_rec.r.rm_flags = flags;
	return scxfs_btree_lookup(cur, SCXFS_LOOKUP_LE, stat);
}

/*
 * Lookup the record exactly matching [bno, len, owner, offset]
 * in the btree given by cur.
 */
int
scxfs_rmap_lookup_eq(
	struct scxfs_btree_cur	*cur,
	scxfs_agblock_t		bno,
	scxfs_extlen_t		len,
	uint64_t		owner,
	uint64_t		offset,
	unsigned int		flags,
	int			*stat)
{
	cur->bc_rec.r.rm_startblock = bno;
	cur->bc_rec.r.rm_blockcount = len;
	cur->bc_rec.r.rm_owner = owner;
	cur->bc_rec.r.rm_offset = offset;
	cur->bc_rec.r.rm_flags = flags;
	return scxfs_btree_lookup(cur, SCXFS_LOOKUP_EQ, stat);
}

/*
 * Update the record referred to by cur to the value given
 * by [bno, len, owner, offset].
 * This either works (return 0) or gets an EFSCORRUPTED error.
 */
STATIC int
scxfs_rmap_update(
	struct scxfs_btree_cur	*cur,
	struct scxfs_rmap_irec	*irec)
{
	union scxfs_btree_rec	rec;
	int			error;

	trace_scxfs_rmap_update(cur->bc_mp, cur->bc_private.a.agno,
			irec->rm_startblock, irec->rm_blockcount,
			irec->rm_owner, irec->rm_offset, irec->rm_flags);

	rec.rmap.rm_startblock = cpu_to_be32(irec->rm_startblock);
	rec.rmap.rm_blockcount = cpu_to_be32(irec->rm_blockcount);
	rec.rmap.rm_owner = cpu_to_be64(irec->rm_owner);
	rec.rmap.rm_offset = cpu_to_be64(
			scxfs_rmap_irec_offset_pack(irec));
	error = scxfs_btree_update(cur, &rec);
	if (error)
		trace_scxfs_rmap_update_error(cur->bc_mp,
				cur->bc_private.a.agno, error, _RET_IP_);
	return error;
}

int
scxfs_rmap_insert(
	struct scxfs_btree_cur	*rcur,
	scxfs_agblock_t		agbno,
	scxfs_extlen_t		len,
	uint64_t		owner,
	uint64_t		offset,
	unsigned int		flags)
{
	int			i;
	int			error;

	trace_scxfs_rmap_insert(rcur->bc_mp, rcur->bc_private.a.agno, agbno,
			len, owner, offset, flags);

	error = scxfs_rmap_lookup_eq(rcur, agbno, len, owner, offset, flags, &i);
	if (error)
		goto done;
	SCXFS_WANT_CORRUPTED_GOTO(rcur->bc_mp, i == 0, done);

	rcur->bc_rec.r.rm_startblock = agbno;
	rcur->bc_rec.r.rm_blockcount = len;
	rcur->bc_rec.r.rm_owner = owner;
	rcur->bc_rec.r.rm_offset = offset;
	rcur->bc_rec.r.rm_flags = flags;
	error = scxfs_btree_insert(rcur, &i);
	if (error)
		goto done;
	SCXFS_WANT_CORRUPTED_GOTO(rcur->bc_mp, i == 1, done);
done:
	if (error)
		trace_scxfs_rmap_insert_error(rcur->bc_mp,
				rcur->bc_private.a.agno, error, _RET_IP_);
	return error;
}

STATIC int
scxfs_rmap_delete(
	struct scxfs_btree_cur	*rcur,
	scxfs_agblock_t		agbno,
	scxfs_extlen_t		len,
	uint64_t		owner,
	uint64_t		offset,
	unsigned int		flags)
{
	int			i;
	int			error;

	trace_scxfs_rmap_delete(rcur->bc_mp, rcur->bc_private.a.agno, agbno,
			len, owner, offset, flags);

	error = scxfs_rmap_lookup_eq(rcur, agbno, len, owner, offset, flags, &i);
	if (error)
		goto done;
	SCXFS_WANT_CORRUPTED_GOTO(rcur->bc_mp, i == 1, done);

	error = scxfs_btree_delete(rcur, &i);
	if (error)
		goto done;
	SCXFS_WANT_CORRUPTED_GOTO(rcur->bc_mp, i == 1, done);
done:
	if (error)
		trace_scxfs_rmap_delete_error(rcur->bc_mp,
				rcur->bc_private.a.agno, error, _RET_IP_);
	return error;
}

/* Convert an internal btree record to an rmap record. */
int
scxfs_rmap_btrec_to_irec(
	union scxfs_btree_rec	*rec,
	struct scxfs_rmap_irec	*irec)
{
	irec->rm_startblock = be32_to_cpu(rec->rmap.rm_startblock);
	irec->rm_blockcount = be32_to_cpu(rec->rmap.rm_blockcount);
	irec->rm_owner = be64_to_cpu(rec->rmap.rm_owner);
	return scxfs_rmap_irec_offset_unpack(be64_to_cpu(rec->rmap.rm_offset),
			irec);
}

/*
 * Get the data from the pointed-to record.
 */
int
scxfs_rmap_get_rec(
	struct scxfs_btree_cur	*cur,
	struct scxfs_rmap_irec	*irec,
	int			*stat)
{
	struct scxfs_mount	*mp = cur->bc_mp;
	scxfs_agnumber_t		agno = cur->bc_private.a.agno;
	union scxfs_btree_rec	*rec;
	int			error;

	error = scxfs_btree_get_rec(cur, &rec, stat);
	if (error || !*stat)
		return error;

	if (scxfs_rmap_btrec_to_irec(rec, irec))
		goto out_bad_rec;

	if (irec->rm_blockcount == 0)
		goto out_bad_rec;
	if (irec->rm_startblock <= SCXFS_AGFL_BLOCK(mp)) {
		if (irec->rm_owner != SCXFS_RMAP_OWN_FS)
			goto out_bad_rec;
		if (irec->rm_blockcount != SCXFS_AGFL_BLOCK(mp) + 1)
			goto out_bad_rec;
	} else {
		/* check for valid extent range, including overflow */
		if (!scxfs_verify_agbno(mp, agno, irec->rm_startblock))
			goto out_bad_rec;
		if (irec->rm_startblock >
				irec->rm_startblock + irec->rm_blockcount)
			goto out_bad_rec;
		if (!scxfs_verify_agbno(mp, agno,
				irec->rm_startblock + irec->rm_blockcount - 1))
			goto out_bad_rec;
	}

	if (!(scxfs_verify_ino(mp, irec->rm_owner) ||
	      (irec->rm_owner <= SCXFS_RMAP_OWN_FS &&
	       irec->rm_owner >= SCXFS_RMAP_OWN_MIN)))
		goto out_bad_rec;

	return 0;
out_bad_rec:
	scxfs_warn(mp,
		"Reverse Mapping BTree record corruption in AG %d detected!",
		agno);
	scxfs_warn(mp,
		"Owner 0x%llx, flags 0x%x, start block 0x%x block count 0x%x",
		irec->rm_owner, irec->rm_flags, irec->rm_startblock,
		irec->rm_blockcount);
	return -EFSCORRUPTED;
}

struct scxfs_find_left_neighbor_info {
	struct scxfs_rmap_irec	high;
	struct scxfs_rmap_irec	*irec;
	int			*stat;
};

/* For each rmap given, figure out if it matches the key we want. */
STATIC int
scxfs_rmap_find_left_neighbor_helper(
	struct scxfs_btree_cur	*cur,
	struct scxfs_rmap_irec	*rec,
	void			*priv)
{
	struct scxfs_find_left_neighbor_info	*info = priv;

	trace_scxfs_rmap_find_left_neighbor_candidate(cur->bc_mp,
			cur->bc_private.a.agno, rec->rm_startblock,
			rec->rm_blockcount, rec->rm_owner, rec->rm_offset,
			rec->rm_flags);

	if (rec->rm_owner != info->high.rm_owner)
		return 0;
	if (!SCXFS_RMAP_NON_INODE_OWNER(rec->rm_owner) &&
	    !(rec->rm_flags & SCXFS_RMAP_BMBT_BLOCK) &&
	    rec->rm_offset + rec->rm_blockcount - 1 != info->high.rm_offset)
		return 0;

	*info->irec = *rec;
	*info->stat = 1;
	return -ECANCELED;
}

/*
 * Find the record to the left of the given extent, being careful only to
 * return a match with the same owner and adjacent physical and logical
 * block ranges.
 */
int
scxfs_rmap_find_left_neighbor(
	struct scxfs_btree_cur	*cur,
	scxfs_agblock_t		bno,
	uint64_t		owner,
	uint64_t		offset,
	unsigned int		flags,
	struct scxfs_rmap_irec	*irec,
	int			*stat)
{
	struct scxfs_find_left_neighbor_info	info;
	int			error;

	*stat = 0;
	if (bno == 0)
		return 0;
	info.high.rm_startblock = bno - 1;
	info.high.rm_owner = owner;
	if (!SCXFS_RMAP_NON_INODE_OWNER(owner) &&
	    !(flags & SCXFS_RMAP_BMBT_BLOCK)) {
		if (offset == 0)
			return 0;
		info.high.rm_offset = offset - 1;
	} else
		info.high.rm_offset = 0;
	info.high.rm_flags = flags;
	info.high.rm_blockcount = 0;
	info.irec = irec;
	info.stat = stat;

	trace_scxfs_rmap_find_left_neighbor_query(cur->bc_mp,
			cur->bc_private.a.agno, bno, 0, owner, offset, flags);

	error = scxfs_rmap_query_range(cur, &info.high, &info.high,
			scxfs_rmap_find_left_neighbor_helper, &info);
	if (error == -ECANCELED)
		error = 0;
	if (*stat)
		trace_scxfs_rmap_find_left_neighbor_result(cur->bc_mp,
				cur->bc_private.a.agno, irec->rm_startblock,
				irec->rm_blockcount, irec->rm_owner,
				irec->rm_offset, irec->rm_flags);
	return error;
}

/* For each rmap given, figure out if it matches the key we want. */
STATIC int
scxfs_rmap_lookup_le_range_helper(
	struct scxfs_btree_cur	*cur,
	struct scxfs_rmap_irec	*rec,
	void			*priv)
{
	struct scxfs_find_left_neighbor_info	*info = priv;

	trace_scxfs_rmap_lookup_le_range_candidate(cur->bc_mp,
			cur->bc_private.a.agno, rec->rm_startblock,
			rec->rm_blockcount, rec->rm_owner, rec->rm_offset,
			rec->rm_flags);

	if (rec->rm_owner != info->high.rm_owner)
		return 0;
	if (!SCXFS_RMAP_NON_INODE_OWNER(rec->rm_owner) &&
	    !(rec->rm_flags & SCXFS_RMAP_BMBT_BLOCK) &&
	    (rec->rm_offset > info->high.rm_offset ||
	     rec->rm_offset + rec->rm_blockcount <= info->high.rm_offset))
		return 0;

	*info->irec = *rec;
	*info->stat = 1;
	return -ECANCELED;
}

/*
 * Find the record to the left of the given extent, being careful only to
 * return a match with the same owner and overlapping physical and logical
 * block ranges.  This is the overlapping-interval version of
 * scxfs_rmap_lookup_le.
 */
int
scxfs_rmap_lookup_le_range(
	struct scxfs_btree_cur	*cur,
	scxfs_agblock_t		bno,
	uint64_t		owner,
	uint64_t		offset,
	unsigned int		flags,
	struct scxfs_rmap_irec	*irec,
	int			*stat)
{
	struct scxfs_find_left_neighbor_info	info;
	int			error;

	info.high.rm_startblock = bno;
	info.high.rm_owner = owner;
	if (!SCXFS_RMAP_NON_INODE_OWNER(owner) && !(flags & SCXFS_RMAP_BMBT_BLOCK))
		info.high.rm_offset = offset;
	else
		info.high.rm_offset = 0;
	info.high.rm_flags = flags;
	info.high.rm_blockcount = 0;
	*stat = 0;
	info.irec = irec;
	info.stat = stat;

	trace_scxfs_rmap_lookup_le_range(cur->bc_mp,
			cur->bc_private.a.agno, bno, 0, owner, offset, flags);
	error = scxfs_rmap_query_range(cur, &info.high, &info.high,
			scxfs_rmap_lookup_le_range_helper, &info);
	if (error == -ECANCELED)
		error = 0;
	if (*stat)
		trace_scxfs_rmap_lookup_le_range_result(cur->bc_mp,
				cur->bc_private.a.agno, irec->rm_startblock,
				irec->rm_blockcount, irec->rm_owner,
				irec->rm_offset, irec->rm_flags);
	return error;
}

/*
 * Perform all the relevant owner checks for a removal op.  If we're doing an
 * unknown-owner removal then we have no owner information to check.
 */
static int
scxfs_rmap_free_check_owner(
	struct scxfs_mount	*mp,
	uint64_t		ltoff,
	struct scxfs_rmap_irec	*rec,
	scxfs_filblks_t		len,
	uint64_t		owner,
	uint64_t		offset,
	unsigned int		flags)
{
	int			error = 0;

	if (owner == SCXFS_RMAP_OWN_UNKNOWN)
		return 0;

	/* Make sure the unwritten flag matches. */
	SCXFS_WANT_CORRUPTED_GOTO(mp, (flags & SCXFS_RMAP_UNWRITTEN) ==
			(rec->rm_flags & SCXFS_RMAP_UNWRITTEN), out);

	/* Make sure the owner matches what we expect to find in the tree. */
	SCXFS_WANT_CORRUPTED_GOTO(mp, owner == rec->rm_owner, out);

	/* Check the offset, if necessary. */
	if (SCXFS_RMAP_NON_INODE_OWNER(owner))
		goto out;

	if (flags & SCXFS_RMAP_BMBT_BLOCK) {
		SCXFS_WANT_CORRUPTED_GOTO(mp, rec->rm_flags & SCXFS_RMAP_BMBT_BLOCK,
				out);
	} else {
		SCXFS_WANT_CORRUPTED_GOTO(mp, rec->rm_offset <= offset, out);
		SCXFS_WANT_CORRUPTED_GOTO(mp,
				ltoff + rec->rm_blockcount >= offset + len,
				out);
	}

out:
	return error;
}

/*
 * Find the extent in the rmap btree and remove it.
 *
 * The record we find should always be an exact match for the extent that we're
 * looking for, since we insert them into the btree without modification.
 *
 * Special Case #1: when growing the filesystem, we "free" an extent when
 * growing the last AG. This extent is new space and so it is not tracked as
 * used space in the btree. The growfs code will pass in an owner of
 * SCXFS_RMAP_OWN_NULL to indicate that it expected that there is no owner of this
 * extent. We verify that - the extent lookup result in a record that does not
 * overlap.
 *
 * Special Case #2: EFIs do not record the owner of the extent, so when
 * recovering EFIs from the log we pass in SCXFS_RMAP_OWN_UNKNOWN to tell the rmap
 * btree to ignore the owner (i.e. wildcard match) so we don't trigger
 * corruption checks during log recovery.
 */
STATIC int
scxfs_rmap_unmap(
	struct scxfs_btree_cur		*cur,
	scxfs_agblock_t			bno,
	scxfs_extlen_t			len,
	bool				unwritten,
	const struct scxfs_owner_info	*oinfo)
{
	struct scxfs_mount		*mp = cur->bc_mp;
	struct scxfs_rmap_irec		ltrec;
	uint64_t			ltoff;
	int				error = 0;
	int				i;
	uint64_t			owner;
	uint64_t			offset;
	unsigned int			flags;
	bool				ignore_off;

	scxfs_owner_info_unpack(oinfo, &owner, &offset, &flags);
	ignore_off = SCXFS_RMAP_NON_INODE_OWNER(owner) ||
			(flags & SCXFS_RMAP_BMBT_BLOCK);
	if (unwritten)
		flags |= SCXFS_RMAP_UNWRITTEN;
	trace_scxfs_rmap_unmap(mp, cur->bc_private.a.agno, bno, len,
			unwritten, oinfo);

	/*
	 * We should always have a left record because there's a static record
	 * for the AG headers at rm_startblock == 0 created by mkfs/growfs that
	 * will not ever be removed from the tree.
	 */
	error = scxfs_rmap_lookup_le(cur, bno, len, owner, offset, flags, &i);
	if (error)
		goto out_error;
	SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, out_error);

	error = scxfs_rmap_get_rec(cur, &ltrec, &i);
	if (error)
		goto out_error;
	SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, out_error);
	trace_scxfs_rmap_lookup_le_range_result(cur->bc_mp,
			cur->bc_private.a.agno, ltrec.rm_startblock,
			ltrec.rm_blockcount, ltrec.rm_owner,
			ltrec.rm_offset, ltrec.rm_flags);
	ltoff = ltrec.rm_offset;

	/*
	 * For growfs, the incoming extent must be beyond the left record we
	 * just found as it is new space and won't be used by anyone. This is
	 * just a corruption check as we don't actually do anything with this
	 * extent.  Note that we need to use >= instead of > because it might
	 * be the case that the "left" extent goes all the way to EOFS.
	 */
	if (owner == SCXFS_RMAP_OWN_NULL) {
		SCXFS_WANT_CORRUPTED_GOTO(mp, bno >= ltrec.rm_startblock +
						ltrec.rm_blockcount, out_error);
		goto out_done;
	}

	/*
	 * If we're doing an unknown-owner removal for EFI recovery, we expect
	 * to find the full range in the rmapbt or nothing at all.  If we
	 * don't find any rmaps overlapping either end of the range, we're
	 * done.  Hopefully this means that the EFI creator already queued
	 * (and finished) a RUI to remove the rmap.
	 */
	if (owner == SCXFS_RMAP_OWN_UNKNOWN &&
	    ltrec.rm_startblock + ltrec.rm_blockcount <= bno) {
		struct scxfs_rmap_irec    rtrec;

		error = scxfs_btree_increment(cur, 0, &i);
		if (error)
			goto out_error;
		if (i == 0)
			goto out_done;
		error = scxfs_rmap_get_rec(cur, &rtrec, &i);
		if (error)
			goto out_error;
		SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, out_error);
		if (rtrec.rm_startblock >= bno + len)
			goto out_done;
	}

	/* Make sure the extent we found covers the entire freeing range. */
	SCXFS_WANT_CORRUPTED_GOTO(mp, ltrec.rm_startblock <= bno &&
			ltrec.rm_startblock + ltrec.rm_blockcount >=
			bno + len, out_error);

	/* Check owner information. */
	error = scxfs_rmap_free_check_owner(mp, ltoff, &ltrec, len, owner,
			offset, flags);
	if (error)
		goto out_error;

	if (ltrec.rm_startblock == bno && ltrec.rm_blockcount == len) {
		/* exact match, simply remove the record from rmap tree */
		trace_scxfs_rmap_delete(mp, cur->bc_private.a.agno,
				ltrec.rm_startblock, ltrec.rm_blockcount,
				ltrec.rm_owner, ltrec.rm_offset,
				ltrec.rm_flags);
		error = scxfs_btree_delete(cur, &i);
		if (error)
			goto out_error;
		SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, out_error);
	} else if (ltrec.rm_startblock == bno) {
		/*
		 * overlap left hand side of extent: move the start, trim the
		 * length and update the current record.
		 *
		 *       ltbno                ltlen
		 * Orig:    |oooooooooooooooooooo|
		 * Freeing: |fffffffff|
		 * Result:            |rrrrrrrrrr|
		 *         bno       len
		 */
		ltrec.rm_startblock += len;
		ltrec.rm_blockcount -= len;
		if (!ignore_off)
			ltrec.rm_offset += len;
		error = scxfs_rmap_update(cur, &ltrec);
		if (error)
			goto out_error;
	} else if (ltrec.rm_startblock + ltrec.rm_blockcount == bno + len) {
		/*
		 * overlap right hand side of extent: trim the length and update
		 * the current record.
		 *
		 *       ltbno                ltlen
		 * Orig:    |oooooooooooooooooooo|
		 * Freeing:            |fffffffff|
		 * Result:  |rrrrrrrrrr|
		 *                    bno       len
		 */
		ltrec.rm_blockcount -= len;
		error = scxfs_rmap_update(cur, &ltrec);
		if (error)
			goto out_error;
	} else {

		/*
		 * overlap middle of extent: trim the length of the existing
		 * record to the length of the new left-extent size, increment
		 * the insertion position so we can insert a new record
		 * containing the remaining right-extent space.
		 *
		 *       ltbno                ltlen
		 * Orig:    |oooooooooooooooooooo|
		 * Freeing:       |fffffffff|
		 * Result:  |rrrrr|         |rrrr|
		 *               bno       len
		 */
		scxfs_extlen_t	orig_len = ltrec.rm_blockcount;

		ltrec.rm_blockcount = bno - ltrec.rm_startblock;
		error = scxfs_rmap_update(cur, &ltrec);
		if (error)
			goto out_error;

		error = scxfs_btree_increment(cur, 0, &i);
		if (error)
			goto out_error;

		cur->bc_rec.r.rm_startblock = bno + len;
		cur->bc_rec.r.rm_blockcount = orig_len - len -
						     ltrec.rm_blockcount;
		cur->bc_rec.r.rm_owner = ltrec.rm_owner;
		if (ignore_off)
			cur->bc_rec.r.rm_offset = 0;
		else
			cur->bc_rec.r.rm_offset = offset + len;
		cur->bc_rec.r.rm_flags = flags;
		trace_scxfs_rmap_insert(mp, cur->bc_private.a.agno,
				cur->bc_rec.r.rm_startblock,
				cur->bc_rec.r.rm_blockcount,
				cur->bc_rec.r.rm_owner,
				cur->bc_rec.r.rm_offset,
				cur->bc_rec.r.rm_flags);
		error = scxfs_btree_insert(cur, &i);
		if (error)
			goto out_error;
	}

out_done:
	trace_scxfs_rmap_unmap_done(mp, cur->bc_private.a.agno, bno, len,
			unwritten, oinfo);
out_error:
	if (error)
		trace_scxfs_rmap_unmap_error(mp, cur->bc_private.a.agno,
				error, _RET_IP_);
	return error;
}

/*
 * Remove a reference to an extent in the rmap btree.
 */
int
scxfs_rmap_free(
	struct scxfs_trans		*tp,
	struct scxfs_buf			*agbp,
	scxfs_agnumber_t			agno,
	scxfs_agblock_t			bno,
	scxfs_extlen_t			len,
	const struct scxfs_owner_info	*oinfo)
{
	struct scxfs_mount		*mp = tp->t_mountp;
	struct scxfs_btree_cur		*cur;
	int				error;

	if (!scxfs_sb_version_hasrmapbt(&mp->m_sb))
		return 0;

	cur = scxfs_rmapbt_init_cursor(mp, tp, agbp, agno);

	error = scxfs_rmap_unmap(cur, bno, len, false, oinfo);

	scxfs_btree_del_cursor(cur, error);
	return error;
}

/*
 * A mergeable rmap must have the same owner and the same values for
 * the unwritten, attr_fork, and bmbt flags.  The startblock and
 * offset are checked separately.
 */
static bool
scxfs_rmap_is_mergeable(
	struct scxfs_rmap_irec	*irec,
	uint64_t		owner,
	unsigned int		flags)
{
	if (irec->rm_owner == SCXFS_RMAP_OWN_NULL)
		return false;
	if (irec->rm_owner != owner)
		return false;
	if ((flags & SCXFS_RMAP_UNWRITTEN) ^
	    (irec->rm_flags & SCXFS_RMAP_UNWRITTEN))
		return false;
	if ((flags & SCXFS_RMAP_ATTR_FORK) ^
	    (irec->rm_flags & SCXFS_RMAP_ATTR_FORK))
		return false;
	if ((flags & SCXFS_RMAP_BMBT_BLOCK) ^
	    (irec->rm_flags & SCXFS_RMAP_BMBT_BLOCK))
		return false;
	return true;
}

/*
 * When we allocate a new block, the first thing we do is add a reference to
 * the extent in the rmap btree. This takes the form of a [agbno, length,
 * owner, offset] record.  Flags are encoded in the high bits of the offset
 * field.
 */
STATIC int
scxfs_rmap_map(
	struct scxfs_btree_cur		*cur,
	scxfs_agblock_t			bno,
	scxfs_extlen_t			len,
	bool				unwritten,
	const struct scxfs_owner_info	*oinfo)
{
	struct scxfs_mount		*mp = cur->bc_mp;
	struct scxfs_rmap_irec		ltrec;
	struct scxfs_rmap_irec		gtrec;
	int				have_gt;
	int				have_lt;
	int				error = 0;
	int				i;
	uint64_t			owner;
	uint64_t			offset;
	unsigned int			flags = 0;
	bool				ignore_off;

	scxfs_owner_info_unpack(oinfo, &owner, &offset, &flags);
	ASSERT(owner != 0);
	ignore_off = SCXFS_RMAP_NON_INODE_OWNER(owner) ||
			(flags & SCXFS_RMAP_BMBT_BLOCK);
	if (unwritten)
		flags |= SCXFS_RMAP_UNWRITTEN;
	trace_scxfs_rmap_map(mp, cur->bc_private.a.agno, bno, len,
			unwritten, oinfo);
	ASSERT(!scxfs_rmap_should_skip_owner_update(oinfo));

	/*
	 * For the initial lookup, look for an exact match or the left-adjacent
	 * record for our insertion point. This will also give us the record for
	 * start block contiguity tests.
	 */
	error = scxfs_rmap_lookup_le(cur, bno, len, owner, offset, flags,
			&have_lt);
	if (error)
		goto out_error;
	if (have_lt) {
		error = scxfs_rmap_get_rec(cur, &ltrec, &have_lt);
		if (error)
			goto out_error;
		SCXFS_WANT_CORRUPTED_GOTO(mp, have_lt == 1, out_error);
		trace_scxfs_rmap_lookup_le_range_result(cur->bc_mp,
				cur->bc_private.a.agno, ltrec.rm_startblock,
				ltrec.rm_blockcount, ltrec.rm_owner,
				ltrec.rm_offset, ltrec.rm_flags);

		if (!scxfs_rmap_is_mergeable(&ltrec, owner, flags))
			have_lt = 0;
	}

	SCXFS_WANT_CORRUPTED_GOTO(mp,
		have_lt == 0 ||
		ltrec.rm_startblock + ltrec.rm_blockcount <= bno, out_error);

	/*
	 * Increment the cursor to see if we have a right-adjacent record to our
	 * insertion point. This will give us the record for end block
	 * contiguity tests.
	 */
	error = scxfs_btree_increment(cur, 0, &have_gt);
	if (error)
		goto out_error;
	if (have_gt) {
		error = scxfs_rmap_get_rec(cur, &gtrec, &have_gt);
		if (error)
			goto out_error;
		SCXFS_WANT_CORRUPTED_GOTO(mp, have_gt == 1, out_error);
		SCXFS_WANT_CORRUPTED_GOTO(mp, bno + len <= gtrec.rm_startblock,
					out_error);
		trace_scxfs_rmap_find_right_neighbor_result(cur->bc_mp,
			cur->bc_private.a.agno, gtrec.rm_startblock,
			gtrec.rm_blockcount, gtrec.rm_owner,
			gtrec.rm_offset, gtrec.rm_flags);
		if (!scxfs_rmap_is_mergeable(&gtrec, owner, flags))
			have_gt = 0;
	}

	/*
	 * Note: cursor currently points one record to the right of ltrec, even
	 * if there is no record in the tree to the right.
	 */
	if (have_lt &&
	    ltrec.rm_startblock + ltrec.rm_blockcount == bno &&
	    (ignore_off || ltrec.rm_offset + ltrec.rm_blockcount == offset)) {
		/*
		 * left edge contiguous, merge into left record.
		 *
		 *       ltbno     ltlen
		 * orig:   |ooooooooo|
		 * adding:           |aaaaaaaaa|
		 * result: |rrrrrrrrrrrrrrrrrrr|
		 *                  bno       len
		 */
		ltrec.rm_blockcount += len;
		if (have_gt &&
		    bno + len == gtrec.rm_startblock &&
		    (ignore_off || offset + len == gtrec.rm_offset) &&
		    (unsigned long)ltrec.rm_blockcount + len +
				gtrec.rm_blockcount <= SCXFS_RMAP_LEN_MAX) {
			/*
			 * right edge also contiguous, delete right record
			 * and merge into left record.
			 *
			 *       ltbno     ltlen    gtbno     gtlen
			 * orig:   |ooooooooo|         |ooooooooo|
			 * adding:           |aaaaaaaaa|
			 * result: |rrrrrrrrrrrrrrrrrrrrrrrrrrrrr|
			 */
			ltrec.rm_blockcount += gtrec.rm_blockcount;
			trace_scxfs_rmap_delete(mp, cur->bc_private.a.agno,
					gtrec.rm_startblock,
					gtrec.rm_blockcount,
					gtrec.rm_owner,
					gtrec.rm_offset,
					gtrec.rm_flags);
			error = scxfs_btree_delete(cur, &i);
			if (error)
				goto out_error;
			SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, out_error);
		}

		/* point the cursor back to the left record and update */
		error = scxfs_btree_decrement(cur, 0, &have_gt);
		if (error)
			goto out_error;
		error = scxfs_rmap_update(cur, &ltrec);
		if (error)
			goto out_error;
	} else if (have_gt &&
		   bno + len == gtrec.rm_startblock &&
		   (ignore_off || offset + len == gtrec.rm_offset)) {
		/*
		 * right edge contiguous, merge into right record.
		 *
		 *                 gtbno     gtlen
		 * Orig:             |ooooooooo|
		 * adding: |aaaaaaaaa|
		 * Result: |rrrrrrrrrrrrrrrrrrr|
		 *        bno       len
		 */
		gtrec.rm_startblock = bno;
		gtrec.rm_blockcount += len;
		if (!ignore_off)
			gtrec.rm_offset = offset;
		error = scxfs_rmap_update(cur, &gtrec);
		if (error)
			goto out_error;
	} else {
		/*
		 * no contiguous edge with identical owner, insert
		 * new record at current cursor position.
		 */
		cur->bc_rec.r.rm_startblock = bno;
		cur->bc_rec.r.rm_blockcount = len;
		cur->bc_rec.r.rm_owner = owner;
		cur->bc_rec.r.rm_offset = offset;
		cur->bc_rec.r.rm_flags = flags;
		trace_scxfs_rmap_insert(mp, cur->bc_private.a.agno, bno, len,
			owner, offset, flags);
		error = scxfs_btree_insert(cur, &i);
		if (error)
			goto out_error;
		SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, out_error);
	}

	trace_scxfs_rmap_map_done(mp, cur->bc_private.a.agno, bno, len,
			unwritten, oinfo);
out_error:
	if (error)
		trace_scxfs_rmap_map_error(mp, cur->bc_private.a.agno,
				error, _RET_IP_);
	return error;
}

/*
 * Add a reference to an extent in the rmap btree.
 */
int
scxfs_rmap_alloc(
	struct scxfs_trans		*tp,
	struct scxfs_buf			*agbp,
	scxfs_agnumber_t			agno,
	scxfs_agblock_t			bno,
	scxfs_extlen_t			len,
	const struct scxfs_owner_info	*oinfo)
{
	struct scxfs_mount		*mp = tp->t_mountp;
	struct scxfs_btree_cur		*cur;
	int				error;

	if (!scxfs_sb_version_hasrmapbt(&mp->m_sb))
		return 0;

	cur = scxfs_rmapbt_init_cursor(mp, tp, agbp, agno);
	error = scxfs_rmap_map(cur, bno, len, false, oinfo);

	scxfs_btree_del_cursor(cur, error);
	return error;
}

#define RMAP_LEFT_CONTIG	(1 << 0)
#define RMAP_RIGHT_CONTIG	(1 << 1)
#define RMAP_LEFT_FILLING	(1 << 2)
#define RMAP_RIGHT_FILLING	(1 << 3)
#define RMAP_LEFT_VALID		(1 << 6)
#define RMAP_RIGHT_VALID	(1 << 7)

#define LEFT		r[0]
#define RIGHT		r[1]
#define PREV		r[2]
#define NEW		r[3]

/*
 * Convert an unwritten extent to a real extent or vice versa.
 * Does not handle overlapping extents.
 */
STATIC int
scxfs_rmap_convert(
	struct scxfs_btree_cur		*cur,
	scxfs_agblock_t			bno,
	scxfs_extlen_t			len,
	bool				unwritten,
	const struct scxfs_owner_info	*oinfo)
{
	struct scxfs_mount		*mp = cur->bc_mp;
	struct scxfs_rmap_irec		r[4];	/* neighbor extent entries */
						/* left is 0, right is 1, */
						/* prev is 2, new is 3 */
	uint64_t		owner;
	uint64_t		offset;
	uint64_t		new_endoff;
	unsigned int		oldext;
	unsigned int		newext;
	unsigned int		flags = 0;
	int			i;
	int			state = 0;
	int			error;

	scxfs_owner_info_unpack(oinfo, &owner, &offset, &flags);
	ASSERT(!(SCXFS_RMAP_NON_INODE_OWNER(owner) ||
			(flags & (SCXFS_RMAP_ATTR_FORK | SCXFS_RMAP_BMBT_BLOCK))));
	oldext = unwritten ? SCXFS_RMAP_UNWRITTEN : 0;
	new_endoff = offset + len;
	trace_scxfs_rmap_convert(mp, cur->bc_private.a.agno, bno, len,
			unwritten, oinfo);

	/*
	 * For the initial lookup, look for an exact match or the left-adjacent
	 * record for our insertion point. This will also give us the record for
	 * start block contiguity tests.
	 */
	error = scxfs_rmap_lookup_le(cur, bno, len, owner, offset, oldext, &i);
	if (error)
		goto done;
	SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);

	error = scxfs_rmap_get_rec(cur, &PREV, &i);
	if (error)
		goto done;
	SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
	trace_scxfs_rmap_lookup_le_range_result(cur->bc_mp,
			cur->bc_private.a.agno, PREV.rm_startblock,
			PREV.rm_blockcount, PREV.rm_owner,
			PREV.rm_offset, PREV.rm_flags);

	ASSERT(PREV.rm_offset <= offset);
	ASSERT(PREV.rm_offset + PREV.rm_blockcount >= new_endoff);
	ASSERT((PREV.rm_flags & SCXFS_RMAP_UNWRITTEN) == oldext);
	newext = ~oldext & SCXFS_RMAP_UNWRITTEN;

	/*
	 * Set flags determining what part of the previous oldext allocation
	 * extent is being replaced by a newext allocation.
	 */
	if (PREV.rm_offset == offset)
		state |= RMAP_LEFT_FILLING;
	if (PREV.rm_offset + PREV.rm_blockcount == new_endoff)
		state |= RMAP_RIGHT_FILLING;

	/*
	 * Decrement the cursor to see if we have a left-adjacent record to our
	 * insertion point. This will give us the record for end block
	 * contiguity tests.
	 */
	error = scxfs_btree_decrement(cur, 0, &i);
	if (error)
		goto done;
	if (i) {
		state |= RMAP_LEFT_VALID;
		error = scxfs_rmap_get_rec(cur, &LEFT, &i);
		if (error)
			goto done;
		SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
		SCXFS_WANT_CORRUPTED_GOTO(mp,
				LEFT.rm_startblock + LEFT.rm_blockcount <= bno,
				done);
		trace_scxfs_rmap_find_left_neighbor_result(cur->bc_mp,
				cur->bc_private.a.agno, LEFT.rm_startblock,
				LEFT.rm_blockcount, LEFT.rm_owner,
				LEFT.rm_offset, LEFT.rm_flags);
		if (LEFT.rm_startblock + LEFT.rm_blockcount == bno &&
		    LEFT.rm_offset + LEFT.rm_blockcount == offset &&
		    scxfs_rmap_is_mergeable(&LEFT, owner, newext))
			state |= RMAP_LEFT_CONTIG;
	}

	/*
	 * Increment the cursor to see if we have a right-adjacent record to our
	 * insertion point. This will give us the record for end block
	 * contiguity tests.
	 */
	error = scxfs_btree_increment(cur, 0, &i);
	if (error)
		goto done;
	SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
	error = scxfs_btree_increment(cur, 0, &i);
	if (error)
		goto done;
	if (i) {
		state |= RMAP_RIGHT_VALID;
		error = scxfs_rmap_get_rec(cur, &RIGHT, &i);
		if (error)
			goto done;
		SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
		SCXFS_WANT_CORRUPTED_GOTO(mp, bno + len <= RIGHT.rm_startblock,
					done);
		trace_scxfs_rmap_find_right_neighbor_result(cur->bc_mp,
				cur->bc_private.a.agno, RIGHT.rm_startblock,
				RIGHT.rm_blockcount, RIGHT.rm_owner,
				RIGHT.rm_offset, RIGHT.rm_flags);
		if (bno + len == RIGHT.rm_startblock &&
		    offset + len == RIGHT.rm_offset &&
		    scxfs_rmap_is_mergeable(&RIGHT, owner, newext))
			state |= RMAP_RIGHT_CONTIG;
	}

	/* check that left + prev + right is not too long */
	if ((state & (RMAP_LEFT_FILLING | RMAP_LEFT_CONTIG |
			 RMAP_RIGHT_FILLING | RMAP_RIGHT_CONTIG)) ==
	    (RMAP_LEFT_FILLING | RMAP_LEFT_CONTIG |
	     RMAP_RIGHT_FILLING | RMAP_RIGHT_CONTIG) &&
	    (unsigned long)LEFT.rm_blockcount + len +
	     RIGHT.rm_blockcount > SCXFS_RMAP_LEN_MAX)
		state &= ~RMAP_RIGHT_CONTIG;

	trace_scxfs_rmap_convert_state(mp, cur->bc_private.a.agno, state,
			_RET_IP_);

	/* reset the cursor back to PREV */
	error = scxfs_rmap_lookup_le(cur, bno, len, owner, offset, oldext, &i);
	if (error)
		goto done;
	SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);

	/*
	 * Switch out based on the FILLING and CONTIG state bits.
	 */
	switch (state & (RMAP_LEFT_FILLING | RMAP_LEFT_CONTIG |
			 RMAP_RIGHT_FILLING | RMAP_RIGHT_CONTIG)) {
	case RMAP_LEFT_FILLING | RMAP_LEFT_CONTIG |
	     RMAP_RIGHT_FILLING | RMAP_RIGHT_CONTIG:
		/*
		 * Setting all of a previous oldext extent to newext.
		 * The left and right neighbors are both contiguous with new.
		 */
		error = scxfs_btree_increment(cur, 0, &i);
		if (error)
			goto done;
		SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
		trace_scxfs_rmap_delete(mp, cur->bc_private.a.agno,
				RIGHT.rm_startblock, RIGHT.rm_blockcount,
				RIGHT.rm_owner, RIGHT.rm_offset,
				RIGHT.rm_flags);
		error = scxfs_btree_delete(cur, &i);
		if (error)
			goto done;
		SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
		error = scxfs_btree_decrement(cur, 0, &i);
		if (error)
			goto done;
		SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
		trace_scxfs_rmap_delete(mp, cur->bc_private.a.agno,
				PREV.rm_startblock, PREV.rm_blockcount,
				PREV.rm_owner, PREV.rm_offset,
				PREV.rm_flags);
		error = scxfs_btree_delete(cur, &i);
		if (error)
			goto done;
		SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
		error = scxfs_btree_decrement(cur, 0, &i);
		if (error)
			goto done;
		SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
		NEW = LEFT;
		NEW.rm_blockcount += PREV.rm_blockcount + RIGHT.rm_blockcount;
		error = scxfs_rmap_update(cur, &NEW);
		if (error)
			goto done;
		break;

	case RMAP_LEFT_FILLING | RMAP_RIGHT_FILLING | RMAP_LEFT_CONTIG:
		/*
		 * Setting all of a previous oldext extent to newext.
		 * The left neighbor is contiguous, the right is not.
		 */
		trace_scxfs_rmap_delete(mp, cur->bc_private.a.agno,
				PREV.rm_startblock, PREV.rm_blockcount,
				PREV.rm_owner, PREV.rm_offset,
				PREV.rm_flags);
		error = scxfs_btree_delete(cur, &i);
		if (error)
			goto done;
		SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
		error = scxfs_btree_decrement(cur, 0, &i);
		if (error)
			goto done;
		SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
		NEW = LEFT;
		NEW.rm_blockcount += PREV.rm_blockcount;
		error = scxfs_rmap_update(cur, &NEW);
		if (error)
			goto done;
		break;

	case RMAP_LEFT_FILLING | RMAP_RIGHT_FILLING | RMAP_RIGHT_CONTIG:
		/*
		 * Setting all of a previous oldext extent to newext.
		 * The right neighbor is contiguous, the left is not.
		 */
		error = scxfs_btree_increment(cur, 0, &i);
		if (error)
			goto done;
		SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
		trace_scxfs_rmap_delete(mp, cur->bc_private.a.agno,
				RIGHT.rm_startblock, RIGHT.rm_blockcount,
				RIGHT.rm_owner, RIGHT.rm_offset,
				RIGHT.rm_flags);
		error = scxfs_btree_delete(cur, &i);
		if (error)
			goto done;
		SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
		error = scxfs_btree_decrement(cur, 0, &i);
		if (error)
			goto done;
		SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
		NEW = PREV;
		NEW.rm_blockcount = len + RIGHT.rm_blockcount;
		NEW.rm_flags = newext;
		error = scxfs_rmap_update(cur, &NEW);
		if (error)
			goto done;
		break;

	case RMAP_LEFT_FILLING | RMAP_RIGHT_FILLING:
		/*
		 * Setting all of a previous oldext extent to newext.
		 * Neither the left nor right neighbors are contiguous with
		 * the new one.
		 */
		NEW = PREV;
		NEW.rm_flags = newext;
		error = scxfs_rmap_update(cur, &NEW);
		if (error)
			goto done;
		break;

	case RMAP_LEFT_FILLING | RMAP_LEFT_CONTIG:
		/*
		 * Setting the first part of a previous oldext extent to newext.
		 * The left neighbor is contiguous.
		 */
		NEW = PREV;
		NEW.rm_offset += len;
		NEW.rm_startblock += len;
		NEW.rm_blockcount -= len;
		error = scxfs_rmap_update(cur, &NEW);
		if (error)
			goto done;
		error = scxfs_btree_decrement(cur, 0, &i);
		if (error)
			goto done;
		NEW = LEFT;
		NEW.rm_blockcount += len;
		error = scxfs_rmap_update(cur, &NEW);
		if (error)
			goto done;
		break;

	case RMAP_LEFT_FILLING:
		/*
		 * Setting the first part of a previous oldext extent to newext.
		 * The left neighbor is not contiguous.
		 */
		NEW = PREV;
		NEW.rm_startblock += len;
		NEW.rm_offset += len;
		NEW.rm_blockcount -= len;
		error = scxfs_rmap_update(cur, &NEW);
		if (error)
			goto done;
		NEW.rm_startblock = bno;
		NEW.rm_owner = owner;
		NEW.rm_offset = offset;
		NEW.rm_blockcount = len;
		NEW.rm_flags = newext;
		cur->bc_rec.r = NEW;
		trace_scxfs_rmap_insert(mp, cur->bc_private.a.agno, bno,
				len, owner, offset, newext);
		error = scxfs_btree_insert(cur, &i);
		if (error)
			goto done;
		SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
		break;

	case RMAP_RIGHT_FILLING | RMAP_RIGHT_CONTIG:
		/*
		 * Setting the last part of a previous oldext extent to newext.
		 * The right neighbor is contiguous with the new allocation.
		 */
		NEW = PREV;
		NEW.rm_blockcount -= len;
		error = scxfs_rmap_update(cur, &NEW);
		if (error)
			goto done;
		error = scxfs_btree_increment(cur, 0, &i);
		if (error)
			goto done;
		NEW = RIGHT;
		NEW.rm_offset = offset;
		NEW.rm_startblock = bno;
		NEW.rm_blockcount += len;
		error = scxfs_rmap_update(cur, &NEW);
		if (error)
			goto done;
		break;

	case RMAP_RIGHT_FILLING:
		/*
		 * Setting the last part of a previous oldext extent to newext.
		 * The right neighbor is not contiguous.
		 */
		NEW = PREV;
		NEW.rm_blockcount -= len;
		error = scxfs_rmap_update(cur, &NEW);
		if (error)
			goto done;
		error = scxfs_rmap_lookup_eq(cur, bno, len, owner, offset,
				oldext, &i);
		if (error)
			goto done;
		SCXFS_WANT_CORRUPTED_GOTO(mp, i == 0, done);
		NEW.rm_startblock = bno;
		NEW.rm_owner = owner;
		NEW.rm_offset = offset;
		NEW.rm_blockcount = len;
		NEW.rm_flags = newext;
		cur->bc_rec.r = NEW;
		trace_scxfs_rmap_insert(mp, cur->bc_private.a.agno, bno,
				len, owner, offset, newext);
		error = scxfs_btree_insert(cur, &i);
		if (error)
			goto done;
		SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
		break;

	case 0:
		/*
		 * Setting the middle part of a previous oldext extent to
		 * newext.  Contiguity is impossible here.
		 * One extent becomes three extents.
		 */
		/* new right extent - oldext */
		NEW.rm_startblock = bno + len;
		NEW.rm_owner = owner;
		NEW.rm_offset = new_endoff;
		NEW.rm_blockcount = PREV.rm_offset + PREV.rm_blockcount -
				new_endoff;
		NEW.rm_flags = PREV.rm_flags;
		error = scxfs_rmap_update(cur, &NEW);
		if (error)
			goto done;
		/* new left extent - oldext */
		NEW = PREV;
		NEW.rm_blockcount = offset - PREV.rm_offset;
		cur->bc_rec.r = NEW;
		trace_scxfs_rmap_insert(mp, cur->bc_private.a.agno,
				NEW.rm_startblock, NEW.rm_blockcount,
				NEW.rm_owner, NEW.rm_offset,
				NEW.rm_flags);
		error = scxfs_btree_insert(cur, &i);
		if (error)
			goto done;
		SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
		/*
		 * Reset the cursor to the position of the new extent
		 * we are about to insert as we can't trust it after
		 * the previous insert.
		 */
		error = scxfs_rmap_lookup_eq(cur, bno, len, owner, offset,
				oldext, &i);
		if (error)
			goto done;
		SCXFS_WANT_CORRUPTED_GOTO(mp, i == 0, done);
		/* new middle extent - newext */
		cur->bc_rec.r.rm_flags &= ~SCXFS_RMAP_UNWRITTEN;
		cur->bc_rec.r.rm_flags |= newext;
		trace_scxfs_rmap_insert(mp, cur->bc_private.a.agno, bno, len,
				owner, offset, newext);
		error = scxfs_btree_insert(cur, &i);
		if (error)
			goto done;
		SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
		break;

	case RMAP_LEFT_FILLING | RMAP_LEFT_CONTIG | RMAP_RIGHT_CONTIG:
	case RMAP_RIGHT_FILLING | RMAP_LEFT_CONTIG | RMAP_RIGHT_CONTIG:
	case RMAP_LEFT_FILLING | RMAP_RIGHT_CONTIG:
	case RMAP_RIGHT_FILLING | RMAP_LEFT_CONTIG:
	case RMAP_LEFT_CONTIG | RMAP_RIGHT_CONTIG:
	case RMAP_LEFT_CONTIG:
	case RMAP_RIGHT_CONTIG:
		/*
		 * These cases are all impossible.
		 */
		ASSERT(0);
	}

	trace_scxfs_rmap_convert_done(mp, cur->bc_private.a.agno, bno, len,
			unwritten, oinfo);
done:
	if (error)
		trace_scxfs_rmap_convert_error(cur->bc_mp,
				cur->bc_private.a.agno, error, _RET_IP_);
	return error;
}

/*
 * Convert an unwritten extent to a real extent or vice versa.  If there is no
 * possibility of overlapping extents, delegate to the simpler convert
 * function.
 */
STATIC int
scxfs_rmap_convert_shared(
	struct scxfs_btree_cur		*cur,
	scxfs_agblock_t			bno,
	scxfs_extlen_t			len,
	bool				unwritten,
	const struct scxfs_owner_info	*oinfo)
{
	struct scxfs_mount		*mp = cur->bc_mp;
	struct scxfs_rmap_irec		r[4];	/* neighbor extent entries */
						/* left is 0, right is 1, */
						/* prev is 2, new is 3 */
	uint64_t		owner;
	uint64_t		offset;
	uint64_t		new_endoff;
	unsigned int		oldext;
	unsigned int		newext;
	unsigned int		flags = 0;
	int			i;
	int			state = 0;
	int			error;

	scxfs_owner_info_unpack(oinfo, &owner, &offset, &flags);
	ASSERT(!(SCXFS_RMAP_NON_INODE_OWNER(owner) ||
			(flags & (SCXFS_RMAP_ATTR_FORK | SCXFS_RMAP_BMBT_BLOCK))));
	oldext = unwritten ? SCXFS_RMAP_UNWRITTEN : 0;
	new_endoff = offset + len;
	trace_scxfs_rmap_convert(mp, cur->bc_private.a.agno, bno, len,
			unwritten, oinfo);

	/*
	 * For the initial lookup, look for and exact match or the left-adjacent
	 * record for our insertion point. This will also give us the record for
	 * start block contiguity tests.
	 */
	error = scxfs_rmap_lookup_le_range(cur, bno, owner, offset, oldext,
			&PREV, &i);
	if (error)
		goto done;
	SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);

	ASSERT(PREV.rm_offset <= offset);
	ASSERT(PREV.rm_offset + PREV.rm_blockcount >= new_endoff);
	ASSERT((PREV.rm_flags & SCXFS_RMAP_UNWRITTEN) == oldext);
	newext = ~oldext & SCXFS_RMAP_UNWRITTEN;

	/*
	 * Set flags determining what part of the previous oldext allocation
	 * extent is being replaced by a newext allocation.
	 */
	if (PREV.rm_offset == offset)
		state |= RMAP_LEFT_FILLING;
	if (PREV.rm_offset + PREV.rm_blockcount == new_endoff)
		state |= RMAP_RIGHT_FILLING;

	/* Is there a left record that abuts our range? */
	error = scxfs_rmap_find_left_neighbor(cur, bno, owner, offset, newext,
			&LEFT, &i);
	if (error)
		goto done;
	if (i) {
		state |= RMAP_LEFT_VALID;
		SCXFS_WANT_CORRUPTED_GOTO(mp,
				LEFT.rm_startblock + LEFT.rm_blockcount <= bno,
				done);
		if (scxfs_rmap_is_mergeable(&LEFT, owner, newext))
			state |= RMAP_LEFT_CONTIG;
	}

	/* Is there a right record that abuts our range? */
	error = scxfs_rmap_lookup_eq(cur, bno + len, len, owner, offset + len,
			newext, &i);
	if (error)
		goto done;
	if (i) {
		state |= RMAP_RIGHT_VALID;
		error = scxfs_rmap_get_rec(cur, &RIGHT, &i);
		if (error)
			goto done;
		SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
		SCXFS_WANT_CORRUPTED_GOTO(mp, bno + len <= RIGHT.rm_startblock,
				done);
		trace_scxfs_rmap_find_right_neighbor_result(cur->bc_mp,
				cur->bc_private.a.agno, RIGHT.rm_startblock,
				RIGHT.rm_blockcount, RIGHT.rm_owner,
				RIGHT.rm_offset, RIGHT.rm_flags);
		if (scxfs_rmap_is_mergeable(&RIGHT, owner, newext))
			state |= RMAP_RIGHT_CONTIG;
	}

	/* check that left + prev + right is not too long */
	if ((state & (RMAP_LEFT_FILLING | RMAP_LEFT_CONTIG |
			 RMAP_RIGHT_FILLING | RMAP_RIGHT_CONTIG)) ==
	    (RMAP_LEFT_FILLING | RMAP_LEFT_CONTIG |
	     RMAP_RIGHT_FILLING | RMAP_RIGHT_CONTIG) &&
	    (unsigned long)LEFT.rm_blockcount + len +
	     RIGHT.rm_blockcount > SCXFS_RMAP_LEN_MAX)
		state &= ~RMAP_RIGHT_CONTIG;

	trace_scxfs_rmap_convert_state(mp, cur->bc_private.a.agno, state,
			_RET_IP_);
	/*
	 * Switch out based on the FILLING and CONTIG state bits.
	 */
	switch (state & (RMAP_LEFT_FILLING | RMAP_LEFT_CONTIG |
			 RMAP_RIGHT_FILLING | RMAP_RIGHT_CONTIG)) {
	case RMAP_LEFT_FILLING | RMAP_LEFT_CONTIG |
	     RMAP_RIGHT_FILLING | RMAP_RIGHT_CONTIG:
		/*
		 * Setting all of a previous oldext extent to newext.
		 * The left and right neighbors are both contiguous with new.
		 */
		error = scxfs_rmap_delete(cur, RIGHT.rm_startblock,
				RIGHT.rm_blockcount, RIGHT.rm_owner,
				RIGHT.rm_offset, RIGHT.rm_flags);
		if (error)
			goto done;
		error = scxfs_rmap_delete(cur, PREV.rm_startblock,
				PREV.rm_blockcount, PREV.rm_owner,
				PREV.rm_offset, PREV.rm_flags);
		if (error)
			goto done;
		NEW = LEFT;
		error = scxfs_rmap_lookup_eq(cur, NEW.rm_startblock,
				NEW.rm_blockcount, NEW.rm_owner,
				NEW.rm_offset, NEW.rm_flags, &i);
		if (error)
			goto done;
		SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
		NEW.rm_blockcount += PREV.rm_blockcount + RIGHT.rm_blockcount;
		error = scxfs_rmap_update(cur, &NEW);
		if (error)
			goto done;
		break;

	case RMAP_LEFT_FILLING | RMAP_RIGHT_FILLING | RMAP_LEFT_CONTIG:
		/*
		 * Setting all of a previous oldext extent to newext.
		 * The left neighbor is contiguous, the right is not.
		 */
		error = scxfs_rmap_delete(cur, PREV.rm_startblock,
				PREV.rm_blockcount, PREV.rm_owner,
				PREV.rm_offset, PREV.rm_flags);
		if (error)
			goto done;
		NEW = LEFT;
		error = scxfs_rmap_lookup_eq(cur, NEW.rm_startblock,
				NEW.rm_blockcount, NEW.rm_owner,
				NEW.rm_offset, NEW.rm_flags, &i);
		if (error)
			goto done;
		SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
		NEW.rm_blockcount += PREV.rm_blockcount;
		error = scxfs_rmap_update(cur, &NEW);
		if (error)
			goto done;
		break;

	case RMAP_LEFT_FILLING | RMAP_RIGHT_FILLING | RMAP_RIGHT_CONTIG:
		/*
		 * Setting all of a previous oldext extent to newext.
		 * The right neighbor is contiguous, the left is not.
		 */
		error = scxfs_rmap_delete(cur, RIGHT.rm_startblock,
				RIGHT.rm_blockcount, RIGHT.rm_owner,
				RIGHT.rm_offset, RIGHT.rm_flags);
		if (error)
			goto done;
		NEW = PREV;
		error = scxfs_rmap_lookup_eq(cur, NEW.rm_startblock,
				NEW.rm_blockcount, NEW.rm_owner,
				NEW.rm_offset, NEW.rm_flags, &i);
		if (error)
			goto done;
		SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
		NEW.rm_blockcount += RIGHT.rm_blockcount;
		NEW.rm_flags = RIGHT.rm_flags;
		error = scxfs_rmap_update(cur, &NEW);
		if (error)
			goto done;
		break;

	case RMAP_LEFT_FILLING | RMAP_RIGHT_FILLING:
		/*
		 * Setting all of a previous oldext extent to newext.
		 * Neither the left nor right neighbors are contiguous with
		 * the new one.
		 */
		NEW = PREV;
		error = scxfs_rmap_lookup_eq(cur, NEW.rm_startblock,
				NEW.rm_blockcount, NEW.rm_owner,
				NEW.rm_offset, NEW.rm_flags, &i);
		if (error)
			goto done;
		SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
		NEW.rm_flags = newext;
		error = scxfs_rmap_update(cur, &NEW);
		if (error)
			goto done;
		break;

	case RMAP_LEFT_FILLING | RMAP_LEFT_CONTIG:
		/*
		 * Setting the first part of a previous oldext extent to newext.
		 * The left neighbor is contiguous.
		 */
		NEW = PREV;
		error = scxfs_rmap_delete(cur, NEW.rm_startblock,
				NEW.rm_blockcount, NEW.rm_owner,
				NEW.rm_offset, NEW.rm_flags);
		if (error)
			goto done;
		NEW.rm_offset += len;
		NEW.rm_startblock += len;
		NEW.rm_blockcount -= len;
		error = scxfs_rmap_insert(cur, NEW.rm_startblock,
				NEW.rm_blockcount, NEW.rm_owner,
				NEW.rm_offset, NEW.rm_flags);
		if (error)
			goto done;
		NEW = LEFT;
		error = scxfs_rmap_lookup_eq(cur, NEW.rm_startblock,
				NEW.rm_blockcount, NEW.rm_owner,
				NEW.rm_offset, NEW.rm_flags, &i);
		if (error)
			goto done;
		SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
		NEW.rm_blockcount += len;
		error = scxfs_rmap_update(cur, &NEW);
		if (error)
			goto done;
		break;

	case RMAP_LEFT_FILLING:
		/*
		 * Setting the first part of a previous oldext extent to newext.
		 * The left neighbor is not contiguous.
		 */
		NEW = PREV;
		error = scxfs_rmap_delete(cur, NEW.rm_startblock,
				NEW.rm_blockcount, NEW.rm_owner,
				NEW.rm_offset, NEW.rm_flags);
		if (error)
			goto done;
		NEW.rm_offset += len;
		NEW.rm_startblock += len;
		NEW.rm_blockcount -= len;
		error = scxfs_rmap_insert(cur, NEW.rm_startblock,
				NEW.rm_blockcount, NEW.rm_owner,
				NEW.rm_offset, NEW.rm_flags);
		if (error)
			goto done;
		error = scxfs_rmap_insert(cur, bno, len, owner, offset, newext);
		if (error)
			goto done;
		break;

	case RMAP_RIGHT_FILLING | RMAP_RIGHT_CONTIG:
		/*
		 * Setting the last part of a previous oldext extent to newext.
		 * The right neighbor is contiguous with the new allocation.
		 */
		NEW = PREV;
		error = scxfs_rmap_lookup_eq(cur, NEW.rm_startblock,
				NEW.rm_blockcount, NEW.rm_owner,
				NEW.rm_offset, NEW.rm_flags, &i);
		if (error)
			goto done;
		SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
		NEW.rm_blockcount = offset - NEW.rm_offset;
		error = scxfs_rmap_update(cur, &NEW);
		if (error)
			goto done;
		NEW = RIGHT;
		error = scxfs_rmap_delete(cur, NEW.rm_startblock,
				NEW.rm_blockcount, NEW.rm_owner,
				NEW.rm_offset, NEW.rm_flags);
		if (error)
			goto done;
		NEW.rm_offset = offset;
		NEW.rm_startblock = bno;
		NEW.rm_blockcount += len;
		error = scxfs_rmap_insert(cur, NEW.rm_startblock,
				NEW.rm_blockcount, NEW.rm_owner,
				NEW.rm_offset, NEW.rm_flags);
		if (error)
			goto done;
		break;

	case RMAP_RIGHT_FILLING:
		/*
		 * Setting the last part of a previous oldext extent to newext.
		 * The right neighbor is not contiguous.
		 */
		NEW = PREV;
		error = scxfs_rmap_lookup_eq(cur, NEW.rm_startblock,
				NEW.rm_blockcount, NEW.rm_owner,
				NEW.rm_offset, NEW.rm_flags, &i);
		if (error)
			goto done;
		SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
		NEW.rm_blockcount -= len;
		error = scxfs_rmap_update(cur, &NEW);
		if (error)
			goto done;
		error = scxfs_rmap_insert(cur, bno, len, owner, offset, newext);
		if (error)
			goto done;
		break;

	case 0:
		/*
		 * Setting the middle part of a previous oldext extent to
		 * newext.  Contiguity is impossible here.
		 * One extent becomes three extents.
		 */
		/* new right extent - oldext */
		NEW.rm_startblock = bno + len;
		NEW.rm_owner = owner;
		NEW.rm_offset = new_endoff;
		NEW.rm_blockcount = PREV.rm_offset + PREV.rm_blockcount -
				new_endoff;
		NEW.rm_flags = PREV.rm_flags;
		error = scxfs_rmap_insert(cur, NEW.rm_startblock,
				NEW.rm_blockcount, NEW.rm_owner, NEW.rm_offset,
				NEW.rm_flags);
		if (error)
			goto done;
		/* new left extent - oldext */
		NEW = PREV;
		error = scxfs_rmap_lookup_eq(cur, NEW.rm_startblock,
				NEW.rm_blockcount, NEW.rm_owner,
				NEW.rm_offset, NEW.rm_flags, &i);
		if (error)
			goto done;
		SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, done);
		NEW.rm_blockcount = offset - NEW.rm_offset;
		error = scxfs_rmap_update(cur, &NEW);
		if (error)
			goto done;
		/* new middle extent - newext */
		NEW.rm_startblock = bno;
		NEW.rm_blockcount = len;
		NEW.rm_owner = owner;
		NEW.rm_offset = offset;
		NEW.rm_flags = newext;
		error = scxfs_rmap_insert(cur, NEW.rm_startblock,
				NEW.rm_blockcount, NEW.rm_owner, NEW.rm_offset,
				NEW.rm_flags);
		if (error)
			goto done;
		break;

	case RMAP_LEFT_FILLING | RMAP_LEFT_CONTIG | RMAP_RIGHT_CONTIG:
	case RMAP_RIGHT_FILLING | RMAP_LEFT_CONTIG | RMAP_RIGHT_CONTIG:
	case RMAP_LEFT_FILLING | RMAP_RIGHT_CONTIG:
	case RMAP_RIGHT_FILLING | RMAP_LEFT_CONTIG:
	case RMAP_LEFT_CONTIG | RMAP_RIGHT_CONTIG:
	case RMAP_LEFT_CONTIG:
	case RMAP_RIGHT_CONTIG:
		/*
		 * These cases are all impossible.
		 */
		ASSERT(0);
	}

	trace_scxfs_rmap_convert_done(mp, cur->bc_private.a.agno, bno, len,
			unwritten, oinfo);
done:
	if (error)
		trace_scxfs_rmap_convert_error(cur->bc_mp,
				cur->bc_private.a.agno, error, _RET_IP_);
	return error;
}

#undef	NEW
#undef	LEFT
#undef	RIGHT
#undef	PREV

/*
 * Find an extent in the rmap btree and unmap it.  For rmap extent types that
 * can overlap (data fork rmaps on reflink filesystems) we must be careful
 * that the prev/next records in the btree might belong to another owner.
 * Therefore we must use delete+insert to alter any of the key fields.
 *
 * For every other situation there can only be one owner for a given extent,
 * so we can call the regular _free function.
 */
STATIC int
scxfs_rmap_unmap_shared(
	struct scxfs_btree_cur		*cur,
	scxfs_agblock_t			bno,
	scxfs_extlen_t			len,
	bool				unwritten,
	const struct scxfs_owner_info	*oinfo)
{
	struct scxfs_mount		*mp = cur->bc_mp;
	struct scxfs_rmap_irec		ltrec;
	uint64_t			ltoff;
	int				error = 0;
	int				i;
	uint64_t			owner;
	uint64_t			offset;
	unsigned int			flags;

	scxfs_owner_info_unpack(oinfo, &owner, &offset, &flags);
	if (unwritten)
		flags |= SCXFS_RMAP_UNWRITTEN;
	trace_scxfs_rmap_unmap(mp, cur->bc_private.a.agno, bno, len,
			unwritten, oinfo);

	/*
	 * We should always have a left record because there's a static record
	 * for the AG headers at rm_startblock == 0 created by mkfs/growfs that
	 * will not ever be removed from the tree.
	 */
	error = scxfs_rmap_lookup_le_range(cur, bno, owner, offset, flags,
			&ltrec, &i);
	if (error)
		goto out_error;
	SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, out_error);
	ltoff = ltrec.rm_offset;

	/* Make sure the extent we found covers the entire freeing range. */
	SCXFS_WANT_CORRUPTED_GOTO(mp, ltrec.rm_startblock <= bno &&
		ltrec.rm_startblock + ltrec.rm_blockcount >=
		bno + len, out_error);

	/* Make sure the owner matches what we expect to find in the tree. */
	SCXFS_WANT_CORRUPTED_GOTO(mp, owner == ltrec.rm_owner, out_error);

	/* Make sure the unwritten flag matches. */
	SCXFS_WANT_CORRUPTED_GOTO(mp, (flags & SCXFS_RMAP_UNWRITTEN) ==
			(ltrec.rm_flags & SCXFS_RMAP_UNWRITTEN), out_error);

	/* Check the offset. */
	SCXFS_WANT_CORRUPTED_GOTO(mp, ltrec.rm_offset <= offset, out_error);
	SCXFS_WANT_CORRUPTED_GOTO(mp, offset <= ltoff + ltrec.rm_blockcount,
			out_error);

	if (ltrec.rm_startblock == bno && ltrec.rm_blockcount == len) {
		/* Exact match, simply remove the record from rmap tree. */
		error = scxfs_rmap_delete(cur, ltrec.rm_startblock,
				ltrec.rm_blockcount, ltrec.rm_owner,
				ltrec.rm_offset, ltrec.rm_flags);
		if (error)
			goto out_error;
	} else if (ltrec.rm_startblock == bno) {
		/*
		 * Overlap left hand side of extent: move the start, trim the
		 * length and update the current record.
		 *
		 *       ltbno                ltlen
		 * Orig:    |oooooooooooooooooooo|
		 * Freeing: |fffffffff|
		 * Result:            |rrrrrrrrrr|
		 *         bno       len
		 */

		/* Delete prev rmap. */
		error = scxfs_rmap_delete(cur, ltrec.rm_startblock,
				ltrec.rm_blockcount, ltrec.rm_owner,
				ltrec.rm_offset, ltrec.rm_flags);
		if (error)
			goto out_error;

		/* Add an rmap at the new offset. */
		ltrec.rm_startblock += len;
		ltrec.rm_blockcount -= len;
		ltrec.rm_offset += len;
		error = scxfs_rmap_insert(cur, ltrec.rm_startblock,
				ltrec.rm_blockcount, ltrec.rm_owner,
				ltrec.rm_offset, ltrec.rm_flags);
		if (error)
			goto out_error;
	} else if (ltrec.rm_startblock + ltrec.rm_blockcount == bno + len) {
		/*
		 * Overlap right hand side of extent: trim the length and
		 * update the current record.
		 *
		 *       ltbno                ltlen
		 * Orig:    |oooooooooooooooooooo|
		 * Freeing:            |fffffffff|
		 * Result:  |rrrrrrrrrr|
		 *                    bno       len
		 */
		error = scxfs_rmap_lookup_eq(cur, ltrec.rm_startblock,
				ltrec.rm_blockcount, ltrec.rm_owner,
				ltrec.rm_offset, ltrec.rm_flags, &i);
		if (error)
			goto out_error;
		SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, out_error);
		ltrec.rm_blockcount -= len;
		error = scxfs_rmap_update(cur, &ltrec);
		if (error)
			goto out_error;
	} else {
		/*
		 * Overlap middle of extent: trim the length of the existing
		 * record to the length of the new left-extent size, increment
		 * the insertion position so we can insert a new record
		 * containing the remaining right-extent space.
		 *
		 *       ltbno                ltlen
		 * Orig:    |oooooooooooooooooooo|
		 * Freeing:       |fffffffff|
		 * Result:  |rrrrr|         |rrrr|
		 *               bno       len
		 */
		scxfs_extlen_t	orig_len = ltrec.rm_blockcount;

		/* Shrink the left side of the rmap */
		error = scxfs_rmap_lookup_eq(cur, ltrec.rm_startblock,
				ltrec.rm_blockcount, ltrec.rm_owner,
				ltrec.rm_offset, ltrec.rm_flags, &i);
		if (error)
			goto out_error;
		SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, out_error);
		ltrec.rm_blockcount = bno - ltrec.rm_startblock;
		error = scxfs_rmap_update(cur, &ltrec);
		if (error)
			goto out_error;

		/* Add an rmap at the new offset */
		error = scxfs_rmap_insert(cur, bno + len,
				orig_len - len - ltrec.rm_blockcount,
				ltrec.rm_owner, offset + len,
				ltrec.rm_flags);
		if (error)
			goto out_error;
	}

	trace_scxfs_rmap_unmap_done(mp, cur->bc_private.a.agno, bno, len,
			unwritten, oinfo);
out_error:
	if (error)
		trace_scxfs_rmap_unmap_error(cur->bc_mp,
				cur->bc_private.a.agno, error, _RET_IP_);
	return error;
}

/*
 * Find an extent in the rmap btree and map it.  For rmap extent types that
 * can overlap (data fork rmaps on reflink filesystems) we must be careful
 * that the prev/next records in the btree might belong to another owner.
 * Therefore we must use delete+insert to alter any of the key fields.
 *
 * For every other situation there can only be one owner for a given extent,
 * so we can call the regular _alloc function.
 */
STATIC int
scxfs_rmap_map_shared(
	struct scxfs_btree_cur		*cur,
	scxfs_agblock_t			bno,
	scxfs_extlen_t			len,
	bool				unwritten,
	const struct scxfs_owner_info	*oinfo)
{
	struct scxfs_mount		*mp = cur->bc_mp;
	struct scxfs_rmap_irec		ltrec;
	struct scxfs_rmap_irec		gtrec;
	int				have_gt;
	int				have_lt;
	int				error = 0;
	int				i;
	uint64_t			owner;
	uint64_t			offset;
	unsigned int			flags = 0;

	scxfs_owner_info_unpack(oinfo, &owner, &offset, &flags);
	if (unwritten)
		flags |= SCXFS_RMAP_UNWRITTEN;
	trace_scxfs_rmap_map(mp, cur->bc_private.a.agno, bno, len,
			unwritten, oinfo);

	/* Is there a left record that abuts our range? */
	error = scxfs_rmap_find_left_neighbor(cur, bno, owner, offset, flags,
			&ltrec, &have_lt);
	if (error)
		goto out_error;
	if (have_lt &&
	    !scxfs_rmap_is_mergeable(&ltrec, owner, flags))
		have_lt = 0;

	/* Is there a right record that abuts our range? */
	error = scxfs_rmap_lookup_eq(cur, bno + len, len, owner, offset + len,
			flags, &have_gt);
	if (error)
		goto out_error;
	if (have_gt) {
		error = scxfs_rmap_get_rec(cur, &gtrec, &have_gt);
		if (error)
			goto out_error;
		SCXFS_WANT_CORRUPTED_GOTO(mp, have_gt == 1, out_error);
		trace_scxfs_rmap_find_right_neighbor_result(cur->bc_mp,
			cur->bc_private.a.agno, gtrec.rm_startblock,
			gtrec.rm_blockcount, gtrec.rm_owner,
			gtrec.rm_offset, gtrec.rm_flags);

		if (!scxfs_rmap_is_mergeable(&gtrec, owner, flags))
			have_gt = 0;
	}

	if (have_lt &&
	    ltrec.rm_startblock + ltrec.rm_blockcount == bno &&
	    ltrec.rm_offset + ltrec.rm_blockcount == offset) {
		/*
		 * Left edge contiguous, merge into left record.
		 *
		 *       ltbno     ltlen
		 * orig:   |ooooooooo|
		 * adding:           |aaaaaaaaa|
		 * result: |rrrrrrrrrrrrrrrrrrr|
		 *                  bno       len
		 */
		ltrec.rm_blockcount += len;
		if (have_gt &&
		    bno + len == gtrec.rm_startblock &&
		    offset + len == gtrec.rm_offset) {
			/*
			 * Right edge also contiguous, delete right record
			 * and merge into left record.
			 *
			 *       ltbno     ltlen    gtbno     gtlen
			 * orig:   |ooooooooo|         |ooooooooo|
			 * adding:           |aaaaaaaaa|
			 * result: |rrrrrrrrrrrrrrrrrrrrrrrrrrrrr|
			 */
			ltrec.rm_blockcount += gtrec.rm_blockcount;
			error = scxfs_rmap_delete(cur, gtrec.rm_startblock,
					gtrec.rm_blockcount, gtrec.rm_owner,
					gtrec.rm_offset, gtrec.rm_flags);
			if (error)
				goto out_error;
		}

		/* Point the cursor back to the left record and update. */
		error = scxfs_rmap_lookup_eq(cur, ltrec.rm_startblock,
				ltrec.rm_blockcount, ltrec.rm_owner,
				ltrec.rm_offset, ltrec.rm_flags, &i);
		if (error)
			goto out_error;
		SCXFS_WANT_CORRUPTED_GOTO(mp, i == 1, out_error);

		error = scxfs_rmap_update(cur, &ltrec);
		if (error)
			goto out_error;
	} else if (have_gt &&
		   bno + len == gtrec.rm_startblock &&
		   offset + len == gtrec.rm_offset) {
		/*
		 * Right edge contiguous, merge into right record.
		 *
		 *                 gtbno     gtlen
		 * Orig:             |ooooooooo|
		 * adding: |aaaaaaaaa|
		 * Result: |rrrrrrrrrrrrrrrrrrr|
		 *        bno       len
		 */
		/* Delete the old record. */
		error = scxfs_rmap_delete(cur, gtrec.rm_startblock,
				gtrec.rm_blockcount, gtrec.rm_owner,
				gtrec.rm_offset, gtrec.rm_flags);
		if (error)
			goto out_error;

		/* Move the start and re-add it. */
		gtrec.rm_startblock = bno;
		gtrec.rm_blockcount += len;
		gtrec.rm_offset = offset;
		error = scxfs_rmap_insert(cur, gtrec.rm_startblock,
				gtrec.rm_blockcount, gtrec.rm_owner,
				gtrec.rm_offset, gtrec.rm_flags);
		if (error)
			goto out_error;
	} else {
		/*
		 * No contiguous edge with identical owner, insert
		 * new record at current cursor position.
		 */
		error = scxfs_rmap_insert(cur, bno, len, owner, offset, flags);
		if (error)
			goto out_error;
	}

	trace_scxfs_rmap_map_done(mp, cur->bc_private.a.agno, bno, len,
			unwritten, oinfo);
out_error:
	if (error)
		trace_scxfs_rmap_map_error(cur->bc_mp,
				cur->bc_private.a.agno, error, _RET_IP_);
	return error;
}

/* Insert a raw rmap into the rmapbt. */
int
scxfs_rmap_map_raw(
	struct scxfs_btree_cur	*cur,
	struct scxfs_rmap_irec	*rmap)
{
	struct scxfs_owner_info	oinfo;

	oinfo.oi_owner = rmap->rm_owner;
	oinfo.oi_offset = rmap->rm_offset;
	oinfo.oi_flags = 0;
	if (rmap->rm_flags & SCXFS_RMAP_ATTR_FORK)
		oinfo.oi_flags |= SCXFS_OWNER_INFO_ATTR_FORK;
	if (rmap->rm_flags & SCXFS_RMAP_BMBT_BLOCK)
		oinfo.oi_flags |= SCXFS_OWNER_INFO_BMBT_BLOCK;

	if (rmap->rm_flags || SCXFS_RMAP_NON_INODE_OWNER(rmap->rm_owner))
		return scxfs_rmap_map(cur, rmap->rm_startblock,
				rmap->rm_blockcount,
				rmap->rm_flags & SCXFS_RMAP_UNWRITTEN,
				&oinfo);

	return scxfs_rmap_map_shared(cur, rmap->rm_startblock,
			rmap->rm_blockcount,
			rmap->rm_flags & SCXFS_RMAP_UNWRITTEN,
			&oinfo);
}

struct scxfs_rmap_query_range_info {
	scxfs_rmap_query_range_fn	fn;
	void				*priv;
};

/* Format btree record and pass to our callback. */
STATIC int
scxfs_rmap_query_range_helper(
	struct scxfs_btree_cur	*cur,
	union scxfs_btree_rec	*rec,
	void			*priv)
{
	struct scxfs_rmap_query_range_info	*query = priv;
	struct scxfs_rmap_irec			irec;
	int					error;

	error = scxfs_rmap_btrec_to_irec(rec, &irec);
	if (error)
		return error;
	return query->fn(cur, &irec, query->priv);
}

/* Find all rmaps between two keys. */
int
scxfs_rmap_query_range(
	struct scxfs_btree_cur			*cur,
	struct scxfs_rmap_irec			*low_rec,
	struct scxfs_rmap_irec			*high_rec,
	scxfs_rmap_query_range_fn			fn,
	void					*priv)
{
	union scxfs_btree_irec			low_brec;
	union scxfs_btree_irec			high_brec;
	struct scxfs_rmap_query_range_info	query;

	low_brec.r = *low_rec;
	high_brec.r = *high_rec;
	query.priv = priv;
	query.fn = fn;
	return scxfs_btree_query_range(cur, &low_brec, &high_brec,
			scxfs_rmap_query_range_helper, &query);
}

/* Find all rmaps. */
int
scxfs_rmap_query_all(
	struct scxfs_btree_cur			*cur,
	scxfs_rmap_query_range_fn			fn,
	void					*priv)
{
	struct scxfs_rmap_query_range_info	query;

	query.priv = priv;
	query.fn = fn;
	return scxfs_btree_query_all(cur, scxfs_rmap_query_range_helper, &query);
}

/* Clean up after calling scxfs_rmap_finish_one. */
void
scxfs_rmap_finish_one_cleanup(
	struct scxfs_trans	*tp,
	struct scxfs_btree_cur	*rcur,
	int			error)
{
	struct scxfs_buf		*agbp;

	if (rcur == NULL)
		return;
	agbp = rcur->bc_private.a.agbp;
	scxfs_btree_del_cursor(rcur, error);
	if (error)
		scxfs_trans_brelse(tp, agbp);
}

/*
 * Process one of the deferred rmap operations.  We pass back the
 * btree cursor to maintain our lock on the rmapbt between calls.
 * This saves time and eliminates a buffer deadlock between the
 * superblock and the AGF because we'll always grab them in the same
 * order.
 */
int
scxfs_rmap_finish_one(
	struct scxfs_trans		*tp,
	enum scxfs_rmap_intent_type	type,
	uint64_t			owner,
	int				whichfork,
	scxfs_fileoff_t			startoff,
	scxfs_fsblock_t			startblock,
	scxfs_filblks_t			blockcount,
	scxfs_exntst_t			state,
	struct scxfs_btree_cur		**pcur)
{
	struct scxfs_mount		*mp = tp->t_mountp;
	struct scxfs_btree_cur		*rcur;
	struct scxfs_buf			*agbp = NULL;
	int				error = 0;
	scxfs_agnumber_t			agno;
	struct scxfs_owner_info		oinfo;
	scxfs_agblock_t			bno;
	bool				unwritten;

	agno = SCXFS_FSB_TO_AGNO(mp, startblock);
	ASSERT(agno != NULLAGNUMBER);
	bno = SCXFS_FSB_TO_AGBNO(mp, startblock);

	trace_scxfs_rmap_deferred(mp, agno, type, bno, owner, whichfork,
			startoff, blockcount, state);

	if (SCXFS_TEST_ERROR(false, mp,
			SCXFS_ERRTAG_RMAP_FINISH_ONE))
		return -EIO;

	/*
	 * If we haven't gotten a cursor or the cursor AG doesn't match
	 * the startblock, get one now.
	 */
	rcur = *pcur;
	if (rcur != NULL && rcur->bc_private.a.agno != agno) {
		scxfs_rmap_finish_one_cleanup(tp, rcur, 0);
		rcur = NULL;
		*pcur = NULL;
	}
	if (rcur == NULL) {
		/*
		 * Refresh the freelist before we start changing the
		 * rmapbt, because a shape change could cause us to
		 * allocate blocks.
		 */
		error = scxfs_free_extent_fix_freelist(tp, agno, &agbp);
		if (error)
			return error;
		if (!agbp)
			return -EFSCORRUPTED;

		rcur = scxfs_rmapbt_init_cursor(mp, tp, agbp, agno);
		if (!rcur) {
			error = -ENOMEM;
			goto out_cur;
		}
	}
	*pcur = rcur;

	scxfs_rmap_ino_owner(&oinfo, owner, whichfork, startoff);
	unwritten = state == SCXFS_EXT_UNWRITTEN;
	bno = SCXFS_FSB_TO_AGBNO(rcur->bc_mp, startblock);

	switch (type) {
	case SCXFS_RMAP_ALLOC:
	case SCXFS_RMAP_MAP:
		error = scxfs_rmap_map(rcur, bno, blockcount, unwritten, &oinfo);
		break;
	case SCXFS_RMAP_MAP_SHARED:
		error = scxfs_rmap_map_shared(rcur, bno, blockcount, unwritten,
				&oinfo);
		break;
	case SCXFS_RMAP_FREE:
	case SCXFS_RMAP_UNMAP:
		error = scxfs_rmap_unmap(rcur, bno, blockcount, unwritten,
				&oinfo);
		break;
	case SCXFS_RMAP_UNMAP_SHARED:
		error = scxfs_rmap_unmap_shared(rcur, bno, blockcount, unwritten,
				&oinfo);
		break;
	case SCXFS_RMAP_CONVERT:
		error = scxfs_rmap_convert(rcur, bno, blockcount, !unwritten,
				&oinfo);
		break;
	case SCXFS_RMAP_CONVERT_SHARED:
		error = scxfs_rmap_convert_shared(rcur, bno, blockcount,
				!unwritten, &oinfo);
		break;
	default:
		ASSERT(0);
		error = -EFSCORRUPTED;
	}
	return error;

out_cur:
	scxfs_trans_brelse(tp, agbp);

	return error;
}

/*
 * Don't defer an rmap if we aren't an rmap filesystem.
 */
static bool
scxfs_rmap_update_is_needed(
	struct scxfs_mount	*mp,
	int			whichfork)
{
	return scxfs_sb_version_hasrmapbt(&mp->m_sb) && whichfork != SCXFS_COW_FORK;
}

/*
 * Record a rmap intent; the list is kept sorted first by AG and then by
 * increasing age.
 */
static void
__scxfs_rmap_add(
	struct scxfs_trans		*tp,
	enum scxfs_rmap_intent_type	type,
	uint64_t			owner,
	int				whichfork,
	struct scxfs_bmbt_irec		*bmap)
{
	struct scxfs_rmap_intent		*ri;

	trace_scxfs_rmap_defer(tp->t_mountp,
			SCXFS_FSB_TO_AGNO(tp->t_mountp, bmap->br_startblock),
			type,
			SCXFS_FSB_TO_AGBNO(tp->t_mountp, bmap->br_startblock),
			owner, whichfork,
			bmap->br_startoff,
			bmap->br_blockcount,
			bmap->br_state);

	ri = kmem_alloc(sizeof(struct scxfs_rmap_intent), KM_NOFS);
	INIT_LIST_HEAD(&ri->ri_list);
	ri->ri_type = type;
	ri->ri_owner = owner;
	ri->ri_whichfork = whichfork;
	ri->ri_bmap = *bmap;

	scxfs_defer_add(tp, SCXFS_DEFER_OPS_TYPE_RMAP, &ri->ri_list);
}

/* Map an extent into a file. */
void
scxfs_rmap_map_extent(
	struct scxfs_trans	*tp,
	struct scxfs_inode	*ip,
	int			whichfork,
	struct scxfs_bmbt_irec	*PREV)
{
	if (!scxfs_rmap_update_is_needed(tp->t_mountp, whichfork))
		return;

	__scxfs_rmap_add(tp, scxfs_is_reflink_inode(ip) ?
			SCXFS_RMAP_MAP_SHARED : SCXFS_RMAP_MAP, ip->i_ino,
			whichfork, PREV);
}

/* Unmap an extent out of a file. */
void
scxfs_rmap_unmap_extent(
	struct scxfs_trans	*tp,
	struct scxfs_inode	*ip,
	int			whichfork,
	struct scxfs_bmbt_irec	*PREV)
{
	if (!scxfs_rmap_update_is_needed(tp->t_mountp, whichfork))
		return;

	__scxfs_rmap_add(tp, scxfs_is_reflink_inode(ip) ?
			SCXFS_RMAP_UNMAP_SHARED : SCXFS_RMAP_UNMAP, ip->i_ino,
			whichfork, PREV);
}

/*
 * Convert a data fork extent from unwritten to real or vice versa.
 *
 * Note that tp can be NULL here as no transaction is used for COW fork
 * unwritten conversion.
 */
void
scxfs_rmap_convert_extent(
	struct scxfs_mount	*mp,
	struct scxfs_trans	*tp,
	struct scxfs_inode	*ip,
	int			whichfork,
	struct scxfs_bmbt_irec	*PREV)
{
	if (!scxfs_rmap_update_is_needed(mp, whichfork))
		return;

	__scxfs_rmap_add(tp, scxfs_is_reflink_inode(ip) ?
			SCXFS_RMAP_CONVERT_SHARED : SCXFS_RMAP_CONVERT, ip->i_ino,
			whichfork, PREV);
}

/* Schedule the creation of an rmap for non-file data. */
void
scxfs_rmap_alloc_extent(
	struct scxfs_trans	*tp,
	scxfs_agnumber_t		agno,
	scxfs_agblock_t		bno,
	scxfs_extlen_t		len,
	uint64_t		owner)
{
	struct scxfs_bmbt_irec	bmap;

	if (!scxfs_rmap_update_is_needed(tp->t_mountp, SCXFS_DATA_FORK))
		return;

	bmap.br_startblock = SCXFS_AGB_TO_FSB(tp->t_mountp, agno, bno);
	bmap.br_blockcount = len;
	bmap.br_startoff = 0;
	bmap.br_state = SCXFS_EXT_NORM;

	__scxfs_rmap_add(tp, SCXFS_RMAP_ALLOC, owner, SCXFS_DATA_FORK, &bmap);
}

/* Schedule the deletion of an rmap for non-file data. */
void
scxfs_rmap_free_extent(
	struct scxfs_trans	*tp,
	scxfs_agnumber_t		agno,
	scxfs_agblock_t		bno,
	scxfs_extlen_t		len,
	uint64_t		owner)
{
	struct scxfs_bmbt_irec	bmap;

	if (!scxfs_rmap_update_is_needed(tp->t_mountp, SCXFS_DATA_FORK))
		return;

	bmap.br_startblock = SCXFS_AGB_TO_FSB(tp->t_mountp, agno, bno);
	bmap.br_blockcount = len;
	bmap.br_startoff = 0;
	bmap.br_state = SCXFS_EXT_NORM;

	__scxfs_rmap_add(tp, SCXFS_RMAP_FREE, owner, SCXFS_DATA_FORK, &bmap);
}

/* Compare rmap records.  Returns -1 if a < b, 1 if a > b, and 0 if equal. */
int
scxfs_rmap_compare(
	const struct scxfs_rmap_irec	*a,
	const struct scxfs_rmap_irec	*b)
{
	__u64				oa;
	__u64				ob;

	oa = scxfs_rmap_irec_offset_pack(a);
	ob = scxfs_rmap_irec_offset_pack(b);

	if (a->rm_startblock < b->rm_startblock)
		return -1;
	else if (a->rm_startblock > b->rm_startblock)
		return 1;
	else if (a->rm_owner < b->rm_owner)
		return -1;
	else if (a->rm_owner > b->rm_owner)
		return 1;
	else if (oa < ob)
		return -1;
	else if (oa > ob)
		return 1;
	else
		return 0;
}

/* Is there a record covering a given extent? */
int
scxfs_rmap_has_record(
	struct scxfs_btree_cur	*cur,
	scxfs_agblock_t		bno,
	scxfs_extlen_t		len,
	bool			*exists)
{
	union scxfs_btree_irec	low;
	union scxfs_btree_irec	high;

	memset(&low, 0, sizeof(low));
	low.r.rm_startblock = bno;
	memset(&high, 0xFF, sizeof(high));
	high.r.rm_startblock = bno + len - 1;

	return scxfs_btree_has_record(cur, &low, &high, exists);
}

/*
 * Is there a record for this owner completely covering a given physical
 * extent?  If so, *has_rmap will be set to true.  If there is no record
 * or the record only covers part of the range, we set *has_rmap to false.
 * This function doesn't perform range lookups or offset checks, so it is
 * not suitable for checking data fork blocks.
 */
int
scxfs_rmap_record_exists(
	struct scxfs_btree_cur		*cur,
	scxfs_agblock_t			bno,
	scxfs_extlen_t			len,
	const struct scxfs_owner_info	*oinfo,
	bool				*has_rmap)
{
	uint64_t			owner;
	uint64_t			offset;
	unsigned int			flags;
	int				has_record;
	struct scxfs_rmap_irec		irec;
	int				error;

	scxfs_owner_info_unpack(oinfo, &owner, &offset, &flags);
	ASSERT(SCXFS_RMAP_NON_INODE_OWNER(owner) ||
	       (flags & SCXFS_RMAP_BMBT_BLOCK));

	error = scxfs_rmap_lookup_le(cur, bno, len, owner, offset, flags,
			&has_record);
	if (error)
		return error;
	if (!has_record) {
		*has_rmap = false;
		return 0;
	}

	error = scxfs_rmap_get_rec(cur, &irec, &has_record);
	if (error)
		return error;
	if (!has_record) {
		*has_rmap = false;
		return 0;
	}

	*has_rmap = (irec.rm_owner == owner && irec.rm_startblock <= bno &&
		     irec.rm_startblock + irec.rm_blockcount >= bno + len);
	return 0;
}

struct scxfs_rmap_key_state {
	uint64_t			owner;
	uint64_t			offset;
	unsigned int			flags;
	bool				has_rmap;
};

/* For each rmap given, figure out if it doesn't match the key we want. */
STATIC int
scxfs_rmap_has_other_keys_helper(
	struct scxfs_btree_cur		*cur,
	struct scxfs_rmap_irec		*rec,
	void				*priv)
{
	struct scxfs_rmap_key_state	*rks = priv;

	if (rks->owner == rec->rm_owner && rks->offset == rec->rm_offset &&
	    ((rks->flags & rec->rm_flags) & SCXFS_RMAP_KEY_FLAGS) == rks->flags)
		return 0;
	rks->has_rmap = true;
	return -ECANCELED;
}

/*
 * Given an extent and some owner info, can we find records overlapping
 * the extent whose owner info does not match the given owner?
 */
int
scxfs_rmap_has_other_keys(
	struct scxfs_btree_cur		*cur,
	scxfs_agblock_t			bno,
	scxfs_extlen_t			len,
	const struct scxfs_owner_info	*oinfo,
	bool				*has_rmap)
{
	struct scxfs_rmap_irec		low = {0};
	struct scxfs_rmap_irec		high;
	struct scxfs_rmap_key_state	rks;
	int				error;

	scxfs_owner_info_unpack(oinfo, &rks.owner, &rks.offset, &rks.flags);
	rks.has_rmap = false;

	low.rm_startblock = bno;
	memset(&high, 0xFF, sizeof(high));
	high.rm_startblock = bno + len - 1;

	error = scxfs_rmap_query_range(cur, &low, &high,
			scxfs_rmap_has_other_keys_helper, &rks);
	if (error < 0)
		return error;

	*has_rmap = rks.has_rmap;
	return 0;
}

const struct scxfs_owner_info SCXFS_RMAP_OINFO_SKIP_UPDATE = {
	.oi_owner = SCXFS_RMAP_OWN_NULL,
};
const struct scxfs_owner_info SCXFS_RMAP_OINFO_ANY_OWNER = {
	.oi_owner = SCXFS_RMAP_OWN_UNKNOWN,
};
const struct scxfs_owner_info SCXFS_RMAP_OINFO_FS = {
	.oi_owner = SCXFS_RMAP_OWN_FS,
};
const struct scxfs_owner_info SCXFS_RMAP_OINFO_LOG = {
	.oi_owner = SCXFS_RMAP_OWN_LOG,
};
const struct scxfs_owner_info SCXFS_RMAP_OINFO_AG = {
	.oi_owner = SCXFS_RMAP_OWN_AG,
};
const struct scxfs_owner_info SCXFS_RMAP_OINFO_INOBT = {
	.oi_owner = SCXFS_RMAP_OWN_INOBT,
};
const struct scxfs_owner_info SCXFS_RMAP_OINFO_INODES = {
	.oi_owner = SCXFS_RMAP_OWN_INODES,
};
const struct scxfs_owner_info SCXFS_RMAP_OINFO_REFC = {
	.oi_owner = SCXFS_RMAP_OWN_REFC,
};
const struct scxfs_owner_info SCXFS_RMAP_OINFO_COW = {
	.oi_owner = SCXFS_RMAP_OWN_COW,
};
