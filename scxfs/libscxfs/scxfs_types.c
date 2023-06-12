// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2002,2005 Silicon Graphics, Inc.
 * Copyright (C) 2017 Oracle.
 * All Rights Reserved.
 */
#include "scxfs.h"
#include "scxfs_fs.h"
#include "scxfs_format.h"
#include "scxfs_shared.h"
#include "scxfs_trans_resv.h"
#include "scxfs_bit.h"
#include "scxfs_mount.h"

/* Find the size of the AG, in blocks. */
scxfs_agblock_t
scxfs_ag_block_count(
	struct scxfs_mount	*mp,
	scxfs_agnumber_t		agno)
{
	ASSERT(agno < mp->m_sb.sb_agcount);

	if (agno < mp->m_sb.sb_agcount - 1)
		return mp->m_sb.sb_agblocks;
	return mp->m_sb.sb_dblocks - (agno * mp->m_sb.sb_agblocks);
}

/*
 * Verify that an AG block number pointer neither points outside the AG
 * nor points at static metadata.
 */
bool
scxfs_verify_agbno(
	struct scxfs_mount	*mp,
	scxfs_agnumber_t		agno,
	scxfs_agblock_t		agbno)
{
	scxfs_agblock_t		eoag;

	eoag = scxfs_ag_block_count(mp, agno);
	if (agbno >= eoag)
		return false;
	if (agbno <= SCXFS_AGFL_BLOCK(mp))
		return false;
	return true;
}

/*
 * Verify that an FS block number pointer neither points outside the
 * filesystem nor points at static AG metadata.
 */
bool
scxfs_verify_fsbno(
	struct scxfs_mount	*mp,
	scxfs_fsblock_t		fsbno)
{
	scxfs_agnumber_t		agno = SCXFS_FSB_TO_AGNO(mp, fsbno);

	if (agno >= mp->m_sb.sb_agcount)
		return false;
	return scxfs_verify_agbno(mp, agno, SCXFS_FSB_TO_AGBNO(mp, fsbno));
}

/* Calculate the first and last possible inode number in an AG. */
void
scxfs_agino_range(
	struct scxfs_mount	*mp,
	scxfs_agnumber_t		agno,
	scxfs_agino_t		*first,
	scxfs_agino_t		*last)
{
	scxfs_agblock_t		bno;
	scxfs_agblock_t		eoag;

	eoag = scxfs_ag_block_count(mp, agno);

	/*
	 * Calculate the first inode, which will be in the first
	 * cluster-aligned block after the AGFL.
	 */
	bno = round_up(SCXFS_AGFL_BLOCK(mp) + 1, M_IGEO(mp)->cluster_align);
	*first = SCXFS_AGB_TO_AGINO(mp, bno);

	/*
	 * Calculate the last inode, which will be at the end of the
	 * last (aligned) cluster that can be allocated in the AG.
	 */
	bno = round_down(eoag, M_IGEO(mp)->cluster_align);
	*last = SCXFS_AGB_TO_AGINO(mp, bno) - 1;
}

/*
 * Verify that an AG inode number pointer neither points outside the AG
 * nor points at static metadata.
 */
bool
scxfs_verify_agino(
	struct scxfs_mount	*mp,
	scxfs_agnumber_t		agno,
	scxfs_agino_t		agino)
{
	scxfs_agino_t		first;
	scxfs_agino_t		last;

	scxfs_agino_range(mp, agno, &first, &last);
	return agino >= first && agino <= last;
}

/*
 * Verify that an AG inode number pointer neither points outside the AG
 * nor points at static metadata, or is NULLAGINO.
 */
bool
scxfs_verify_agino_or_null(
	struct scxfs_mount	*mp,
	scxfs_agnumber_t		agno,
	scxfs_agino_t		agino)
{
	return agino == NULLAGINO || scxfs_verify_agino(mp, agno, agino);
}

/*
 * Verify that an FS inode number pointer neither points outside the
 * filesystem nor points at static AG metadata.
 */
bool
scxfs_verify_ino(
	struct scxfs_mount	*mp,
	scxfs_ino_t		ino)
{
	scxfs_agnumber_t		agno = SCXFS_INO_TO_AGNO(mp, ino);
	scxfs_agino_t		agino = SCXFS_INO_TO_AGINO(mp, ino);

	if (agno >= mp->m_sb.sb_agcount)
		return false;
	if (SCXFS_AGINO_TO_INO(mp, agno, agino) != ino)
		return false;
	return scxfs_verify_agino(mp, agno, agino);
}

/* Is this an internal inode number? */
bool
scxfs_internal_inum(
	struct scxfs_mount	*mp,
	scxfs_ino_t		ino)
{
	return ino == mp->m_sb.sb_rbmino || ino == mp->m_sb.sb_rsumino ||
		(scxfs_sb_version_hasquota(&mp->m_sb) &&
		 scxfs_is_quota_inode(&mp->m_sb, ino));
}

/*
 * Verify that a directory entry's inode number doesn't point at an internal
 * inode, empty space, or static AG metadata.
 */
bool
scxfs_verify_dir_ino(
	struct scxfs_mount	*mp,
	scxfs_ino_t		ino)
{
	if (scxfs_internal_inum(mp, ino))
		return false;
	return scxfs_verify_ino(mp, ino);
}

/*
 * Verify that an realtime block number pointer doesn't point off the
 * end of the realtime device.
 */
bool
scxfs_verify_rtbno(
	struct scxfs_mount	*mp,
	scxfs_rtblock_t		rtbno)
{
	return rtbno < mp->m_sb.sb_rblocks;
}

/* Calculate the range of valid icount values. */
void
scxfs_icount_range(
	struct scxfs_mount	*mp,
	unsigned long long	*min,
	unsigned long long	*max)
{
	unsigned long long	nr_inos = 0;
	scxfs_agnumber_t		agno;

	/* root, rtbitmap, rtsum all live in the first chunk */
	*min = SCXFS_INODES_PER_CHUNK;

	for (agno = 0; agno < mp->m_sb.sb_agcount; agno++) {
		scxfs_agino_t	first, last;

		scxfs_agino_range(mp, agno, &first, &last);
		nr_inos += last - first + 1;
	}
	*max = nr_inos;
}

/* Sanity-checking of inode counts. */
bool
scxfs_verify_icount(
	struct scxfs_mount	*mp,
	unsigned long long	icount)
{
	unsigned long long	min, max;

	scxfs_icount_range(mp, &min, &max);
	return icount >= min && icount <= max;
}

/* Sanity-checking of dir/attr block offsets. */
bool
scxfs_verify_dablk(
	struct scxfs_mount	*mp,
	scxfs_fileoff_t		dabno)
{
	scxfs_dablk_t		max_dablk = -1U;

	return dabno <= max_dablk;
}
