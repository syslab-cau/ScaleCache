/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2000-2005 Silicon Graphics, Inc.
 * Copyright (c) 2018 Red Hat, Inc.
 * All rights reserved.
 */

#include "scxfs.h"
#include "scxfs_fs.h"
#include "scxfs_shared.h"
#include "scxfs_format.h"
#include "scxfs_trans_resv.h"
#include "scxfs_bit.h"
#include "scxfs_sb.h"
#include "scxfs_mount.h"
#include "scxfs_btree.h"
#include "scxfs_alloc_btree.h"
#include "scxfs_rmap_btree.h"
#include "scxfs_alloc.h"
#include "scxfs_ialloc.h"
#include "scxfs_rmap.h"
#include "scxfs_ag.h"
#include "scxfs_ag_resv.h"
#include "scxfs_health.h"

static struct scxfs_buf *
scxfs_get_aghdr_buf(
	struct scxfs_mount	*mp,
	scxfs_daddr_t		blkno,
	size_t			numblks,
	const struct scxfs_buf_ops *ops)
{
	struct scxfs_buf		*bp;

	bp = scxfs_buf_get_uncached(mp->m_ddev_targp, numblks, 0);
	if (!bp)
		return NULL;

	scxfs_buf_zero(bp, 0, BBTOB(bp->b_length));
	bp->b_bn = blkno;
	bp->b_maps[0].bm_bn = blkno;
	bp->b_ops = ops;

	return bp;
}

static inline bool is_log_ag(struct scxfs_mount *mp, struct aghdr_init_data *id)
{
	return mp->m_sb.sb_logstart > 0 &&
	       id->agno == SCXFS_FSB_TO_AGNO(mp, mp->m_sb.sb_logstart);
}

/*
 * Generic btree root block init function
 */
static void
scxfs_btroot_init(
	struct scxfs_mount	*mp,
	struct scxfs_buf		*bp,
	struct aghdr_init_data	*id)
{
	scxfs_btree_init_block(mp, bp, id->type, 0, 0, id->agno);
}

/* Finish initializing a free space btree. */
static void
scxfs_freesp_init_recs(
	struct scxfs_mount	*mp,
	struct scxfs_buf		*bp,
	struct aghdr_init_data	*id)
{
	struct scxfs_alloc_rec	*arec;
	struct scxfs_btree_block	*block = SCXFS_BUF_TO_BLOCK(bp);

	arec = SCXFS_ALLOC_REC_ADDR(mp, SCXFS_BUF_TO_BLOCK(bp), 1);
	arec->ar_startblock = cpu_to_be32(mp->m_ag_prealloc_blocks);

	if (is_log_ag(mp, id)) {
		struct scxfs_alloc_rec	*nrec;
		scxfs_agblock_t		start = SCXFS_FSB_TO_AGBNO(mp,
							mp->m_sb.sb_logstart);

		ASSERT(start >= mp->m_ag_prealloc_blocks);
		if (start != mp->m_ag_prealloc_blocks) {
			/*
			 * Modify first record to pad stripe align of log
			 */
			arec->ar_blockcount = cpu_to_be32(start -
						mp->m_ag_prealloc_blocks);
			nrec = arec + 1;

			/*
			 * Insert second record at start of internal log
			 * which then gets trimmed.
			 */
			nrec->ar_startblock = cpu_to_be32(
					be32_to_cpu(arec->ar_startblock) +
					be32_to_cpu(arec->ar_blockcount));
			arec = nrec;
			be16_add_cpu(&block->bb_numrecs, 1);
		}
		/*
		 * Change record start to after the internal log
		 */
		be32_add_cpu(&arec->ar_startblock, mp->m_sb.sb_logblocks);
	}

	/*
	 * Calculate the record block count and check for the case where
	 * the log might have consumed all available space in the AG. If
	 * so, reset the record count to 0 to avoid exposure of an invalid
	 * record start block.
	 */
	arec->ar_blockcount = cpu_to_be32(id->agsize -
					  be32_to_cpu(arec->ar_startblock));
	if (!arec->ar_blockcount)
		block->bb_numrecs = 0;
}

/*
 * Alloc btree root block init functions
 */
static void
scxfs_bnoroot_init(
	struct scxfs_mount	*mp,
	struct scxfs_buf		*bp,
	struct aghdr_init_data	*id)
{
	scxfs_btree_init_block(mp, bp, SCXFS_BTNUM_BNO, 0, 1, id->agno);
	scxfs_freesp_init_recs(mp, bp, id);
}

static void
scxfs_cntroot_init(
	struct scxfs_mount	*mp,
	struct scxfs_buf		*bp,
	struct aghdr_init_data	*id)
{
	scxfs_btree_init_block(mp, bp, SCXFS_BTNUM_CNT, 0, 1, id->agno);
	scxfs_freesp_init_recs(mp, bp, id);
}

/*
 * Reverse map root block init
 */
static void
scxfs_rmaproot_init(
	struct scxfs_mount	*mp,
	struct scxfs_buf		*bp,
	struct aghdr_init_data	*id)
{
	struct scxfs_btree_block	*block = SCXFS_BUF_TO_BLOCK(bp);
	struct scxfs_rmap_rec	*rrec;

	scxfs_btree_init_block(mp, bp, SCXFS_BTNUM_RMAP, 0, 4, id->agno);

	/*
	 * mark the AG header regions as static metadata The BNO
	 * btree block is the first block after the headers, so
	 * it's location defines the size of region the static
	 * metadata consumes.
	 *
	 * Note: unlike mkfs, we never have to account for log
	 * space when growing the data regions
	 */
	rrec = SCXFS_RMAP_REC_ADDR(block, 1);
	rrec->rm_startblock = 0;
	rrec->rm_blockcount = cpu_to_be32(SCXFS_BNO_BLOCK(mp));
	rrec->rm_owner = cpu_to_be64(SCXFS_RMAP_OWN_FS);
	rrec->rm_offset = 0;

	/* account freespace btree root blocks */
	rrec = SCXFS_RMAP_REC_ADDR(block, 2);
	rrec->rm_startblock = cpu_to_be32(SCXFS_BNO_BLOCK(mp));
	rrec->rm_blockcount = cpu_to_be32(2);
	rrec->rm_owner = cpu_to_be64(SCXFS_RMAP_OWN_AG);
	rrec->rm_offset = 0;

	/* account inode btree root blocks */
	rrec = SCXFS_RMAP_REC_ADDR(block, 3);
	rrec->rm_startblock = cpu_to_be32(SCXFS_IBT_BLOCK(mp));
	rrec->rm_blockcount = cpu_to_be32(SCXFS_RMAP_BLOCK(mp) -
					  SCXFS_IBT_BLOCK(mp));
	rrec->rm_owner = cpu_to_be64(SCXFS_RMAP_OWN_INOBT);
	rrec->rm_offset = 0;

	/* account for rmap btree root */
	rrec = SCXFS_RMAP_REC_ADDR(block, 4);
	rrec->rm_startblock = cpu_to_be32(SCXFS_RMAP_BLOCK(mp));
	rrec->rm_blockcount = cpu_to_be32(1);
	rrec->rm_owner = cpu_to_be64(SCXFS_RMAP_OWN_AG);
	rrec->rm_offset = 0;

	/* account for refc btree root */
	if (scxfs_sb_version_hasreflink(&mp->m_sb)) {
		rrec = SCXFS_RMAP_REC_ADDR(block, 5);
		rrec->rm_startblock = cpu_to_be32(scxfs_refc_block(mp));
		rrec->rm_blockcount = cpu_to_be32(1);
		rrec->rm_owner = cpu_to_be64(SCXFS_RMAP_OWN_REFC);
		rrec->rm_offset = 0;
		be16_add_cpu(&block->bb_numrecs, 1);
	}

	/* account for the log space */
	if (is_log_ag(mp, id)) {
		rrec = SCXFS_RMAP_REC_ADDR(block,
				be16_to_cpu(block->bb_numrecs) + 1);
		rrec->rm_startblock = cpu_to_be32(
				SCXFS_FSB_TO_AGBNO(mp, mp->m_sb.sb_logstart));
		rrec->rm_blockcount = cpu_to_be32(mp->m_sb.sb_logblocks);
		rrec->rm_owner = cpu_to_be64(SCXFS_RMAP_OWN_LOG);
		rrec->rm_offset = 0;
		be16_add_cpu(&block->bb_numrecs, 1);
	}
}

/*
 * Initialise new secondary superblocks with the pre-grow geometry, but mark
 * them as "in progress" so we know they haven't yet been activated. This will
 * get cleared when the update with the new geometry information is done after
 * changes to the primary are committed. This isn't strictly necessary, but we
 * get it for free with the delayed buffer write lists and it means we can tell
 * if a grow operation didn't complete properly after the fact.
 */
static void
scxfs_sbblock_init(
	struct scxfs_mount	*mp,
	struct scxfs_buf		*bp,
	struct aghdr_init_data	*id)
{
	struct scxfs_dsb		*dsb = SCXFS_BUF_TO_SBP(bp);

	scxfs_sb_to_disk(dsb, &mp->m_sb);
	dsb->sb_inprogress = 1;
}

static void
scxfs_agfblock_init(
	struct scxfs_mount	*mp,
	struct scxfs_buf		*bp,
	struct aghdr_init_data	*id)
{
	struct scxfs_agf		*agf = SCXFS_BUF_TO_AGF(bp);
	scxfs_extlen_t		tmpsize;

	agf->agf_magicnum = cpu_to_be32(SCXFS_AGF_MAGIC);
	agf->agf_versionnum = cpu_to_be32(SCXFS_AGF_VERSION);
	agf->agf_seqno = cpu_to_be32(id->agno);
	agf->agf_length = cpu_to_be32(id->agsize);
	agf->agf_roots[SCXFS_BTNUM_BNOi] = cpu_to_be32(SCXFS_BNO_BLOCK(mp));
	agf->agf_roots[SCXFS_BTNUM_CNTi] = cpu_to_be32(SCXFS_CNT_BLOCK(mp));
	agf->agf_levels[SCXFS_BTNUM_BNOi] = cpu_to_be32(1);
	agf->agf_levels[SCXFS_BTNUM_CNTi] = cpu_to_be32(1);
	if (scxfs_sb_version_hasrmapbt(&mp->m_sb)) {
		agf->agf_roots[SCXFS_BTNUM_RMAPi] =
					cpu_to_be32(SCXFS_RMAP_BLOCK(mp));
		agf->agf_levels[SCXFS_BTNUM_RMAPi] = cpu_to_be32(1);
		agf->agf_rmap_blocks = cpu_to_be32(1);
	}

	agf->agf_flfirst = cpu_to_be32(1);
	agf->agf_fllast = 0;
	agf->agf_flcount = 0;
	tmpsize = id->agsize - mp->m_ag_prealloc_blocks;
	agf->agf_freeblks = cpu_to_be32(tmpsize);
	agf->agf_longest = cpu_to_be32(tmpsize);
	if (scxfs_sb_version_hascrc(&mp->m_sb))
		uuid_copy(&agf->agf_uuid, &mp->m_sb.sb_meta_uuid);
	if (scxfs_sb_version_hasreflink(&mp->m_sb)) {
		agf->agf_refcount_root = cpu_to_be32(
				scxfs_refc_block(mp));
		agf->agf_refcount_level = cpu_to_be32(1);
		agf->agf_refcount_blocks = cpu_to_be32(1);
	}

	if (is_log_ag(mp, id)) {
		int64_t	logblocks = mp->m_sb.sb_logblocks;

		be32_add_cpu(&agf->agf_freeblks, -logblocks);
		agf->agf_longest = cpu_to_be32(id->agsize -
			SCXFS_FSB_TO_AGBNO(mp, mp->m_sb.sb_logstart) - logblocks);
	}
}

static void
scxfs_agflblock_init(
	struct scxfs_mount	*mp,
	struct scxfs_buf		*bp,
	struct aghdr_init_data	*id)
{
	struct scxfs_agfl		*agfl = SCXFS_BUF_TO_AGFL(bp);
	__be32			*agfl_bno;
	int			bucket;

	if (scxfs_sb_version_hascrc(&mp->m_sb)) {
		agfl->agfl_magicnum = cpu_to_be32(SCXFS_AGFL_MAGIC);
		agfl->agfl_seqno = cpu_to_be32(id->agno);
		uuid_copy(&agfl->agfl_uuid, &mp->m_sb.sb_meta_uuid);
	}

	agfl_bno = SCXFS_BUF_TO_AGFL_BNO(mp, bp);
	for (bucket = 0; bucket < scxfs_agfl_size(mp); bucket++)
		agfl_bno[bucket] = cpu_to_be32(NULLAGBLOCK);
}

static void
scxfs_agiblock_init(
	struct scxfs_mount	*mp,
	struct scxfs_buf		*bp,
	struct aghdr_init_data	*id)
{
	struct scxfs_agi		*agi = SCXFS_BUF_TO_AGI(bp);
	int			bucket;

	agi->agi_magicnum = cpu_to_be32(SCXFS_AGI_MAGIC);
	agi->agi_versionnum = cpu_to_be32(SCXFS_AGI_VERSION);
	agi->agi_seqno = cpu_to_be32(id->agno);
	agi->agi_length = cpu_to_be32(id->agsize);
	agi->agi_count = 0;
	agi->agi_root = cpu_to_be32(SCXFS_IBT_BLOCK(mp));
	agi->agi_level = cpu_to_be32(1);
	agi->agi_freecount = 0;
	agi->agi_newino = cpu_to_be32(NULLAGINO);
	agi->agi_dirino = cpu_to_be32(NULLAGINO);
	if (scxfs_sb_version_hascrc(&mp->m_sb))
		uuid_copy(&agi->agi_uuid, &mp->m_sb.sb_meta_uuid);
	if (scxfs_sb_version_hasfinobt(&mp->m_sb)) {
		agi->agi_free_root = cpu_to_be32(SCXFS_FIBT_BLOCK(mp));
		agi->agi_free_level = cpu_to_be32(1);
	}
	for (bucket = 0; bucket < SCXFS_AGI_UNLINKED_BUCKETS; bucket++)
		agi->agi_unlinked[bucket] = cpu_to_be32(NULLAGINO);
}

typedef void (*aghdr_init_work_f)(struct scxfs_mount *mp, struct scxfs_buf *bp,
				  struct aghdr_init_data *id);
static int
scxfs_ag_init_hdr(
	struct scxfs_mount	*mp,
	struct aghdr_init_data	*id,
	aghdr_init_work_f	work,
	const struct scxfs_buf_ops *ops)

{
	struct scxfs_buf		*bp;

	bp = scxfs_get_aghdr_buf(mp, id->daddr, id->numblks, ops);
	if (!bp)
		return -ENOMEM;

	(*work)(mp, bp, id);

	scxfs_buf_delwri_queue(bp, &id->buffer_list);
	scxfs_buf_relse(bp);
	return 0;
}

struct scxfs_aghdr_grow_data {
	scxfs_daddr_t		daddr;
	size_t			numblks;
	const struct scxfs_buf_ops *ops;
	aghdr_init_work_f	work;
	scxfs_btnum_t		type;
	bool			need_init;
};

/*
 * Prepare new AG headers to be written to disk. We use uncached buffers here,
 * as it is assumed these new AG headers are currently beyond the currently
 * valid filesystem address space. Using cached buffers would trip over EOFS
 * corruption detection alogrithms in the buffer cache lookup routines.
 *
 * This is a non-transactional function, but the prepared buffers are added to a
 * delayed write buffer list supplied by the caller so they can submit them to
 * disk and wait on them as required.
 */
int
scxfs_ag_init_headers(
	struct scxfs_mount	*mp,
	struct aghdr_init_data	*id)

{
	struct scxfs_aghdr_grow_data aghdr_data[] = {
	{ /* SB */
		.daddr = SCXFS_AG_DADDR(mp, id->agno, SCXFS_SB_DADDR),
		.numblks = SCXFS_FSS_TO_BB(mp, 1),
		.ops = &scxfs_sb_buf_ops,
		.work = &scxfs_sbblock_init,
		.need_init = true
	},
	{ /* AGF */
		.daddr = SCXFS_AG_DADDR(mp, id->agno, SCXFS_AGF_DADDR(mp)),
		.numblks = SCXFS_FSS_TO_BB(mp, 1),
		.ops = &scxfs_agf_buf_ops,
		.work = &scxfs_agfblock_init,
		.need_init = true
	},
	{ /* AGFL */
		.daddr = SCXFS_AG_DADDR(mp, id->agno, SCXFS_AGFL_DADDR(mp)),
		.numblks = SCXFS_FSS_TO_BB(mp, 1),
		.ops = &scxfs_agfl_buf_ops,
		.work = &scxfs_agflblock_init,
		.need_init = true
	},
	{ /* AGI */
		.daddr = SCXFS_AG_DADDR(mp, id->agno, SCXFS_AGI_DADDR(mp)),
		.numblks = SCXFS_FSS_TO_BB(mp, 1),
		.ops = &scxfs_agi_buf_ops,
		.work = &scxfs_agiblock_init,
		.need_init = true
	},
	{ /* BNO root block */
		.daddr = SCXFS_AGB_TO_DADDR(mp, id->agno, SCXFS_BNO_BLOCK(mp)),
		.numblks = BTOBB(mp->m_sb.sb_blocksize),
		.ops = &scxfs_bnobt_buf_ops,
		.work = &scxfs_bnoroot_init,
		.need_init = true
	},
	{ /* CNT root block */
		.daddr = SCXFS_AGB_TO_DADDR(mp, id->agno, SCXFS_CNT_BLOCK(mp)),
		.numblks = BTOBB(mp->m_sb.sb_blocksize),
		.ops = &scxfs_cntbt_buf_ops,
		.work = &scxfs_cntroot_init,
		.need_init = true
	},
	{ /* INO root block */
		.daddr = SCXFS_AGB_TO_DADDR(mp, id->agno, SCXFS_IBT_BLOCK(mp)),
		.numblks = BTOBB(mp->m_sb.sb_blocksize),
		.ops = &scxfs_inobt_buf_ops,
		.work = &scxfs_btroot_init,
		.type = SCXFS_BTNUM_INO,
		.need_init = true
	},
	{ /* FINO root block */
		.daddr = SCXFS_AGB_TO_DADDR(mp, id->agno, SCXFS_FIBT_BLOCK(mp)),
		.numblks = BTOBB(mp->m_sb.sb_blocksize),
		.ops = &scxfs_finobt_buf_ops,
		.work = &scxfs_btroot_init,
		.type = SCXFS_BTNUM_FINO,
		.need_init =  scxfs_sb_version_hasfinobt(&mp->m_sb)
	},
	{ /* RMAP root block */
		.daddr = SCXFS_AGB_TO_DADDR(mp, id->agno, SCXFS_RMAP_BLOCK(mp)),
		.numblks = BTOBB(mp->m_sb.sb_blocksize),
		.ops = &scxfs_rmapbt_buf_ops,
		.work = &scxfs_rmaproot_init,
		.need_init = scxfs_sb_version_hasrmapbt(&mp->m_sb)
	},
	{ /* REFC root block */
		.daddr = SCXFS_AGB_TO_DADDR(mp, id->agno, scxfs_refc_block(mp)),
		.numblks = BTOBB(mp->m_sb.sb_blocksize),
		.ops = &scxfs_refcountbt_buf_ops,
		.work = &scxfs_btroot_init,
		.type = SCXFS_BTNUM_REFC,
		.need_init = scxfs_sb_version_hasreflink(&mp->m_sb)
	},
	{ /* NULL terminating block */
		.daddr = SCXFS_BUF_DADDR_NULL,
	}
	};
	struct  scxfs_aghdr_grow_data *dp;
	int			error = 0;

	/* Account for AG free space in new AG */
	id->nfree += id->agsize - mp->m_ag_prealloc_blocks;
	for (dp = &aghdr_data[0]; dp->daddr != SCXFS_BUF_DADDR_NULL; dp++) {
		if (!dp->need_init)
			continue;

		id->daddr = dp->daddr;
		id->numblks = dp->numblks;
		id->type = dp->type;
		error = scxfs_ag_init_hdr(mp, id, dp->work, dp->ops);
		if (error)
			break;
	}
	return error;
}

/*
 * Extent the AG indicated by the @id by the length passed in
 */
int
scxfs_ag_extend_space(
	struct scxfs_mount	*mp,
	struct scxfs_trans	*tp,
	struct aghdr_init_data	*id,
	scxfs_extlen_t		len)
{
	struct scxfs_buf		*bp;
	struct scxfs_agi		*agi;
	struct scxfs_agf		*agf;
	int			error;

	/*
	 * Change the agi length.
	 */
	error = scxfs_ialloc_read_agi(mp, tp, id->agno, &bp);
	if (error)
		return error;

	agi = SCXFS_BUF_TO_AGI(bp);
	be32_add_cpu(&agi->agi_length, len);
	ASSERT(id->agno == mp->m_sb.sb_agcount - 1 ||
	       be32_to_cpu(agi->agi_length) == mp->m_sb.sb_agblocks);
	scxfs_ialloc_log_agi(tp, bp, SCXFS_AGI_LENGTH);

	/*
	 * Change agf length.
	 */
	error = scxfs_alloc_read_agf(mp, tp, id->agno, 0, &bp);
	if (error)
		return error;

	agf = SCXFS_BUF_TO_AGF(bp);
	be32_add_cpu(&agf->agf_length, len);
	ASSERT(agf->agf_length == agi->agi_length);
	scxfs_alloc_log_agf(tp, bp, SCXFS_AGF_LENGTH);

	/*
	 * Free the new space.
	 *
	 * SCXFS_RMAP_OINFO_SKIP_UPDATE is used here to tell the rmap btree that
	 * this doesn't actually exist in the rmap btree.
	 */
	error = scxfs_rmap_free(tp, bp, id->agno,
				be32_to_cpu(agf->agf_length) - len,
				len, &SCXFS_RMAP_OINFO_SKIP_UPDATE);
	if (error)
		return error;

	return  scxfs_free_extent(tp, SCXFS_AGB_TO_FSB(mp, id->agno,
					be32_to_cpu(agf->agf_length) - len),
				len, &SCXFS_RMAP_OINFO_SKIP_UPDATE,
				SCXFS_AG_RESV_NONE);
}

/* Retrieve AG geometry. */
int
scxfs_ag_get_geometry(
	struct scxfs_mount	*mp,
	scxfs_agnumber_t		agno,
	struct scxfs_ag_geometry	*ageo)
{
	struct scxfs_buf		*agi_bp;
	struct scxfs_buf		*agf_bp;
	struct scxfs_agi		*agi;
	struct scxfs_agf		*agf;
	struct scxfs_perag	*pag;
	unsigned int		freeblks;
	int			error;

	if (agno >= mp->m_sb.sb_agcount)
		return -EINVAL;

	/* Lock the AG headers. */
	error = scxfs_ialloc_read_agi(mp, NULL, agno, &agi_bp);
	if (error)
		return error;
	error = scxfs_alloc_read_agf(mp, NULL, agno, 0, &agf_bp);
	if (error)
		goto out_agi;
	pag = scxfs_perag_get(mp, agno);

	/* Fill out form. */
	memset(ageo, 0, sizeof(*ageo));
	ageo->ag_number = agno;

	agi = SCXFS_BUF_TO_AGI(agi_bp);
	ageo->ag_icount = be32_to_cpu(agi->agi_count);
	ageo->ag_ifree = be32_to_cpu(agi->agi_freecount);

	agf = SCXFS_BUF_TO_AGF(agf_bp);
	ageo->ag_length = be32_to_cpu(agf->agf_length);
	freeblks = pag->pagf_freeblks +
		   pag->pagf_flcount +
		   pag->pagf_btreeblks -
		   scxfs_ag_resv_needed(pag, SCXFS_AG_RESV_NONE);
	ageo->ag_freeblks = freeblks;
	scxfs_ag_geom_health(pag, ageo);

	/* Release resources. */
	scxfs_perag_put(pag);
	scxfs_buf_relse(agf_bp);
out_agi:
	scxfs_buf_relse(agi_bp);
	return error;
}
