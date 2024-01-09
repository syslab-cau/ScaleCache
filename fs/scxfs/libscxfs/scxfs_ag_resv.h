// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2016 Oracle.  All Rights Reserved.
 * Author: Darrick J. Wong <darrick.wong@oracle.com>
 */
#ifndef __SCXFS_AG_RESV_H__
#define	__SCXFS_AG_RESV_H__

int scxfs_ag_resv_free(struct scxfs_perag *pag);
int scxfs_ag_resv_init(struct scxfs_perag *pag, struct scxfs_trans *tp);

bool scxfs_ag_resv_critical(struct scxfs_perag *pag, enum scxfs_ag_resv_type type);
scxfs_extlen_t scxfs_ag_resv_needed(struct scxfs_perag *pag,
		enum scxfs_ag_resv_type type);

void scxfs_ag_resv_alloc_extent(struct scxfs_perag *pag, enum scxfs_ag_resv_type type,
		struct scxfs_alloc_arg *args);
void scxfs_ag_resv_free_extent(struct scxfs_perag *pag, enum scxfs_ag_resv_type type,
		struct scxfs_trans *tp, scxfs_extlen_t len);

/*
 * RMAPBT reservation accounting wrappers. Since rmapbt blocks are sourced from
 * the AGFL, they are allocated one at a time and the reservation updates don't
 * require a transaction.
 */
static inline void
scxfs_ag_resv_rmapbt_alloc(
	struct scxfs_mount	*mp,
	scxfs_agnumber_t		agno)
{
	struct scxfs_alloc_arg	args = { NULL };
	struct scxfs_perag	*pag;

	args.len = 1;
	pag = scxfs_perag_get(mp, agno);
	scxfs_ag_resv_alloc_extent(pag, SCXFS_AG_RESV_RMAPBT, &args);
	scxfs_perag_put(pag);
}

static inline void
scxfs_ag_resv_rmapbt_free(
	struct scxfs_mount	*mp,
	scxfs_agnumber_t		agno)
{
	struct scxfs_perag	*pag;

	pag = scxfs_perag_get(mp, agno);
	scxfs_ag_resv_free_extent(pag, SCXFS_AG_RESV_RMAPBT, NULL, 1);
	scxfs_perag_put(pag);
}

#endif	/* __SCXFS_AG_RESV_H__ */
