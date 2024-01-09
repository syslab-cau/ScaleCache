// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000,2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#ifndef __SCXFS_TRANS_SPACE_H__
#define __SCXFS_TRANS_SPACE_H__

/*
 * Components of space reservations.
 */

/* Worst case number of rmaps that can be held in a block. */
#define SCXFS_MAX_CONTIG_RMAPS_PER_BLOCK(mp)    \
		(((mp)->m_rmap_mxr[0]) - ((mp)->m_rmap_mnr[0]))

/* Adding one rmap could split every level up to the top of the tree. */
#define SCXFS_RMAPADD_SPACE_RES(mp) ((mp)->m_rmap_maxlevels)

/* Blocks we might need to add "b" rmaps to a tree. */
#define SCXFS_NRMAPADD_SPACE_RES(mp, b)\
	(((b + SCXFS_MAX_CONTIG_RMAPS_PER_BLOCK(mp) - 1) / \
	  SCXFS_MAX_CONTIG_RMAPS_PER_BLOCK(mp)) * \
	  SCXFS_RMAPADD_SPACE_RES(mp))

#define SCXFS_MAX_CONTIG_EXTENTS_PER_BLOCK(mp)    \
		(((mp)->m_alloc_mxr[0]) - ((mp)->m_alloc_mnr[0]))
#define	SCXFS_EXTENTADD_SPACE_RES(mp,w)	(SCXFS_BM_MAXLEVELS(mp,w) - 1)
#define SCXFS_NEXTENTADD_SPACE_RES(mp,b,w)\
	(((b + SCXFS_MAX_CONTIG_EXTENTS_PER_BLOCK(mp) - 1) / \
	  SCXFS_MAX_CONTIG_EXTENTS_PER_BLOCK(mp)) * \
	  SCXFS_EXTENTADD_SPACE_RES(mp,w))

/* Blocks we might need to add "b" mappings & rmappings to a file. */
#define SCXFS_SWAP_RMAP_SPACE_RES(mp,b,w)\
	(SCXFS_NEXTENTADD_SPACE_RES((mp), (b), (w)) + \
	 SCXFS_NRMAPADD_SPACE_RES((mp), (b)))

#define	SCXFS_DAENTER_1B(mp,w)	\
	((w) == SCXFS_DATA_FORK ? (mp)->m_dir_geo->fsbcount : 1)
#define	SCXFS_DAENTER_DBS(mp,w)	\
	(SCXFS_DA_NODE_MAXDEPTH + (((w) == SCXFS_DATA_FORK) ? 2 : 0))
#define	SCXFS_DAENTER_BLOCKS(mp,w)	\
	(SCXFS_DAENTER_1B(mp,w) * SCXFS_DAENTER_DBS(mp,w))
#define	SCXFS_DAENTER_BMAP1B(mp,w)	\
	SCXFS_NEXTENTADD_SPACE_RES(mp, SCXFS_DAENTER_1B(mp, w), w)
#define	SCXFS_DAENTER_BMAPS(mp,w)		\
	(SCXFS_DAENTER_DBS(mp,w) * SCXFS_DAENTER_BMAP1B(mp,w))
#define	SCXFS_DAENTER_SPACE_RES(mp,w)	\
	(SCXFS_DAENTER_BLOCKS(mp,w) + SCXFS_DAENTER_BMAPS(mp,w))
#define	SCXFS_DAREMOVE_SPACE_RES(mp,w)	SCXFS_DAENTER_BMAPS(mp,w)
#define	SCXFS_DIRENTER_MAX_SPLIT(mp,nl)	1
#define	SCXFS_DIRENTER_SPACE_RES(mp,nl)	\
	(SCXFS_DAENTER_SPACE_RES(mp, SCXFS_DATA_FORK) * \
	 SCXFS_DIRENTER_MAX_SPLIT(mp,nl))
#define	SCXFS_DIRREMOVE_SPACE_RES(mp)	\
	SCXFS_DAREMOVE_SPACE_RES(mp, SCXFS_DATA_FORK)
#define	SCXFS_IALLOC_SPACE_RES(mp)	\
	(M_IGEO(mp)->ialloc_blks + \
	 ((scxfs_sb_version_hasfinobt(&mp->m_sb) ? 2 : 1) * \
	  M_IGEO(mp)->inobt_maxlevels))

/*
 * Space reservation values for various transactions.
 */
#define	SCXFS_ADDAFORK_SPACE_RES(mp)	\
	((mp)->m_dir_geo->fsbcount + SCXFS_DAENTER_BMAP1B(mp, SCXFS_DATA_FORK))
#define	SCXFS_ATTRRM_SPACE_RES(mp)	\
	SCXFS_DAREMOVE_SPACE_RES(mp, SCXFS_ATTR_FORK)
/* This macro is not used - see inline code in scxfs_attr_set */
#define	SCXFS_ATTRSET_SPACE_RES(mp, v)	\
	(SCXFS_DAENTER_SPACE_RES(mp, SCXFS_ATTR_FORK) + SCXFS_B_TO_FSB(mp, v))
#define	SCXFS_CREATE_SPACE_RES(mp,nl)	\
	(SCXFS_IALLOC_SPACE_RES(mp) + SCXFS_DIRENTER_SPACE_RES(mp,nl))
#define	SCXFS_DIOSTRAT_SPACE_RES(mp, v)	\
	(SCXFS_EXTENTADD_SPACE_RES(mp, SCXFS_DATA_FORK) + (v))
#define	SCXFS_GROWFS_SPACE_RES(mp)	\
	(2 * (mp)->m_ag_maxlevels)
#define	SCXFS_GROWFSRT_SPACE_RES(mp,b)	\
	((b) + SCXFS_EXTENTADD_SPACE_RES(mp, SCXFS_DATA_FORK))
#define	SCXFS_LINK_SPACE_RES(mp,nl)	\
	SCXFS_DIRENTER_SPACE_RES(mp,nl)
#define	SCXFS_MKDIR_SPACE_RES(mp,nl)	\
	(SCXFS_IALLOC_SPACE_RES(mp) + SCXFS_DIRENTER_SPACE_RES(mp,nl))
#define	SCXFS_QM_DQALLOC_SPACE_RES(mp)	\
	(SCXFS_EXTENTADD_SPACE_RES(mp, SCXFS_DATA_FORK) + \
	 SCXFS_DQUOT_CLUSTER_SIZE_FSB)
#define	SCXFS_QM_QINOCREATE_SPACE_RES(mp)	\
	SCXFS_IALLOC_SPACE_RES(mp)
#define	SCXFS_REMOVE_SPACE_RES(mp)	\
	SCXFS_DIRREMOVE_SPACE_RES(mp)
#define	SCXFS_RENAME_SPACE_RES(mp,nl)	\
	(SCXFS_DIRREMOVE_SPACE_RES(mp) + SCXFS_DIRENTER_SPACE_RES(mp,nl))
#define	SCXFS_SYMLINK_SPACE_RES(mp,nl,b)	\
	(SCXFS_IALLOC_SPACE_RES(mp) + SCXFS_DIRENTER_SPACE_RES(mp,nl) + (b))
#define SCXFS_IFREE_SPACE_RES(mp)		\
	(scxfs_sb_version_hasfinobt(&mp->m_sb) ? \
			M_IGEO(mp)->inobt_maxlevels : 0)


#endif	/* __SCXFS_TRANS_SPACE_H__ */
