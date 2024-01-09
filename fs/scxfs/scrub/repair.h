// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2018 Oracle.  All Rights Reserved.
 * Author: Darrick J. Wong <darrick.wong@oracle.com>
 */
#ifndef __SCXFS_SCRUB_REPAIR_H__
#define __SCXFS_SCRUB_REPAIR_H__

static inline int xrep_notsupported(struct scxfs_scrub *sc)
{
	return -EOPNOTSUPP;
}

#ifdef CONFIG_XFS_ONLINE_REPAIR

/* Repair helpers */

int xrep_attempt(struct scxfs_inode *ip, struct scxfs_scrub *sc);
void xrep_failure(struct scxfs_mount *mp);
int xrep_roll_ag_trans(struct scxfs_scrub *sc);
bool xrep_ag_has_space(struct scxfs_perag *pag, scxfs_extlen_t nr_blocks,
		enum scxfs_ag_resv_type type);
scxfs_extlen_t xrep_calc_ag_resblks(struct scxfs_scrub *sc);
int xrep_alloc_ag_block(struct scxfs_scrub *sc,
		const struct scxfs_owner_info *oinfo, scxfs_fsblock_t *fsbno,
		enum scxfs_ag_resv_type resv);
int xrep_init_btblock(struct scxfs_scrub *sc, scxfs_fsblock_t fsb,
		struct scxfs_buf **bpp, scxfs_btnum_t btnum,
		const struct scxfs_buf_ops *ops);

struct scxfs_bitmap;

int xrep_fix_freelist(struct scxfs_scrub *sc, bool can_shrink);
int xrep_invalidate_blocks(struct scxfs_scrub *sc, struct scxfs_bitmap *btlist);
int xrep_reap_extents(struct scxfs_scrub *sc, struct scxfs_bitmap *exlist,
		const struct scxfs_owner_info *oinfo, enum scxfs_ag_resv_type type);

struct xrep_find_ag_btree {
	/* in: rmap owner of the btree we're looking for */
	uint64_t			rmap_owner;

	/* in: buffer ops */
	const struct scxfs_buf_ops	*buf_ops;

	/* out: the highest btree block found and the tree height */
	scxfs_agblock_t			root;
	unsigned int			height;
};

int xrep_find_ag_btree_roots(struct scxfs_scrub *sc, struct scxfs_buf *agf_bp,
		struct xrep_find_ag_btree *btree_info, struct scxfs_buf *agfl_bp);
void xrep_force_quotacheck(struct scxfs_scrub *sc, uint dqtype);
int xrep_ino_dqattach(struct scxfs_scrub *sc);

/* Metadata repairers */

int xrep_probe(struct scxfs_scrub *sc);
int xrep_superblock(struct scxfs_scrub *sc);
int xrep_agf(struct scxfs_scrub *sc);
int xrep_agfl(struct scxfs_scrub *sc);
int xrep_agi(struct scxfs_scrub *sc);

#else

static inline int xrep_attempt(
	struct scxfs_inode	*ip,
	struct scxfs_scrub	*sc)
{
	return -EOPNOTSUPP;
}

static inline void xrep_failure(struct scxfs_mount *mp) {}

static inline scxfs_extlen_t
xrep_calc_ag_resblks(
	struct scxfs_scrub	*sc)
{
	ASSERT(!(sc->sm->sm_flags & SCXFS_SCRUB_IFLAG_REPAIR));
	return 0;
}

#define xrep_probe			xrep_notsupported
#define xrep_superblock			xrep_notsupported
#define xrep_agf			xrep_notsupported
#define xrep_agfl			xrep_notsupported
#define xrep_agi			xrep_notsupported

#endif /* CONFIG_XFS_ONLINE_REPAIR */

#endif	/* __SCXFS_SCRUB_REPAIR_H__ */
