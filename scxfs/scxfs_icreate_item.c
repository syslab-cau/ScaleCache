// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2008-2010, 2013 Dave Chinner
 * All Rights Reserved.
 */
#include "scxfs.h"
#include "scxfs_fs.h"
#include "scxfs_shared.h"
#include "scxfs_log_format.h"
#include "scxfs_trans.h"
#include "scxfs_trans_priv.h"
#include "scxfs_icreate_item.h"
#include "scxfs_log.h"

kmem_zone_t	*scxfs_icreate_zone;		/* inode create item zone */

static inline struct scxfs_icreate_item *ICR_ITEM(struct scxfs_log_item *lip)
{
	return container_of(lip, struct scxfs_icreate_item, ic_item);
}

/*
 * This returns the number of iovecs needed to log the given inode item.
 *
 * We only need one iovec for the icreate log structure.
 */
STATIC void
scxfs_icreate_item_size(
	struct scxfs_log_item	*lip,
	int			*nvecs,
	int			*nbytes)
{
	*nvecs += 1;
	*nbytes += sizeof(struct scxfs_icreate_log);
}

/*
 * This is called to fill in the vector of log iovecs for the
 * given inode create log item.
 */
STATIC void
scxfs_icreate_item_format(
	struct scxfs_log_item	*lip,
	struct scxfs_log_vec	*lv)
{
	struct scxfs_icreate_item	*icp = ICR_ITEM(lip);
	struct scxfs_log_iovec	*vecp = NULL;

	xlog_copy_iovec(lv, &vecp, XLOG_REG_TYPE_ICREATE,
			&icp->ic_format,
			sizeof(struct scxfs_icreate_log));
}

STATIC void
scxfs_icreate_item_release(
	struct scxfs_log_item	*lip)
{
	kmem_zone_free(scxfs_icreate_zone, ICR_ITEM(lip));
}

static const struct scxfs_item_ops scxfs_icreate_item_ops = {
	.flags		= SCXFS_ITEM_RELEASE_WHEN_COMMITTED,
	.iop_size	= scxfs_icreate_item_size,
	.iop_format	= scxfs_icreate_item_format,
	.iop_release	= scxfs_icreate_item_release,
};


/*
 * Initialize the inode log item for a newly allocated (in-core) inode.
 *
 * Inode extents can only reside within an AG. Hence specify the starting
 * block for the inode chunk by offset within an AG as well as the
 * length of the allocated extent.
 *
 * This joins the item to the transaction and marks it dirty so
 * that we don't need a separate call to do this, nor does the
 * caller need to know anything about the icreate item.
 */
void
scxfs_icreate_log(
	struct scxfs_trans	*tp,
	scxfs_agnumber_t		agno,
	scxfs_agblock_t		agbno,
	unsigned int		count,
	unsigned int		inode_size,
	scxfs_agblock_t		length,
	unsigned int		generation)
{
	struct scxfs_icreate_item	*icp;

	icp = kmem_zone_zalloc(scxfs_icreate_zone, 0);

	scxfs_log_item_init(tp->t_mountp, &icp->ic_item, SCXFS_LI_ICREATE,
			  &scxfs_icreate_item_ops);

	icp->ic_format.icl_type = SCXFS_LI_ICREATE;
	icp->ic_format.icl_size = 1;	/* single vector */
	icp->ic_format.icl_ag = cpu_to_be32(agno);
	icp->ic_format.icl_agbno = cpu_to_be32(agbno);
	icp->ic_format.icl_count = cpu_to_be32(count);
	icp->ic_format.icl_isize = cpu_to_be32(inode_size);
	icp->ic_format.icl_length = cpu_to_be32(length);
	icp->ic_format.icl_gen = cpu_to_be32(generation);

	scxfs_trans_add_item(tp, &icp->ic_item);
	tp->t_flags |= SCXFS_TRANS_DIRTY;
	set_bit(SCXFS_LI_DIRTY, &icp->ic_item.li_flags);
}
