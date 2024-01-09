// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2008-2010, Dave Chinner
 * All Rights Reserved.
 */
#ifndef SCXFS_ICREATE_ITEM_H
#define SCXFS_ICREATE_ITEM_H	1

/* in memory log item structure */
struct scxfs_icreate_item {
	struct scxfs_log_item	ic_item;
	struct scxfs_icreate_log	ic_format;
};

extern kmem_zone_t *scxfs_icreate_zone;	/* inode create item zone */

void scxfs_icreate_log(struct scxfs_trans *tp, scxfs_agnumber_t agno,
			scxfs_agblock_t agbno, unsigned int count,
			unsigned int inode_size, scxfs_agblock_t length,
			unsigned int generation);

#endif	/* SCXFS_ICREATE_ITEM_H */
