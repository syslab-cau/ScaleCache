/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2018 Red Hat, Inc.
 * All rights reserved.
 */

#ifndef __LIBSCXFS_AG_H
#define __LIBSCXFS_AG_H 1

struct scxfs_mount;
struct scxfs_trans;

struct aghdr_init_data {
	/* per ag data */
	scxfs_agblock_t		agno;		/* ag to init */
	scxfs_extlen_t		agsize;		/* new AG size */
	struct list_head	buffer_list;	/* buffer writeback list */
	scxfs_rfsblock_t		nfree;		/* cumulative new free space */

	/* per header data */
	scxfs_daddr_t		daddr;		/* header location */
	size_t			numblks;	/* size of header */
	scxfs_btnum_t		type;		/* type of btree root block */
};

int scxfs_ag_init_headers(struct scxfs_mount *mp, struct aghdr_init_data *id);
int scxfs_ag_extend_space(struct scxfs_mount *mp, struct scxfs_trans *tp,
			struct aghdr_init_data *id, scxfs_extlen_t len);
int scxfs_ag_get_geometry(struct scxfs_mount *mp, scxfs_agnumber_t agno,
			struct scxfs_ag_geometry *ageo);

#endif /* __LIBSCXFS_AG_H */
