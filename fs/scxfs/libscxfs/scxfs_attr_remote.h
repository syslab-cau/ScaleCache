// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2013 Red Hat, Inc.
 * All Rights Reserved.
 */
#ifndef __SCXFS_ATTR_REMOTE_H__
#define	__SCXFS_ATTR_REMOTE_H__

int scxfs_attr3_rmt_blocks(struct scxfs_mount *mp, int attrlen);

int scxfs_attr_rmtval_get(struct scxfs_da_args *args);
int scxfs_attr_rmtval_set(struct scxfs_da_args *args);
int scxfs_attr_rmtval_remove(struct scxfs_da_args *args);

#endif /* __SCXFS_ATTR_REMOTE_H__ */
