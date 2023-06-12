// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2003 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#ifndef __SCXFS_DQUOT_ITEM_H__
#define __SCXFS_DQUOT_ITEM_H__

struct scxfs_dquot;
struct scxfs_trans;
struct scxfs_mount;
struct scxfs_qoff_logitem;

typedef struct scxfs_dq_logitem {
	struct scxfs_log_item	 qli_item;	   /* common portion */
	struct scxfs_dquot	*qli_dquot;	   /* dquot ptr */
	scxfs_lsn_t		 qli_flush_lsn;	   /* lsn at last flush */
} scxfs_dq_logitem_t;

typedef struct scxfs_qoff_logitem {
	struct scxfs_log_item	 qql_item;	/* common portion */
	struct scxfs_qoff_logitem *qql_start_lip; /* qoff-start logitem, if any */
	unsigned int		qql_flags;
} scxfs_qoff_logitem_t;


extern void		   scxfs_qm_dquot_logitem_init(struct scxfs_dquot *);
extern scxfs_qoff_logitem_t *scxfs_qm_qoff_logitem_init(struct scxfs_mount *,
					struct scxfs_qoff_logitem *, uint);
extern scxfs_qoff_logitem_t *scxfs_trans_get_qoff_item(struct scxfs_trans *,
					struct scxfs_qoff_logitem *, uint);
extern void		   scxfs_trans_log_quotaoff_item(struct scxfs_trans *,
					struct scxfs_qoff_logitem *);

#endif	/* __SCXFS_DQUOT_ITEM_H__ */
