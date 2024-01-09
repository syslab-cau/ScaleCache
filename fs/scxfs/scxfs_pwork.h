/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2019 Oracle.  All Rights Reserved.
 * Author: Darrick J. Wong <darrick.wong@oracle.com>
 */
#ifndef __SCXFS_PWORK_H__
#define __SCXFS_PWORK_H__

struct scxfs_pwork;
struct scxfs_mount;

typedef int (*scxfs_pwork_work_fn)(struct scxfs_mount *mp, struct scxfs_pwork *pwork);

/*
 * Parallel work coordination structure.
 */
struct scxfs_pwork_ctl {
	struct workqueue_struct	*wq;
	struct scxfs_mount	*mp;
	scxfs_pwork_work_fn	work_fn;
	struct wait_queue_head	poll_wait;
	atomic_t		nr_work;
	int			error;
};

/*
 * Embed this parallel work control item inside your own work structure,
 * then queue work with it.
 */
struct scxfs_pwork {
	struct work_struct	work;
	struct scxfs_pwork_ctl	*pctl;
};

#define SCXFS_PWORK_SINGLE_THREADED	{ .pctl = NULL }

/* Have we been told to abort? */
static inline bool
scxfs_pwork_ctl_want_abort(
	struct scxfs_pwork_ctl	*pctl)
{
	return pctl && pctl->error;
}

/* Have we been told to abort? */
static inline bool
scxfs_pwork_want_abort(
	struct scxfs_pwork	*pwork)
{
	return scxfs_pwork_ctl_want_abort(pwork->pctl);
}

int scxfs_pwork_init(struct scxfs_mount *mp, struct scxfs_pwork_ctl *pctl,
		scxfs_pwork_work_fn work_fn, const char *tag,
		unsigned int nr_threads);
void scxfs_pwork_queue(struct scxfs_pwork_ctl *pctl, struct scxfs_pwork *pwork);
int scxfs_pwork_destroy(struct scxfs_pwork_ctl *pctl);
void scxfs_pwork_poll(struct scxfs_pwork_ctl *pctl);
unsigned int scxfs_pwork_guess_datadev_parallelism(struct scxfs_mount *mp);

#endif /* __SCXFS_PWORK_H__ */
