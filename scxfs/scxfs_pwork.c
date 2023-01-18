// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2019 Oracle.  All Rights Reserved.
 * Author: Darrick J. Wong <darrick.wong@oracle.com>
 */
#include "scxfs.h"
#include "scxfs_fs.h"
#include "scxfs_shared.h"
#include "scxfs_format.h"
#include "scxfs_log_format.h"
#include "scxfs_trans_resv.h"
#include "scxfs_mount.h"
#include "scxfs_trace.h"
#include "scxfs_sysctl.h"
#include "scxfs_pwork.h"
#include <linux/nmi.h>

/*
 * Parallel Work Queue
 * ===================
 *
 * Abstract away the details of running a large and "obviously" parallelizable
 * task across multiple CPUs.  Callers initialize the pwork control object with
 * a desired level of parallelization and a work function.  Next, they embed
 * struct scxfs_pwork in whatever structure they use to pass work context to a
 * worker thread and queue that pwork.  The work function will be passed the
 * pwork item when it is run (from process context) and any returned error will
 * be recorded in scxfs_pwork_ctl.error.  Work functions should check for errors
 * and abort if necessary; the non-zeroness of scxfs_pwork_ctl.error does not
 * stop workqueue item processing.
 *
 * This is the rough equivalent of the xfsprogs workqueue code, though we can't
 * reuse that name here.
 */

/* Invoke our caller's function. */
static void
scxfs_pwork_work(
	struct work_struct	*work)
{
	struct scxfs_pwork	*pwork;
	struct scxfs_pwork_ctl	*pctl;
	int			error;

	pwork = container_of(work, struct scxfs_pwork, work);
	pctl = pwork->pctl;
	error = pctl->work_fn(pctl->mp, pwork);
	if (error && !pctl->error)
		pctl->error = error;
	if (atomic_dec_and_test(&pctl->nr_work))
		wake_up(&pctl->poll_wait);
}

/*
 * Set up control data for parallel work.  @work_fn is the function that will
 * be called.  @tag will be written into the kernel threads.  @nr_threads is
 * the level of parallelism desired, or 0 for no limit.
 */
int
scxfs_pwork_init(
	struct scxfs_mount	*mp,
	struct scxfs_pwork_ctl	*pctl,
	scxfs_pwork_work_fn	work_fn,
	const char		*tag,
	unsigned int		nr_threads)
{
#ifdef DEBUG
	if (scxfs_globals.pwork_threads >= 0)
		nr_threads = scxfs_globals.pwork_threads;
#endif
	trace_scxfs_pwork_init(mp, nr_threads, current->pid);

	pctl->wq = alloc_workqueue("%s-%d", WQ_FREEZABLE, nr_threads, tag,
			current->pid);
	if (!pctl->wq)
		return -ENOMEM;
	pctl->work_fn = work_fn;
	pctl->error = 0;
	pctl->mp = mp;
	atomic_set(&pctl->nr_work, 0);
	init_waitqueue_head(&pctl->poll_wait);

	return 0;
}

/* Queue some parallel work. */
void
scxfs_pwork_queue(
	struct scxfs_pwork_ctl	*pctl,
	struct scxfs_pwork	*pwork)
{
	INIT_WORK(&pwork->work, scxfs_pwork_work);
	pwork->pctl = pctl;
	atomic_inc(&pctl->nr_work);
	queue_work(pctl->wq, &pwork->work);
}

/* Wait for the work to finish and tear down the control structure. */
int
scxfs_pwork_destroy(
	struct scxfs_pwork_ctl	*pctl)
{
	destroy_workqueue(pctl->wq);
	pctl->wq = NULL;
	return pctl->error;
}

/*
 * Wait for the work to finish by polling completion status and touch the soft
 * lockup watchdog.  This is for callers such as mount which hold locks.
 */
void
scxfs_pwork_poll(
	struct scxfs_pwork_ctl	*pctl)
{
	while (wait_event_timeout(pctl->poll_wait,
				atomic_read(&pctl->nr_work) == 0, HZ) == 0)
		touch_softlockup_watchdog();
}

/*
 * Return the amount of parallelism that the data device can handle, or 0 for
 * no limit.
 */
unsigned int
scxfs_pwork_guess_datadev_parallelism(
	struct scxfs_mount	*mp)
{
	struct scxfs_buftarg	*btp = mp->m_ddev_targp;

	/*
	 * For now we'll go with the most conservative setting possible,
	 * which is two threads for an SSD and 1 thread everywhere else.
	 */
	return blk_queue_nonrot(btp->bt_bdev->bd_queue) ? 2 : 1;
}
