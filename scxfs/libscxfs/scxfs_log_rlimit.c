// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2013 Jie Liu.
 * All Rights Reserved.
 */
#include "scxfs.h"
#include "scxfs_fs.h"
#include "scxfs_shared.h"
#include "scxfs_format.h"
#include "scxfs_log_format.h"
#include "scxfs_trans_resv.h"
#include "scxfs_mount.h"
#include "scxfs_da_format.h"
#include "scxfs_trans_space.h"
#include "scxfs_da_btree.h"
#include "scxfs_bmap_btree.h"

/*
 * Calculate the maximum length in bytes that would be required for a local
 * attribute value as large attributes out of line are not logged.
 */
STATIC int
scxfs_log_calc_max_attrsetm_res(
	struct scxfs_mount	*mp)
{
	int			size;
	int			nblks;

	size = scxfs_attr_leaf_entsize_local_max(mp->m_attr_geo->blksize) -
	       MAXNAMELEN - 1;
	nblks = SCXFS_DAENTER_SPACE_RES(mp, SCXFS_ATTR_FORK);
	nblks += SCXFS_B_TO_FSB(mp, size);
	nblks += SCXFS_NEXTENTADD_SPACE_RES(mp, size, SCXFS_ATTR_FORK);

	return  M_RES(mp)->tr_attrsetm.tr_logres +
		M_RES(mp)->tr_attrsetrt.tr_logres * nblks;
}

/*
 * Iterate over the log space reservation table to figure out and return
 * the maximum one in terms of the pre-calculated values which were done
 * at mount time.
 */
void
scxfs_log_get_max_trans_res(
	struct scxfs_mount	*mp,
	struct scxfs_trans_res	*max_resp)
{
	struct scxfs_trans_res	*resp;
	struct scxfs_trans_res	*end_resp;
	int			log_space = 0;
	int			attr_space;

	attr_space = scxfs_log_calc_max_attrsetm_res(mp);

	resp = (struct scxfs_trans_res *)M_RES(mp);
	end_resp = (struct scxfs_trans_res *)(M_RES(mp) + 1);
	for (; resp < end_resp; resp++) {
		int		tmp = resp->tr_logcount > 1 ?
				      resp->tr_logres * resp->tr_logcount :
				      resp->tr_logres;
		if (log_space < tmp) {
			log_space = tmp;
			*max_resp = *resp;		/* struct copy */
		}
	}

	if (attr_space > log_space) {
		*max_resp = M_RES(mp)->tr_attrsetm;	/* struct copy */
		max_resp->tr_logres = attr_space;
	}
}

/*
 * Calculate the minimum valid log size for the given superblock configuration.
 * Used to calculate the minimum log size at mkfs time, and to determine if
 * the log is large enough or not at mount time. Returns the minimum size in
 * filesystem block size units.
 */
int
scxfs_log_calc_minimum_size(
	struct scxfs_mount	*mp)
{
	struct scxfs_trans_res	tres = {0};
	int			max_logres;
	int			min_logblks = 0;
	int			lsunit = 0;

	scxfs_log_get_max_trans_res(mp, &tres);

	max_logres = scxfs_log_calc_unit_res(mp, tres.tr_logres);
	if (tres.tr_logcount > 1)
		max_logres *= tres.tr_logcount;

	if (scxfs_sb_version_haslogv2(&mp->m_sb) && mp->m_sb.sb_logsunit > 1)
		lsunit = BTOBB(mp->m_sb.sb_logsunit);

	/*
	 * Two factors should be taken into account for calculating the minimum
	 * log space.
	 * 1) The fundamental limitation is that no single transaction can be
	 *    larger than half size of the log.
	 *
	 *    From mkfs.xfs, this is considered by the SCXFS_MIN_LOG_FACTOR
	 *    define, which is set to 3. That means we can definitely fit
	 *    maximally sized 2 transactions in the log. We'll use this same
	 *    value here.
	 *
	 * 2) If the lsunit option is specified, a transaction requires 2 LSU
	 *    for the reservation because there are two log writes that can
	 *    require padding - the transaction data and the commit record which
	 *    are written separately and both can require padding to the LSU.
	 *    Consider that we can have an active CIL reservation holding 2*LSU,
	 *    but the CIL is not over a push threshold, in this case, if we
	 *    don't have enough log space for at one new transaction, which
	 *    includes another 2*LSU in the reservation, we will run into dead
	 *    loop situation in log space grant procedure. i.e.
	 *    xlog_grant_head_wait().
	 *
	 *    Hence the log size needs to be able to contain two maximally sized
	 *    and padded transactions, which is (2 * (2 * LSU + maxlres)).
	 *
	 * Also, the log size should be a multiple of the log stripe unit, round
	 * it up to lsunit boundary if lsunit is specified.
	 */
	if (lsunit) {
		min_logblks = roundup_64(BTOBB(max_logres), lsunit) +
			      2 * lsunit;
	} else
		min_logblks = BTOBB(max_logres) + 2 * BBSIZE;
	min_logblks *= SCXFS_MIN_LOG_FACTOR;

	return SCXFS_BB_TO_FSB(mp, min_logblks);
}
