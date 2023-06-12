// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2006 Silicon Graphics, Inc.
 * Copyright (c) 2013 Red Hat, Inc.
 * All Rights Reserved.
 */
#include "scxfs.h"
#include "scxfs_fs.h"
#include "scxfs_shared.h"
#include "scxfs_format.h"
#include "scxfs_log_format.h"
#include "scxfs_trans_resv.h"
#include "scxfs_mount.h"
#include "scxfs_inode.h"
#include "scxfs_quota.h"
#include "scxfs_trans.h"
#include "scxfs_qm.h"
#include "scxfs_error.h"

int
scxfs_calc_dquots_per_chunk(
	unsigned int		nbblks)	/* basic block units */
{
	ASSERT(nbblks > 0);
	return BBTOB(nbblks) / sizeof(scxfs_dqblk_t);
}

/*
 * Do some primitive error checking on ondisk dquot data structures.
 *
 * The scxfs_dqblk structure /contains/ the scxfs_disk_dquot structure;
 * we verify them separately because at some points we have only the
 * smaller scxfs_disk_dquot structure available.
 */

scxfs_failaddr_t
scxfs_dquot_verify(
	struct scxfs_mount *mp,
	scxfs_disk_dquot_t *ddq,
	scxfs_dqid_t	 id,
	uint		 type)	  /* used only during quotacheck */
{
	/*
	 * We can encounter an uninitialized dquot buffer for 2 reasons:
	 * 1. If we crash while deleting the quotainode(s), and those blks got
	 *    used for user data. This is because we take the path of regular
	 *    file deletion; however, the size field of quotainodes is never
	 *    updated, so all the tricks that we play in itruncate_finish
	 *    don't quite matter.
	 *
	 * 2. We don't play the quota buffers when there's a quotaoff logitem.
	 *    But the allocation will be replayed so we'll end up with an
	 *    uninitialized quota block.
	 *
	 * This is all fine; things are still consistent, and we haven't lost
	 * any quota information. Just don't complain about bad dquot blks.
	 */
	if (ddq->d_magic != cpu_to_be16(SCXFS_DQUOT_MAGIC))
		return __this_address;
	if (ddq->d_version != SCXFS_DQUOT_VERSION)
		return __this_address;

	if (type && ddq->d_flags != type)
		return __this_address;
	if (ddq->d_flags != SCXFS_DQ_USER &&
	    ddq->d_flags != SCXFS_DQ_PROJ &&
	    ddq->d_flags != SCXFS_DQ_GROUP)
		return __this_address;

	if (id != -1 && id != be32_to_cpu(ddq->d_id))
		return __this_address;

	if (!ddq->d_id)
		return NULL;

	if (ddq->d_blk_softlimit &&
	    be64_to_cpu(ddq->d_bcount) > be64_to_cpu(ddq->d_blk_softlimit) &&
	    !ddq->d_btimer)
		return __this_address;

	if (ddq->d_ino_softlimit &&
	    be64_to_cpu(ddq->d_icount) > be64_to_cpu(ddq->d_ino_softlimit) &&
	    !ddq->d_itimer)
		return __this_address;

	if (ddq->d_rtb_softlimit &&
	    be64_to_cpu(ddq->d_rtbcount) > be64_to_cpu(ddq->d_rtb_softlimit) &&
	    !ddq->d_rtbtimer)
		return __this_address;

	return NULL;
}

scxfs_failaddr_t
scxfs_dqblk_verify(
	struct scxfs_mount	*mp,
	struct scxfs_dqblk	*dqb,
	scxfs_dqid_t	 	id,
	uint		 	type)	/* used only during quotacheck */
{
	if (scxfs_sb_version_hascrc(&mp->m_sb) &&
	    !uuid_equal(&dqb->dd_uuid, &mp->m_sb.sb_meta_uuid))
		return __this_address;

	return scxfs_dquot_verify(mp, &dqb->dd_diskdq, id, type);
}

/*
 * Do some primitive error checking on ondisk dquot data structures.
 */
void
scxfs_dqblk_repair(
	struct scxfs_mount	*mp,
	struct scxfs_dqblk	*dqb,
	scxfs_dqid_t		id,
	uint			type)
{
	/*
	 * Typically, a repair is only requested by quotacheck.
	 */
	ASSERT(id != -1);
	memset(dqb, 0, sizeof(scxfs_dqblk_t));

	dqb->dd_diskdq.d_magic = cpu_to_be16(SCXFS_DQUOT_MAGIC);
	dqb->dd_diskdq.d_version = SCXFS_DQUOT_VERSION;
	dqb->dd_diskdq.d_flags = type;
	dqb->dd_diskdq.d_id = cpu_to_be32(id);

	if (scxfs_sb_version_hascrc(&mp->m_sb)) {
		uuid_copy(&dqb->dd_uuid, &mp->m_sb.sb_meta_uuid);
		scxfs_update_cksum((char *)dqb, sizeof(struct scxfs_dqblk),
				 SCXFS_DQUOT_CRC_OFF);
	}
}

STATIC bool
scxfs_dquot_buf_verify_crc(
	struct scxfs_mount	*mp,
	struct scxfs_buf		*bp,
	bool			readahead)
{
	struct scxfs_dqblk	*d = (struct scxfs_dqblk *)bp->b_addr;
	int			ndquots;
	int			i;

	if (!scxfs_sb_version_hascrc(&mp->m_sb))
		return true;

	/*
	 * if we are in log recovery, the quota subsystem has not been
	 * initialised so we have no quotainfo structure. In that case, we need
	 * to manually calculate the number of dquots in the buffer.
	 */
	if (mp->m_quotainfo)
		ndquots = mp->m_quotainfo->qi_dqperchunk;
	else
		ndquots = scxfs_calc_dquots_per_chunk(bp->b_length);

	for (i = 0; i < ndquots; i++, d++) {
		if (!scxfs_verify_cksum((char *)d, sizeof(struct scxfs_dqblk),
				 SCXFS_DQUOT_CRC_OFF)) {
			if (!readahead)
				scxfs_buf_verifier_error(bp, -EFSBADCRC, __func__,
					d, sizeof(*d), __this_address);
			return false;
		}
	}
	return true;
}

STATIC scxfs_failaddr_t
scxfs_dquot_buf_verify(
	struct scxfs_mount	*mp,
	struct scxfs_buf		*bp,
	bool			readahead)
{
	struct scxfs_dqblk	*dqb = bp->b_addr;
	scxfs_failaddr_t		fa;
	scxfs_dqid_t		id = 0;
	int			ndquots;
	int			i;

	/*
	 * if we are in log recovery, the quota subsystem has not been
	 * initialised so we have no quotainfo structure. In that case, we need
	 * to manually calculate the number of dquots in the buffer.
	 */
	if (mp->m_quotainfo)
		ndquots = mp->m_quotainfo->qi_dqperchunk;
	else
		ndquots = scxfs_calc_dquots_per_chunk(bp->b_length);

	/*
	 * On the first read of the buffer, verify that each dquot is valid.
	 * We don't know what the id of the dquot is supposed to be, just that
	 * they should be increasing monotonically within the buffer. If the
	 * first id is corrupt, then it will fail on the second dquot in the
	 * buffer so corruptions could point to the wrong dquot in this case.
	 */
	for (i = 0; i < ndquots; i++) {
		struct scxfs_disk_dquot	*ddq;

		ddq = &dqb[i].dd_diskdq;

		if (i == 0)
			id = be32_to_cpu(ddq->d_id);

		fa = scxfs_dqblk_verify(mp, &dqb[i], id + i, 0);
		if (fa) {
			if (!readahead)
				scxfs_buf_verifier_error(bp, -EFSCORRUPTED,
					__func__, &dqb[i],
					sizeof(struct scxfs_dqblk), fa);
			return fa;
		}
	}

	return NULL;
}

static scxfs_failaddr_t
scxfs_dquot_buf_verify_struct(
	struct scxfs_buf		*bp)
{
	struct scxfs_mount	*mp = bp->b_mount;

	return scxfs_dquot_buf_verify(mp, bp, false);
}

static void
scxfs_dquot_buf_read_verify(
	struct scxfs_buf		*bp)
{
	struct scxfs_mount	*mp = bp->b_mount;

	if (!scxfs_dquot_buf_verify_crc(mp, bp, false))
		return;
	scxfs_dquot_buf_verify(mp, bp, false);
}

/*
 * readahead errors are silent and simply leave the buffer as !done so a real
 * read will then be run with the scxfs_dquot_buf_ops verifier. See
 * scxfs_inode_buf_verify() for why we use EIO and ~XBF_DONE here rather than
 * reporting the failure.
 */
static void
scxfs_dquot_buf_readahead_verify(
	struct scxfs_buf	*bp)
{
	struct scxfs_mount	*mp = bp->b_mount;

	if (!scxfs_dquot_buf_verify_crc(mp, bp, true) ||
	    scxfs_dquot_buf_verify(mp, bp, true) != NULL) {
		scxfs_buf_ioerror(bp, -EIO);
		bp->b_flags &= ~XBF_DONE;
	}
}

/*
 * we don't calculate the CRC here as that is done when the dquot is flushed to
 * the buffer after the update is done. This ensures that the dquot in the
 * buffer always has an up-to-date CRC value.
 */
static void
scxfs_dquot_buf_write_verify(
	struct scxfs_buf		*bp)
{
	struct scxfs_mount	*mp = bp->b_mount;

	scxfs_dquot_buf_verify(mp, bp, false);
}

const struct scxfs_buf_ops scxfs_dquot_buf_ops = {
	.name = "scxfs_dquot",
	.magic16 = { cpu_to_be16(SCXFS_DQUOT_MAGIC),
		     cpu_to_be16(SCXFS_DQUOT_MAGIC) },
	.verify_read = scxfs_dquot_buf_read_verify,
	.verify_write = scxfs_dquot_buf_write_verify,
	.verify_struct = scxfs_dquot_buf_verify_struct,
};

const struct scxfs_buf_ops scxfs_dquot_buf_ra_ops = {
	.name = "scxfs_dquot_ra",
	.magic16 = { cpu_to_be16(SCXFS_DQUOT_MAGIC),
		     cpu_to_be16(SCXFS_DQUOT_MAGIC) },
	.verify_read = scxfs_dquot_buf_readahead_verify,
	.verify_write = scxfs_dquot_buf_write_verify,
};
