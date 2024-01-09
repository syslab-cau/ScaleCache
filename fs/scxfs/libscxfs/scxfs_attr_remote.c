// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2005 Silicon Graphics, Inc.
 * Copyright (c) 2013 Red Hat, Inc.
 * All Rights Reserved.
 */
#include "scxfs.h"
#include "scxfs_fs.h"
#include "scxfs_shared.h"
#include "scxfs_format.h"
#include "scxfs_log_format.h"
#include "scxfs_trans_resv.h"
#include "scxfs_bit.h"
#include "scxfs_mount.h"
#include "scxfs_defer.h"
#include "scxfs_da_format.h"
#include "scxfs_da_btree.h"
#include "scxfs_inode.h"
#include "scxfs_trans.h"
#include "scxfs_bmap.h"
#include "scxfs_attr.h"
#include "scxfs_trace.h"
#include "scxfs_error.h"

#define ATTR_RMTVALUE_MAPSIZE	1	/* # of map entries at once */

/*
 * Each contiguous block has a header, so it is not just a simple attribute
 * length to FSB conversion.
 */
int
scxfs_attr3_rmt_blocks(
	struct scxfs_mount *mp,
	int		attrlen)
{
	if (scxfs_sb_version_hascrc(&mp->m_sb)) {
		int buflen = SCXFS_ATTR3_RMT_BUF_SPACE(mp, mp->m_sb.sb_blocksize);
		return (attrlen + buflen - 1) / buflen;
	}
	return SCXFS_B_TO_FSB(mp, attrlen);
}

/*
 * Checking of the remote attribute header is split into two parts. The verifier
 * does CRC, location and bounds checking, the unpacking function checks the
 * attribute parameters and owner.
 */
static scxfs_failaddr_t
scxfs_attr3_rmt_hdr_ok(
	void			*ptr,
	scxfs_ino_t		ino,
	uint32_t		offset,
	uint32_t		size,
	scxfs_daddr_t		bno)
{
	struct scxfs_attr3_rmt_hdr *rmt = ptr;

	if (bno != be64_to_cpu(rmt->rm_blkno))
		return __this_address;
	if (offset != be32_to_cpu(rmt->rm_offset))
		return __this_address;
	if (size != be32_to_cpu(rmt->rm_bytes))
		return __this_address;
	if (ino != be64_to_cpu(rmt->rm_owner))
		return __this_address;

	/* ok */
	return NULL;
}

static scxfs_failaddr_t
scxfs_attr3_rmt_verify(
	struct scxfs_mount	*mp,
	struct scxfs_buf		*bp,
	void			*ptr,
	int			fsbsize,
	scxfs_daddr_t		bno)
{
	struct scxfs_attr3_rmt_hdr *rmt = ptr;

	if (!scxfs_sb_version_hascrc(&mp->m_sb))
		return __this_address;
	if (!scxfs_verify_magic(bp, rmt->rm_magic))
		return __this_address;
	if (!uuid_equal(&rmt->rm_uuid, &mp->m_sb.sb_meta_uuid))
		return __this_address;
	if (be64_to_cpu(rmt->rm_blkno) != bno)
		return __this_address;
	if (be32_to_cpu(rmt->rm_bytes) > fsbsize - sizeof(*rmt))
		return __this_address;
	if (be32_to_cpu(rmt->rm_offset) +
				be32_to_cpu(rmt->rm_bytes) > SCXFS_XATTR_SIZE_MAX)
		return __this_address;
	if (rmt->rm_owner == 0)
		return __this_address;

	return NULL;
}

static int
__scxfs_attr3_rmt_read_verify(
	struct scxfs_buf	*bp,
	bool		check_crc,
	scxfs_failaddr_t	*failaddr)
{
	struct scxfs_mount *mp = bp->b_mount;
	char		*ptr;
	int		len;
	scxfs_daddr_t	bno;
	int		blksize = mp->m_attr_geo->blksize;

	/* no verification of non-crc buffers */
	if (!scxfs_sb_version_hascrc(&mp->m_sb))
		return 0;

	ptr = bp->b_addr;
	bno = bp->b_bn;
	len = BBTOB(bp->b_length);
	ASSERT(len >= blksize);

	while (len > 0) {
		if (check_crc &&
		    !scxfs_verify_cksum(ptr, blksize, SCXFS_ATTR3_RMT_CRC_OFF)) {
			*failaddr = __this_address;
			return -EFSBADCRC;
		}
		*failaddr = scxfs_attr3_rmt_verify(mp, bp, ptr, blksize, bno);
		if (*failaddr)
			return -EFSCORRUPTED;
		len -= blksize;
		ptr += blksize;
		bno += BTOBB(blksize);
	}

	if (len != 0) {
		*failaddr = __this_address;
		return -EFSCORRUPTED;
	}

	return 0;
}

static void
scxfs_attr3_rmt_read_verify(
	struct scxfs_buf	*bp)
{
	scxfs_failaddr_t	fa;
	int		error;

	error = __scxfs_attr3_rmt_read_verify(bp, true, &fa);
	if (error)
		scxfs_verifier_error(bp, error, fa);
}

static scxfs_failaddr_t
scxfs_attr3_rmt_verify_struct(
	struct scxfs_buf	*bp)
{
	scxfs_failaddr_t	fa;
	int		error;

	error = __scxfs_attr3_rmt_read_verify(bp, false, &fa);
	return error ? fa : NULL;
}

static void
scxfs_attr3_rmt_write_verify(
	struct scxfs_buf	*bp)
{
	struct scxfs_mount *mp = bp->b_mount;
	scxfs_failaddr_t	fa;
	int		blksize = mp->m_attr_geo->blksize;
	char		*ptr;
	int		len;
	scxfs_daddr_t	bno;

	/* no verification of non-crc buffers */
	if (!scxfs_sb_version_hascrc(&mp->m_sb))
		return;

	ptr = bp->b_addr;
	bno = bp->b_bn;
	len = BBTOB(bp->b_length);
	ASSERT(len >= blksize);

	while (len > 0) {
		struct scxfs_attr3_rmt_hdr *rmt = (struct scxfs_attr3_rmt_hdr *)ptr;

		fa = scxfs_attr3_rmt_verify(mp, bp, ptr, blksize, bno);
		if (fa) {
			scxfs_verifier_error(bp, -EFSCORRUPTED, fa);
			return;
		}

		/*
		 * Ensure we aren't writing bogus LSNs to disk. See
		 * scxfs_attr3_rmt_hdr_set() for the explanation.
		 */
		if (rmt->rm_lsn != cpu_to_be64(NULLCOMMITLSN)) {
			scxfs_verifier_error(bp, -EFSCORRUPTED, __this_address);
			return;
		}
		scxfs_update_cksum(ptr, blksize, SCXFS_ATTR3_RMT_CRC_OFF);

		len -= blksize;
		ptr += blksize;
		bno += BTOBB(blksize);
	}

	if (len != 0)
		scxfs_verifier_error(bp, -EFSCORRUPTED, __this_address);
}

const struct scxfs_buf_ops scxfs_attr3_rmt_buf_ops = {
	.name = "scxfs_attr3_rmt",
	.magic = { 0, cpu_to_be32(SCXFS_ATTR3_RMT_MAGIC) },
	.verify_read = scxfs_attr3_rmt_read_verify,
	.verify_write = scxfs_attr3_rmt_write_verify,
	.verify_struct = scxfs_attr3_rmt_verify_struct,
};

STATIC int
scxfs_attr3_rmt_hdr_set(
	struct scxfs_mount	*mp,
	void			*ptr,
	scxfs_ino_t		ino,
	uint32_t		offset,
	uint32_t		size,
	scxfs_daddr_t		bno)
{
	struct scxfs_attr3_rmt_hdr *rmt = ptr;

	if (!scxfs_sb_version_hascrc(&mp->m_sb))
		return 0;

	rmt->rm_magic = cpu_to_be32(SCXFS_ATTR3_RMT_MAGIC);
	rmt->rm_offset = cpu_to_be32(offset);
	rmt->rm_bytes = cpu_to_be32(size);
	uuid_copy(&rmt->rm_uuid, &mp->m_sb.sb_meta_uuid);
	rmt->rm_owner = cpu_to_be64(ino);
	rmt->rm_blkno = cpu_to_be64(bno);

	/*
	 * Remote attribute blocks are written synchronously, so we don't
	 * have an LSN that we can stamp in them that makes any sense to log
	 * recovery. To ensure that log recovery handles overwrites of these
	 * blocks sanely (i.e. once they've been freed and reallocated as some
	 * other type of metadata) we need to ensure that the LSN has a value
	 * that tells log recovery to ignore the LSN and overwrite the buffer
	 * with whatever is in it's log. To do this, we use the magic
	 * NULLCOMMITLSN to indicate that the LSN is invalid.
	 */
	rmt->rm_lsn = cpu_to_be64(NULLCOMMITLSN);

	return sizeof(struct scxfs_attr3_rmt_hdr);
}

/*
 * Helper functions to copy attribute data in and out of the one disk extents
 */
STATIC int
scxfs_attr_rmtval_copyout(
	struct scxfs_mount *mp,
	struct scxfs_buf	*bp,
	scxfs_ino_t	ino,
	int		*offset,
	int		*valuelen,
	uint8_t		**dst)
{
	char		*src = bp->b_addr;
	scxfs_daddr_t	bno = bp->b_bn;
	int		len = BBTOB(bp->b_length);
	int		blksize = mp->m_attr_geo->blksize;

	ASSERT(len >= blksize);

	while (len > 0 && *valuelen > 0) {
		int hdr_size = 0;
		int byte_cnt = SCXFS_ATTR3_RMT_BUF_SPACE(mp, blksize);

		byte_cnt = min(*valuelen, byte_cnt);

		if (scxfs_sb_version_hascrc(&mp->m_sb)) {
			if (scxfs_attr3_rmt_hdr_ok(src, ino, *offset,
						  byte_cnt, bno)) {
				scxfs_alert(mp,
"remote attribute header mismatch bno/off/len/owner (0x%llx/0x%x/Ox%x/0x%llx)",
					bno, *offset, byte_cnt, ino);
				return -EFSCORRUPTED;
			}
			hdr_size = sizeof(struct scxfs_attr3_rmt_hdr);
		}

		memcpy(*dst, src + hdr_size, byte_cnt);

		/* roll buffer forwards */
		len -= blksize;
		src += blksize;
		bno += BTOBB(blksize);

		/* roll attribute data forwards */
		*valuelen -= byte_cnt;
		*dst += byte_cnt;
		*offset += byte_cnt;
	}
	return 0;
}

STATIC void
scxfs_attr_rmtval_copyin(
	struct scxfs_mount *mp,
	struct scxfs_buf	*bp,
	scxfs_ino_t	ino,
	int		*offset,
	int		*valuelen,
	uint8_t		**src)
{
	char		*dst = bp->b_addr;
	scxfs_daddr_t	bno = bp->b_bn;
	int		len = BBTOB(bp->b_length);
	int		blksize = mp->m_attr_geo->blksize;

	ASSERT(len >= blksize);

	while (len > 0 && *valuelen > 0) {
		int hdr_size;
		int byte_cnt = SCXFS_ATTR3_RMT_BUF_SPACE(mp, blksize);

		byte_cnt = min(*valuelen, byte_cnt);
		hdr_size = scxfs_attr3_rmt_hdr_set(mp, dst, ino, *offset,
						 byte_cnt, bno);

		memcpy(dst + hdr_size, *src, byte_cnt);

		/*
		 * If this is the last block, zero the remainder of it.
		 * Check that we are actually the last block, too.
		 */
		if (byte_cnt + hdr_size < blksize) {
			ASSERT(*valuelen - byte_cnt == 0);
			ASSERT(len == blksize);
			memset(dst + hdr_size + byte_cnt, 0,
					blksize - hdr_size - byte_cnt);
		}

		/* roll buffer forwards */
		len -= blksize;
		dst += blksize;
		bno += BTOBB(blksize);

		/* roll attribute data forwards */
		*valuelen -= byte_cnt;
		*src += byte_cnt;
		*offset += byte_cnt;
	}
}

/*
 * Read the value associated with an attribute from the out-of-line buffer
 * that we stored it in.
 *
 * Returns 0 on successful retrieval, otherwise an error.
 */
int
scxfs_attr_rmtval_get(
	struct scxfs_da_args	*args)
{
	struct scxfs_bmbt_irec	map[ATTR_RMTVALUE_MAPSIZE];
	struct scxfs_mount	*mp = args->dp->i_mount;
	struct scxfs_buf		*bp;
	scxfs_dablk_t		lblkno = args->rmtblkno;
	uint8_t			*dst = args->value;
	int			valuelen;
	int			nmap;
	int			error;
	int			blkcnt = args->rmtblkcnt;
	int			i;
	int			offset = 0;

	trace_scxfs_attr_rmtval_get(args);

	ASSERT(!(args->flags & ATTR_KERNOVAL));
	ASSERT(args->rmtvaluelen == args->valuelen);

	valuelen = args->rmtvaluelen;
	while (valuelen > 0) {
		nmap = ATTR_RMTVALUE_MAPSIZE;
		error = scxfs_bmapi_read(args->dp, (scxfs_fileoff_t)lblkno,
				       blkcnt, map, &nmap,
				       SCXFS_BMAPI_ATTRFORK);
		if (error)
			return error;
		ASSERT(nmap >= 1);

		for (i = 0; (i < nmap) && (valuelen > 0); i++) {
			scxfs_daddr_t	dblkno;
			int		dblkcnt;

			ASSERT((map[i].br_startblock != DELAYSTARTBLOCK) &&
			       (map[i].br_startblock != HOLESTARTBLOCK));
			dblkno = SCXFS_FSB_TO_DADDR(mp, map[i].br_startblock);
			dblkcnt = SCXFS_FSB_TO_BB(mp, map[i].br_blockcount);
			error = scxfs_trans_read_buf(mp, args->trans,
						   mp->m_ddev_targp,
						   dblkno, dblkcnt, 0, &bp,
						   &scxfs_attr3_rmt_buf_ops);
			if (error)
				return error;

			error = scxfs_attr_rmtval_copyout(mp, bp, args->dp->i_ino,
							&offset, &valuelen,
							&dst);
			scxfs_trans_brelse(args->trans, bp);
			if (error)
				return error;

			/* roll attribute extent map forwards */
			lblkno += map[i].br_blockcount;
			blkcnt -= map[i].br_blockcount;
		}
	}
	ASSERT(valuelen == 0);
	return 0;
}

/*
 * Write the value associated with an attribute into the out-of-line buffer
 * that we have defined for it.
 */
int
scxfs_attr_rmtval_set(
	struct scxfs_da_args	*args)
{
	struct scxfs_inode	*dp = args->dp;
	struct scxfs_mount	*mp = dp->i_mount;
	struct scxfs_bmbt_irec	map;
	scxfs_dablk_t		lblkno;
	scxfs_fileoff_t		lfileoff = 0;
	uint8_t			*src = args->value;
	int			blkcnt;
	int			valuelen;
	int			nmap;
	int			error;
	int			offset = 0;

	trace_scxfs_attr_rmtval_set(args);

	/*
	 * Find a "hole" in the attribute address space large enough for
	 * us to drop the new attribute's value into. Because CRC enable
	 * attributes have headers, we can't just do a straight byte to FSB
	 * conversion and have to take the header space into account.
	 */
	blkcnt = scxfs_attr3_rmt_blocks(mp, args->rmtvaluelen);
	error = scxfs_bmap_first_unused(args->trans, args->dp, blkcnt, &lfileoff,
						   SCXFS_ATTR_FORK);
	if (error)
		return error;

	args->rmtblkno = lblkno = (scxfs_dablk_t)lfileoff;
	args->rmtblkcnt = blkcnt;

	/*
	 * Roll through the "value", allocating blocks on disk as required.
	 */
	while (blkcnt > 0) {
		/*
		 * Allocate a single extent, up to the size of the value.
		 *
		 * Note that we have to consider this a data allocation as we
		 * write the remote attribute without logging the contents.
		 * Hence we must ensure that we aren't using blocks that are on
		 * the busy list so that we don't overwrite blocks which have
		 * recently been freed but their transactions are not yet
		 * committed to disk. If we overwrite the contents of a busy
		 * extent and then crash then the block may not contain the
		 * correct metadata after log recovery occurs.
		 */
		nmap = 1;
		error = scxfs_bmapi_write(args->trans, dp, (scxfs_fileoff_t)lblkno,
				  blkcnt, SCXFS_BMAPI_ATTRFORK, args->total, &map,
				  &nmap);
		if (error)
			return error;
		error = scxfs_defer_finish(&args->trans);
		if (error)
			return error;

		ASSERT(nmap == 1);
		ASSERT((map.br_startblock != DELAYSTARTBLOCK) &&
		       (map.br_startblock != HOLESTARTBLOCK));
		lblkno += map.br_blockcount;
		blkcnt -= map.br_blockcount;

		/*
		 * Start the next trans in the chain.
		 */
		error = scxfs_trans_roll_inode(&args->trans, dp);
		if (error)
			return error;
	}

	/*
	 * Roll through the "value", copying the attribute value to the
	 * already-allocated blocks.  Blocks are written synchronously
	 * so that we can know they are all on disk before we turn off
	 * the INCOMPLETE flag.
	 */
	lblkno = args->rmtblkno;
	blkcnt = args->rmtblkcnt;
	valuelen = args->rmtvaluelen;
	while (valuelen > 0) {
		struct scxfs_buf	*bp;
		scxfs_daddr_t	dblkno;
		int		dblkcnt;

		ASSERT(blkcnt > 0);

		nmap = 1;
		error = scxfs_bmapi_read(dp, (scxfs_fileoff_t)lblkno,
				       blkcnt, &map, &nmap,
				       SCXFS_BMAPI_ATTRFORK);
		if (error)
			return error;
		ASSERT(nmap == 1);
		ASSERT((map.br_startblock != DELAYSTARTBLOCK) &&
		       (map.br_startblock != HOLESTARTBLOCK));

		dblkno = SCXFS_FSB_TO_DADDR(mp, map.br_startblock),
		dblkcnt = SCXFS_FSB_TO_BB(mp, map.br_blockcount);

		bp = scxfs_buf_get(mp->m_ddev_targp, dblkno, dblkcnt);
		if (!bp)
			return -ENOMEM;
		bp->b_ops = &scxfs_attr3_rmt_buf_ops;

		scxfs_attr_rmtval_copyin(mp, bp, args->dp->i_ino, &offset,
				       &valuelen, &src);

		error = scxfs_bwrite(bp);	/* GROT: NOTE: synchronous write */
		scxfs_buf_relse(bp);
		if (error)
			return error;


		/* roll attribute extent map forwards */
		lblkno += map.br_blockcount;
		blkcnt -= map.br_blockcount;
	}
	ASSERT(valuelen == 0);
	return 0;
}

/*
 * Remove the value associated with an attribute by deleting the
 * out-of-line buffer that it is stored on.
 */
int
scxfs_attr_rmtval_remove(
	struct scxfs_da_args	*args)
{
	struct scxfs_mount	*mp = args->dp->i_mount;
	scxfs_dablk_t		lblkno;
	int			blkcnt;
	int			error;
	int			done;

	trace_scxfs_attr_rmtval_remove(args);

	/*
	 * Roll through the "value", invalidating the attribute value's blocks.
	 */
	lblkno = args->rmtblkno;
	blkcnt = args->rmtblkcnt;
	while (blkcnt > 0) {
		struct scxfs_bmbt_irec	map;
		struct scxfs_buf		*bp;
		scxfs_daddr_t		dblkno;
		int			dblkcnt;
		int			nmap;

		/*
		 * Try to remember where we decided to put the value.
		 */
		nmap = 1;
		error = scxfs_bmapi_read(args->dp, (scxfs_fileoff_t)lblkno,
				       blkcnt, &map, &nmap, SCXFS_BMAPI_ATTRFORK);
		if (error)
			return error;
		ASSERT(nmap == 1);
		ASSERT((map.br_startblock != DELAYSTARTBLOCK) &&
		       (map.br_startblock != HOLESTARTBLOCK));

		dblkno = SCXFS_FSB_TO_DADDR(mp, map.br_startblock),
		dblkcnt = SCXFS_FSB_TO_BB(mp, map.br_blockcount);

		/*
		 * If the "remote" value is in the cache, remove it.
		 */
		bp = scxfs_buf_incore(mp->m_ddev_targp, dblkno, dblkcnt, XBF_TRYLOCK);
		if (bp) {
			scxfs_buf_stale(bp);
			scxfs_buf_relse(bp);
			bp = NULL;
		}

		lblkno += map.br_blockcount;
		blkcnt -= map.br_blockcount;
	}

	/*
	 * Keep de-allocating extents until the remote-value region is gone.
	 */
	lblkno = args->rmtblkno;
	blkcnt = args->rmtblkcnt;
	done = 0;
	while (!done) {
		error = scxfs_bunmapi(args->trans, args->dp, lblkno, blkcnt,
				    SCXFS_BMAPI_ATTRFORK, 1, &done);
		if (error)
			return error;
		error = scxfs_defer_finish(&args->trans);
		if (error)
			return error;

		/*
		 * Close out trans and start the next one in the chain.
		 */
		error = scxfs_trans_roll_inode(&args->trans, args->dp);
		if (error)
			return error;
	}
	return 0;
}
