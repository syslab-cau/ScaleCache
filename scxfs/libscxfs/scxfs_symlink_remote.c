// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2006 Silicon Graphics, Inc.
 * Copyright (c) 2012-2013 Red Hat, Inc.
 * All rights reserved.
 */
#include "scxfs.h"
#include "scxfs_fs.h"
#include "scxfs_format.h"
#include "scxfs_log_format.h"
#include "scxfs_shared.h"
#include "scxfs_trans_resv.h"
#include "scxfs_mount.h"
#include "scxfs_inode.h"
#include "scxfs_error.h"
#include "scxfs_trans.h"
#include "scxfs_buf_item.h"
#include "scxfs_log.h"


/*
 * Each contiguous block has a header, so it is not just a simple pathlen
 * to FSB conversion.
 */
int
scxfs_symlink_blocks(
	struct scxfs_mount *mp,
	int		pathlen)
{
	int buflen = SCXFS_SYMLINK_BUF_SPACE(mp, mp->m_sb.sb_blocksize);

	return (pathlen + buflen - 1) / buflen;
}

int
scxfs_symlink_hdr_set(
	struct scxfs_mount	*mp,
	scxfs_ino_t		ino,
	uint32_t		offset,
	uint32_t		size,
	struct scxfs_buf		*bp)
{
	struct scxfs_dsymlink_hdr	*dsl = bp->b_addr;

	if (!scxfs_sb_version_hascrc(&mp->m_sb))
		return 0;

	memset(dsl, 0, sizeof(struct scxfs_dsymlink_hdr));
	dsl->sl_magic = cpu_to_be32(SCXFS_SYMLINK_MAGIC);
	dsl->sl_offset = cpu_to_be32(offset);
	dsl->sl_bytes = cpu_to_be32(size);
	uuid_copy(&dsl->sl_uuid, &mp->m_sb.sb_meta_uuid);
	dsl->sl_owner = cpu_to_be64(ino);
	dsl->sl_blkno = cpu_to_be64(bp->b_bn);
	bp->b_ops = &scxfs_symlink_buf_ops;

	return sizeof(struct scxfs_dsymlink_hdr);
}

/*
 * Checking of the symlink header is split into two parts. the verifier does
 * CRC, location and bounds checking, the unpacking function checks the path
 * parameters and owner.
 */
bool
scxfs_symlink_hdr_ok(
	scxfs_ino_t		ino,
	uint32_t		offset,
	uint32_t		size,
	struct scxfs_buf		*bp)
{
	struct scxfs_dsymlink_hdr *dsl = bp->b_addr;

	if (offset != be32_to_cpu(dsl->sl_offset))
		return false;
	if (size != be32_to_cpu(dsl->sl_bytes))
		return false;
	if (ino != be64_to_cpu(dsl->sl_owner))
		return false;

	/* ok */
	return true;
}

static scxfs_failaddr_t
scxfs_symlink_verify(
	struct scxfs_buf		*bp)
{
	struct scxfs_mount	*mp = bp->b_mount;
	struct scxfs_dsymlink_hdr	*dsl = bp->b_addr;

	if (!scxfs_sb_version_hascrc(&mp->m_sb))
		return __this_address;
	if (!scxfs_verify_magic(bp, dsl->sl_magic))
		return __this_address;
	if (!uuid_equal(&dsl->sl_uuid, &mp->m_sb.sb_meta_uuid))
		return __this_address;
	if (bp->b_bn != be64_to_cpu(dsl->sl_blkno))
		return __this_address;
	if (be32_to_cpu(dsl->sl_offset) +
				be32_to_cpu(dsl->sl_bytes) >= SCXFS_SYMLINK_MAXLEN)
		return __this_address;
	if (dsl->sl_owner == 0)
		return __this_address;
	if (!scxfs_log_check_lsn(mp, be64_to_cpu(dsl->sl_lsn)))
		return __this_address;

	return NULL;
}

static void
scxfs_symlink_read_verify(
	struct scxfs_buf	*bp)
{
	struct scxfs_mount *mp = bp->b_mount;
	scxfs_failaddr_t	fa;

	/* no verification of non-crc buffers */
	if (!scxfs_sb_version_hascrc(&mp->m_sb))
		return;

	if (!scxfs_buf_verify_cksum(bp, SCXFS_SYMLINK_CRC_OFF))
		scxfs_verifier_error(bp, -EFSBADCRC, __this_address);
	else {
		fa = scxfs_symlink_verify(bp);
		if (fa)
			scxfs_verifier_error(bp, -EFSCORRUPTED, fa);
	}
}

static void
scxfs_symlink_write_verify(
	struct scxfs_buf	*bp)
{
	struct scxfs_mount *mp = bp->b_mount;
	struct scxfs_buf_log_item	*bip = bp->b_log_item;
	scxfs_failaddr_t		fa;

	/* no verification of non-crc buffers */
	if (!scxfs_sb_version_hascrc(&mp->m_sb))
		return;

	fa = scxfs_symlink_verify(bp);
	if (fa) {
		scxfs_verifier_error(bp, -EFSCORRUPTED, fa);
		return;
	}

	if (bip) {
		struct scxfs_dsymlink_hdr *dsl = bp->b_addr;
		dsl->sl_lsn = cpu_to_be64(bip->bli_item.li_lsn);
	}
	scxfs_buf_update_cksum(bp, SCXFS_SYMLINK_CRC_OFF);
}

const struct scxfs_buf_ops scxfs_symlink_buf_ops = {
	.name = "scxfs_symlink",
	.magic = { 0, cpu_to_be32(SCXFS_SYMLINK_MAGIC) },
	.verify_read = scxfs_symlink_read_verify,
	.verify_write = scxfs_symlink_write_verify,
	.verify_struct = scxfs_symlink_verify,
};

void
scxfs_symlink_local_to_remote(
	struct scxfs_trans	*tp,
	struct scxfs_buf		*bp,
	struct scxfs_inode	*ip,
	struct scxfs_ifork	*ifp)
{
	struct scxfs_mount	*mp = ip->i_mount;
	char			*buf;

	scxfs_trans_buf_set_type(tp, bp, SCXFS_BLFT_SYMLINK_BUF);

	if (!scxfs_sb_version_hascrc(&mp->m_sb)) {
		bp->b_ops = NULL;
		memcpy(bp->b_addr, ifp->if_u1.if_data, ifp->if_bytes);
		scxfs_trans_log_buf(tp, bp, 0, ifp->if_bytes - 1);
		return;
	}

	/*
	 * As this symlink fits in an inode literal area, it must also fit in
	 * the smallest buffer the filesystem supports.
	 */
	ASSERT(BBTOB(bp->b_length) >=
			ifp->if_bytes + sizeof(struct scxfs_dsymlink_hdr));

	bp->b_ops = &scxfs_symlink_buf_ops;

	buf = bp->b_addr;
	buf += scxfs_symlink_hdr_set(mp, ip->i_ino, 0, ifp->if_bytes, bp);
	memcpy(buf, ifp->if_u1.if_data, ifp->if_bytes);
	scxfs_trans_log_buf(tp, bp, 0, sizeof(struct scxfs_dsymlink_hdr) +
					ifp->if_bytes - 1);
}

/*
 * Verify the in-memory consistency of an inline symlink data fork. This
 * does not do on-disk format checks.
 */
scxfs_failaddr_t
scxfs_symlink_shortform_verify(
	struct scxfs_inode	*ip)
{
	char			*sfp;
	char			*endp;
	struct scxfs_ifork	*ifp;
	int			size;

	ASSERT(ip->i_d.di_format == SCXFS_DINODE_FMT_LOCAL);
	ifp = SCXFS_IFORK_PTR(ip, SCXFS_DATA_FORK);
	sfp = (char *)ifp->if_u1.if_data;
	size = ifp->if_bytes;
	endp = sfp + size;

	/*
	 * Zero length symlinks should never occur in memory as they are
	 * never alllowed to exist on disk.
	 */
	if (!size)
		return __this_address;

	/* No negative sizes or overly long symlink targets. */
	if (size < 0 || size > SCXFS_SYMLINK_MAXLEN)
		return __this_address;

	/* No NULLs in the target either. */
	if (memchr(sfp, 0, size - 1))
		return __this_address;

	/* We /did/ null-terminate the buffer, right? */
	if (*endp != 0)
		return __this_address;
	return NULL;
}
