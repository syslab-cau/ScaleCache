// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2006 Silicon Graphics, Inc.
 * All Rights Reserved.
 */

#include "scxfs.h"
#include "scxfs_shared.h"
#include "scxfs_format.h"
#include "scxfs_log_format.h"
#include "scxfs_trans_resv.h"
#include "scxfs_sb.h"
#include "scxfs_mount.h"
#include "scxfs_inode.h"
#include "scxfs_btree.h"
#include "scxfs_bmap.h"
#include "scxfs_alloc.h"
#include "scxfs_fsops.h"
#include "scxfs_trans.h"
#include "scxfs_buf_item.h"
#include "scxfs_log.h"
#include "scxfs_log_priv.h"
#include "scxfs_dir2.h"
#include "scxfs_extfree_item.h"
#include "scxfs_mru_cache.h"
#include "scxfs_inode_item.h"
#include "scxfs_icache.h"
#include "scxfs_trace.h"
#include "scxfs_icreate_item.h"
#include "scxfs_filestream.h"
#include "scxfs_quota.h"
#include "scxfs_sysfs.h"
#include "scxfs_ondisk.h"
#include "scxfs_rmap_item.h"
#include "scxfs_refcount_item.h"
#include "scxfs_bmap_item.h"
#include "scxfs_reflink.h"

#include <linux/magic.h>
#include <linux/parser.h>

static const struct super_operations scxfs_super_operations;
struct bio_set scxfs_ioend_bioset;

static struct kset *scxfs_kset;		/* top-level scxfs sysfs dir */
#ifdef DEBUG
static struct scxfs_kobj scxfs_dbg_kobj;	/* global debug sysfs attrs */
#endif

/*
 * Table driven mount option parser.
 */
enum {
	Opt_logbufs, Opt_logbsize, Opt_logdev, Opt_rtdev, Opt_biosize,
	Opt_wsync, Opt_noalign, Opt_swalloc, Opt_sunit, Opt_swidth, Opt_nouuid,
	Opt_grpid, Opt_nogrpid, Opt_bsdgroups, Opt_sysvgroups,
	Opt_allocsize, Opt_norecovery, Opt_inode64, Opt_inode32, Opt_ikeep,
	Opt_noikeep, Opt_largeio, Opt_nolargeio, Opt_attr2, Opt_noattr2,
	Opt_filestreams, Opt_quota, Opt_noquota, Opt_usrquota, Opt_grpquota,
	Opt_prjquota, Opt_uquota, Opt_gquota, Opt_pquota,
	Opt_uqnoenforce, Opt_gqnoenforce, Opt_pqnoenforce, Opt_qnoenforce,
	Opt_discard, Opt_nodiscard, Opt_dax, Opt_err,
};

static const match_table_t tokens = {
	{Opt_logbufs,	"logbufs=%u"},	/* number of SCXFS log buffers */
	{Opt_logbsize,	"logbsize=%s"},	/* size of SCXFS log buffers */
	{Opt_logdev,	"logdev=%s"},	/* log device */
	{Opt_rtdev,	"rtdev=%s"},	/* realtime I/O device */
	{Opt_biosize,	"biosize=%u"},	/* log2 of preferred buffered io size */
	{Opt_wsync,	"wsync"},	/* safe-mode nfs compatible mount */
	{Opt_noalign,	"noalign"},	/* turn off stripe alignment */
	{Opt_swalloc,	"swalloc"},	/* turn on stripe width allocation */
	{Opt_sunit,	"sunit=%u"},	/* data volume stripe unit */
	{Opt_swidth,	"swidth=%u"},	/* data volume stripe width */
	{Opt_nouuid,	"nouuid"},	/* ignore filesystem UUID */
	{Opt_grpid,	"grpid"},	/* group-ID from parent directory */
	{Opt_nogrpid,	"nogrpid"},	/* group-ID from current process */
	{Opt_bsdgroups,	"bsdgroups"},	/* group-ID from parent directory */
	{Opt_sysvgroups,"sysvgroups"},	/* group-ID from current process */
	{Opt_allocsize,	"allocsize=%s"},/* preferred allocation size */
	{Opt_norecovery,"norecovery"},	/* don't run SCXFS recovery */
	{Opt_inode64,	"inode64"},	/* inodes can be allocated anywhere */
	{Opt_inode32,   "inode32"},	/* inode allocation limited to
					 * SCXFS_MAXINUMBER_32 */
	{Opt_ikeep,	"ikeep"},	/* do not free empty inode clusters */
	{Opt_noikeep,	"noikeep"},	/* free empty inode clusters */
	{Opt_largeio,	"largeio"},	/* report large I/O sizes in stat() */
	{Opt_nolargeio,	"nolargeio"},	/* do not report large I/O sizes
					 * in stat(). */
	{Opt_attr2,	"attr2"},	/* do use attr2 attribute format */
	{Opt_noattr2,	"noattr2"},	/* do not use attr2 attribute format */
	{Opt_filestreams,"filestreams"},/* use filestreams allocator */
	{Opt_quota,	"quota"},	/* disk quotas (user) */
	{Opt_noquota,	"noquota"},	/* no quotas */
	{Opt_usrquota,	"usrquota"},	/* user quota enabled */
	{Opt_grpquota,	"grpquota"},	/* group quota enabled */
	{Opt_prjquota,	"prjquota"},	/* project quota enabled */
	{Opt_uquota,	"uquota"},	/* user quota (IRIX variant) */
	{Opt_gquota,	"gquota"},	/* group quota (IRIX variant) */
	{Opt_pquota,	"pquota"},	/* project quota (IRIX variant) */
	{Opt_uqnoenforce,"uqnoenforce"},/* user quota limit enforcement */
	{Opt_gqnoenforce,"gqnoenforce"},/* group quota limit enforcement */
	{Opt_pqnoenforce,"pqnoenforce"},/* project quota limit enforcement */
	{Opt_qnoenforce, "qnoenforce"},	/* same as uqnoenforce */
	{Opt_discard,	"discard"},	/* Discard unused blocks */
	{Opt_nodiscard,	"nodiscard"},	/* Do not discard unused blocks */
	{Opt_dax,	"dax"},		/* Enable direct access to bdev pages */
	{Opt_err,	NULL},
};


STATIC int
suffix_kstrtoint(const substring_t *s, unsigned int base, int *res)
{
	int	last, shift_left_factor = 0, _res;
	char	*value;
	int	ret = 0;

	value = match_strdup(s);
	if (!value)
		return -ENOMEM;

	last = strlen(value) - 1;
	if (value[last] == 'K' || value[last] == 'k') {
		shift_left_factor = 10;
		value[last] = '\0';
	}
	if (value[last] == 'M' || value[last] == 'm') {
		shift_left_factor = 20;
		value[last] = '\0';
	}
	if (value[last] == 'G' || value[last] == 'g') {
		shift_left_factor = 30;
		value[last] = '\0';
	}

	if (kstrtoint(value, base, &_res))
		ret = -EINVAL;
	kfree(value);
	*res = _res << shift_left_factor;
	return ret;
}

/*
 * This function fills in scxfs_mount_t fields based on mount args.
 * Note: the superblock has _not_ yet been read in.
 *
 * Note that this function leaks the various device name allocations on
 * failure.  The caller takes care of them.
 *
 * *sb is const because this is also used to test options on the remount
 * path, and we don't want this to have any side effects at remount time.
 * Today this function does not change *sb, but just to future-proof...
 */
STATIC int
scxfs_parseargs(
	struct scxfs_mount	*mp,
	char			*options)
{
	const struct super_block *sb = mp->m_super;
	char			*p;
	substring_t		args[MAX_OPT_ARGS];
	int			dsunit = 0;
	int			dswidth = 0;
	int			iosize = 0;
	uint8_t			iosizelog = 0;

	/*
	 * set up the mount name first so all the errors will refer to the
	 * correct device.
	 */
	mp->m_fsname = kstrndup(sb->s_id, MAXNAMELEN, GFP_KERNEL);
	if (!mp->m_fsname)
		return -ENOMEM;
	mp->m_fsname_len = strlen(mp->m_fsname) + 1;

	/*
	 * Copy binary VFS mount flags we are interested in.
	 */
	if (sb_rdonly(sb))
		mp->m_flags |= SCXFS_MOUNT_RDONLY;
	if (sb->s_flags & SB_DIRSYNC)
		mp->m_flags |= SCXFS_MOUNT_DIRSYNC;
	if (sb->s_flags & SB_SYNCHRONOUS)
		mp->m_flags |= SCXFS_MOUNT_WSYNC;

	/*
	 * Set some default flags that could be cleared by the mount option
	 * parsing.
	 */
	mp->m_flags |= SCXFS_MOUNT_COMPAT_IOSIZE;

	/*
	 * These can be overridden by the mount option parsing.
	 */
	mp->m_logbufs = -1;
	mp->m_logbsize = -1;

	if (!options)
		goto done;

	while ((p = strsep(&options, ",")) != NULL) {
		int		token;

		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
		case Opt_logbufs:
			if (match_int(args, &mp->m_logbufs))
				return -EINVAL;
			break;
		case Opt_logbsize:
			if (suffix_kstrtoint(args, 10, &mp->m_logbsize))
				return -EINVAL;
			break;
		case Opt_logdev:
			kfree(mp->m_logname);
			mp->m_logname = match_strdup(args);
			if (!mp->m_logname)
				return -ENOMEM;
			break;
		case Opt_rtdev:
			kfree(mp->m_rtname);
			mp->m_rtname = match_strdup(args);
			if (!mp->m_rtname)
				return -ENOMEM;
			break;
		case Opt_allocsize:
		case Opt_biosize:
			if (suffix_kstrtoint(args, 10, &iosize))
				return -EINVAL;
			iosizelog = ffs(iosize) - 1;
			break;
		case Opt_grpid:
		case Opt_bsdgroups:
			mp->m_flags |= SCXFS_MOUNT_GRPID;
			break;
		case Opt_nogrpid:
		case Opt_sysvgroups:
			mp->m_flags &= ~SCXFS_MOUNT_GRPID;
			break;
		case Opt_wsync:
			mp->m_flags |= SCXFS_MOUNT_WSYNC;
			break;
		case Opt_norecovery:
			mp->m_flags |= SCXFS_MOUNT_NORECOVERY;
			break;
		case Opt_noalign:
			mp->m_flags |= SCXFS_MOUNT_NOALIGN;
			break;
		case Opt_swalloc:
			mp->m_flags |= SCXFS_MOUNT_SWALLOC;
			break;
		case Opt_sunit:
			if (match_int(args, &dsunit))
				return -EINVAL;
			break;
		case Opt_swidth:
			if (match_int(args, &dswidth))
				return -EINVAL;
			break;
		case Opt_inode32:
			mp->m_flags |= SCXFS_MOUNT_SMALL_INUMS;
			break;
		case Opt_inode64:
			mp->m_flags &= ~SCXFS_MOUNT_SMALL_INUMS;
			break;
		case Opt_nouuid:
			mp->m_flags |= SCXFS_MOUNT_NOUUID;
			break;
		case Opt_ikeep:
			mp->m_flags |= SCXFS_MOUNT_IKEEP;
			break;
		case Opt_noikeep:
			mp->m_flags &= ~SCXFS_MOUNT_IKEEP;
			break;
		case Opt_largeio:
			mp->m_flags &= ~SCXFS_MOUNT_COMPAT_IOSIZE;
			break;
		case Opt_nolargeio:
			mp->m_flags |= SCXFS_MOUNT_COMPAT_IOSIZE;
			break;
		case Opt_attr2:
			mp->m_flags |= SCXFS_MOUNT_ATTR2;
			break;
		case Opt_noattr2:
			mp->m_flags &= ~SCXFS_MOUNT_ATTR2;
			mp->m_flags |= SCXFS_MOUNT_NOATTR2;
			break;
		case Opt_filestreams:
			mp->m_flags |= SCXFS_MOUNT_FILESTREAMS;
			break;
		case Opt_noquota:
			mp->m_qflags &= ~SCXFS_ALL_QUOTA_ACCT;
			mp->m_qflags &= ~SCXFS_ALL_QUOTA_ENFD;
			mp->m_qflags &= ~SCXFS_ALL_QUOTA_ACTIVE;
			break;
		case Opt_quota:
		case Opt_uquota:
		case Opt_usrquota:
			mp->m_qflags |= (SCXFS_UQUOTA_ACCT | SCXFS_UQUOTA_ACTIVE |
					 SCXFS_UQUOTA_ENFD);
			break;
		case Opt_qnoenforce:
		case Opt_uqnoenforce:
			mp->m_qflags |= (SCXFS_UQUOTA_ACCT | SCXFS_UQUOTA_ACTIVE);
			mp->m_qflags &= ~SCXFS_UQUOTA_ENFD;
			break;
		case Opt_pquota:
		case Opt_prjquota:
			mp->m_qflags |= (SCXFS_PQUOTA_ACCT | SCXFS_PQUOTA_ACTIVE |
					 SCXFS_PQUOTA_ENFD);
			break;
		case Opt_pqnoenforce:
			mp->m_qflags |= (SCXFS_PQUOTA_ACCT | SCXFS_PQUOTA_ACTIVE);
			mp->m_qflags &= ~SCXFS_PQUOTA_ENFD;
			break;
		case Opt_gquota:
		case Opt_grpquota:
			mp->m_qflags |= (SCXFS_GQUOTA_ACCT | SCXFS_GQUOTA_ACTIVE |
					 SCXFS_GQUOTA_ENFD);
			break;
		case Opt_gqnoenforce:
			mp->m_qflags |= (SCXFS_GQUOTA_ACCT | SCXFS_GQUOTA_ACTIVE);
			mp->m_qflags &= ~SCXFS_GQUOTA_ENFD;
			break;
		case Opt_discard:
			mp->m_flags |= SCXFS_MOUNT_DISCARD;
			break;
		case Opt_nodiscard:
			mp->m_flags &= ~SCXFS_MOUNT_DISCARD;
			break;
#ifdef CONFIG_FS_DAX
		case Opt_dax:
			mp->m_flags |= SCXFS_MOUNT_DAX;
			break;
#endif
		default:
			scxfs_warn(mp, "unknown mount option [%s].", p);
			return -EINVAL;
		}
	}

	/*
	 * no recovery flag requires a read-only mount
	 */
	if ((mp->m_flags & SCXFS_MOUNT_NORECOVERY) &&
	    !(mp->m_flags & SCXFS_MOUNT_RDONLY)) {
		scxfs_warn(mp, "no-recovery mounts must be read-only.");
		return -EINVAL;
	}

	if ((mp->m_flags & SCXFS_MOUNT_NOALIGN) && (dsunit || dswidth)) {
		scxfs_warn(mp,
	"sunit and swidth options incompatible with the noalign option");
		return -EINVAL;
	}

#ifndef CONFIG_XFS_QUOTA
	if (SCXFS_IS_QUOTA_RUNNING(mp)) {
		scxfs_warn(mp, "quota support not available in this kernel.");
		return -EINVAL;
	}
#endif

	if ((dsunit && !dswidth) || (!dsunit && dswidth)) {
		scxfs_warn(mp, "sunit and swidth must be specified together");
		return -EINVAL;
	}

	if (dsunit && (dswidth % dsunit != 0)) {
		scxfs_warn(mp,
	"stripe width (%d) must be a multiple of the stripe unit (%d)",
			dswidth, dsunit);
		return -EINVAL;
	}

done:
	if (dsunit && !(mp->m_flags & SCXFS_MOUNT_NOALIGN)) {
		/*
		 * At this point the superblock has not been read
		 * in, therefore we do not know the block size.
		 * Before the mount call ends we will convert
		 * these to FSBs.
		 */
		mp->m_dalign = dsunit;
		mp->m_swidth = dswidth;
	}

	if (mp->m_logbufs != -1 &&
	    mp->m_logbufs != 0 &&
	    (mp->m_logbufs < XLOG_MIN_ICLOGS ||
	     mp->m_logbufs > XLOG_MAX_ICLOGS)) {
		scxfs_warn(mp, "invalid logbufs value: %d [not %d-%d]",
			mp->m_logbufs, XLOG_MIN_ICLOGS, XLOG_MAX_ICLOGS);
		return -EINVAL;
	}
	if (mp->m_logbsize != -1 &&
	    mp->m_logbsize !=  0 &&
	    (mp->m_logbsize < XLOG_MIN_RECORD_BSIZE ||
	     mp->m_logbsize > XLOG_MAX_RECORD_BSIZE ||
	     !is_power_of_2(mp->m_logbsize))) {
		scxfs_warn(mp,
			"invalid logbufsize: %d [not 16k,32k,64k,128k or 256k]",
			mp->m_logbsize);
		return -EINVAL;
	}

	if (iosizelog) {
		if (iosizelog > SCXFS_MAX_IO_LOG ||
		    iosizelog < SCXFS_MIN_IO_LOG) {
			scxfs_warn(mp, "invalid log iosize: %d [not %d-%d]",
				iosizelog, SCXFS_MIN_IO_LOG,
				SCXFS_MAX_IO_LOG);
			return -EINVAL;
		}

		mp->m_flags |= SCXFS_MOUNT_DFLT_IOSIZE;
		mp->m_readio_log = iosizelog;
		mp->m_writeio_log = iosizelog;
	}

	return 0;
}

struct proc_scxfs_info {
	uint64_t	flag;
	char		*str;
};

STATIC void
scxfs_showargs(
	struct scxfs_mount	*mp,
	struct seq_file		*m)
{
	static struct proc_scxfs_info scxfs_info_set[] = {
		/* the few simple ones we can get from the mount struct */
		{ SCXFS_MOUNT_IKEEP,		",ikeep" },
		{ SCXFS_MOUNT_WSYNC,		",wsync" },
		{ SCXFS_MOUNT_NOALIGN,		",noalign" },
		{ SCXFS_MOUNT_SWALLOC,		",swalloc" },
		{ SCXFS_MOUNT_NOUUID,		",nouuid" },
		{ SCXFS_MOUNT_NORECOVERY,		",norecovery" },
		{ SCXFS_MOUNT_ATTR2,		",attr2" },
		{ SCXFS_MOUNT_FILESTREAMS,	",filestreams" },
		{ SCXFS_MOUNT_GRPID,		",grpid" },
		{ SCXFS_MOUNT_DISCARD,		",discard" },
		{ SCXFS_MOUNT_SMALL_INUMS,	",inode32" },
		{ SCXFS_MOUNT_DAX,		",dax" },
		{ 0, NULL }
	};
	static struct proc_scxfs_info scxfs_info_unset[] = {
		/* the few simple ones we can get from the mount struct */
		{ SCXFS_MOUNT_COMPAT_IOSIZE,	",largeio" },
		{ SCXFS_MOUNT_SMALL_INUMS,	",inode64" },
		{ 0, NULL }
	};
	struct proc_scxfs_info	*scxfs_infop;

	for (scxfs_infop = scxfs_info_set; scxfs_infop->flag; scxfs_infop++) {
		if (mp->m_flags & scxfs_infop->flag)
			seq_puts(m, scxfs_infop->str);
	}
	for (scxfs_infop = scxfs_info_unset; scxfs_infop->flag; scxfs_infop++) {
		if (!(mp->m_flags & scxfs_infop->flag))
			seq_puts(m, scxfs_infop->str);
	}

	if (mp->m_flags & SCXFS_MOUNT_DFLT_IOSIZE)
		seq_printf(m, ",allocsize=%dk",
				(int)(1 << mp->m_writeio_log) >> 10);

	if (mp->m_logbufs > 0)
		seq_printf(m, ",logbufs=%d", mp->m_logbufs);
	if (mp->m_logbsize > 0)
		seq_printf(m, ",logbsize=%dk", mp->m_logbsize >> 10);

	if (mp->m_logname)
		seq_show_option(m, "logdev", mp->m_logname);
	if (mp->m_rtname)
		seq_show_option(m, "rtdev", mp->m_rtname);

	if (mp->m_dalign > 0)
		seq_printf(m, ",sunit=%d",
				(int)SCXFS_FSB_TO_BB(mp, mp->m_dalign));
	if (mp->m_swidth > 0)
		seq_printf(m, ",swidth=%d",
				(int)SCXFS_FSB_TO_BB(mp, mp->m_swidth));

	if (mp->m_qflags & (SCXFS_UQUOTA_ACCT|SCXFS_UQUOTA_ENFD))
		seq_puts(m, ",usrquota");
	else if (mp->m_qflags & SCXFS_UQUOTA_ACCT)
		seq_puts(m, ",uqnoenforce");

	if (mp->m_qflags & SCXFS_PQUOTA_ACCT) {
		if (mp->m_qflags & SCXFS_PQUOTA_ENFD)
			seq_puts(m, ",prjquota");
		else
			seq_puts(m, ",pqnoenforce");
	}
	if (mp->m_qflags & SCXFS_GQUOTA_ACCT) {
		if (mp->m_qflags & SCXFS_GQUOTA_ENFD)
			seq_puts(m, ",grpquota");
		else
			seq_puts(m, ",gqnoenforce");
	}

	if (!(mp->m_qflags & SCXFS_ALL_QUOTA_ACCT))
		seq_puts(m, ",noquota");
}

static uint64_t
scxfs_max_file_offset(
	unsigned int		blockshift)
{
	unsigned int		pagefactor = 1;
	unsigned int		bitshift = BITS_PER_LONG - 1;

	/* Figure out maximum filesize, on Linux this can depend on
	 * the filesystem blocksize (on 32 bit platforms).
	 * __block_write_begin does this in an [unsigned] long long...
	 *      page->index << (PAGE_SHIFT - bbits)
	 * So, for page sized blocks (4K on 32 bit platforms),
	 * this wraps at around 8Tb (hence MAX_LFS_FILESIZE which is
	 *      (((u64)PAGE_SIZE << (BITS_PER_LONG-1))-1)
	 * but for smaller blocksizes it is less (bbits = log2 bsize).
	 */

#if BITS_PER_LONG == 32
	ASSERT(sizeof(sector_t) == 8);
	pagefactor = PAGE_SIZE;
	bitshift = BITS_PER_LONG;
#endif

	return (((uint64_t)pagefactor) << bitshift) - 1;
}

/*
 * Set parameters for inode allocation heuristics, taking into account
 * filesystem size and inode32/inode64 mount options; i.e. specifically
 * whether or not SCXFS_MOUNT_SMALL_INUMS is set.
 *
 * Inode allocation patterns are altered only if inode32 is requested
 * (SCXFS_MOUNT_SMALL_INUMS), and the filesystem is sufficiently large.
 * If altered, SCXFS_MOUNT_32BITINODES is set as well.
 *
 * An agcount independent of that in the mount structure is provided
 * because in the growfs case, mp->m_sb.sb_agcount is not yet updated
 * to the potentially higher ag count.
 *
 * Returns the maximum AG index which may contain inodes.
 */
scxfs_agnumber_t
scxfs_set_inode_alloc(
	struct scxfs_mount *mp,
	scxfs_agnumber_t	agcount)
{
	scxfs_agnumber_t	index;
	scxfs_agnumber_t	maxagi = 0;
	scxfs_sb_t	*sbp = &mp->m_sb;
	scxfs_agnumber_t	max_metadata;
	scxfs_agino_t	agino;
	scxfs_ino_t	ino;

	/*
	 * Calculate how much should be reserved for inodes to meet
	 * the max inode percentage.  Used only for inode32.
	 */
	if (M_IGEO(mp)->maxicount) {
		uint64_t	icount;

		icount = sbp->sb_dblocks * sbp->sb_imax_pct;
		do_div(icount, 100);
		icount += sbp->sb_agblocks - 1;
		do_div(icount, sbp->sb_agblocks);
		max_metadata = icount;
	} else {
		max_metadata = agcount;
	}

	/* Get the last possible inode in the filesystem */
	agino =	SCXFS_AGB_TO_AGINO(mp, sbp->sb_agblocks - 1);
	ino = SCXFS_AGINO_TO_INO(mp, agcount - 1, agino);

	/*
	 * If user asked for no more than 32-bit inodes, and the fs is
	 * sufficiently large, set SCXFS_MOUNT_32BITINODES if we must alter
	 * the allocator to accommodate the request.
	 */
	if ((mp->m_flags & SCXFS_MOUNT_SMALL_INUMS) && ino > SCXFS_MAXINUMBER_32)
		mp->m_flags |= SCXFS_MOUNT_32BITINODES;
	else
		mp->m_flags &= ~SCXFS_MOUNT_32BITINODES;

	for (index = 0; index < agcount; index++) {
		struct scxfs_perag	*pag;

		ino = SCXFS_AGINO_TO_INO(mp, index, agino);

		pag = scxfs_perag_get(mp, index);

		if (mp->m_flags & SCXFS_MOUNT_32BITINODES) {
			if (ino > SCXFS_MAXINUMBER_32) {
				pag->pagi_inodeok = 0;
				pag->pagf_metadata = 0;
			} else {
				pag->pagi_inodeok = 1;
				maxagi++;
				if (index < max_metadata)
					pag->pagf_metadata = 1;
				else
					pag->pagf_metadata = 0;
			}
		} else {
			pag->pagi_inodeok = 1;
			pag->pagf_metadata = 0;
		}

		scxfs_perag_put(pag);
	}

	return (mp->m_flags & SCXFS_MOUNT_32BITINODES) ? maxagi : agcount;
}

STATIC int
scxfs_blkdev_get(
	scxfs_mount_t		*mp,
	const char		*name,
	struct block_device	**bdevp)
{
	int			error = 0;

	*bdevp = blkdev_get_by_path(name, FMODE_READ|FMODE_WRITE|FMODE_EXCL,
				    mp);
	if (IS_ERR(*bdevp)) {
		error = PTR_ERR(*bdevp);
		scxfs_warn(mp, "Invalid device [%s], error=%d", name, error);
	}

	return error;
}

STATIC void
scxfs_blkdev_put(
	struct block_device	*bdev)
{
	if (bdev)
		blkdev_put(bdev, FMODE_READ|FMODE_WRITE|FMODE_EXCL);
}

void
scxfs_blkdev_issue_flush(
	scxfs_buftarg_t		*buftarg)
{
	blkdev_issue_flush(buftarg->bt_bdev, GFP_NOFS, NULL);
}

STATIC void
scxfs_close_devices(
	struct scxfs_mount	*mp)
{
	struct dax_device *dax_ddev = mp->m_ddev_targp->bt_daxdev;

	if (mp->m_logdev_targp && mp->m_logdev_targp != mp->m_ddev_targp) {
		struct block_device *logdev = mp->m_logdev_targp->bt_bdev;
		struct dax_device *dax_logdev = mp->m_logdev_targp->bt_daxdev;

		scxfs_free_buftarg(mp->m_logdev_targp);
		scxfs_blkdev_put(logdev);
		fs_put_dax(dax_logdev);
	}
	if (mp->m_rtdev_targp) {
		struct block_device *rtdev = mp->m_rtdev_targp->bt_bdev;
		struct dax_device *dax_rtdev = mp->m_rtdev_targp->bt_daxdev;

		scxfs_free_buftarg(mp->m_rtdev_targp);
		scxfs_blkdev_put(rtdev);
		fs_put_dax(dax_rtdev);
	}
	scxfs_free_buftarg(mp->m_ddev_targp);
	fs_put_dax(dax_ddev);
}

/*
 * The file system configurations are:
 *	(1) device (partition) with data and internal log
 *	(2) logical volume with data and log subvolumes.
 *	(3) logical volume with data, log, and realtime subvolumes.
 *
 * We only have to handle opening the log and realtime volumes here if
 * they are present.  The data subvolume has already been opened by
 * get_sb_bdev() and is stored in sb->s_bdev.
 */
STATIC int
scxfs_open_devices(
	struct scxfs_mount	*mp)
{
	struct block_device	*ddev = mp->m_super->s_bdev;
	struct dax_device	*dax_ddev = fs_dax_get_by_bdev(ddev);
	struct dax_device	*dax_logdev = NULL, *dax_rtdev = NULL;
	struct block_device	*logdev = NULL, *rtdev = NULL;
	int			error;

	/*
	 * Open real time and log devices - order is important.
	 */
	if (mp->m_logname) {
		error = scxfs_blkdev_get(mp, mp->m_logname, &logdev);
		if (error)
			goto out;
		dax_logdev = fs_dax_get_by_bdev(logdev);
	}

	if (mp->m_rtname) {
		error = scxfs_blkdev_get(mp, mp->m_rtname, &rtdev);
		if (error)
			goto out_close_logdev;

		if (rtdev == ddev || rtdev == logdev) {
			scxfs_warn(mp,
	"Cannot mount filesystem with identical rtdev and ddev/logdev.");
			error = -EINVAL;
			goto out_close_rtdev;
		}
		dax_rtdev = fs_dax_get_by_bdev(rtdev);
	}

	/*
	 * Setup scxfs_mount buffer target pointers
	 */
	error = -ENOMEM;
	mp->m_ddev_targp = scxfs_alloc_buftarg(mp, ddev, dax_ddev);
	if (!mp->m_ddev_targp)
		goto out_close_rtdev;

	if (rtdev) {
		mp->m_rtdev_targp = scxfs_alloc_buftarg(mp, rtdev, dax_rtdev);
		if (!mp->m_rtdev_targp)
			goto out_free_ddev_targ;
	}

	if (logdev && logdev != ddev) {
		mp->m_logdev_targp = scxfs_alloc_buftarg(mp, logdev, dax_logdev);
		if (!mp->m_logdev_targp)
			goto out_free_rtdev_targ;
	} else {
		mp->m_logdev_targp = mp->m_ddev_targp;
	}

	return 0;

 out_free_rtdev_targ:
	if (mp->m_rtdev_targp)
		scxfs_free_buftarg(mp->m_rtdev_targp);
 out_free_ddev_targ:
	scxfs_free_buftarg(mp->m_ddev_targp);
 out_close_rtdev:
	scxfs_blkdev_put(rtdev);
	fs_put_dax(dax_rtdev);
 out_close_logdev:
	if (logdev && logdev != ddev) {
		scxfs_blkdev_put(logdev);
		fs_put_dax(dax_logdev);
	}
 out:
	fs_put_dax(dax_ddev);
	return error;
}

/*
 * Setup scxfs_mount buffer target pointers based on superblock
 */
STATIC int
scxfs_setup_devices(
	struct scxfs_mount	*mp)
{
	int			error;

	error = scxfs_setsize_buftarg(mp->m_ddev_targp, mp->m_sb.sb_sectsize);
	if (error)
		return error;

	if (mp->m_logdev_targp && mp->m_logdev_targp != mp->m_ddev_targp) {
		unsigned int	log_sector_size = BBSIZE;

		if (scxfs_sb_version_hassector(&mp->m_sb))
			log_sector_size = mp->m_sb.sb_logsectsize;
		error = scxfs_setsize_buftarg(mp->m_logdev_targp,
					    log_sector_size);
		if (error)
			return error;
	}
	if (mp->m_rtdev_targp) {
		error = scxfs_setsize_buftarg(mp->m_rtdev_targp,
					    mp->m_sb.sb_sectsize);
		if (error)
			return error;
	}

	return 0;
}

STATIC int
scxfs_init_mount_workqueues(
	struct scxfs_mount	*mp)
{
	mp->m_buf_workqueue = alloc_workqueue("scxfs-buf/%s",
			WQ_MEM_RECLAIM|WQ_FREEZABLE, 1, mp->m_fsname);
	if (!mp->m_buf_workqueue)
		goto out;

	mp->m_unwritten_workqueue = alloc_workqueue("scxfs-conv/%s",
			WQ_MEM_RECLAIM|WQ_FREEZABLE, 0, mp->m_fsname);
	if (!mp->m_unwritten_workqueue)
		goto out_destroy_buf;

	mp->m_cil_workqueue = alloc_workqueue("scxfs-cil/%s",
			WQ_MEM_RECLAIM | WQ_FREEZABLE | WQ_UNBOUND,
			0, mp->m_fsname);
	if (!mp->m_cil_workqueue)
		goto out_destroy_unwritten;

	mp->m_reclaim_workqueue = alloc_workqueue("scxfs-reclaim/%s",
			WQ_MEM_RECLAIM|WQ_FREEZABLE, 0, mp->m_fsname);
	if (!mp->m_reclaim_workqueue)
		goto out_destroy_cil;

	mp->m_eofblocks_workqueue = alloc_workqueue("scxfs-eofblocks/%s",
			WQ_MEM_RECLAIM|WQ_FREEZABLE, 0, mp->m_fsname);
	if (!mp->m_eofblocks_workqueue)
		goto out_destroy_reclaim;

	mp->m_sync_workqueue = alloc_workqueue("scxfs-sync/%s", WQ_FREEZABLE, 0,
					       mp->m_fsname);
	if (!mp->m_sync_workqueue)
		goto out_destroy_eofb;

	return 0;

out_destroy_eofb:
	destroy_workqueue(mp->m_eofblocks_workqueue);
out_destroy_reclaim:
	destroy_workqueue(mp->m_reclaim_workqueue);
out_destroy_cil:
	destroy_workqueue(mp->m_cil_workqueue);
out_destroy_unwritten:
	destroy_workqueue(mp->m_unwritten_workqueue);
out_destroy_buf:
	destroy_workqueue(mp->m_buf_workqueue);
out:
	return -ENOMEM;
}

STATIC void
scxfs_destroy_mount_workqueues(
	struct scxfs_mount	*mp)
{
	destroy_workqueue(mp->m_sync_workqueue);
	destroy_workqueue(mp->m_eofblocks_workqueue);
	destroy_workqueue(mp->m_reclaim_workqueue);
	destroy_workqueue(mp->m_cil_workqueue);
	destroy_workqueue(mp->m_unwritten_workqueue);
	destroy_workqueue(mp->m_buf_workqueue);
}

/*
 * Flush all dirty data to disk. Must not be called while holding an SCXFS_ILOCK
 * or a page lock. We use sync_inodes_sb() here to ensure we block while waiting
 * for IO to complete so that we effectively throttle multiple callers to the
 * rate at which IO is completing.
 */
void
scxfs_flush_inodes(
	struct scxfs_mount	*mp)
{
	struct super_block	*sb = mp->m_super;

	if (down_read_trylock(&sb->s_umount)) {
		sync_inodes_sb(sb);
		up_read(&sb->s_umount);
	}
}

/* Catch misguided souls that try to use this interface on SCXFS */
STATIC struct inode *
scxfs_fs_alloc_inode(
	struct super_block	*sb)
{
	BUG();
	return NULL;
}

#ifdef DEBUG
static void
scxfs_check_delalloc(
	struct scxfs_inode	*ip,
	int			whichfork)
{
	struct scxfs_ifork	*ifp = SCXFS_IFORK_PTR(ip, whichfork);
	struct scxfs_bmbt_irec	got;
	struct scxfs_iext_cursor	icur;

	if (!ifp || !scxfs_iext_lookup_extent(ip, ifp, 0, &icur, &got))
		return;
	do {
		if (isnullstartblock(got.br_startblock)) {
			scxfs_warn(ip->i_mount,
	"ino %llx %s fork has delalloc extent at [0x%llx:0x%llx]",
				ip->i_ino,
				whichfork == SCXFS_DATA_FORK ? "data" : "cow",
				got.br_startoff, got.br_blockcount);
		}
	} while (scxfs_iext_next_extent(ifp, &icur, &got));
}
#else
#define scxfs_check_delalloc(ip, whichfork)	do { } while (0)
#endif

/*
 * Now that the generic code is guaranteed not to be accessing
 * the linux inode, we can inactivate and reclaim the inode.
 */
STATIC void
scxfs_fs_destroy_inode(
	struct inode		*inode)
{
	struct scxfs_inode	*ip = SCXFS_I(inode);

	trace_scxfs_destroy_inode(ip);

	ASSERT(!rwsem_is_locked(&inode->i_rwsem));
	SCXFS_STATS_INC(ip->i_mount, vn_rele);
	SCXFS_STATS_INC(ip->i_mount, vn_remove);

	scxfs_inactive(ip);

	if (!SCXFS_FORCED_SHUTDOWN(ip->i_mount) && ip->i_delayed_blks) {
		scxfs_check_delalloc(ip, SCXFS_DATA_FORK);
		scxfs_check_delalloc(ip, SCXFS_COW_FORK);
		ASSERT(0);
	}

	SCXFS_STATS_INC(ip->i_mount, vn_reclaim);

	/*
	 * We should never get here with one of the reclaim flags already set.
	 */
	ASSERT_ALWAYS(!scxfs_iflags_test(ip, SCXFS_IRECLAIMABLE));
	ASSERT_ALWAYS(!scxfs_iflags_test(ip, SCXFS_IRECLAIM));

	/*
	 * We always use background reclaim here because even if the
	 * inode is clean, it still may be under IO and hence we have
	 * to take the flush lock. The background reclaim path handles
	 * this more efficiently than we can here, so simply let background
	 * reclaim tear down all inodes.
	 */
	scxfs_inode_set_reclaim_tag(ip);
}

static void
scxfs_fs_dirty_inode(
	struct inode			*inode,
	int				flag)
{
	struct scxfs_inode		*ip = SCXFS_I(inode);
	struct scxfs_mount		*mp = ip->i_mount;
	struct scxfs_trans		*tp;

	if (!(inode->i_sb->s_flags & SB_LAZYTIME))
		return;
	if (flag != I_DIRTY_SYNC || !(inode->i_state & I_DIRTY_TIME))
		return;

	if (scxfs_trans_alloc(mp, &M_RES(mp)->tr_fsyncts, 0, 0, 0, &tp))
		return;
	scxfs_ilock(ip, SCXFS_ILOCK_EXCL);
	scxfs_trans_ijoin(tp, ip, SCXFS_ILOCK_EXCL);
	scxfs_trans_log_inode(tp, ip, SCXFS_ILOG_TIMESTAMP);
	scxfs_trans_commit(tp);
}

/*
 * Slab object creation initialisation for the SCXFS inode.
 * This covers only the idempotent fields in the SCXFS inode;
 * all other fields need to be initialised on allocation
 * from the slab. This avoids the need to repeatedly initialise
 * fields in the scxfs inode that left in the initialise state
 * when freeing the inode.
 */
STATIC void
scxfs_fs_inode_init_once(
	void			*inode)
{
	struct scxfs_inode	*ip = inode;

	memset(ip, 0, sizeof(struct scxfs_inode));

	/* vfs inode */
	inode_init_once(VFS_I(ip));

	/* scxfs inode */
	atomic_set(&ip->i_pincount, 0);
	spin_lock_init(&ip->i_flags_lock);

	mrlock_init(&ip->i_mmaplock, MRLOCK_ALLOW_EQUAL_PRI|MRLOCK_BARRIER,
		     "xfsino", ip->i_ino);
	mrlock_init(&ip->i_lock, MRLOCK_ALLOW_EQUAL_PRI|MRLOCK_BARRIER,
		     "xfsino", ip->i_ino);
}

/*
 * We do an unlocked check for SCXFS_IDONTCACHE here because we are already
 * serialised against cache hits here via the inode->i_lock and igrab() in
 * scxfs_iget_cache_hit(). Hence a lookup that might clear this flag will not be
 * racing with us, and it avoids needing to grab a spinlock here for every inode
 * we drop the final reference on.
 */
STATIC int
scxfs_fs_drop_inode(
	struct inode		*inode)
{
	struct scxfs_inode	*ip = SCXFS_I(inode);

	/*
	 * If this unlinked inode is in the middle of recovery, don't
	 * drop the inode just yet; log recovery will take care of
	 * that.  See the comment for this inode flag.
	 */
	if (ip->i_flags & SCXFS_IRECOVERY) {
		ASSERT(ip->i_mount->m_log->l_flags & XLOG_RECOVERY_NEEDED);
		return 0;
	}

	return generic_drop_inode(inode) || (ip->i_flags & SCXFS_IDONTCACHE);
}

STATIC void
scxfs_free_fsname(
	struct scxfs_mount	*mp)
{
	kfree(mp->m_fsname);
	kfree(mp->m_rtname);
	kfree(mp->m_logname);
}

STATIC int
scxfs_fs_sync_fs(
	struct super_block	*sb,
	int			wait)
{
	struct scxfs_mount	*mp = SCXFS_M(sb);

	/*
	 * Doing anything during the async pass would be counterproductive.
	 */
	if (!wait)
		return 0;

	scxfs_log_force(mp, SCXFS_LOG_SYNC);
	if (laptop_mode) {
		/*
		 * The disk must be active because we're syncing.
		 * We schedule log work now (now that the disk is
		 * active) instead of later (when it might not be).
		 */
		flush_delayed_work(&mp->m_log->l_work);
	}

	return 0;
}

STATIC int
scxfs_fs_statfs(
	struct dentry		*dentry,
	struct kstatfs		*statp)
{
	struct scxfs_mount	*mp = SCXFS_M(dentry->d_sb);
	scxfs_sb_t		*sbp = &mp->m_sb;
	struct scxfs_inode	*ip = SCXFS_I(d_inode(dentry));
	uint64_t		fakeinos, id;
	uint64_t		icount;
	uint64_t		ifree;
	uint64_t		fdblocks;
	scxfs_extlen_t		lsize;
	int64_t			ffree;

	statp->f_type = SCXFS_SUPER_MAGIC;
	statp->f_namelen = MAXNAMELEN - 1;

	id = huge_encode_dev(mp->m_ddev_targp->bt_dev);
	statp->f_fsid.val[0] = (u32)id;
	statp->f_fsid.val[1] = (u32)(id >> 32);

	icount = percpu_counter_sum(&mp->m_icount);
	ifree = percpu_counter_sum(&mp->m_ifree);
	fdblocks = percpu_counter_sum(&mp->m_fdblocks);

	spin_lock(&mp->m_sb_lock);
	statp->f_bsize = sbp->sb_blocksize;
	lsize = sbp->sb_logstart ? sbp->sb_logblocks : 0;
	statp->f_blocks = sbp->sb_dblocks - lsize;
	spin_unlock(&mp->m_sb_lock);

	statp->f_bfree = fdblocks - mp->m_alloc_set_aside;
	statp->f_bavail = statp->f_bfree;

	fakeinos = SCXFS_FSB_TO_INO(mp, statp->f_bfree);
	statp->f_files = min(icount + fakeinos, (uint64_t)SCXFS_MAXINUMBER);
	if (M_IGEO(mp)->maxicount)
		statp->f_files = min_t(typeof(statp->f_files),
					statp->f_files,
					M_IGEO(mp)->maxicount);

	/* If sb_icount overshot maxicount, report actual allocation */
	statp->f_files = max_t(typeof(statp->f_files),
					statp->f_files,
					sbp->sb_icount);

	/* make sure statp->f_ffree does not underflow */
	ffree = statp->f_files - (icount - ifree);
	statp->f_ffree = max_t(int64_t, ffree, 0);


	if ((ip->i_d.di_flags & SCXFS_DIFLAG_PROJINHERIT) &&
	    ((mp->m_qflags & (SCXFS_PQUOTA_ACCT|SCXFS_PQUOTA_ENFD))) ==
			      (SCXFS_PQUOTA_ACCT|SCXFS_PQUOTA_ENFD))
		scxfs_qm_statvfs(ip, statp);

	if (SCXFS_IS_REALTIME_MOUNT(mp) &&
	    (ip->i_d.di_flags & (SCXFS_DIFLAG_RTINHERIT | SCXFS_DIFLAG_REALTIME))) {
		statp->f_blocks = sbp->sb_rblocks;
		statp->f_bavail = statp->f_bfree =
			sbp->sb_frextents * sbp->sb_rextsize;
	}

	return 0;
}

STATIC void
scxfs_save_resvblks(struct scxfs_mount *mp)
{
	uint64_t resblks = 0;

	mp->m_resblks_save = mp->m_resblks;
	scxfs_reserve_blocks(mp, &resblks, NULL);
}

STATIC void
scxfs_restore_resvblks(struct scxfs_mount *mp)
{
	uint64_t resblks;

	if (mp->m_resblks_save) {
		resblks = mp->m_resblks_save;
		mp->m_resblks_save = 0;
	} else
		resblks = scxfs_default_resblks(mp);

	scxfs_reserve_blocks(mp, &resblks, NULL);
}

/*
 * Trigger writeback of all the dirty metadata in the file system.
 *
 * This ensures that the metadata is written to their location on disk rather
 * than just existing in transactions in the log. This means after a quiesce
 * there is no log replay required to write the inodes to disk - this is the
 * primary difference between a sync and a quiesce.
 *
 * Note: scxfs_log_quiesce() stops background log work - the callers must ensure
 * it is started again when appropriate.
 */
void
scxfs_quiesce_attr(
	struct scxfs_mount	*mp)
{
	int	error = 0;

	/* wait for all modifications to complete */
	while (atomic_read(&mp->m_active_trans) > 0)
		delay(100);

	/* force the log to unpin objects from the now complete transactions */
	scxfs_log_force(mp, SCXFS_LOG_SYNC);

	/* reclaim inodes to do any IO before the freeze completes */
	scxfs_reclaim_inodes(mp, 0);
	scxfs_reclaim_inodes(mp, SYNC_WAIT);

	/* Push the superblock and write an unmount record */
	error = scxfs_log_sbcount(mp);
	if (error)
		scxfs_warn(mp, "scxfs_attr_quiesce: failed to log sb changes. "
				"Frozen image may not be consistent.");
	/*
	 * Just warn here till VFS can correctly support
	 * read-only remount without racing.
	 */
	WARN_ON(atomic_read(&mp->m_active_trans) != 0);

	scxfs_log_quiesce(mp);
}

STATIC int
scxfs_test_remount_options(
	struct super_block	*sb,
	char			*options)
{
	int			error = 0;
	struct scxfs_mount	*tmp_mp;

	tmp_mp = kmem_zalloc(sizeof(*tmp_mp), KM_MAYFAIL);
	if (!tmp_mp)
		return -ENOMEM;

	tmp_mp->m_super = sb;
	error = scxfs_parseargs(tmp_mp, options);
	scxfs_free_fsname(tmp_mp);
	kmem_free(tmp_mp);

	return error;
}

STATIC int
scxfs_fs_remount(
	struct super_block	*sb,
	int			*flags,
	char			*options)
{
	struct scxfs_mount	*mp = SCXFS_M(sb);
	scxfs_sb_t		*sbp = &mp->m_sb;
	substring_t		args[MAX_OPT_ARGS];
	char			*p;
	int			error;

	/* First, check for complete junk; i.e. invalid options */
	error = scxfs_test_remount_options(sb, options);
	if (error)
		return error;

	sync_filesystem(sb);
	while ((p = strsep(&options, ",")) != NULL) {
		int token;

		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
		case Opt_inode64:
			mp->m_flags &= ~SCXFS_MOUNT_SMALL_INUMS;
			mp->m_maxagi = scxfs_set_inode_alloc(mp, sbp->sb_agcount);
			break;
		case Opt_inode32:
			mp->m_flags |= SCXFS_MOUNT_SMALL_INUMS;
			mp->m_maxagi = scxfs_set_inode_alloc(mp, sbp->sb_agcount);
			break;
		default:
			/*
			 * Logically we would return an error here to prevent
			 * users from believing they might have changed
			 * mount options using remount which can't be changed.
			 *
			 * But unfortunately mount(8) adds all options from
			 * mtab and fstab to the mount arguments in some cases
			 * so we can't blindly reject options, but have to
			 * check for each specified option if it actually
			 * differs from the currently set option and only
			 * reject it if that's the case.
			 *
			 * Until that is implemented we return success for
			 * every remount request, and silently ignore all
			 * options that we can't actually change.
			 */
#if 0
			scxfs_info(mp,
		"mount option \"%s\" not supported for remount", p);
			return -EINVAL;
#else
			break;
#endif
		}
	}

	/* ro -> rw */
	if ((mp->m_flags & SCXFS_MOUNT_RDONLY) && !(*flags & SB_RDONLY)) {
		if (mp->m_flags & SCXFS_MOUNT_NORECOVERY) {
			scxfs_warn(mp,
		"ro->rw transition prohibited on norecovery mount");
			return -EINVAL;
		}

		if (SCXFS_SB_VERSION_NUM(sbp) == SCXFS_SB_VERSION_5 &&
		    scxfs_sb_has_ro_compat_feature(sbp,
					SCXFS_SB_FEAT_RO_COMPAT_UNKNOWN)) {
			scxfs_warn(mp,
"ro->rw transition prohibited on unknown (0x%x) ro-compat filesystem",
				(sbp->sb_features_ro_compat &
					SCXFS_SB_FEAT_RO_COMPAT_UNKNOWN));
			return -EINVAL;
		}

		mp->m_flags &= ~SCXFS_MOUNT_RDONLY;

		/*
		 * If this is the first remount to writeable state we
		 * might have some superblock changes to update.
		 */
		if (mp->m_update_sb) {
			error = scxfs_sync_sb(mp, false);
			if (error) {
				scxfs_warn(mp, "failed to write sb changes");
				return error;
			}
			mp->m_update_sb = false;
		}

		/*
		 * Fill out the reserve pool if it is empty. Use the stashed
		 * value if it is non-zero, otherwise go with the default.
		 */
		scxfs_restore_resvblks(mp);
		scxfs_log_work_queue(mp);

		/* Recover any CoW blocks that never got remapped. */
		error = scxfs_reflink_recover_cow(mp);
		if (error) {
			scxfs_err(mp,
	"Error %d recovering leftover CoW allocations.", error);
			scxfs_force_shutdown(mp, SHUTDOWN_CORRUPT_INCORE);
			return error;
		}
		scxfs_start_block_reaping(mp);

		/* Create the per-AG metadata reservation pool .*/
		error = scxfs_fs_reserve_ag_blocks(mp);
		if (error && error != -ENOSPC)
			return error;
	}

	/* rw -> ro */
	if (!(mp->m_flags & SCXFS_MOUNT_RDONLY) && (*flags & SB_RDONLY)) {
		/*
		 * Cancel background eofb scanning so it cannot race with the
		 * final log force+buftarg wait and deadlock the remount.
		 */
		scxfs_stop_block_reaping(mp);

		/* Get rid of any leftover CoW reservations... */
		error = scxfs_icache_free_cowblocks(mp, NULL);
		if (error) {
			scxfs_force_shutdown(mp, SHUTDOWN_CORRUPT_INCORE);
			return error;
		}

		/* Free the per-AG metadata reservation pool. */
		error = scxfs_fs_unreserve_ag_blocks(mp);
		if (error) {
			scxfs_force_shutdown(mp, SHUTDOWN_CORRUPT_INCORE);
			return error;
		}

		/*
		 * Before we sync the metadata, we need to free up the reserve
		 * block pool so that the used block count in the superblock on
		 * disk is correct at the end of the remount. Stash the current
		 * reserve pool size so that if we get remounted rw, we can
		 * return it to the same size.
		 */
		scxfs_save_resvblks(mp);

		scxfs_quiesce_attr(mp);
		mp->m_flags |= SCXFS_MOUNT_RDONLY;
	}

	return 0;
}

/*
 * Second stage of a freeze. The data is already frozen so we only
 * need to take care of the metadata. Once that's done sync the superblock
 * to the log to dirty it in case of a crash while frozen. This ensures that we
 * will recover the unlinked inode lists on the next mount.
 */
STATIC int
scxfs_fs_freeze(
	struct super_block	*sb)
{
	struct scxfs_mount	*mp = SCXFS_M(sb);

	scxfs_stop_block_reaping(mp);
	scxfs_save_resvblks(mp);
	scxfs_quiesce_attr(mp);
	return scxfs_sync_sb(mp, true);
}

STATIC int
scxfs_fs_unfreeze(
	struct super_block	*sb)
{
	struct scxfs_mount	*mp = SCXFS_M(sb);

	scxfs_restore_resvblks(mp);
	scxfs_log_work_queue(mp);
	scxfs_start_block_reaping(mp);
	return 0;
}

STATIC int
scxfs_fs_show_options(
	struct seq_file		*m,
	struct dentry		*root)
{
	scxfs_showargs(SCXFS_M(root->d_sb), m);
	return 0;
}

/*
 * This function fills in scxfs_mount_t fields based on mount args.
 * Note: the superblock _has_ now been read in.
 */
STATIC int
scxfs_finish_flags(
	struct scxfs_mount	*mp)
{
	int			ronly = (mp->m_flags & SCXFS_MOUNT_RDONLY);

	/* Fail a mount where the logbuf is smaller than the log stripe */
	if (scxfs_sb_version_haslogv2(&mp->m_sb)) {
		if (mp->m_logbsize <= 0 &&
		    mp->m_sb.sb_logsunit > XLOG_BIG_RECORD_BSIZE) {
			mp->m_logbsize = mp->m_sb.sb_logsunit;
		} else if (mp->m_logbsize > 0 &&
			   mp->m_logbsize < mp->m_sb.sb_logsunit) {
			scxfs_warn(mp,
		"logbuf size must be greater than or equal to log stripe size");
			return -EINVAL;
		}
	} else {
		/* Fail a mount if the logbuf is larger than 32K */
		if (mp->m_logbsize > XLOG_BIG_RECORD_BSIZE) {
			scxfs_warn(mp,
		"logbuf size for version 1 logs must be 16K or 32K");
			return -EINVAL;
		}
	}

	/*
	 * V5 filesystems always use attr2 format for attributes.
	 */
	if (scxfs_sb_version_hascrc(&mp->m_sb) &&
	    (mp->m_flags & SCXFS_MOUNT_NOATTR2)) {
		scxfs_warn(mp, "Cannot mount a V5 filesystem as noattr2. "
			     "attr2 is always enabled for V5 filesystems.");
		return -EINVAL;
	}

	/*
	 * mkfs'ed attr2 will turn on attr2 mount unless explicitly
	 * told by noattr2 to turn it off
	 */
	if (scxfs_sb_version_hasattr2(&mp->m_sb) &&
	    !(mp->m_flags & SCXFS_MOUNT_NOATTR2))
		mp->m_flags |= SCXFS_MOUNT_ATTR2;

	/*
	 * prohibit r/w mounts of read-only filesystems
	 */
	if ((mp->m_sb.sb_flags & SCXFS_SBF_READONLY) && !ronly) {
		scxfs_warn(mp,
			"cannot mount a read-only filesystem as read-write");
		return -EROFS;
	}

	if ((mp->m_qflags & (SCXFS_GQUOTA_ACCT | SCXFS_GQUOTA_ACTIVE)) &&
	    (mp->m_qflags & (SCXFS_PQUOTA_ACCT | SCXFS_PQUOTA_ACTIVE)) &&
	    !scxfs_sb_version_has_pquotino(&mp->m_sb)) {
		scxfs_warn(mp,
		  "Super block does not support project and group quota together");
		return -EINVAL;
	}

	return 0;
}

static int
scxfs_init_percpu_counters(
	struct scxfs_mount	*mp)
{
	int		error;

	error = percpu_counter_init(&mp->m_icount, 0, GFP_KERNEL);
	if (error)
		return -ENOMEM;

	error = percpu_counter_init(&mp->m_ifree, 0, GFP_KERNEL);
	if (error)
		goto free_icount;

	error = percpu_counter_init(&mp->m_fdblocks, 0, GFP_KERNEL);
	if (error)
		goto free_ifree;

	error = percpu_counter_init(&mp->m_delalloc_blks, 0, GFP_KERNEL);
	if (error)
		goto free_fdblocks;

	return 0;

free_fdblocks:
	percpu_counter_destroy(&mp->m_fdblocks);
free_ifree:
	percpu_counter_destroy(&mp->m_ifree);
free_icount:
	percpu_counter_destroy(&mp->m_icount);
	return -ENOMEM;
}

void
scxfs_reinit_percpu_counters(
	struct scxfs_mount	*mp)
{
	percpu_counter_set(&mp->m_icount, mp->m_sb.sb_icount);
	percpu_counter_set(&mp->m_ifree, mp->m_sb.sb_ifree);
	percpu_counter_set(&mp->m_fdblocks, mp->m_sb.sb_fdblocks);
}

static void
scxfs_destroy_percpu_counters(
	struct scxfs_mount	*mp)
{
	percpu_counter_destroy(&mp->m_icount);
	percpu_counter_destroy(&mp->m_ifree);
	percpu_counter_destroy(&mp->m_fdblocks);
	ASSERT(SCXFS_FORCED_SHUTDOWN(mp) ||
	       percpu_counter_sum(&mp->m_delalloc_blks) == 0);
	percpu_counter_destroy(&mp->m_delalloc_blks);
}

static struct scxfs_mount *
scxfs_mount_alloc(
	struct super_block	*sb)
{
	struct scxfs_mount	*mp;

	mp = kzalloc(sizeof(struct scxfs_mount), GFP_KERNEL);
	if (!mp)
		return NULL;

	mp->m_super = sb;
	spin_lock_init(&mp->m_sb_lock);
	spin_lock_init(&mp->m_agirotor_lock);
	INIT_RADIX_TREE(&mp->m_perag_tree, GFP_ATOMIC);
	spin_lock_init(&mp->m_perag_lock);
	mutex_init(&mp->m_growlock);
	atomic_set(&mp->m_active_trans, 0);
	INIT_DELAYED_WORK(&mp->m_reclaim_work, scxfs_reclaim_worker);
	INIT_DELAYED_WORK(&mp->m_eofblocks_work, scxfs_eofblocks_worker);
	INIT_DELAYED_WORK(&mp->m_cowblocks_work, scxfs_cowblocks_worker);
	mp->m_kobj.kobject.kset = scxfs_kset;
	/*
	 * We don't create the finobt per-ag space reservation until after log
	 * recovery, so we must set this to true so that an ifree transaction
	 * started during log recovery will not depend on space reservations
	 * for finobt expansion.
	 */
	mp->m_finobt_nores = true;
	return mp;
}


STATIC int
scxfs_fs_fill_super(
	struct super_block	*sb,
	void			*data,
	int			silent)
{
	struct inode		*root;
	struct scxfs_mount	*mp = NULL;
	int			flags = 0, error = -ENOMEM;

	/*
	 * allocate mp and do all low-level struct initializations before we
	 * attach it to the super
	 */
	mp = scxfs_mount_alloc(sb);
	if (!mp)
		goto out;
	sb->s_fs_info = mp;

	error = scxfs_parseargs(mp, (char *)data);
	if (error)
		goto out_free_fsname;

	sb_min_blocksize(sb, BBSIZE);
	sb->s_xattr = scxfs_xattr_handlers;
	sb->s_export_op = &scxfs_export_operations;
#ifdef CONFIG_XFS_QUOTA
	sb->s_qcop = &scxfs_quotactl_operations;
	sb->s_quota_types = QTYPE_MASK_USR | QTYPE_MASK_GRP | QTYPE_MASK_PRJ;
#endif
	sb->s_op = &scxfs_super_operations;

	/*
	 * Delay mount work if the debug hook is set. This is debug
	 * instrumention to coordinate simulation of scxfs mount failures with
	 * VFS superblock operations
	 */
	if (scxfs_globals.mount_delay) {
		scxfs_notice(mp, "Delaying mount for %d seconds.",
			scxfs_globals.mount_delay);
		msleep(scxfs_globals.mount_delay * 1000);
	}

	if (silent)
		flags |= SCXFS_MFSI_QUIET;

	error = scxfs_open_devices(mp);
	if (error)
		goto out_free_fsname;

	error = scxfs_init_mount_workqueues(mp);
	if (error)
		goto out_close_devices;

	error = scxfs_init_percpu_counters(mp);
	if (error)
		goto out_destroy_workqueues;

	/* Allocate stats memory before we do operations that might use it */
	mp->m_stats.xs_stats = alloc_percpu(struct xfsstats);
	if (!mp->m_stats.xs_stats) {
		error = -ENOMEM;
		goto out_destroy_counters;
	}

	error = scxfs_readsb(mp, flags);
	if (error)
		goto out_free_stats;

	error = scxfs_finish_flags(mp);
	if (error)
		goto out_free_sb;

	error = scxfs_setup_devices(mp);
	if (error)
		goto out_free_sb;

	error = scxfs_filestream_mount(mp);
	if (error)
		goto out_free_sb;

	/*
	 * we must configure the block size in the superblock before we run the
	 * full mount process as the mount process can lookup and cache inodes.
	 */
	sb->s_magic = SCXFS_SUPER_MAGIC;
	sb->s_blocksize = mp->m_sb.sb_blocksize;
	sb->s_blocksize_bits = ffs(sb->s_blocksize) - 1;
	sb->s_maxbytes = scxfs_max_file_offset(sb->s_blocksize_bits);
	sb->s_max_links = SCXFS_MAXLINK;
	sb->s_time_gran = 1;
	sb->s_time_min = S32_MIN;
	sb->s_time_max = S32_MAX;
	sb->s_iflags |= SB_I_CGROUPWB;

	set_posix_acl_flag(sb);

	/* version 5 superblocks support inode version counters. */
	if (SCXFS_SB_VERSION_NUM(&mp->m_sb) == SCXFS_SB_VERSION_5)
		sb->s_flags |= SB_I_VERSION;

	if (mp->m_flags & SCXFS_MOUNT_DAX) {
		bool rtdev_is_dax = false, datadev_is_dax;

		scxfs_warn(mp,
		"DAX enabled. Warning: EXPERIMENTAL, use at your own risk");

		datadev_is_dax = bdev_dax_supported(mp->m_ddev_targp->bt_bdev,
			sb->s_blocksize);
		if (mp->m_rtdev_targp)
			rtdev_is_dax = bdev_dax_supported(
				mp->m_rtdev_targp->bt_bdev, sb->s_blocksize);
		if (!rtdev_is_dax && !datadev_is_dax) {
			scxfs_alert(mp,
			"DAX unsupported by block device. Turning off DAX.");
			mp->m_flags &= ~SCXFS_MOUNT_DAX;
		}
		if (scxfs_sb_version_hasreflink(&mp->m_sb)) {
			scxfs_alert(mp,
		"DAX and reflink cannot be used together!");
			error = -EINVAL;
			goto out_filestream_unmount;
		}
	}

	if (mp->m_flags & SCXFS_MOUNT_DISCARD) {
		struct request_queue *q = bdev_get_queue(sb->s_bdev);

		if (!blk_queue_discard(q)) {
			scxfs_warn(mp, "mounting with \"discard\" option, but "
					"the device does not support discard");
			mp->m_flags &= ~SCXFS_MOUNT_DISCARD;
		}
	}

	if (scxfs_sb_version_hasreflink(&mp->m_sb)) {
		if (mp->m_sb.sb_rblocks) {
			scxfs_alert(mp,
	"reflink not compatible with realtime device!");
			error = -EINVAL;
			goto out_filestream_unmount;
		}

		if (scxfs_globals.always_cow) {
			scxfs_info(mp, "using DEBUG-only always_cow mode.");
			mp->m_always_cow = true;
		}
	}

	if (scxfs_sb_version_hasrmapbt(&mp->m_sb) && mp->m_sb.sb_rblocks) {
		scxfs_alert(mp,
	"reverse mapping btree not compatible with realtime device!");
		error = -EINVAL;
		goto out_filestream_unmount;
	}

	error = scxfs_mountfs(mp);
	if (error)
		goto out_filestream_unmount;

	root = igrab(VFS_I(mp->m_rootip));
	if (!root) {
		error = -ENOENT;
		goto out_unmount;
	}
	sb->s_root = d_make_root(root);
	if (!sb->s_root) {
		error = -ENOMEM;
		goto out_unmount;
	}

	return 0;

 out_filestream_unmount:
	scxfs_filestream_unmount(mp);
 out_free_sb:
	scxfs_freesb(mp);
 out_free_stats:
	free_percpu(mp->m_stats.xs_stats);
 out_destroy_counters:
	scxfs_destroy_percpu_counters(mp);
 out_destroy_workqueues:
	scxfs_destroy_mount_workqueues(mp);
 out_close_devices:
	scxfs_close_devices(mp);
 out_free_fsname:
	sb->s_fs_info = NULL;
	scxfs_free_fsname(mp);
	kfree(mp);
 out:
	return error;

 out_unmount:
	scxfs_filestream_unmount(mp);
	scxfs_unmountfs(mp);
	goto out_free_sb;
}

STATIC void
scxfs_fs_put_super(
	struct super_block	*sb)
{
	struct scxfs_mount	*mp = SCXFS_M(sb);

	/* if ->fill_super failed, we have no mount to tear down */
	if (!sb->s_fs_info)
		return;

	scxfs_notice(mp, "Unmounting Filesystem");
	scxfs_filestream_unmount(mp);
	scxfs_unmountfs(mp);

	scxfs_freesb(mp);
	free_percpu(mp->m_stats.xs_stats);
	scxfs_destroy_percpu_counters(mp);
	scxfs_destroy_mount_workqueues(mp);
	scxfs_close_devices(mp);

	sb->s_fs_info = NULL;
	scxfs_free_fsname(mp);
	kfree(mp);
}

STATIC struct dentry *
scxfs_fs_mount(
	struct file_system_type	*fs_type,
	int			flags,
	const char		*dev_name,
	void			*data)
{
	return mount_bdev(fs_type, flags, dev_name, data, scxfs_fs_fill_super);
}

static long
scxfs_fs_nr_cached_objects(
	struct super_block	*sb,
	struct shrink_control	*sc)
{
	/* Paranoia: catch incorrect calls during mount setup or teardown */
	if (WARN_ON_ONCE(!sb->s_fs_info))
		return 0;
	return scxfs_reclaim_inodes_count(SCXFS_M(sb));
}

static long
scxfs_fs_free_cached_objects(
	struct super_block	*sb,
	struct shrink_control	*sc)
{
	return scxfs_reclaim_inodes_nr(SCXFS_M(sb), sc->nr_to_scan);
}

static const struct super_operations scxfs_super_operations = {
	.alloc_inode		= scxfs_fs_alloc_inode,
	.destroy_inode		= scxfs_fs_destroy_inode,
	.dirty_inode		= scxfs_fs_dirty_inode,
	.drop_inode		= scxfs_fs_drop_inode,
	.put_super		= scxfs_fs_put_super,
	.sync_fs		= scxfs_fs_sync_fs,
	.freeze_fs		= scxfs_fs_freeze,
	.unfreeze_fs		= scxfs_fs_unfreeze,
	.statfs			= scxfs_fs_statfs,
	.remount_fs		= scxfs_fs_remount,
	.show_options		= scxfs_fs_show_options,
	.nr_cached_objects	= scxfs_fs_nr_cached_objects,
	.free_cached_objects	= scxfs_fs_free_cached_objects,
};

static struct file_system_type scxfs_fs_type = {
	.owner			= THIS_MODULE,
	.name			= "scxfs",
	.mount			= scxfs_fs_mount,
	.kill_sb		= kill_block_super,
	.fs_flags		= FS_REQUIRES_DEV,
};
MODULE_ALIAS_FS("scxfs");

STATIC int __init
scxfs_init_zones(void)
{
	if (bioset_init(&scxfs_ioend_bioset, 4 * (PAGE_SIZE / SECTOR_SIZE),
			offsetof(struct scxfs_ioend, io_inline_bio),
			BIOSET_NEED_BVECS))
		goto out;

	scxfs_log_ticket_zone = kmem_zone_init(sizeof(xlog_ticket_t),
						"scxfs_log_ticket");
	if (!scxfs_log_ticket_zone)
		goto out_free_ioend_bioset;

	scxfs_bmap_free_item_zone = kmem_zone_init(
			sizeof(struct scxfs_extent_free_item),
			"scxfs_bmap_free_item");
	if (!scxfs_bmap_free_item_zone)
		goto out_destroy_log_ticket_zone;

	scxfs_btree_cur_zone = kmem_zone_init(sizeof(scxfs_btree_cur_t),
						"scxfs_btree_cur");
	if (!scxfs_btree_cur_zone)
		goto out_destroy_bmap_free_item_zone;

	scxfs_da_state_zone = kmem_zone_init(sizeof(scxfs_da_state_t),
						"scxfs_da_state");
	if (!scxfs_da_state_zone)
		goto out_destroy_btree_cur_zone;

	scxfs_ifork_zone = kmem_zone_init(sizeof(struct scxfs_ifork), "scxfs_ifork");
	if (!scxfs_ifork_zone)
		goto out_destroy_da_state_zone;

	scxfs_trans_zone = kmem_zone_init(sizeof(scxfs_trans_t), "scxfs_trans");
	if (!scxfs_trans_zone)
		goto out_destroy_ifork_zone;


	/*
	 * The size of the zone allocated buf log item is the maximum
	 * size possible under SCXFS.  This wastes a little bit of memory,
	 * but it is much faster.
	 */
	scxfs_buf_item_zone = kmem_zone_init(sizeof(struct scxfs_buf_log_item),
					   "scxfs_buf_item");
	if (!scxfs_buf_item_zone)
		goto out_destroy_trans_zone;

	scxfs_efd_zone = kmem_zone_init((sizeof(scxfs_efd_log_item_t) +
			((SCXFS_EFD_MAX_FAST_EXTENTS - 1) *
				 sizeof(scxfs_extent_t))), "scxfs_efd_item");
	if (!scxfs_efd_zone)
		goto out_destroy_buf_item_zone;

	scxfs_efi_zone = kmem_zone_init((sizeof(scxfs_efi_log_item_t) +
			((SCXFS_EFI_MAX_FAST_EXTENTS - 1) *
				sizeof(scxfs_extent_t))), "scxfs_efi_item");
	if (!scxfs_efi_zone)
		goto out_destroy_efd_zone;

	scxfs_inode_zone =
		kmem_zone_init_flags(sizeof(scxfs_inode_t), "scxfs_inode",
			KM_ZONE_HWALIGN | KM_ZONE_RECLAIM | KM_ZONE_SPREAD |
			KM_ZONE_ACCOUNT, scxfs_fs_inode_init_once);
	if (!scxfs_inode_zone)
		goto out_destroy_efi_zone;

	scxfs_ili_zone =
		kmem_zone_init_flags(sizeof(scxfs_inode_log_item_t), "scxfs_ili",
					KM_ZONE_SPREAD, NULL);
	if (!scxfs_ili_zone)
		goto out_destroy_inode_zone;
	scxfs_icreate_zone = kmem_zone_init(sizeof(struct scxfs_icreate_item),
					"scxfs_icr");
	if (!scxfs_icreate_zone)
		goto out_destroy_ili_zone;

	scxfs_rud_zone = kmem_zone_init(sizeof(struct scxfs_rud_log_item),
			"scxfs_rud_item");
	if (!scxfs_rud_zone)
		goto out_destroy_icreate_zone;

	scxfs_rui_zone = kmem_zone_init(
			scxfs_rui_log_item_sizeof(SCXFS_RUI_MAX_FAST_EXTENTS),
			"scxfs_rui_item");
	if (!scxfs_rui_zone)
		goto out_destroy_rud_zone;

	scxfs_cud_zone = kmem_zone_init(sizeof(struct scxfs_cud_log_item),
			"scxfs_cud_item");
	if (!scxfs_cud_zone)
		goto out_destroy_rui_zone;

	scxfs_cui_zone = kmem_zone_init(
			scxfs_cui_log_item_sizeof(SCXFS_CUI_MAX_FAST_EXTENTS),
			"scxfs_cui_item");
	if (!scxfs_cui_zone)
		goto out_destroy_cud_zone;

	scxfs_bud_zone = kmem_zone_init(sizeof(struct scxfs_bud_log_item),
			"scxfs_bud_item");
	if (!scxfs_bud_zone)
		goto out_destroy_cui_zone;

	scxfs_bui_zone = kmem_zone_init(
			scxfs_bui_log_item_sizeof(SCXFS_BUI_MAX_FAST_EXTENTS),
			"scxfs_bui_item");
	if (!scxfs_bui_zone)
		goto out_destroy_bud_zone;

	return 0;

 out_destroy_bud_zone:
	kmem_zone_destroy(scxfs_bud_zone);
 out_destroy_cui_zone:
	kmem_zone_destroy(scxfs_cui_zone);
 out_destroy_cud_zone:
	kmem_zone_destroy(scxfs_cud_zone);
 out_destroy_rui_zone:
	kmem_zone_destroy(scxfs_rui_zone);
 out_destroy_rud_zone:
	kmem_zone_destroy(scxfs_rud_zone);
 out_destroy_icreate_zone:
	kmem_zone_destroy(scxfs_icreate_zone);
 out_destroy_ili_zone:
	kmem_zone_destroy(scxfs_ili_zone);
 out_destroy_inode_zone:
	kmem_zone_destroy(scxfs_inode_zone);
 out_destroy_efi_zone:
	kmem_zone_destroy(scxfs_efi_zone);
 out_destroy_efd_zone:
	kmem_zone_destroy(scxfs_efd_zone);
 out_destroy_buf_item_zone:
	kmem_zone_destroy(scxfs_buf_item_zone);
 out_destroy_trans_zone:
	kmem_zone_destroy(scxfs_trans_zone);
 out_destroy_ifork_zone:
	kmem_zone_destroy(scxfs_ifork_zone);
 out_destroy_da_state_zone:
	kmem_zone_destroy(scxfs_da_state_zone);
 out_destroy_btree_cur_zone:
	kmem_zone_destroy(scxfs_btree_cur_zone);
 out_destroy_bmap_free_item_zone:
	kmem_zone_destroy(scxfs_bmap_free_item_zone);
 out_destroy_log_ticket_zone:
	kmem_zone_destroy(scxfs_log_ticket_zone);
 out_free_ioend_bioset:
	bioset_exit(&scxfs_ioend_bioset);
 out:
	return -ENOMEM;
}

STATIC void
scxfs_destroy_zones(void)
{
	/*
	 * Make sure all delayed rcu free are flushed before we
	 * destroy caches.
	 */
	rcu_barrier();
	kmem_zone_destroy(scxfs_bui_zone);
	kmem_zone_destroy(scxfs_bud_zone);
	kmem_zone_destroy(scxfs_cui_zone);
	kmem_zone_destroy(scxfs_cud_zone);
	kmem_zone_destroy(scxfs_rui_zone);
	kmem_zone_destroy(scxfs_rud_zone);
	kmem_zone_destroy(scxfs_icreate_zone);
	kmem_zone_destroy(scxfs_ili_zone);
	kmem_zone_destroy(scxfs_inode_zone);
	kmem_zone_destroy(scxfs_efi_zone);
	kmem_zone_destroy(scxfs_efd_zone);
	kmem_zone_destroy(scxfs_buf_item_zone);
	kmem_zone_destroy(scxfs_trans_zone);
	kmem_zone_destroy(scxfs_ifork_zone);
	kmem_zone_destroy(scxfs_da_state_zone);
	kmem_zone_destroy(scxfs_btree_cur_zone);
	kmem_zone_destroy(scxfs_bmap_free_item_zone);
	kmem_zone_destroy(scxfs_log_ticket_zone);
	bioset_exit(&scxfs_ioend_bioset);
}

STATIC int __init
scxfs_init_workqueues(void)
{
	/*
	 * The allocation workqueue can be used in memory reclaim situations
	 * (writepage path), and parallelism is only limited by the number of
	 * AGs in all the filesystems mounted. Hence use the default large
	 * max_active value for this workqueue.
	 */
	scxfs_alloc_wq = alloc_workqueue("xfsalloc",
			WQ_MEM_RECLAIM|WQ_FREEZABLE, 0);
	if (!scxfs_alloc_wq)
		return -ENOMEM;

	scxfs_discard_wq = alloc_workqueue("xfsdiscard", WQ_UNBOUND, 0);
	if (!scxfs_discard_wq)
		goto out_free_alloc_wq;

	return 0;
out_free_alloc_wq:
	destroy_workqueue(scxfs_alloc_wq);
	return -ENOMEM;
}

STATIC void
scxfs_destroy_workqueues(void)
{
	destroy_workqueue(scxfs_discard_wq);
	destroy_workqueue(scxfs_alloc_wq);
}

STATIC int __init
init_scxfs_fs(void)
{
	int			error;

	scxfs_check_ondisk_structs();

	printk(KERN_INFO SCXFS_VERSION_STRING " with "
			 SCXFS_BUILD_OPTIONS " enabled\n");

	scxfs_dir_startup();

	error = scxfs_init_zones();
	if (error)
		goto out;

	error = scxfs_init_workqueues();
	if (error)
		goto out_destroy_zones;

	error = scxfs_mru_cache_init();
	if (error)
		goto out_destroy_wq;

	error = scxfs_buf_init();
	if (error)
		goto out_mru_cache_uninit;

	error = scxfs_init_procfs();
	if (error)
		goto out_buf_terminate;

	error = scxfs_sysctl_register();
	if (error)
		goto out_cleanup_procfs;

	scxfs_kset = kset_create_and_add("scxfs", NULL, fs_kobj);
	if (!scxfs_kset) {
		error = -ENOMEM;
		goto out_sysctl_unregister;
	}

	xfsstats.xs_kobj.kobject.kset = scxfs_kset;

	xfsstats.xs_stats = alloc_percpu(struct xfsstats);
	if (!xfsstats.xs_stats) {
		error = -ENOMEM;
		goto out_kset_unregister;
	}

	error = scxfs_sysfs_init(&xfsstats.xs_kobj, &scxfs_stats_ktype, NULL,
			       "stats");
	if (error)
		goto out_free_stats;

#ifdef DEBUG
	scxfs_dbg_kobj.kobject.kset = scxfs_kset;
	error = scxfs_sysfs_init(&scxfs_dbg_kobj, &scxfs_dbg_ktype, NULL, "debug");
	if (error)
		goto out_remove_stats_kobj;
#endif

	error = scxfs_qm_init();
	if (error)
		goto out_remove_dbg_kobj;

	error = register_filesystem(&scxfs_fs_type);
	if (error)
		goto out_qm_exit;
	return 0;

 out_qm_exit:
	scxfs_qm_exit();
 out_remove_dbg_kobj:
#ifdef DEBUG
	scxfs_sysfs_del(&scxfs_dbg_kobj);
 out_remove_stats_kobj:
#endif
	scxfs_sysfs_del(&xfsstats.xs_kobj);
 out_free_stats:
	free_percpu(xfsstats.xs_stats);
 out_kset_unregister:
	kset_unregister(scxfs_kset);
 out_sysctl_unregister:
	scxfs_sysctl_unregister();
 out_cleanup_procfs:
	scxfs_cleanup_procfs();
 out_buf_terminate:
	scxfs_buf_terminate();
 out_mru_cache_uninit:
	scxfs_mru_cache_uninit();
 out_destroy_wq:
	scxfs_destroy_workqueues();
 out_destroy_zones:
	scxfs_destroy_zones();
 out:
	return error;
}

STATIC void __exit
exit_scxfs_fs(void)
{
	scxfs_qm_exit();
	unregister_filesystem(&scxfs_fs_type);
#ifdef DEBUG
	scxfs_sysfs_del(&scxfs_dbg_kobj);
#endif
	scxfs_sysfs_del(&xfsstats.xs_kobj);
	free_percpu(xfsstats.xs_stats);
	kset_unregister(scxfs_kset);
	scxfs_sysctl_unregister();
	scxfs_cleanup_procfs();
	scxfs_buf_terminate();
	scxfs_mru_cache_uninit();
	scxfs_destroy_workqueues();
	scxfs_destroy_zones();
	scxfs_uuid_table_free();
}

module_init(init_scxfs_fs);
module_exit(exit_scxfs_fs);

MODULE_AUTHOR("Silicon Graphics, Inc.");
MODULE_DESCRIPTION(SCXFS_VERSION_STRING " with " SCXFS_BUILD_OPTIONS " enabled");
MODULE_LICENSE("GPL");
