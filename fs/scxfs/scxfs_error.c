// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2001,2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#include "scxfs.h"
#include "scxfs_shared.h"
#include "scxfs_format.h"
#include "scxfs_fs.h"
#include "scxfs_log_format.h"
#include "scxfs_trans_resv.h"
#include "scxfs_mount.h"
#include "scxfs_errortag.h"
#include "scxfs_error.h"
#include "scxfs_sysfs.h"
#include "scxfs_inode.h"

#ifdef DEBUG

static unsigned int scxfs_errortag_random_default[] = {
	SCXFS_RANDOM_DEFAULT,
	SCXFS_RANDOM_IFLUSH_1,
	SCXFS_RANDOM_IFLUSH_2,
	SCXFS_RANDOM_IFLUSH_3,
	SCXFS_RANDOM_IFLUSH_4,
	SCXFS_RANDOM_IFLUSH_5,
	SCXFS_RANDOM_IFLUSH_6,
	SCXFS_RANDOM_DA_READ_BUF,
	SCXFS_RANDOM_BTREE_CHECK_LBLOCK,
	SCXFS_RANDOM_BTREE_CHECK_SBLOCK,
	SCXFS_RANDOM_ALLOC_READ_AGF,
	SCXFS_RANDOM_IALLOC_READ_AGI,
	SCXFS_RANDOM_ITOBP_INOTOBP,
	SCXFS_RANDOM_IUNLINK,
	SCXFS_RANDOM_IUNLINK_REMOVE,
	SCXFS_RANDOM_DIR_INO_VALIDATE,
	SCXFS_RANDOM_BULKSTAT_READ_CHUNK,
	SCXFS_RANDOM_IODONE_IOERR,
	SCXFS_RANDOM_STRATREAD_IOERR,
	SCXFS_RANDOM_STRATCMPL_IOERR,
	SCXFS_RANDOM_DIOWRITE_IOERR,
	SCXFS_RANDOM_BMAPIFORMAT,
	SCXFS_RANDOM_FREE_EXTENT,
	SCXFS_RANDOM_RMAP_FINISH_ONE,
	SCXFS_RANDOM_REFCOUNT_CONTINUE_UPDATE,
	SCXFS_RANDOM_REFCOUNT_FINISH_ONE,
	SCXFS_RANDOM_BMAP_FINISH_ONE,
	SCXFS_RANDOM_AG_RESV_CRITICAL,
	SCXFS_RANDOM_DROP_WRITES,
	SCXFS_RANDOM_LOG_BAD_CRC,
	SCXFS_RANDOM_LOG_ITEM_PIN,
	SCXFS_RANDOM_BUF_LRU_REF,
	SCXFS_RANDOM_FORCE_SCRUB_REPAIR,
	SCXFS_RANDOM_FORCE_SUMMARY_RECALC,
	SCXFS_RANDOM_IUNLINK_FALLBACK,
};

struct scxfs_errortag_attr {
	struct attribute	attr;
	unsigned int		tag;
};

static inline struct scxfs_errortag_attr *
to_attr(struct attribute *attr)
{
	return container_of(attr, struct scxfs_errortag_attr, attr);
}

static inline struct scxfs_mount *
to_mp(struct kobject *kobject)
{
	struct scxfs_kobj *kobj = to_kobj(kobject);

	return container_of(kobj, struct scxfs_mount, m_errortag_kobj);
}

STATIC ssize_t
scxfs_errortag_attr_store(
	struct kobject		*kobject,
	struct attribute	*attr,
	const char		*buf,
	size_t			count)
{
	struct scxfs_mount	*mp = to_mp(kobject);
	struct scxfs_errortag_attr *scxfs_attr = to_attr(attr);
	int			ret;
	unsigned int		val;

	if (strcmp(buf, "default") == 0) {
		val = scxfs_errortag_random_default[scxfs_attr->tag];
	} else {
		ret = kstrtouint(buf, 0, &val);
		if (ret)
			return ret;
	}

	ret = scxfs_errortag_set(mp, scxfs_attr->tag, val);
	if (ret)
		return ret;
	return count;
}

STATIC ssize_t
scxfs_errortag_attr_show(
	struct kobject		*kobject,
	struct attribute	*attr,
	char			*buf)
{
	struct scxfs_mount	*mp = to_mp(kobject);
	struct scxfs_errortag_attr *scxfs_attr = to_attr(attr);

	return snprintf(buf, PAGE_SIZE, "%u\n",
			scxfs_errortag_get(mp, scxfs_attr->tag));
}

static const struct sysfs_ops scxfs_errortag_sysfs_ops = {
	.show = scxfs_errortag_attr_show,
	.store = scxfs_errortag_attr_store,
};

#define SCXFS_ERRORTAG_ATTR_RW(_name, _tag) \
static struct scxfs_errortag_attr scxfs_errortag_attr_##_name = {		\
	.attr = {.name = __stringify(_name),				\
		 .mode = VERIFY_OCTAL_PERMISSIONS(S_IWUSR | S_IRUGO) },	\
	.tag	= (_tag),						\
}

#define SCXFS_ERRORTAG_ATTR_LIST(_name) &scxfs_errortag_attr_##_name.attr

SCXFS_ERRORTAG_ATTR_RW(noerror,		SCXFS_ERRTAG_NOERROR);
SCXFS_ERRORTAG_ATTR_RW(iflush1,		SCXFS_ERRTAG_IFLUSH_1);
SCXFS_ERRORTAG_ATTR_RW(iflush2,		SCXFS_ERRTAG_IFLUSH_2);
SCXFS_ERRORTAG_ATTR_RW(iflush3,		SCXFS_ERRTAG_IFLUSH_3);
SCXFS_ERRORTAG_ATTR_RW(iflush4,		SCXFS_ERRTAG_IFLUSH_4);
SCXFS_ERRORTAG_ATTR_RW(iflush5,		SCXFS_ERRTAG_IFLUSH_5);
SCXFS_ERRORTAG_ATTR_RW(iflush6,		SCXFS_ERRTAG_IFLUSH_6);
SCXFS_ERRORTAG_ATTR_RW(dareadbuf,		SCXFS_ERRTAG_DA_READ_BUF);
SCXFS_ERRORTAG_ATTR_RW(btree_chk_lblk,	SCXFS_ERRTAG_BTREE_CHECK_LBLOCK);
SCXFS_ERRORTAG_ATTR_RW(btree_chk_sblk,	SCXFS_ERRTAG_BTREE_CHECK_SBLOCK);
SCXFS_ERRORTAG_ATTR_RW(readagf,		SCXFS_ERRTAG_ALLOC_READ_AGF);
SCXFS_ERRORTAG_ATTR_RW(readagi,		SCXFS_ERRTAG_IALLOC_READ_AGI);
SCXFS_ERRORTAG_ATTR_RW(itobp,		SCXFS_ERRTAG_ITOBP_INOTOBP);
SCXFS_ERRORTAG_ATTR_RW(iunlink,		SCXFS_ERRTAG_IUNLINK);
SCXFS_ERRORTAG_ATTR_RW(iunlinkrm,		SCXFS_ERRTAG_IUNLINK_REMOVE);
SCXFS_ERRORTAG_ATTR_RW(dirinovalid,	SCXFS_ERRTAG_DIR_INO_VALIDATE);
SCXFS_ERRORTAG_ATTR_RW(bulkstat,		SCXFS_ERRTAG_BULKSTAT_READ_CHUNK);
SCXFS_ERRORTAG_ATTR_RW(logiodone,		SCXFS_ERRTAG_IODONE_IOERR);
SCXFS_ERRORTAG_ATTR_RW(stratread,		SCXFS_ERRTAG_STRATREAD_IOERR);
SCXFS_ERRORTAG_ATTR_RW(stratcmpl,		SCXFS_ERRTAG_STRATCMPL_IOERR);
SCXFS_ERRORTAG_ATTR_RW(diowrite,		SCXFS_ERRTAG_DIOWRITE_IOERR);
SCXFS_ERRORTAG_ATTR_RW(bmapifmt,		SCXFS_ERRTAG_BMAPIFORMAT);
SCXFS_ERRORTAG_ATTR_RW(free_extent,	SCXFS_ERRTAG_FREE_EXTENT);
SCXFS_ERRORTAG_ATTR_RW(rmap_finish_one,	SCXFS_ERRTAG_RMAP_FINISH_ONE);
SCXFS_ERRORTAG_ATTR_RW(refcount_continue_update,	SCXFS_ERRTAG_REFCOUNT_CONTINUE_UPDATE);
SCXFS_ERRORTAG_ATTR_RW(refcount_finish_one,	SCXFS_ERRTAG_REFCOUNT_FINISH_ONE);
SCXFS_ERRORTAG_ATTR_RW(bmap_finish_one,	SCXFS_ERRTAG_BMAP_FINISH_ONE);
SCXFS_ERRORTAG_ATTR_RW(ag_resv_critical,	SCXFS_ERRTAG_AG_RESV_CRITICAL);
SCXFS_ERRORTAG_ATTR_RW(drop_writes,	SCXFS_ERRTAG_DROP_WRITES);
SCXFS_ERRORTAG_ATTR_RW(log_bad_crc,	SCXFS_ERRTAG_LOG_BAD_CRC);
SCXFS_ERRORTAG_ATTR_RW(log_item_pin,	SCXFS_ERRTAG_LOG_ITEM_PIN);
SCXFS_ERRORTAG_ATTR_RW(buf_lru_ref,	SCXFS_ERRTAG_BUF_LRU_REF);
SCXFS_ERRORTAG_ATTR_RW(force_repair,	SCXFS_ERRTAG_FORCE_SCRUB_REPAIR);
SCXFS_ERRORTAG_ATTR_RW(bad_summary,	SCXFS_ERRTAG_FORCE_SUMMARY_RECALC);
SCXFS_ERRORTAG_ATTR_RW(iunlink_fallback,	SCXFS_ERRTAG_IUNLINK_FALLBACK);

static struct attribute *scxfs_errortag_attrs[] = {
	SCXFS_ERRORTAG_ATTR_LIST(noerror),
	SCXFS_ERRORTAG_ATTR_LIST(iflush1),
	SCXFS_ERRORTAG_ATTR_LIST(iflush2),
	SCXFS_ERRORTAG_ATTR_LIST(iflush3),
	SCXFS_ERRORTAG_ATTR_LIST(iflush4),
	SCXFS_ERRORTAG_ATTR_LIST(iflush5),
	SCXFS_ERRORTAG_ATTR_LIST(iflush6),
	SCXFS_ERRORTAG_ATTR_LIST(dareadbuf),
	SCXFS_ERRORTAG_ATTR_LIST(btree_chk_lblk),
	SCXFS_ERRORTAG_ATTR_LIST(btree_chk_sblk),
	SCXFS_ERRORTAG_ATTR_LIST(readagf),
	SCXFS_ERRORTAG_ATTR_LIST(readagi),
	SCXFS_ERRORTAG_ATTR_LIST(itobp),
	SCXFS_ERRORTAG_ATTR_LIST(iunlink),
	SCXFS_ERRORTAG_ATTR_LIST(iunlinkrm),
	SCXFS_ERRORTAG_ATTR_LIST(dirinovalid),
	SCXFS_ERRORTAG_ATTR_LIST(bulkstat),
	SCXFS_ERRORTAG_ATTR_LIST(logiodone),
	SCXFS_ERRORTAG_ATTR_LIST(stratread),
	SCXFS_ERRORTAG_ATTR_LIST(stratcmpl),
	SCXFS_ERRORTAG_ATTR_LIST(diowrite),
	SCXFS_ERRORTAG_ATTR_LIST(bmapifmt),
	SCXFS_ERRORTAG_ATTR_LIST(free_extent),
	SCXFS_ERRORTAG_ATTR_LIST(rmap_finish_one),
	SCXFS_ERRORTAG_ATTR_LIST(refcount_continue_update),
	SCXFS_ERRORTAG_ATTR_LIST(refcount_finish_one),
	SCXFS_ERRORTAG_ATTR_LIST(bmap_finish_one),
	SCXFS_ERRORTAG_ATTR_LIST(ag_resv_critical),
	SCXFS_ERRORTAG_ATTR_LIST(drop_writes),
	SCXFS_ERRORTAG_ATTR_LIST(log_bad_crc),
	SCXFS_ERRORTAG_ATTR_LIST(log_item_pin),
	SCXFS_ERRORTAG_ATTR_LIST(buf_lru_ref),
	SCXFS_ERRORTAG_ATTR_LIST(force_repair),
	SCXFS_ERRORTAG_ATTR_LIST(bad_summary),
	SCXFS_ERRORTAG_ATTR_LIST(iunlink_fallback),
	NULL,
};

static struct kobj_type scxfs_errortag_ktype = {
	.release = scxfs_sysfs_release,
	.sysfs_ops = &scxfs_errortag_sysfs_ops,
	.default_attrs = scxfs_errortag_attrs,
};

int
scxfs_errortag_init(
	struct scxfs_mount	*mp)
{
	mp->m_errortag = kmem_zalloc(sizeof(unsigned int) * SCXFS_ERRTAG_MAX,
			KM_MAYFAIL);
	if (!mp->m_errortag)
		return -ENOMEM;

	return scxfs_sysfs_init(&mp->m_errortag_kobj, &scxfs_errortag_ktype,
			       &mp->m_kobj, "errortag");
}

void
scxfs_errortag_del(
	struct scxfs_mount	*mp)
{
	scxfs_sysfs_del(&mp->m_errortag_kobj);
	kmem_free(mp->m_errortag);
}

bool
scxfs_errortag_test(
	struct scxfs_mount	*mp,
	const char		*expression,
	const char		*file,
	int			line,
	unsigned int		error_tag)
{
	unsigned int		randfactor;

	/*
	 * To be able to use error injection anywhere, we need to ensure error
	 * injection mechanism is already initialized.
	 *
	 * Code paths like I/O completion can be called before the
	 * initialization is complete, but be able to inject errors in such
	 * places is still useful.
	 */
	if (!mp->m_errortag)
		return false;

	ASSERT(error_tag < SCXFS_ERRTAG_MAX);
	randfactor = mp->m_errortag[error_tag];
	if (!randfactor || prandom_u32() % randfactor)
		return false;

	scxfs_warn_ratelimited(mp,
"Injecting error (%s) at file %s, line %d, on filesystem \"%s\"",
			expression, file, line, mp->m_fsname);
	return true;
}

int
scxfs_errortag_get(
	struct scxfs_mount	*mp,
	unsigned int		error_tag)
{
	if (error_tag >= SCXFS_ERRTAG_MAX)
		return -EINVAL;

	return mp->m_errortag[error_tag];
}

int
scxfs_errortag_set(
	struct scxfs_mount	*mp,
	unsigned int		error_tag,
	unsigned int		tag_value)
{
	if (error_tag >= SCXFS_ERRTAG_MAX)
		return -EINVAL;

	mp->m_errortag[error_tag] = tag_value;
	return 0;
}

int
scxfs_errortag_add(
	struct scxfs_mount	*mp,
	unsigned int		error_tag)
{
	if (error_tag >= SCXFS_ERRTAG_MAX)
		return -EINVAL;

	return scxfs_errortag_set(mp, error_tag,
			scxfs_errortag_random_default[error_tag]);
}

int
scxfs_errortag_clearall(
	struct scxfs_mount	*mp)
{
	memset(mp->m_errortag, 0, sizeof(unsigned int) * SCXFS_ERRTAG_MAX);
	return 0;
}
#endif /* DEBUG */

void
scxfs_error_report(
	const char		*tag,
	int			level,
	struct scxfs_mount	*mp,
	const char		*filename,
	int			linenum,
	scxfs_failaddr_t		failaddr)
{
	if (level <= scxfs_error_level) {
		scxfs_alert_tag(mp, SCXFS_PTAG_ERROR_REPORT,
		"Internal error %s at line %d of file %s.  Caller %pS",
			    tag, linenum, filename, failaddr);

		scxfs_stack_trace();
	}
}

void
scxfs_corruption_error(
	const char		*tag,
	int			level,
	struct scxfs_mount	*mp,
	void			*buf,
	size_t			bufsize,
	const char		*filename,
	int			linenum,
	scxfs_failaddr_t		failaddr)
{
	if (level <= scxfs_error_level)
		scxfs_hex_dump(buf, bufsize);
	scxfs_error_report(tag, level, mp, filename, linenum, failaddr);
	scxfs_alert(mp, "Corruption detected. Unmount and run scxfs_repair");
}

/*
 * Warnings specifically for verifier errors.  Differentiate CRC vs. invalid
 * values, and omit the stack trace unless the error level is tuned high.
 */
void
scxfs_buf_verifier_error(
	struct scxfs_buf		*bp,
	int			error,
	const char		*name,
	void			*buf,
	size_t			bufsz,
	scxfs_failaddr_t		failaddr)
{
	struct scxfs_mount	*mp = bp->b_mount;
	scxfs_failaddr_t		fa;
	int			sz;

	fa = failaddr ? failaddr : __return_address;
	__scxfs_buf_ioerror(bp, error, fa);

	scxfs_alert_tag(mp, SCXFS_PTAG_VERIFIER_ERROR,
		  "Metadata %s detected at %pS, %s block 0x%llx %s",
		  bp->b_error == -EFSBADCRC ? "CRC error" : "corruption",
		  fa, bp->b_ops->name, bp->b_bn, name);

	scxfs_alert(mp, "Unmount and run scxfs_repair");

	if (scxfs_error_level >= SCXFS_ERRLEVEL_LOW) {
		sz = min_t(size_t, SCXFS_CORRUPTION_DUMP_LEN, bufsz);
		scxfs_alert(mp, "First %d bytes of corrupted metadata buffer:",
				sz);
		scxfs_hex_dump(buf, sz);
	}

	if (scxfs_error_level >= SCXFS_ERRLEVEL_HIGH)
		scxfs_stack_trace();
}

/*
 * Warnings specifically for verifier errors.  Differentiate CRC vs. invalid
 * values, and omit the stack trace unless the error level is tuned high.
 */
void
scxfs_verifier_error(
	struct scxfs_buf		*bp,
	int			error,
	scxfs_failaddr_t		failaddr)
{
	return scxfs_buf_verifier_error(bp, error, "", scxfs_buf_offset(bp, 0),
			SCXFS_CORRUPTION_DUMP_LEN, failaddr);
}

/*
 * Warnings for inode corruption problems.  Don't bother with the stack
 * trace unless the error level is turned up high.
 */
void
scxfs_inode_verifier_error(
	struct scxfs_inode	*ip,
	int			error,
	const char		*name,
	void			*buf,
	size_t			bufsz,
	scxfs_failaddr_t		failaddr)
{
	struct scxfs_mount	*mp = ip->i_mount;
	scxfs_failaddr_t		fa;
	int			sz;

	fa = failaddr ? failaddr : __return_address;

	scxfs_alert(mp, "Metadata %s detected at %pS, inode 0x%llx %s",
		  error == -EFSBADCRC ? "CRC error" : "corruption",
		  fa, ip->i_ino, name);

	scxfs_alert(mp, "Unmount and run scxfs_repair");

	if (buf && scxfs_error_level >= SCXFS_ERRLEVEL_LOW) {
		sz = min_t(size_t, SCXFS_CORRUPTION_DUMP_LEN, bufsz);
		scxfs_alert(mp, "First %d bytes of corrupted metadata buffer:",
				sz);
		scxfs_hex_dump(buf, sz);
	}

	if (scxfs_error_level >= SCXFS_ERRLEVEL_HIGH)
		scxfs_stack_trace();
}
