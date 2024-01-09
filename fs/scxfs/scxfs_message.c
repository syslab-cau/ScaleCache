// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2011 Red Hat, Inc.  All Rights Reserved.
 */

#include "scxfs.h"
#include "scxfs_fs.h"
#include "scxfs_error.h"
#include "scxfs_shared.h"
#include "scxfs_format.h"
#include "scxfs_trans_resv.h"
#include "scxfs_mount.h"

/*
 * SCXFS logging functions
 */
static void
__scxfs_printk(
	const char		*level,
	const struct scxfs_mount	*mp,
	struct va_format	*vaf)
{
	if (mp && mp->m_fsname) {
		printk("%sSCXFS (%s): %pV\n", level, mp->m_fsname, vaf);
		return;
	}
	printk("%sSCXFS: %pV\n", level, vaf);
}

#define define_scxfs_printk_level(func, kern_level)		\
void func(const struct scxfs_mount *mp, const char *fmt, ...)	\
{								\
	struct va_format	vaf;				\
	va_list			args;				\
	int			level;				\
								\
	va_start(args, fmt);					\
								\
	vaf.fmt = fmt;						\
	vaf.va = &args;						\
								\
	__scxfs_printk(kern_level, mp, &vaf);			\
	va_end(args);						\
								\
	if (!kstrtoint(kern_level, 0, &level) &&		\
	    level <= LOGLEVEL_ERR &&				\
	    scxfs_error_level >= SCXFS_ERRLEVEL_HIGH)		\
		scxfs_stack_trace();				\
}								\

define_scxfs_printk_level(scxfs_emerg, KERN_EMERG);
define_scxfs_printk_level(scxfs_alert, KERN_ALERT);
define_scxfs_printk_level(scxfs_crit, KERN_CRIT);
define_scxfs_printk_level(scxfs_err, KERN_ERR);
define_scxfs_printk_level(scxfs_warn, KERN_WARNING);
define_scxfs_printk_level(scxfs_notice, KERN_NOTICE);
define_scxfs_printk_level(scxfs_info, KERN_INFO);
#ifdef DEBUG
define_scxfs_printk_level(scxfs_debug, KERN_DEBUG);
#endif

void
scxfs_alert_tag(
	const struct scxfs_mount	*mp,
	int			panic_tag,
	const char		*fmt, ...)
{
	struct va_format	vaf;
	va_list			args;
	int			do_panic = 0;

	if (scxfs_panic_mask && (scxfs_panic_mask & panic_tag)) {
		scxfs_alert(mp, "Transforming an alert into a BUG.");
		do_panic = 1;
	}

	va_start(args, fmt);

	vaf.fmt = fmt;
	vaf.va = &args;

	__scxfs_printk(KERN_ALERT, mp, &vaf);
	va_end(args);

	BUG_ON(do_panic);
}

void
asswarn(char *expr, char *file, int line)
{
	scxfs_warn(NULL, "Assertion failed: %s, file: %s, line: %d",
		expr, file, line);
	WARN_ON(1);
}

void
assfail(char *expr, char *file, int line)
{
	scxfs_emerg(NULL, "Assertion failed: %s, file: %s, line: %d",
		expr, file, line);
	if (scxfs_globals.bug_on_assert)
		BUG();
	else
		WARN_ON(1);
}

void
scxfs_hex_dump(void *p, int length)
{
	print_hex_dump(KERN_ALERT, "", DUMP_PREFIX_OFFSET, 16, 1, p, length, 1);
}
