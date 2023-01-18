// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#ifndef __SCXFS_LINUX__
#define __SCXFS_LINUX__

#include <linux/types.h>
#include <linux/uuid.h>

/*
 * Kernel specific type declarations for SCXFS
 */

typedef __s64			scxfs_off_t;	/* <file offset> type */
typedef unsigned long long	scxfs_ino_t;	/* <inode> type */
typedef __s64			scxfs_daddr_t;	/* <disk address> type */
typedef __u32			scxfs_dev_t;
typedef __u32			scxfs_nlink_t;

#include "scxfs_types.h"

#include "kmem.h"
#include "mrlock.h"

#include <linux/semaphore.h>
#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/kernel.h>
#include <linux/blkdev.h>
#include <linux/slab.h>
#include <linux/crc32c.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/file.h>
#include <linux/swap.h>
#include <linux/errno.h>
#include <linux/sched/signal.h>
#include <linux/bitops.h>
#include <linux/major.h>
#include <linux/pagemap.h>
#include <linux/vfs.h>
#include <linux/seq_file.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/sort.h>
#include <linux/cpu.h>
#include <linux/notifier.h>
#include <linux/delay.h>
#include <linux/log2.h>
#include <linux/spinlock.h>
#include <linux/random.h>
#include <linux/ctype.h>
#include <linux/writeback.h>
#include <linux/capability.h>
#include <linux/kthread.h>
#include <linux/freezer.h>
#include <linux/list_sort.h>
#include <linux/ratelimit.h>
#include <linux/rhashtable.h>

#include <asm/page.h>
#include <asm/div64.h>
#include <asm/param.h>
#include <linux/uaccess.h>
#include <asm/byteorder.h>
#include <asm/unaligned.h>

#include "scxfs_fs.h"
#include "scxfs_stats.h"
#include "scxfs_sysctl.h"
#include "scxfs_iops.h"
#include "scxfs_aops.h"
#include "scxfs_super.h"
#include "scxfs_cksum.h"
#include "scxfs_buf.h"
#include "scxfs_message.h"

#ifdef __BIG_ENDIAN
#define SCXFS_NATIVE_HOST 1
#else
#undef SCXFS_NATIVE_HOST
#endif

#define irix_sgid_inherit	scxfs_params.sgid_inherit.val
#define irix_symlink_mode	scxfs_params.symlink_mode.val
#define scxfs_panic_mask		scxfs_params.panic_mask.val
#define scxfs_error_level		scxfs_params.error_level.val
#define scxfs_syncd_centisecs	scxfs_params.syncd_timer.val
#define scxfs_stats_clear		scxfs_params.stats_clear.val
#define scxfs_inherit_sync	scxfs_params.inherit_sync.val
#define scxfs_inherit_nodump	scxfs_params.inherit_nodump.val
#define scxfs_inherit_noatime	scxfs_params.inherit_noatim.val
#define scxfs_inherit_nosymlinks	scxfs_params.inherit_nosym.val
#define scxfs_rotorstep		scxfs_params.rotorstep.val
#define scxfs_inherit_nodefrag	scxfs_params.inherit_nodfrg.val
#define scxfs_fstrm_centisecs	scxfs_params.fstrm_timer.val
#define scxfs_eofb_secs		scxfs_params.eofb_timer.val
#define scxfs_cowb_secs		scxfs_params.cowb_timer.val

#define current_cpu()		(raw_smp_processor_id())
#define current_pid()		(current->pid)
#define current_test_flags(f)	(current->flags & (f))
#define current_set_flags_nested(sp, f)		\
		(*(sp) = current->flags, current->flags |= (f))
#define current_clear_flags_nested(sp, f)	\
		(*(sp) = current->flags, current->flags &= ~(f))
#define current_restore_flags_nested(sp, f)	\
		(current->flags = ((current->flags & ~(f)) | (*(sp) & (f))))

#define NBBY		8		/* number of bits per byte */

/*
 * Size of block device i/o is parameterized here.
 * Currently the system supports page-sized i/o.
 */
#define	BLKDEV_IOSHIFT		PAGE_SHIFT
#define	BLKDEV_IOSIZE		(1<<BLKDEV_IOSHIFT)
/* number of BB's per block device block */
#define	BLKDEV_BB		BTOBB(BLKDEV_IOSIZE)

#define ENOATTR		ENODATA		/* Attribute not found */
#define EWRONGFS	EINVAL		/* Mount with wrong filesystem type */
#define EFSCORRUPTED	EUCLEAN		/* Filesystem is corrupted */
#define EFSBADCRC	EBADMSG		/* Bad CRC detected */

#define SYNCHRONIZE()	barrier()
#define __return_address __builtin_return_address(0)

/*
 * Return the address of a label.  Use barrier() so that the optimizer
 * won't reorder code to refactor the error jumpouts into a single
 * return, which throws off the reported address.
 */
#define __this_address	({ __label__ __here; __here: barrier(); &&__here; })

#define SCXFS_PROJID_DEFAULT	0

#define howmany(x, y)	(((x)+((y)-1))/(y))

static inline void delay(long ticks)
{
	schedule_timeout_uninterruptible(ticks);
}

/*
 * SCXFS wrapper structure for sysfs support. It depends on external data
 * structures and is embedded in various internal data structures to implement
 * the SCXFS sysfs object heirarchy. Define it here for broad access throughout
 * the codebase.
 */
struct scxfs_kobj {
	struct kobject		kobject;
	struct completion	complete;
};

struct xstats {
	struct xfsstats __percpu	*xs_stats;
	struct scxfs_kobj			xs_kobj;
};

extern struct xstats xfsstats;

/* Kernel uid/gid conversion. These are used to convert to/from the on disk
 * uid_t/gid_t types to the kuid_t/kgid_t types that the kernel uses internally.
 * The conversion here is type only, the value will remain the same since we
 * are converting to the init_user_ns. The uid is later mapped to a particular
 * user namespace value when crossing the kernel/user boundary.
 */
static inline uint32_t scxfs_kuid_to_uid(kuid_t uid)
{
	return from_kuid(&init_user_ns, uid);
}

static inline kuid_t scxfs_uid_to_kuid(uint32_t uid)
{
	return make_kuid(&init_user_ns, uid);
}

static inline uint32_t scxfs_kgid_to_gid(kgid_t gid)
{
	return from_kgid(&init_user_ns, gid);
}

static inline kgid_t scxfs_gid_to_kgid(uint32_t gid)
{
	return make_kgid(&init_user_ns, gid);
}

static inline dev_t scxfs_to_linux_dev_t(scxfs_dev_t dev)
{
	return MKDEV(sysv_major(dev) & 0x1ff, sysv_minor(dev));
}

static inline scxfs_dev_t linux_to_scxfs_dev_t(dev_t dev)
{
	return sysv_encode_dev(dev);
}

/*
 * Various platform dependent calls that don't fit anywhere else
 */
#define scxfs_sort(a,n,s,fn)	sort(a,n,s,fn,NULL)
#define scxfs_stack_trace()	dump_stack()

static inline uint64_t roundup_64(uint64_t x, uint32_t y)
{
	x += y - 1;
	do_div(x, y);
	return x * y;
}

static inline uint64_t howmany_64(uint64_t x, uint32_t y)
{
	x += y - 1;
	do_div(x, y);
	return x;
}

int scxfs_rw_bdev(struct block_device *bdev, sector_t sector, unsigned int count,
		char *data, unsigned int op);

#define ASSERT_ALWAYS(expr)	\
	(likely(expr) ? (void)0 : assfail(#expr, __FILE__, __LINE__))

#ifdef DEBUG
#define ASSERT(expr)	\
	(likely(expr) ? (void)0 : assfail(#expr, __FILE__, __LINE__))

#else	/* !DEBUG */

#ifdef SCXFS_WARN

#define ASSERT(expr)	\
	(likely(expr) ? (void)0 : asswarn(#expr, __FILE__, __LINE__))

#else	/* !DEBUG && !SCXFS_WARN */

#define ASSERT(expr)	((void)0)

#endif /* SCXFS_WARN */
#endif /* DEBUG */

#define STATIC static noinline

#ifdef CONFIG_XFS_RT

/*
 * make sure we ignore the inode flag if the filesystem doesn't have a
 * configured realtime device.
 */
#define SCXFS_IS_REALTIME_INODE(ip)			\
	(((ip)->i_d.di_flags & SCXFS_DIFLAG_REALTIME) &&	\
	 (ip)->i_mount->m_rtdev_targp)
#define SCXFS_IS_REALTIME_MOUNT(mp) ((mp)->m_rtdev_targp ? 1 : 0)
#else
#define SCXFS_IS_REALTIME_INODE(ip) (0)
#define SCXFS_IS_REALTIME_MOUNT(mp) (0)
#endif

/*
 * Starting in Linux 4.15, the %p (raw pointer value) printk modifier
 * prints a hashed version of the pointer to avoid leaking kernel
 * pointers into dmesg.  If we're trying to debug the kernel we want the
 * raw values, so override this behavior as best we can.
 */
#ifdef DEBUG
# define PTR_FMT "%px"
#else
# define PTR_FMT "%p"
#endif

#endif /* __SCXFS_LINUX__ */
