// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2003,2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#ifndef	__SCXFS_INODE_H__
#define	__SCXFS_INODE_H__

#include "scxfs_inode_buf.h"
#include "scxfs_inode_fork.h"

/*
 * Kernel only inode definitions
 */
struct scxfs_dinode;
struct scxfs_inode;
struct scxfs_buf;
struct scxfs_bmbt_irec;
struct scxfs_inode_log_item;
struct scxfs_mount;
struct scxfs_trans;
struct scxfs_dquot;

typedef struct scxfs_inode {
	/* Inode linking and identification information. */
	struct scxfs_mount	*i_mount;	/* fs mount struct ptr */
	struct scxfs_dquot	*i_udquot;	/* user dquot */
	struct scxfs_dquot	*i_gdquot;	/* group dquot */
	struct scxfs_dquot	*i_pdquot;	/* project dquot */

	/* Inode location stuff */
	scxfs_ino_t		i_ino;		/* inode number (agno/agino)*/
	struct scxfs_imap		i_imap;		/* location for scxfs_imap() */

	/* Extent information. */
	struct scxfs_ifork	*i_afp;		/* attribute fork pointer */
	struct scxfs_ifork	*i_cowfp;	/* copy on write extents */
	struct scxfs_ifork	i_df;		/* data fork */

	/* operations vectors */
	const struct scxfs_dir_ops *d_ops;		/* directory ops vector */

	/* Transaction and locking information. */
	struct scxfs_inode_log_item *i_itemp;	/* logging information */
	mrlock_t		i_lock;		/* inode lock */
	mrlock_t		i_mmaplock;	/* inode mmap IO lock */
	atomic_t		i_pincount;	/* inode pin count */

	/*
	 * Bitsets of inode metadata that have been checked and/or are sick.
	 * Callers must hold i_flags_lock before accessing this field.
	 */
	uint16_t		i_checked;
	uint16_t		i_sick;

	spinlock_t		i_flags_lock;	/* inode i_flags lock */
	/* Miscellaneous state. */
	unsigned long		i_flags;	/* see defined flags below */
	uint64_t		i_delayed_blks;	/* count of delay alloc blks */

	struct scxfs_icdinode	i_d;		/* most of ondisk inode */

	scxfs_extnum_t		i_cnextents;	/* # of extents in cow fork */
	unsigned int		i_cformat;	/* format of cow fork */

	/* VFS inode */
	struct inode		i_vnode;	/* embedded VFS inode */

	/* pending io completions */
	spinlock_t		i_ioend_lock;
	struct work_struct	i_ioend_work;
	struct list_head	i_ioend_list;
} scxfs_inode_t;

/* Convert from vfs inode to scxfs inode */
static inline struct scxfs_inode *SCXFS_I(struct inode *inode)
{
	return container_of(inode, struct scxfs_inode, i_vnode);
}

/* convert from scxfs inode to vfs inode */
static inline struct inode *VFS_I(struct scxfs_inode *ip)
{
	return &ip->i_vnode;
}

/*
 * For regular files we only update the on-disk filesize when actually
 * writing data back to disk.  Until then only the copy in the VFS inode
 * is uptodate.
 */
static inline scxfs_fsize_t SCXFS_ISIZE(struct scxfs_inode *ip)
{
	if (S_ISREG(VFS_I(ip)->i_mode))
		return i_size_read(VFS_I(ip));
	return ip->i_d.di_size;
}

/*
 * If this I/O goes past the on-disk inode size update it unless it would
 * be past the current in-core inode size.
 */
static inline scxfs_fsize_t
scxfs_new_eof(struct scxfs_inode *ip, scxfs_fsize_t new_size)
{
	scxfs_fsize_t i_size = i_size_read(VFS_I(ip));

	if (new_size > i_size || new_size < 0)
		new_size = i_size;
	return new_size > ip->i_d.di_size ? new_size : 0;
}

/*
 * i_flags helper functions
 */
static inline void
__scxfs_iflags_set(scxfs_inode_t *ip, unsigned short flags)
{
	ip->i_flags |= flags;
}

static inline void
scxfs_iflags_set(scxfs_inode_t *ip, unsigned short flags)
{
	spin_lock(&ip->i_flags_lock);
	__scxfs_iflags_set(ip, flags);
	spin_unlock(&ip->i_flags_lock);
}

static inline void
scxfs_iflags_clear(scxfs_inode_t *ip, unsigned short flags)
{
	spin_lock(&ip->i_flags_lock);
	ip->i_flags &= ~flags;
	spin_unlock(&ip->i_flags_lock);
}

static inline int
__scxfs_iflags_test(scxfs_inode_t *ip, unsigned short flags)
{
	return (ip->i_flags & flags);
}

static inline int
scxfs_iflags_test(scxfs_inode_t *ip, unsigned short flags)
{
	int ret;
	spin_lock(&ip->i_flags_lock);
	ret = __scxfs_iflags_test(ip, flags);
	spin_unlock(&ip->i_flags_lock);
	return ret;
}

static inline int
scxfs_iflags_test_and_clear(scxfs_inode_t *ip, unsigned short flags)
{
	int ret;

	spin_lock(&ip->i_flags_lock);
	ret = ip->i_flags & flags;
	if (ret)
		ip->i_flags &= ~flags;
	spin_unlock(&ip->i_flags_lock);
	return ret;
}

static inline int
scxfs_iflags_test_and_set(scxfs_inode_t *ip, unsigned short flags)
{
	int ret;

	spin_lock(&ip->i_flags_lock);
	ret = ip->i_flags & flags;
	if (!ret)
		ip->i_flags |= flags;
	spin_unlock(&ip->i_flags_lock);
	return ret;
}

/*
 * Project quota id helpers (previously projid was 16bit only
 * and using two 16bit values to hold new 32bit projid was chosen
 * to retain compatibility with "old" filesystems).
 */
static inline prid_t
scxfs_get_projid(struct scxfs_inode *ip)
{
	return (prid_t)ip->i_d.di_projid_hi << 16 | ip->i_d.di_projid_lo;
}

static inline void
scxfs_set_projid(struct scxfs_inode *ip,
		prid_t projid)
{
	ip->i_d.di_projid_hi = (uint16_t) (projid >> 16);
	ip->i_d.di_projid_lo = (uint16_t) (projid & 0xffff);
}

static inline prid_t
scxfs_get_initial_prid(struct scxfs_inode *dp)
{
	if (dp->i_d.di_flags & SCXFS_DIFLAG_PROJINHERIT)
		return scxfs_get_projid(dp);

	return SCXFS_PROJID_DEFAULT;
}

static inline bool scxfs_is_reflink_inode(struct scxfs_inode *ip)
{
	return ip->i_d.di_flags2 & SCXFS_DIFLAG2_REFLINK;
}

/*
 * Check if an inode has any data in the COW fork.  This might be often false
 * even for inodes with the reflink flag when there is no pending COW operation.
 */
static inline bool scxfs_inode_has_cow_data(struct scxfs_inode *ip)
{
	return ip->i_cowfp && ip->i_cowfp->if_bytes;
}

/*
 * In-core inode flags.
 */
#define SCXFS_IRECLAIM		(1 << 0) /* started reclaiming this inode */
#define SCXFS_ISTALE		(1 << 1) /* inode has been staled */
#define SCXFS_IRECLAIMABLE	(1 << 2) /* inode can be reclaimed */
#define __SCXFS_INEW_BIT		3	 /* inode has just been allocated */
#define SCXFS_INEW		(1 << __SCXFS_INEW_BIT)
#define SCXFS_ITRUNCATED		(1 << 5) /* truncated down so flush-on-close */
#define SCXFS_IDIRTY_RELEASE	(1 << 6) /* dirty release already seen */
#define __SCXFS_IFLOCK_BIT	7	 /* inode is being flushed right now */
#define SCXFS_IFLOCK		(1 << __SCXFS_IFLOCK_BIT)
#define __SCXFS_IPINNED_BIT	8	 /* wakeup key for zero pin count */
#define SCXFS_IPINNED		(1 << __SCXFS_IPINNED_BIT)
#define SCXFS_IDONTCACHE		(1 << 9) /* don't cache the inode long term */
#define SCXFS_IEOFBLOCKS		(1 << 10)/* has the preallocblocks tag set */
/*
 * If this unlinked inode is in the middle of recovery, don't let drop_inode
 * truncate and free the inode.  This can happen if we iget the inode during
 * log recovery to replay a bmap operation on the inode.
 */
#define SCXFS_IRECOVERY		(1 << 11)
#define SCXFS_ICOWBLOCKS		(1 << 12)/* has the cowblocks tag set */

/*
 * Per-lifetime flags need to be reset when re-using a reclaimable inode during
 * inode lookup. This prevents unintended behaviour on the new inode from
 * ocurring.
 */
#define SCXFS_IRECLAIM_RESET_FLAGS	\
	(SCXFS_IRECLAIMABLE | SCXFS_IRECLAIM | \
	 SCXFS_IDIRTY_RELEASE | SCXFS_ITRUNCATED)

/*
 * Synchronize processes attempting to flush the in-core inode back to disk.
 */

static inline int scxfs_isiflocked(struct scxfs_inode *ip)
{
	return scxfs_iflags_test(ip, SCXFS_IFLOCK);
}

extern void __scxfs_iflock(struct scxfs_inode *ip);

static inline int scxfs_iflock_nowait(struct scxfs_inode *ip)
{
	return !scxfs_iflags_test_and_set(ip, SCXFS_IFLOCK);
}

static inline void scxfs_iflock(struct scxfs_inode *ip)
{
	if (!scxfs_iflock_nowait(ip))
		__scxfs_iflock(ip);
}

static inline void scxfs_ifunlock(struct scxfs_inode *ip)
{
	ASSERT(scxfs_isiflocked(ip));
	scxfs_iflags_clear(ip, SCXFS_IFLOCK);
	smp_mb();
	wake_up_bit(&ip->i_flags, __SCXFS_IFLOCK_BIT);
}

/*
 * Flags for inode locking.
 * Bit ranges:	1<<1  - 1<<16-1 -- iolock/ilock modes (bitfield)
 *		1<<16 - 1<<32-1 -- lockdep annotation (integers)
 */
#define	SCXFS_IOLOCK_EXCL		(1<<0)
#define	SCXFS_IOLOCK_SHARED	(1<<1)
#define	SCXFS_ILOCK_EXCL		(1<<2)
#define	SCXFS_ILOCK_SHARED	(1<<3)
#define	SCXFS_MMAPLOCK_EXCL	(1<<4)
#define	SCXFS_MMAPLOCK_SHARED	(1<<5)

#define SCXFS_LOCK_MASK		(SCXFS_IOLOCK_EXCL | SCXFS_IOLOCK_SHARED \
				| SCXFS_ILOCK_EXCL | SCXFS_ILOCK_SHARED \
				| SCXFS_MMAPLOCK_EXCL | SCXFS_MMAPLOCK_SHARED)

#define SCXFS_LOCK_FLAGS \
	{ SCXFS_IOLOCK_EXCL,	"IOLOCK_EXCL" }, \
	{ SCXFS_IOLOCK_SHARED,	"IOLOCK_SHARED" }, \
	{ SCXFS_ILOCK_EXCL,	"ILOCK_EXCL" }, \
	{ SCXFS_ILOCK_SHARED,	"ILOCK_SHARED" }, \
	{ SCXFS_MMAPLOCK_EXCL,	"MMAPLOCK_EXCL" }, \
	{ SCXFS_MMAPLOCK_SHARED,	"MMAPLOCK_SHARED" }


/*
 * Flags for lockdep annotations.
 *
 * SCXFS_LOCK_PARENT - for directory operations that require locking a
 * parent directory inode and a child entry inode. IOLOCK requires nesting,
 * MMAPLOCK does not support this class, ILOCK requires a single subclass
 * to differentiate parent from child.
 *
 * SCXFS_LOCK_RTBITMAP/SCXFS_LOCK_RTSUM - the realtime device bitmap and summary
 * inodes do not participate in the normal lock order, and thus have their
 * own subclasses.
 *
 * SCXFS_LOCK_INUMORDER - for locking several inodes at the some time
 * with scxfs_lock_inodes().  This flag is used as the starting subclass
 * and each subsequent lock acquired will increment the subclass by one.
 * However, MAX_LOCKDEP_SUBCLASSES == 8, which means we are greatly
 * limited to the subclasses we can represent via nesting. We need at least
 * 5 inodes nest depth for the ILOCK through rename, and we also have to support
 * SCXFS_ILOCK_PARENT, which gives 6 subclasses. Then we have SCXFS_ILOCK_RTBITMAP
 * and SCXFS_ILOCK_RTSUM, which are another 2 unique subclasses, so that's all
 * 8 subclasses supported by lockdep.
 *
 * This also means we have to number the sub-classes in the lowest bits of
 * the mask we keep, and we have to ensure we never exceed 3 bits of lockdep
 * mask and we can't use bit-masking to build the subclasses. What a mess.
 *
 * Bit layout:
 *
 * Bit		Lock Region
 * 16-19	SCXFS_IOLOCK_SHIFT dependencies
 * 20-23	SCXFS_MMAPLOCK_SHIFT dependencies
 * 24-31	SCXFS_ILOCK_SHIFT dependencies
 *
 * IOLOCK values
 *
 * 0-3		subclass value
 * 4-7		unused
 *
 * MMAPLOCK values
 *
 * 0-3		subclass value
 * 4-7		unused
 *
 * ILOCK values
 * 0-4		subclass values
 * 5		PARENT subclass (not nestable)
 * 6		RTBITMAP subclass (not nestable)
 * 7		RTSUM subclass (not nestable)
 * 
 */
#define SCXFS_IOLOCK_SHIFT		16
#define SCXFS_IOLOCK_MAX_SUBCLASS		3
#define SCXFS_IOLOCK_DEP_MASK		0x000f0000

#define SCXFS_MMAPLOCK_SHIFT		20
#define SCXFS_MMAPLOCK_NUMORDER		0
#define SCXFS_MMAPLOCK_MAX_SUBCLASS	3
#define SCXFS_MMAPLOCK_DEP_MASK		0x00f00000

#define SCXFS_ILOCK_SHIFT			24
#define SCXFS_ILOCK_PARENT_VAL		5
#define SCXFS_ILOCK_MAX_SUBCLASS		(SCXFS_ILOCK_PARENT_VAL - 1)
#define SCXFS_ILOCK_RTBITMAP_VAL		6
#define SCXFS_ILOCK_RTSUM_VAL		7
#define SCXFS_ILOCK_DEP_MASK		0xff000000
#define	SCXFS_ILOCK_PARENT		(SCXFS_ILOCK_PARENT_VAL << SCXFS_ILOCK_SHIFT)
#define	SCXFS_ILOCK_RTBITMAP		(SCXFS_ILOCK_RTBITMAP_VAL << SCXFS_ILOCK_SHIFT)
#define	SCXFS_ILOCK_RTSUM			(SCXFS_ILOCK_RTSUM_VAL << SCXFS_ILOCK_SHIFT)

#define SCXFS_LOCK_SUBCLASS_MASK	(SCXFS_IOLOCK_DEP_MASK | \
				 SCXFS_MMAPLOCK_DEP_MASK | \
				 SCXFS_ILOCK_DEP_MASK)

#define SCXFS_IOLOCK_DEP(flags)	(((flags) & SCXFS_IOLOCK_DEP_MASK) \
					>> SCXFS_IOLOCK_SHIFT)
#define SCXFS_MMAPLOCK_DEP(flags)	(((flags) & SCXFS_MMAPLOCK_DEP_MASK) \
					>> SCXFS_MMAPLOCK_SHIFT)
#define SCXFS_ILOCK_DEP(flags)	(((flags) & SCXFS_ILOCK_DEP_MASK) \
					>> SCXFS_ILOCK_SHIFT)

/*
 * Layouts are broken in the BREAK_WRITE case to ensure that
 * layout-holders do not collide with local writes. Additionally,
 * layouts are broken in the BREAK_UNMAP case to make sure the
 * layout-holder has a consistent view of the file's extent map. While
 * BREAK_WRITE breaks can be satisfied by recalling FL_LAYOUT leases,
 * BREAK_UNMAP breaks additionally require waiting for busy dax-pages to
 * go idle.
 */
enum layout_break_reason {
        BREAK_WRITE,
        BREAK_UNMAP,
};

/*
 * For multiple groups support: if S_ISGID bit is set in the parent
 * directory, group of new file is set to that of the parent, and
 * new subdirectory gets S_ISGID bit from parent.
 */
#define SCXFS_INHERIT_GID(pip)	\
	(((pip)->i_mount->m_flags & SCXFS_MOUNT_GRPID) || \
	 (VFS_I(pip)->i_mode & S_ISGID))

int		scxfs_release(struct scxfs_inode *ip);
void		scxfs_inactive(struct scxfs_inode *ip);
int		scxfs_lookup(struct scxfs_inode *dp, struct scxfs_name *name,
			   struct scxfs_inode **ipp, struct scxfs_name *ci_name);
int		scxfs_create(struct scxfs_inode *dp, struct scxfs_name *name,
			   umode_t mode, dev_t rdev, struct scxfs_inode **ipp);
int		scxfs_create_tmpfile(struct scxfs_inode *dp, umode_t mode,
			   struct scxfs_inode **ipp);
int		scxfs_remove(struct scxfs_inode *dp, struct scxfs_name *name,
			   struct scxfs_inode *ip);
int		scxfs_link(struct scxfs_inode *tdp, struct scxfs_inode *sip,
			 struct scxfs_name *target_name);
int		scxfs_rename(struct scxfs_inode *src_dp, struct scxfs_name *src_name,
			   struct scxfs_inode *src_ip, struct scxfs_inode *target_dp,
			   struct scxfs_name *target_name,
			   struct scxfs_inode *target_ip, unsigned int flags);

void		scxfs_ilock(scxfs_inode_t *, uint);
int		scxfs_ilock_nowait(scxfs_inode_t *, uint);
void		scxfs_iunlock(scxfs_inode_t *, uint);
void		scxfs_ilock_demote(scxfs_inode_t *, uint);
int		scxfs_isilocked(scxfs_inode_t *, uint);
uint		scxfs_ilock_data_map_shared(struct scxfs_inode *);
uint		scxfs_ilock_attr_map_shared(struct scxfs_inode *);

uint		scxfs_ip2xflags(struct scxfs_inode *);
int		scxfs_ifree(struct scxfs_trans *, struct scxfs_inode *);
int		scxfs_itruncate_extents_flags(struct scxfs_trans **,
				struct scxfs_inode *, int, scxfs_fsize_t, int);
void		scxfs_iext_realloc(scxfs_inode_t *, int, int);

void		scxfs_iunpin_wait(scxfs_inode_t *);
#define scxfs_ipincount(ip)	((unsigned int) atomic_read(&ip->i_pincount))

int		scxfs_iflush(struct scxfs_inode *, struct scxfs_buf **);
void		scxfs_lock_two_inodes(struct scxfs_inode *ip0, uint ip0_mode,
				struct scxfs_inode *ip1, uint ip1_mode);

scxfs_extlen_t	scxfs_get_extsz_hint(struct scxfs_inode *ip);
scxfs_extlen_t	scxfs_get_cowextsz_hint(struct scxfs_inode *ip);

int		scxfs_dir_ialloc(struct scxfs_trans **, struct scxfs_inode *, umode_t,
			       scxfs_nlink_t, dev_t, prid_t,
			       struct scxfs_inode **);

static inline int
scxfs_itruncate_extents(
	struct scxfs_trans	**tpp,
	struct scxfs_inode	*ip,
	int			whichfork,
	scxfs_fsize_t		new_size)
{
	return scxfs_itruncate_extents_flags(tpp, ip, whichfork, new_size, 0);
}

/* from scxfs_file.c */
enum scxfs_prealloc_flags {
	SCXFS_PREALLOC_SET	= (1 << 1),
	SCXFS_PREALLOC_CLEAR	= (1 << 2),
	SCXFS_PREALLOC_SYNC	= (1 << 3),
	SCXFS_PREALLOC_INVISIBLE	= (1 << 4),
};

int	scxfs_update_prealloc_flags(struct scxfs_inode *ip,
				  enum scxfs_prealloc_flags flags);
int	scxfs_break_layouts(struct inode *inode, uint *iolock,
		enum layout_break_reason reason);

/* from scxfs_iops.c */
extern void scxfs_setup_inode(struct scxfs_inode *ip);
extern void scxfs_setup_iops(struct scxfs_inode *ip);

/*
 * When setting up a newly allocated inode, we need to call
 * scxfs_finish_inode_setup() once the inode is fully instantiated at
 * the VFS level to prevent the rest of the world seeing the inode
 * before we've completed instantiation. Otherwise we can do it
 * the moment the inode lookup is complete.
 */
static inline void scxfs_finish_inode_setup(struct scxfs_inode *ip)
{
	scxfs_iflags_clear(ip, SCXFS_INEW);
	barrier();
	unlock_new_inode(VFS_I(ip));
	wake_up_bit(&ip->i_flags, __SCXFS_INEW_BIT);
}

static inline void scxfs_setup_existing_inode(struct scxfs_inode *ip)
{
	scxfs_setup_inode(ip);
	scxfs_setup_iops(ip);
	scxfs_finish_inode_setup(ip);
}

void scxfs_irele(struct scxfs_inode *ip);

extern struct kmem_zone	*scxfs_inode_zone;

/* The default CoW extent size hint. */
#define SCXFS_DEFAULT_COWEXTSZ_HINT 32

bool scxfs_inode_verify_forks(struct scxfs_inode *ip);

int scxfs_iunlink_init(struct scxfs_perag *pag);
void scxfs_iunlink_destroy(struct scxfs_perag *pag);

void scxfs_end_io(struct work_struct *work);

#endif	/* __SCXFS_INODE_H__ */
