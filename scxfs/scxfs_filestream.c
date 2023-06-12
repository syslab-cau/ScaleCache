// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2006-2007 Silicon Graphics, Inc.
 * Copyright (c) 2014 Christoph Hellwig.
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
#include "scxfs_bmap.h"
#include "scxfs_alloc.h"
#include "scxfs_mru_cache.h"
#include "scxfs_trace.h"
#include "scxfs_ag_resv.h"
#include "scxfs_trans.h"

struct scxfs_fstrm_item {
	struct scxfs_mru_cache_elem	mru;
	scxfs_agnumber_t			ag; /* AG in use for this directory */
};

enum scxfs_fstrm_alloc {
	SCXFS_PICK_USERDATA = 1,
	SCXFS_PICK_LOWSPACE = 2,
};

/*
 * Allocation group filestream associations are tracked with per-ag atomic
 * counters.  These counters allow scxfs_filestream_pick_ag() to tell whether a
 * particular AG already has active filestreams associated with it. The mount
 * point's m_peraglock is used to protect these counters from per-ag array
 * re-allocation during a growfs operation.  When scxfs_growfs_data_private() is
 * about to reallocate the array, it calls scxfs_filestream_flush() with the
 * m_peraglock held in write mode.
 *
 * Since scxfs_mru_cache_flush() guarantees that all the free functions for all
 * the cache elements have finished executing before it returns, it's safe for
 * the free functions to use the atomic counters without m_peraglock protection.
 * This allows the implementation of scxfs_fstrm_free_func() to be agnostic about
 * whether it was called with the m_peraglock held in read mode, write mode or
 * not held at all.  The race condition this addresses is the following:
 *
 *  - The work queue scheduler fires and pulls a filestream directory cache
 *    element off the LRU end of the cache for deletion, then gets pre-empted.
 *  - A growfs operation grabs the m_peraglock in write mode, flushes all the
 *    remaining items from the cache and reallocates the mount point's per-ag
 *    array, resetting all the counters to zero.
 *  - The work queue thread resumes and calls the free function for the element
 *    it started cleaning up earlier.  In the process it decrements the
 *    filestreams counter for an AG that now has no references.
 *
 * With a shrinkfs feature, the above scenario could panic the system.
 *
 * All other uses of the following macros should be protected by either the
 * m_peraglock held in read mode, or the cache's internal locking exposed by the
 * interval between a call to scxfs_mru_cache_lookup() and a call to
 * scxfs_mru_cache_done().  In addition, the m_peraglock must be held in read mode
 * when new elements are added to the cache.
 *
 * Combined, these locking rules ensure that no associations will ever exist in
 * the cache that reference per-ag array elements that have since been
 * reallocated.
 */
int
scxfs_filestream_peek_ag(
	scxfs_mount_t	*mp,
	scxfs_agnumber_t	agno)
{
	struct scxfs_perag *pag;
	int		ret;

	pag = scxfs_perag_get(mp, agno);
	ret = atomic_read(&pag->pagf_fstrms);
	scxfs_perag_put(pag);
	return ret;
}

static int
scxfs_filestream_get_ag(
	scxfs_mount_t	*mp,
	scxfs_agnumber_t	agno)
{
	struct scxfs_perag *pag;
	int		ret;

	pag = scxfs_perag_get(mp, agno);
	ret = atomic_inc_return(&pag->pagf_fstrms);
	scxfs_perag_put(pag);
	return ret;
}

static void
scxfs_filestream_put_ag(
	scxfs_mount_t	*mp,
	scxfs_agnumber_t	agno)
{
	struct scxfs_perag *pag;

	pag = scxfs_perag_get(mp, agno);
	atomic_dec(&pag->pagf_fstrms);
	scxfs_perag_put(pag);
}

static void
scxfs_fstrm_free_func(
	void			*data,
	struct scxfs_mru_cache_elem *mru)
{
	struct scxfs_mount	*mp = data;
	struct scxfs_fstrm_item	*item =
		container_of(mru, struct scxfs_fstrm_item, mru);

	scxfs_filestream_put_ag(mp, item->ag);
	trace_scxfs_filestream_free(mp, mru->key, item->ag);

	kmem_free(item);
}

/*
 * Scan the AGs starting at startag looking for an AG that isn't in use and has
 * at least minlen blocks free.
 */
static int
scxfs_filestream_pick_ag(
	struct scxfs_inode	*ip,
	scxfs_agnumber_t		startag,
	scxfs_agnumber_t		*agp,
	int			flags,
	scxfs_extlen_t		minlen)
{
	struct scxfs_mount	*mp = ip->i_mount;
	struct scxfs_fstrm_item	*item;
	struct scxfs_perag	*pag;
	scxfs_extlen_t		longest, free = 0, minfree, maxfree = 0;
	scxfs_agnumber_t		ag, max_ag = NULLAGNUMBER;
	int			err, trylock, nscan;

	ASSERT(S_ISDIR(VFS_I(ip)->i_mode));

	/* 2% of an AG's blocks must be free for it to be chosen. */
	minfree = mp->m_sb.sb_agblocks / 50;

	ag = startag;
	*agp = NULLAGNUMBER;

	/* For the first pass, don't sleep trying to init the per-AG. */
	trylock = SCXFS_ALLOC_FLAG_TRYLOCK;

	for (nscan = 0; 1; nscan++) {
		trace_scxfs_filestream_scan(mp, ip->i_ino, ag);

		pag = scxfs_perag_get(mp, ag);

		if (!pag->pagf_init) {
			err = scxfs_alloc_pagf_init(mp, NULL, ag, trylock);
			if (err && !trylock) {
				scxfs_perag_put(pag);
				return err;
			}
		}

		/* Might fail sometimes during the 1st pass with trylock set. */
		if (!pag->pagf_init)
			goto next_ag;

		/* Keep track of the AG with the most free blocks. */
		if (pag->pagf_freeblks > maxfree) {
			maxfree = pag->pagf_freeblks;
			max_ag = ag;
		}

		/*
		 * The AG reference count does two things: it enforces mutual
		 * exclusion when examining the suitability of an AG in this
		 * loop, and it guards against two filestreams being established
		 * in the same AG as each other.
		 */
		if (scxfs_filestream_get_ag(mp, ag) > 1) {
			scxfs_filestream_put_ag(mp, ag);
			goto next_ag;
		}

		longest = scxfs_alloc_longest_free_extent(pag,
				scxfs_alloc_min_freelist(mp, pag),
				scxfs_ag_resv_needed(pag, SCXFS_AG_RESV_NONE));
		if (((minlen && longest >= minlen) ||
		     (!minlen && pag->pagf_freeblks >= minfree)) &&
		    (!pag->pagf_metadata || !(flags & SCXFS_PICK_USERDATA) ||
		     (flags & SCXFS_PICK_LOWSPACE))) {

			/* Break out, retaining the reference on the AG. */
			free = pag->pagf_freeblks;
			scxfs_perag_put(pag);
			*agp = ag;
			break;
		}

		/* Drop the reference on this AG, it's not usable. */
		scxfs_filestream_put_ag(mp, ag);
next_ag:
		scxfs_perag_put(pag);
		/* Move to the next AG, wrapping to AG 0 if necessary. */
		if (++ag >= mp->m_sb.sb_agcount)
			ag = 0;

		/* If a full pass of the AGs hasn't been done yet, continue. */
		if (ag != startag)
			continue;

		/* Allow sleeping in scxfs_alloc_pagf_init() on the 2nd pass. */
		if (trylock != 0) {
			trylock = 0;
			continue;
		}

		/* Finally, if lowspace wasn't set, set it for the 3rd pass. */
		if (!(flags & SCXFS_PICK_LOWSPACE)) {
			flags |= SCXFS_PICK_LOWSPACE;
			continue;
		}

		/*
		 * Take the AG with the most free space, regardless of whether
		 * it's already in use by another filestream.
		 */
		if (max_ag != NULLAGNUMBER) {
			scxfs_filestream_get_ag(mp, max_ag);
			free = maxfree;
			*agp = max_ag;
			break;
		}

		/* take AG 0 if none matched */
		trace_scxfs_filestream_pick(ip, *agp, free, nscan);
		*agp = 0;
		return 0;
	}

	trace_scxfs_filestream_pick(ip, *agp, free, nscan);

	if (*agp == NULLAGNUMBER)
		return 0;

	err = -ENOMEM;
	item = kmem_alloc(sizeof(*item), KM_MAYFAIL);
	if (!item)
		goto out_put_ag;

	item->ag = *agp;

	err = scxfs_mru_cache_insert(mp->m_filestream, ip->i_ino, &item->mru);
	if (err) {
		if (err == -EEXIST)
			err = 0;
		goto out_free_item;
	}

	return 0;

out_free_item:
	kmem_free(item);
out_put_ag:
	scxfs_filestream_put_ag(mp, *agp);
	return err;
}

static struct scxfs_inode *
scxfs_filestream_get_parent(
	struct scxfs_inode	*ip)
{
	struct inode		*inode = VFS_I(ip), *dir = NULL;
	struct dentry		*dentry, *parent;

	dentry = d_find_alias(inode);
	if (!dentry)
		goto out;

	parent = dget_parent(dentry);
	if (!parent)
		goto out_dput;

	dir = igrab(d_inode(parent));
	dput(parent);

out_dput:
	dput(dentry);
out:
	return dir ? SCXFS_I(dir) : NULL;
}

/*
 * Find the right allocation group for a file, either by finding an
 * existing file stream or creating a new one.
 *
 * Returns NULLAGNUMBER in case of an error.
 */
scxfs_agnumber_t
scxfs_filestream_lookup_ag(
	struct scxfs_inode	*ip)
{
	struct scxfs_mount	*mp = ip->i_mount;
	struct scxfs_inode	*pip = NULL;
	scxfs_agnumber_t		startag, ag = NULLAGNUMBER;
	struct scxfs_mru_cache_elem *mru;

	ASSERT(S_ISREG(VFS_I(ip)->i_mode));

	pip = scxfs_filestream_get_parent(ip);
	if (!pip)
		return NULLAGNUMBER;

	mru = scxfs_mru_cache_lookup(mp->m_filestream, pip->i_ino);
	if (mru) {
		ag = container_of(mru, struct scxfs_fstrm_item, mru)->ag;
		scxfs_mru_cache_done(mp->m_filestream);

		trace_scxfs_filestream_lookup(mp, ip->i_ino, ag);
		goto out;
	}

	/*
	 * Set the starting AG using the rotor for inode32, otherwise
	 * use the directory inode's AG.
	 */
	if (mp->m_flags & SCXFS_MOUNT_32BITINODES) {
		scxfs_agnumber_t	 rotorstep = scxfs_rotorstep;
		startag = (mp->m_agfrotor / rotorstep) % mp->m_sb.sb_agcount;
		mp->m_agfrotor = (mp->m_agfrotor + 1) %
		                 (mp->m_sb.sb_agcount * rotorstep);
	} else
		startag = SCXFS_INO_TO_AGNO(mp, pip->i_ino);

	if (scxfs_filestream_pick_ag(pip, startag, &ag, 0, 0))
		ag = NULLAGNUMBER;
out:
	scxfs_irele(pip);
	return ag;
}

/*
 * Pick a new allocation group for the current file and its file stream.
 *
 * This is called when the allocator can't find a suitable extent in the
 * current AG, and we have to move the stream into a new AG with more space.
 */
int
scxfs_filestream_new_ag(
	struct scxfs_bmalloca	*ap,
	scxfs_agnumber_t		*agp)
{
	struct scxfs_inode	*ip = ap->ip, *pip;
	struct scxfs_mount	*mp = ip->i_mount;
	scxfs_extlen_t		minlen = ap->length;
	scxfs_agnumber_t		startag = 0;
	int			flags = 0;
	int			err = 0;
	struct scxfs_mru_cache_elem *mru;

	*agp = NULLAGNUMBER;

	pip = scxfs_filestream_get_parent(ip);
	if (!pip)
		goto exit;

	mru = scxfs_mru_cache_remove(mp->m_filestream, pip->i_ino);
	if (mru) {
		struct scxfs_fstrm_item *item =
			container_of(mru, struct scxfs_fstrm_item, mru);
		startag = (item->ag + 1) % mp->m_sb.sb_agcount;
	}

	if (scxfs_alloc_is_userdata(ap->datatype))
		flags |= SCXFS_PICK_USERDATA;
	if (ap->tp->t_flags & SCXFS_TRANS_LOWMODE)
		flags |= SCXFS_PICK_LOWSPACE;

	err = scxfs_filestream_pick_ag(pip, startag, agp, flags, minlen);

	/*
	 * Only free the item here so we skip over the old AG earlier.
	 */
	if (mru)
		scxfs_fstrm_free_func(mp, mru);

	scxfs_irele(pip);
exit:
	if (*agp == NULLAGNUMBER)
		*agp = 0;
	return err;
}

void
scxfs_filestream_deassociate(
	struct scxfs_inode	*ip)
{
	scxfs_mru_cache_delete(ip->i_mount->m_filestream, ip->i_ino);
}

int
scxfs_filestream_mount(
	scxfs_mount_t	*mp)
{
	/*
	 * The filestream timer tunable is currently fixed within the range of
	 * one second to four minutes, with five seconds being the default.  The
	 * group count is somewhat arbitrary, but it'd be nice to adhere to the
	 * timer tunable to within about 10 percent.  This requires at least 10
	 * groups.
	 */
	return scxfs_mru_cache_create(&mp->m_filestream, mp,
			scxfs_fstrm_centisecs * 10, 10, scxfs_fstrm_free_func);
}

void
scxfs_filestream_unmount(
	scxfs_mount_t	*mp)
{
	scxfs_mru_cache_destroy(mp->m_filestream);
}
