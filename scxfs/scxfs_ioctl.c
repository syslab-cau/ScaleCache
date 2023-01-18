// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2005 Silicon Graphics, Inc.
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
#include "scxfs_rtalloc.h"
#include "scxfs_iwalk.h"
#include "scxfs_itable.h"
#include "scxfs_error.h"
#include "scxfs_attr.h"
#include "scxfs_bmap.h"
#include "scxfs_bmap_util.h"
#include "scxfs_fsops.h"
#include "scxfs_discard.h"
#include "scxfs_quota.h"
#include "scxfs_export.h"
#include "scxfs_trace.h"
#include "scxfs_icache.h"
#include "scxfs_trans.h"
#include "scxfs_acl.h"
#include "scxfs_btree.h"
#include <linux/fsmap.h>
#include "scxfs_fsmap.h"
#include "scrub/scxfs_scrub.h"
#include "scxfs_sb.h"
#include "scxfs_ag.h"
#include "scxfs_health.h"

#include <linux/mount.h>
#include <linux/namei.h>

/*
 * scxfs_find_handle maps from userspace scxfs_fsop_handlereq structure to
 * a file or fs handle.
 *
 * SCXFS_IOC_PATH_TO_FSHANDLE
 *    returns fs handle for a mount point or path within that mount point
 * SCXFS_IOC_FD_TO_HANDLE
 *    returns full handle for a FD opened in user space
 * SCXFS_IOC_PATH_TO_HANDLE
 *    returns full handle for a path
 */
int
scxfs_find_handle(
	unsigned int		cmd,
	scxfs_fsop_handlereq_t	*hreq)
{
	int			hsize;
	scxfs_handle_t		handle;
	struct inode		*inode;
	struct fd		f = {NULL};
	struct path		path;
	int			error;
	struct scxfs_inode	*ip;

	if (cmd == SCXFS_IOC_FD_TO_HANDLE) {
		f = fdget(hreq->fd);
		if (!f.file)
			return -EBADF;
		inode = file_inode(f.file);
	} else {
		error = user_path_at(AT_FDCWD, hreq->path, 0, &path);
		if (error)
			return error;
		inode = d_inode(path.dentry);
	}
	ip = SCXFS_I(inode);

	/*
	 * We can only generate handles for inodes residing on a SCXFS filesystem,
	 * and only for regular files, directories or symbolic links.
	 */
	error = -EINVAL;
	if (inode->i_sb->s_magic != SCXFS_SB_MAGIC)
		goto out_put;

	error = -EBADF;
	if (!S_ISREG(inode->i_mode) &&
	    !S_ISDIR(inode->i_mode) &&
	    !S_ISLNK(inode->i_mode))
		goto out_put;


	memcpy(&handle.ha_fsid, ip->i_mount->m_fixedfsid, sizeof(scxfs_fsid_t));

	if (cmd == SCXFS_IOC_PATH_TO_FSHANDLE) {
		/*
		 * This handle only contains an fsid, zero the rest.
		 */
		memset(&handle.ha_fid, 0, sizeof(handle.ha_fid));
		hsize = sizeof(scxfs_fsid_t);
	} else {
		handle.ha_fid.fid_len = sizeof(scxfs_fid_t) -
					sizeof(handle.ha_fid.fid_len);
		handle.ha_fid.fid_pad = 0;
		handle.ha_fid.fid_gen = inode->i_generation;
		handle.ha_fid.fid_ino = ip->i_ino;
		hsize = sizeof(scxfs_handle_t);
	}

	error = -EFAULT;
	if (copy_to_user(hreq->ohandle, &handle, hsize) ||
	    copy_to_user(hreq->ohandlen, &hsize, sizeof(__s32)))
		goto out_put;

	error = 0;

 out_put:
	if (cmd == SCXFS_IOC_FD_TO_HANDLE)
		fdput(f);
	else
		path_put(&path);
	return error;
}

/*
 * No need to do permission checks on the various pathname components
 * as the handle operations are privileged.
 */
STATIC int
scxfs_handle_acceptable(
	void			*context,
	struct dentry		*dentry)
{
	return 1;
}

/*
 * Convert userspace handle data into a dentry.
 */
struct dentry *
scxfs_handle_to_dentry(
	struct file		*parfilp,
	void __user		*uhandle,
	u32			hlen)
{
	scxfs_handle_t		handle;
	struct scxfs_fid64	fid;

	/*
	 * Only allow handle opens under a directory.
	 */
	if (!S_ISDIR(file_inode(parfilp)->i_mode))
		return ERR_PTR(-ENOTDIR);

	if (hlen != sizeof(scxfs_handle_t))
		return ERR_PTR(-EINVAL);
	if (copy_from_user(&handle, uhandle, hlen))
		return ERR_PTR(-EFAULT);
	if (handle.ha_fid.fid_len !=
	    sizeof(handle.ha_fid) - sizeof(handle.ha_fid.fid_len))
		return ERR_PTR(-EINVAL);

	memset(&fid, 0, sizeof(struct fid));
	fid.ino = handle.ha_fid.fid_ino;
	fid.gen = handle.ha_fid.fid_gen;

	return exportfs_decode_fh(parfilp->f_path.mnt, (struct fid *)&fid, 3,
			FILEID_INO32_GEN | SCXFS_FILEID_TYPE_64FLAG,
			scxfs_handle_acceptable, NULL);
}

STATIC struct dentry *
scxfs_handlereq_to_dentry(
	struct file		*parfilp,
	scxfs_fsop_handlereq_t	*hreq)
{
	return scxfs_handle_to_dentry(parfilp, hreq->ihandle, hreq->ihandlen);
}

int
scxfs_open_by_handle(
	struct file		*parfilp,
	scxfs_fsop_handlereq_t	*hreq)
{
	const struct cred	*cred = current_cred();
	int			error;
	int			fd;
	int			permflag;
	struct file		*filp;
	struct inode		*inode;
	struct dentry		*dentry;
	fmode_t			fmode;
	struct path		path;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	dentry = scxfs_handlereq_to_dentry(parfilp, hreq);
	if (IS_ERR(dentry))
		return PTR_ERR(dentry);
	inode = d_inode(dentry);

	/* Restrict scxfs_open_by_handle to directories & regular files. */
	if (!(S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode))) {
		error = -EPERM;
		goto out_dput;
	}

#if BITS_PER_LONG != 32
	hreq->oflags |= O_LARGEFILE;
#endif

	permflag = hreq->oflags;
	fmode = OPEN_FMODE(permflag);
	if ((!(permflag & O_APPEND) || (permflag & O_TRUNC)) &&
	    (fmode & FMODE_WRITE) && IS_APPEND(inode)) {
		error = -EPERM;
		goto out_dput;
	}

	if ((fmode & FMODE_WRITE) && IS_IMMUTABLE(inode)) {
		error = -EPERM;
		goto out_dput;
	}

	/* Can't write directories. */
	if (S_ISDIR(inode->i_mode) && (fmode & FMODE_WRITE)) {
		error = -EISDIR;
		goto out_dput;
	}

	fd = get_unused_fd_flags(0);
	if (fd < 0) {
		error = fd;
		goto out_dput;
	}

	path.mnt = parfilp->f_path.mnt;
	path.dentry = dentry;
	filp = dentry_open(&path, hreq->oflags, cred);
	dput(dentry);
	if (IS_ERR(filp)) {
		put_unused_fd(fd);
		return PTR_ERR(filp);
	}

	if (S_ISREG(inode->i_mode)) {
		filp->f_flags |= O_NOATIME;
		filp->f_mode |= FMODE_NOCMTIME;
	}

	fd_install(fd, filp);
	return fd;

 out_dput:
	dput(dentry);
	return error;
}

int
scxfs_readlink_by_handle(
	struct file		*parfilp,
	scxfs_fsop_handlereq_t	*hreq)
{
	struct dentry		*dentry;
	__u32			olen;
	int			error;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	dentry = scxfs_handlereq_to_dentry(parfilp, hreq);
	if (IS_ERR(dentry))
		return PTR_ERR(dentry);

	/* Restrict this handle operation to symlinks only. */
	if (!d_is_symlink(dentry)) {
		error = -EINVAL;
		goto out_dput;
	}

	if (copy_from_user(&olen, hreq->ohandlen, sizeof(__u32))) {
		error = -EFAULT;
		goto out_dput;
	}

	error = vfs_readlink(dentry, hreq->ohandle, olen);

 out_dput:
	dput(dentry);
	return error;
}

int
scxfs_set_dmattrs(
	scxfs_inode_t     *ip,
	uint		evmask,
	uint16_t	state)
{
	scxfs_mount_t	*mp = ip->i_mount;
	scxfs_trans_t	*tp;
	int		error;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (SCXFS_FORCED_SHUTDOWN(mp))
		return -EIO;

	error = scxfs_trans_alloc(mp, &M_RES(mp)->tr_ichange, 0, 0, 0, &tp);
	if (error)
		return error;

	scxfs_ilock(ip, SCXFS_ILOCK_EXCL);
	scxfs_trans_ijoin(tp, ip, SCXFS_ILOCK_EXCL);

	ip->i_d.di_dmevmask = evmask;
	ip->i_d.di_dmstate  = state;

	scxfs_trans_log_inode(tp, ip, SCXFS_ILOG_CORE);
	error = scxfs_trans_commit(tp);

	return error;
}

STATIC int
scxfs_fssetdm_by_handle(
	struct file		*parfilp,
	void			__user *arg)
{
	int			error;
	struct fsdmidata	fsd;
	scxfs_fsop_setdm_handlereq_t dmhreq;
	struct dentry		*dentry;

	if (!capable(CAP_MKNOD))
		return -EPERM;
	if (copy_from_user(&dmhreq, arg, sizeof(scxfs_fsop_setdm_handlereq_t)))
		return -EFAULT;

	error = mnt_want_write_file(parfilp);
	if (error)
		return error;

	dentry = scxfs_handlereq_to_dentry(parfilp, &dmhreq.hreq);
	if (IS_ERR(dentry)) {
		mnt_drop_write_file(parfilp);
		return PTR_ERR(dentry);
	}

	if (IS_IMMUTABLE(d_inode(dentry)) || IS_APPEND(d_inode(dentry))) {
		error = -EPERM;
		goto out;
	}

	if (copy_from_user(&fsd, dmhreq.data, sizeof(fsd))) {
		error = -EFAULT;
		goto out;
	}

	error = scxfs_set_dmattrs(SCXFS_I(d_inode(dentry)), fsd.fsd_dmevmask,
				 fsd.fsd_dmstate);

 out:
	mnt_drop_write_file(parfilp);
	dput(dentry);
	return error;
}

STATIC int
scxfs_attrlist_by_handle(
	struct file		*parfilp,
	void			__user *arg)
{
	int			error = -ENOMEM;
	attrlist_cursor_kern_t	*cursor;
	struct scxfs_fsop_attrlist_handlereq __user	*p = arg;
	scxfs_fsop_attrlist_handlereq_t al_hreq;
	struct dentry		*dentry;
	char			*kbuf;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (copy_from_user(&al_hreq, arg, sizeof(scxfs_fsop_attrlist_handlereq_t)))
		return -EFAULT;
	if (al_hreq.buflen < sizeof(struct attrlist) ||
	    al_hreq.buflen > SCXFS_XATTR_LIST_MAX)
		return -EINVAL;

	/*
	 * Reject flags, only allow namespaces.
	 */
	if (al_hreq.flags & ~(ATTR_ROOT | ATTR_SECURE))
		return -EINVAL;

	dentry = scxfs_handlereq_to_dentry(parfilp, &al_hreq.hreq);
	if (IS_ERR(dentry))
		return PTR_ERR(dentry);

	kbuf = kmem_zalloc_large(al_hreq.buflen, 0);
	if (!kbuf)
		goto out_dput;

	cursor = (attrlist_cursor_kern_t *)&al_hreq.pos;
	error = scxfs_attr_list(SCXFS_I(d_inode(dentry)), kbuf, al_hreq.buflen,
					al_hreq.flags, cursor);
	if (error)
		goto out_kfree;

	if (copy_to_user(&p->pos, cursor, sizeof(attrlist_cursor_kern_t))) {
		error = -EFAULT;
		goto out_kfree;
	}

	if (copy_to_user(al_hreq.buffer, kbuf, al_hreq.buflen))
		error = -EFAULT;

out_kfree:
	kmem_free(kbuf);
out_dput:
	dput(dentry);
	return error;
}

int
scxfs_attrmulti_attr_get(
	struct inode		*inode,
	unsigned char		*name,
	unsigned char		__user *ubuf,
	uint32_t		*len,
	uint32_t		flags)
{
	unsigned char		*kbuf;
	int			error = -EFAULT;

	if (*len > SCXFS_XATTR_SIZE_MAX)
		return -EINVAL;
	kbuf = kmem_zalloc_large(*len, 0);
	if (!kbuf)
		return -ENOMEM;

	error = scxfs_attr_get(SCXFS_I(inode), name, &kbuf, (int *)len, flags);
	if (error)
		goto out_kfree;

	if (copy_to_user(ubuf, kbuf, *len))
		error = -EFAULT;

out_kfree:
	kmem_free(kbuf);
	return error;
}

int
scxfs_attrmulti_attr_set(
	struct inode		*inode,
	unsigned char		*name,
	const unsigned char	__user *ubuf,
	uint32_t		len,
	uint32_t		flags)
{
	unsigned char		*kbuf;
	int			error;

	if (IS_IMMUTABLE(inode) || IS_APPEND(inode))
		return -EPERM;
	if (len > SCXFS_XATTR_SIZE_MAX)
		return -EINVAL;

	kbuf = memdup_user(ubuf, len);
	if (IS_ERR(kbuf))
		return PTR_ERR(kbuf);

	error = scxfs_attr_set(SCXFS_I(inode), name, kbuf, len, flags);
	if (!error)
		scxfs_forget_acl(inode, name, flags);
	kfree(kbuf);
	return error;
}

int
scxfs_attrmulti_attr_remove(
	struct inode		*inode,
	unsigned char		*name,
	uint32_t		flags)
{
	int			error;

	if (IS_IMMUTABLE(inode) || IS_APPEND(inode))
		return -EPERM;
	error = scxfs_attr_remove(SCXFS_I(inode), name, flags);
	if (!error)
		scxfs_forget_acl(inode, name, flags);
	return error;
}

STATIC int
scxfs_attrmulti_by_handle(
	struct file		*parfilp,
	void			__user *arg)
{
	int			error;
	scxfs_attr_multiop_t	*ops;
	scxfs_fsop_attrmulti_handlereq_t am_hreq;
	struct dentry		*dentry;
	unsigned int		i, size;
	unsigned char		*attr_name;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (copy_from_user(&am_hreq, arg, sizeof(scxfs_fsop_attrmulti_handlereq_t)))
		return -EFAULT;

	/* overflow check */
	if (am_hreq.opcount >= INT_MAX / sizeof(scxfs_attr_multiop_t))
		return -E2BIG;

	dentry = scxfs_handlereq_to_dentry(parfilp, &am_hreq.hreq);
	if (IS_ERR(dentry))
		return PTR_ERR(dentry);

	error = -E2BIG;
	size = am_hreq.opcount * sizeof(scxfs_attr_multiop_t);
	if (!size || size > 16 * PAGE_SIZE)
		goto out_dput;

	ops = memdup_user(am_hreq.ops, size);
	if (IS_ERR(ops)) {
		error = PTR_ERR(ops);
		goto out_dput;
	}

	error = -ENOMEM;
	attr_name = kmalloc(MAXNAMELEN, GFP_KERNEL);
	if (!attr_name)
		goto out_kfree_ops;

	error = 0;
	for (i = 0; i < am_hreq.opcount; i++) {
		ops[i].am_flags &= ~ATTR_KERNEL_FLAGS;

		ops[i].am_error = strncpy_from_user((char *)attr_name,
				ops[i].am_attrname, MAXNAMELEN);
		if (ops[i].am_error == 0 || ops[i].am_error == MAXNAMELEN)
			error = -ERANGE;
		if (ops[i].am_error < 0)
			break;

		switch (ops[i].am_opcode) {
		case ATTR_OP_GET:
			ops[i].am_error = scxfs_attrmulti_attr_get(
					d_inode(dentry), attr_name,
					ops[i].am_attrvalue, &ops[i].am_length,
					ops[i].am_flags);
			break;
		case ATTR_OP_SET:
			ops[i].am_error = mnt_want_write_file(parfilp);
			if (ops[i].am_error)
				break;
			ops[i].am_error = scxfs_attrmulti_attr_set(
					d_inode(dentry), attr_name,
					ops[i].am_attrvalue, ops[i].am_length,
					ops[i].am_flags);
			mnt_drop_write_file(parfilp);
			break;
		case ATTR_OP_REMOVE:
			ops[i].am_error = mnt_want_write_file(parfilp);
			if (ops[i].am_error)
				break;
			ops[i].am_error = scxfs_attrmulti_attr_remove(
					d_inode(dentry), attr_name,
					ops[i].am_flags);
			mnt_drop_write_file(parfilp);
			break;
		default:
			ops[i].am_error = -EINVAL;
		}
	}

	if (copy_to_user(am_hreq.ops, ops, size))
		error = -EFAULT;

	kfree(attr_name);
 out_kfree_ops:
	kfree(ops);
 out_dput:
	dput(dentry);
	return error;
}

int
scxfs_ioc_space(
	struct file		*filp,
	unsigned int		cmd,
	scxfs_flock64_t		*bf)
{
	struct inode		*inode = file_inode(filp);
	struct scxfs_inode	*ip = SCXFS_I(inode);
	struct iattr		iattr;
	enum scxfs_prealloc_flags	flags = 0;
	uint			iolock = SCXFS_IOLOCK_EXCL | SCXFS_MMAPLOCK_EXCL;
	int			error;

	if (inode->i_flags & (S_IMMUTABLE|S_APPEND))
		return -EPERM;

	if (!(filp->f_mode & FMODE_WRITE))
		return -EBADF;

	if (!S_ISREG(inode->i_mode))
		return -EINVAL;

	if (filp->f_flags & O_DSYNC)
		flags |= SCXFS_PREALLOC_SYNC;
	if (filp->f_mode & FMODE_NOCMTIME)
		flags |= SCXFS_PREALLOC_INVISIBLE;

	error = mnt_want_write_file(filp);
	if (error)
		return error;

	scxfs_ilock(ip, iolock);
	error = scxfs_break_layouts(inode, &iolock, BREAK_UNMAP);
	if (error)
		goto out_unlock;

	switch (bf->l_whence) {
	case 0: /*SEEK_SET*/
		break;
	case 1: /*SEEK_CUR*/
		bf->l_start += filp->f_pos;
		break;
	case 2: /*SEEK_END*/
		bf->l_start += SCXFS_ISIZE(ip);
		break;
	default:
		error = -EINVAL;
		goto out_unlock;
	}

	/*
	 * length of <= 0 for resv/unresv/zero is invalid.  length for
	 * alloc/free is ignored completely and we have no idea what userspace
	 * might have set it to, so set it to zero to allow range
	 * checks to pass.
	 */
	switch (cmd) {
	case SCXFS_IOC_ZERO_RANGE:
	case SCXFS_IOC_RESVSP:
	case SCXFS_IOC_RESVSP64:
	case SCXFS_IOC_UNRESVSP:
	case SCXFS_IOC_UNRESVSP64:
		if (bf->l_len <= 0) {
			error = -EINVAL;
			goto out_unlock;
		}
		break;
	default:
		bf->l_len = 0;
		break;
	}

	if (bf->l_start < 0 ||
	    bf->l_start > inode->i_sb->s_maxbytes ||
	    bf->l_start + bf->l_len < 0 ||
	    bf->l_start + bf->l_len >= inode->i_sb->s_maxbytes) {
		error = -EINVAL;
		goto out_unlock;
	}

	/*
	 * Must wait for all AIO to complete before we continue as AIO can
	 * change the file size on completion without holding any locks we
	 * currently hold. We must do this first because AIO can update both
	 * the on disk and in memory inode sizes, and the operations that follow
	 * require the in-memory size to be fully up-to-date.
	 */
	inode_dio_wait(inode);

	/*
	 * Now that AIO and DIO has drained we can flush and (if necessary)
	 * invalidate the cached range over the first operation we are about to
	 * run. We include zero range here because it starts with a hole punch
	 * over the target range.
	 */
	switch (cmd) {
	case SCXFS_IOC_ZERO_RANGE:
	case SCXFS_IOC_UNRESVSP:
	case SCXFS_IOC_UNRESVSP64:
		error = scxfs_flush_unmap_range(ip, bf->l_start, bf->l_len);
		if (error)
			goto out_unlock;
		break;
	}

	switch (cmd) {
	case SCXFS_IOC_ZERO_RANGE:
		flags |= SCXFS_PREALLOC_SET;
		error = scxfs_zero_file_space(ip, bf->l_start, bf->l_len);
		break;
	case SCXFS_IOC_RESVSP:
	case SCXFS_IOC_RESVSP64:
		flags |= SCXFS_PREALLOC_SET;
		error = scxfs_alloc_file_space(ip, bf->l_start, bf->l_len,
						SCXFS_BMAPI_PREALLOC);
		break;
	case SCXFS_IOC_UNRESVSP:
	case SCXFS_IOC_UNRESVSP64:
		error = scxfs_free_file_space(ip, bf->l_start, bf->l_len);
		break;
	case SCXFS_IOC_ALLOCSP:
	case SCXFS_IOC_ALLOCSP64:
	case SCXFS_IOC_FREESP:
	case SCXFS_IOC_FREESP64:
		flags |= SCXFS_PREALLOC_CLEAR;
		if (bf->l_start > SCXFS_ISIZE(ip)) {
			error = scxfs_alloc_file_space(ip, SCXFS_ISIZE(ip),
					bf->l_start - SCXFS_ISIZE(ip), 0);
			if (error)
				goto out_unlock;
		}

		iattr.ia_valid = ATTR_SIZE;
		iattr.ia_size = bf->l_start;

		error = scxfs_vn_setattr_size(file_dentry(filp), &iattr);
		break;
	default:
		ASSERT(0);
		error = -EINVAL;
	}

	if (error)
		goto out_unlock;

	error = scxfs_update_prealloc_flags(ip, flags);

out_unlock:
	scxfs_iunlock(ip, iolock);
	mnt_drop_write_file(filp);
	return error;
}

/* Return 0 on success or positive error */
int
scxfs_fsbulkstat_one_fmt(
	struct scxfs_ibulk		*breq,
	const struct scxfs_bulkstat	*bstat)
{
	struct scxfs_bstat		bs1;

	scxfs_bulkstat_to_bstat(breq->mp, &bs1, bstat);
	if (copy_to_user(breq->ubuffer, &bs1, sizeof(bs1)))
		return -EFAULT;
	return scxfs_ibulk_advance(breq, sizeof(struct scxfs_bstat));
}

int
scxfs_fsinumbers_fmt(
	struct scxfs_ibulk		*breq,
	const struct scxfs_inumbers	*igrp)
{
	struct scxfs_inogrp		ig1;

	scxfs_inumbers_to_inogrp(&ig1, igrp);
	if (copy_to_user(breq->ubuffer, &ig1, sizeof(struct scxfs_inogrp)))
		return -EFAULT;
	return scxfs_ibulk_advance(breq, sizeof(struct scxfs_inogrp));
}

STATIC int
scxfs_ioc_fsbulkstat(
	scxfs_mount_t		*mp,
	unsigned int		cmd,
	void			__user *arg)
{
	struct scxfs_fsop_bulkreq	bulkreq;
	struct scxfs_ibulk	breq = {
		.mp		= mp,
		.ocount		= 0,
	};
	scxfs_ino_t		lastino;
	int			error;

	/* done = 1 if there are more stats to get and if bulkstat */
	/* should be called again (unused here, but used in dmapi) */

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (SCXFS_FORCED_SHUTDOWN(mp))
		return -EIO;

	if (copy_from_user(&bulkreq, arg, sizeof(struct scxfs_fsop_bulkreq)))
		return -EFAULT;

	if (copy_from_user(&lastino, bulkreq.lastip, sizeof(__s64)))
		return -EFAULT;

	if (bulkreq.icount <= 0)
		return -EINVAL;

	if (bulkreq.ubuffer == NULL)
		return -EINVAL;

	breq.ubuffer = bulkreq.ubuffer;
	breq.icount = bulkreq.icount;

	/*
	 * FSBULKSTAT_SINGLE expects that *lastip contains the inode number
	 * that we want to stat.  However, FSINUMBERS and FSBULKSTAT expect
	 * that *lastip contains either zero or the number of the last inode to
	 * be examined by the previous call and return results starting with
	 * the next inode after that.  The new bulk request back end functions
	 * take the inode to start with, so we have to compute the startino
	 * parameter from lastino to maintain correct function.  lastino == 0
	 * is a special case because it has traditionally meant "first inode
	 * in filesystem".
	 */
	if (cmd == SCXFS_IOC_FSINUMBERS) {
		breq.startino = lastino ? lastino + 1 : 0;
		error = scxfs_inumbers(&breq, scxfs_fsinumbers_fmt);
		lastino = breq.startino - 1;
	} else if (cmd == SCXFS_IOC_FSBULKSTAT_SINGLE) {
		breq.startino = lastino;
		breq.icount = 1;
		error = scxfs_bulkstat_one(&breq, scxfs_fsbulkstat_one_fmt);
	} else {	/* SCXFS_IOC_FSBULKSTAT */
		breq.startino = lastino ? lastino + 1 : 0;
		error = scxfs_bulkstat(&breq, scxfs_fsbulkstat_one_fmt);
		lastino = breq.startino - 1;
	}

	if (error)
		return error;

	if (bulkreq.lastip != NULL &&
	    copy_to_user(bulkreq.lastip, &lastino, sizeof(scxfs_ino_t)))
		return -EFAULT;

	if (bulkreq.ocount != NULL &&
	    copy_to_user(bulkreq.ocount, &breq.ocount, sizeof(__s32)))
		return -EFAULT;

	return 0;
}

/* Return 0 on success or positive error */
static int
scxfs_bulkstat_fmt(
	struct scxfs_ibulk		*breq,
	const struct scxfs_bulkstat	*bstat)
{
	if (copy_to_user(breq->ubuffer, bstat, sizeof(struct scxfs_bulkstat)))
		return -EFAULT;
	return scxfs_ibulk_advance(breq, sizeof(struct scxfs_bulkstat));
}

/*
 * Check the incoming bulk request @hdr from userspace and initialize the
 * internal @breq bulk request appropriately.  Returns 0 if the bulk request
 * should proceed; -ECANCELED if there's nothing to do; or the usual
 * negative error code.
 */
static int
scxfs_bulk_ireq_setup(
	struct scxfs_mount	*mp,
	struct scxfs_bulk_ireq	*hdr,
	struct scxfs_ibulk	*breq,
	void __user		*ubuffer)
{
	if (hdr->icount == 0 ||
	    (hdr->flags & ~SCXFS_BULK_IREQ_FLAGS_ALL) ||
	    memchr_inv(hdr->reserved, 0, sizeof(hdr->reserved)))
		return -EINVAL;

	breq->startino = hdr->ino;
	breq->ubuffer = ubuffer;
	breq->icount = hdr->icount;
	breq->ocount = 0;
	breq->flags = 0;

	/*
	 * The @ino parameter is a special value, so we must look it up here.
	 * We're not allowed to have IREQ_AGNO, and we only return one inode
	 * worth of data.
	 */
	if (hdr->flags & SCXFS_BULK_IREQ_SPECIAL) {
		if (hdr->flags & SCXFS_BULK_IREQ_AGNO)
			return -EINVAL;

		switch (hdr->ino) {
		case SCXFS_BULK_IREQ_SPECIAL_ROOT:
			hdr->ino = mp->m_sb.sb_rootino;
			break;
		default:
			return -EINVAL;
		}
		breq->icount = 1;
	}

	/*
	 * The IREQ_AGNO flag means that we only want results from a given AG.
	 * If @hdr->ino is zero, we start iterating in that AG.  If @hdr->ino is
	 * beyond the specified AG then we return no results.
	 */
	if (hdr->flags & SCXFS_BULK_IREQ_AGNO) {
		if (hdr->agno >= mp->m_sb.sb_agcount)
			return -EINVAL;

		if (breq->startino == 0)
			breq->startino = SCXFS_AGINO_TO_INO(mp, hdr->agno, 0);
		else if (SCXFS_INO_TO_AGNO(mp, breq->startino) < hdr->agno)
			return -EINVAL;

		breq->flags |= SCXFS_IBULK_SAME_AG;

		/* Asking for an inode past the end of the AG?  We're done! */
		if (SCXFS_INO_TO_AGNO(mp, breq->startino) > hdr->agno)
			return -ECANCELED;
	} else if (hdr->agno)
		return -EINVAL;

	/* Asking for an inode past the end of the FS?  We're done! */
	if (SCXFS_INO_TO_AGNO(mp, breq->startino) >= mp->m_sb.sb_agcount)
		return -ECANCELED;

	return 0;
}

/*
 * Update the userspace bulk request @hdr to reflect the end state of the
 * internal bulk request @breq.
 */
static void
scxfs_bulk_ireq_teardown(
	struct scxfs_bulk_ireq	*hdr,
	struct scxfs_ibulk	*breq)
{
	hdr->ino = breq->startino;
	hdr->ocount = breq->ocount;
}

/* Handle the v5 bulkstat ioctl. */
STATIC int
scxfs_ioc_bulkstat(
	struct scxfs_mount		*mp,
	unsigned int			cmd,
	struct scxfs_bulkstat_req __user	*arg)
{
	struct scxfs_bulk_ireq		hdr;
	struct scxfs_ibulk		breq = {
		.mp			= mp,
	};
	int				error;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (SCXFS_FORCED_SHUTDOWN(mp))
		return -EIO;

	if (copy_from_user(&hdr, &arg->hdr, sizeof(hdr)))
		return -EFAULT;

	error = scxfs_bulk_ireq_setup(mp, &hdr, &breq, arg->bulkstat);
	if (error == -ECANCELED)
		goto out_teardown;
	if (error < 0)
		return error;

	error = scxfs_bulkstat(&breq, scxfs_bulkstat_fmt);
	if (error)
		return error;

out_teardown:
	scxfs_bulk_ireq_teardown(&hdr, &breq);
	if (copy_to_user(&arg->hdr, &hdr, sizeof(hdr)))
		return -EFAULT;

	return 0;
}

STATIC int
scxfs_inumbers_fmt(
	struct scxfs_ibulk		*breq,
	const struct scxfs_inumbers	*igrp)
{
	if (copy_to_user(breq->ubuffer, igrp, sizeof(struct scxfs_inumbers)))
		return -EFAULT;
	return scxfs_ibulk_advance(breq, sizeof(struct scxfs_inumbers));
}

/* Handle the v5 inumbers ioctl. */
STATIC int
scxfs_ioc_inumbers(
	struct scxfs_mount		*mp,
	unsigned int			cmd,
	struct scxfs_inumbers_req __user	*arg)
{
	struct scxfs_bulk_ireq		hdr;
	struct scxfs_ibulk		breq = {
		.mp			= mp,
	};
	int				error;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (SCXFS_FORCED_SHUTDOWN(mp))
		return -EIO;

	if (copy_from_user(&hdr, &arg->hdr, sizeof(hdr)))
		return -EFAULT;

	error = scxfs_bulk_ireq_setup(mp, &hdr, &breq, arg->inumbers);
	if (error == -ECANCELED)
		goto out_teardown;
	if (error < 0)
		return error;

	error = scxfs_inumbers(&breq, scxfs_inumbers_fmt);
	if (error)
		return error;

out_teardown:
	scxfs_bulk_ireq_teardown(&hdr, &breq);
	if (copy_to_user(&arg->hdr, &hdr, sizeof(hdr)))
		return -EFAULT;

	return 0;
}

STATIC int
scxfs_ioc_fsgeometry(
	struct scxfs_mount	*mp,
	void			__user *arg,
	int			struct_version)
{
	struct scxfs_fsop_geom	fsgeo;
	size_t			len;

	scxfs_fs_geometry(&mp->m_sb, &fsgeo, struct_version);

	if (struct_version <= 3)
		len = sizeof(struct scxfs_fsop_geom_v1);
	else if (struct_version == 4)
		len = sizeof(struct scxfs_fsop_geom_v4);
	else {
		scxfs_fsop_geom_health(mp, &fsgeo);
		len = sizeof(fsgeo);
	}

	if (copy_to_user(arg, &fsgeo, len))
		return -EFAULT;
	return 0;
}

STATIC int
scxfs_ioc_ag_geometry(
	struct scxfs_mount	*mp,
	void			__user *arg)
{
	struct scxfs_ag_geometry	ageo;
	int			error;

	if (copy_from_user(&ageo, arg, sizeof(ageo)))
		return -EFAULT;
	if (ageo.ag_flags)
		return -EINVAL;
	if (memchr_inv(&ageo.ag_reserved, 0, sizeof(ageo.ag_reserved)))
		return -EINVAL;

	error = scxfs_ag_get_geometry(mp, ageo.ag_number, &ageo);
	if (error)
		return error;

	if (copy_to_user(arg, &ageo, sizeof(ageo)))
		return -EFAULT;
	return 0;
}

/*
 * Linux extended inode flags interface.
 */

STATIC unsigned int
scxfs_merge_ioc_xflags(
	unsigned int	flags,
	unsigned int	start)
{
	unsigned int	xflags = start;

	if (flags & FS_IMMUTABLE_FL)
		xflags |= FS_XFLAG_IMMUTABLE;
	else
		xflags &= ~FS_XFLAG_IMMUTABLE;
	if (flags & FS_APPEND_FL)
		xflags |= FS_XFLAG_APPEND;
	else
		xflags &= ~FS_XFLAG_APPEND;
	if (flags & FS_SYNC_FL)
		xflags |= FS_XFLAG_SYNC;
	else
		xflags &= ~FS_XFLAG_SYNC;
	if (flags & FS_NOATIME_FL)
		xflags |= FS_XFLAG_NOATIME;
	else
		xflags &= ~FS_XFLAG_NOATIME;
	if (flags & FS_NODUMP_FL)
		xflags |= FS_XFLAG_NODUMP;
	else
		xflags &= ~FS_XFLAG_NODUMP;

	return xflags;
}

STATIC unsigned int
scxfs_di2lxflags(
	uint16_t	di_flags)
{
	unsigned int	flags = 0;

	if (di_flags & SCXFS_DIFLAG_IMMUTABLE)
		flags |= FS_IMMUTABLE_FL;
	if (di_flags & SCXFS_DIFLAG_APPEND)
		flags |= FS_APPEND_FL;
	if (di_flags & SCXFS_DIFLAG_SYNC)
		flags |= FS_SYNC_FL;
	if (di_flags & SCXFS_DIFLAG_NOATIME)
		flags |= FS_NOATIME_FL;
	if (di_flags & SCXFS_DIFLAG_NODUMP)
		flags |= FS_NODUMP_FL;
	return flags;
}

static void
scxfs_fill_fsxattr(
	struct scxfs_inode	*ip,
	bool			attr,
	struct fsxattr		*fa)
{
	simple_fill_fsxattr(fa, scxfs_ip2xflags(ip));
	fa->fsx_extsize = ip->i_d.di_extsize << ip->i_mount->m_sb.sb_blocklog;
	fa->fsx_cowextsize = ip->i_d.di_cowextsize <<
			ip->i_mount->m_sb.sb_blocklog;
	fa->fsx_projid = scxfs_get_projid(ip);

	if (attr) {
		if (ip->i_afp) {
			if (ip->i_afp->if_flags & SCXFS_IFEXTENTS)
				fa->fsx_nextents = scxfs_iext_count(ip->i_afp);
			else
				fa->fsx_nextents = ip->i_d.di_anextents;
		} else
			fa->fsx_nextents = 0;
	} else {
		if (ip->i_df.if_flags & SCXFS_IFEXTENTS)
			fa->fsx_nextents = scxfs_iext_count(&ip->i_df);
		else
			fa->fsx_nextents = ip->i_d.di_nextents;
	}
}

STATIC int
scxfs_ioc_fsgetxattr(
	scxfs_inode_t		*ip,
	int			attr,
	void			__user *arg)
{
	struct fsxattr		fa;

	scxfs_ilock(ip, SCXFS_ILOCK_SHARED);
	scxfs_fill_fsxattr(ip, attr, &fa);
	scxfs_iunlock(ip, SCXFS_ILOCK_SHARED);

	if (copy_to_user(arg, &fa, sizeof(fa)))
		return -EFAULT;
	return 0;
}

STATIC uint16_t
scxfs_flags2diflags(
	struct scxfs_inode	*ip,
	unsigned int		xflags)
{
	/* can't set PREALLOC this way, just preserve it */
	uint16_t		di_flags =
		(ip->i_d.di_flags & SCXFS_DIFLAG_PREALLOC);

	if (xflags & FS_XFLAG_IMMUTABLE)
		di_flags |= SCXFS_DIFLAG_IMMUTABLE;
	if (xflags & FS_XFLAG_APPEND)
		di_flags |= SCXFS_DIFLAG_APPEND;
	if (xflags & FS_XFLAG_SYNC)
		di_flags |= SCXFS_DIFLAG_SYNC;
	if (xflags & FS_XFLAG_NOATIME)
		di_flags |= SCXFS_DIFLAG_NOATIME;
	if (xflags & FS_XFLAG_NODUMP)
		di_flags |= SCXFS_DIFLAG_NODUMP;
	if (xflags & FS_XFLAG_NODEFRAG)
		di_flags |= SCXFS_DIFLAG_NODEFRAG;
	if (xflags & FS_XFLAG_FILESTREAM)
		di_flags |= SCXFS_DIFLAG_FILESTREAM;
	if (S_ISDIR(VFS_I(ip)->i_mode)) {
		if (xflags & FS_XFLAG_RTINHERIT)
			di_flags |= SCXFS_DIFLAG_RTINHERIT;
		if (xflags & FS_XFLAG_NOSYMLINKS)
			di_flags |= SCXFS_DIFLAG_NOSYMLINKS;
		if (xflags & FS_XFLAG_EXTSZINHERIT)
			di_flags |= SCXFS_DIFLAG_EXTSZINHERIT;
		if (xflags & FS_XFLAG_PROJINHERIT)
			di_flags |= SCXFS_DIFLAG_PROJINHERIT;
	} else if (S_ISREG(VFS_I(ip)->i_mode)) {
		if (xflags & FS_XFLAG_REALTIME)
			di_flags |= SCXFS_DIFLAG_REALTIME;
		if (xflags & FS_XFLAG_EXTSIZE)
			di_flags |= SCXFS_DIFLAG_EXTSIZE;
	}

	return di_flags;
}

STATIC uint64_t
scxfs_flags2diflags2(
	struct scxfs_inode	*ip,
	unsigned int		xflags)
{
	uint64_t		di_flags2 =
		(ip->i_d.di_flags2 & SCXFS_DIFLAG2_REFLINK);

	if (xflags & FS_XFLAG_DAX)
		di_flags2 |= SCXFS_DIFLAG2_DAX;
	if (xflags & FS_XFLAG_COWEXTSIZE)
		di_flags2 |= SCXFS_DIFLAG2_COWEXTSIZE;

	return di_flags2;
}

STATIC void
scxfs_diflags_to_linux(
	struct scxfs_inode	*ip)
{
	struct inode		*inode = VFS_I(ip);
	unsigned int		xflags = scxfs_ip2xflags(ip);

	if (xflags & FS_XFLAG_IMMUTABLE)
		inode->i_flags |= S_IMMUTABLE;
	else
		inode->i_flags &= ~S_IMMUTABLE;
	if (xflags & FS_XFLAG_APPEND)
		inode->i_flags |= S_APPEND;
	else
		inode->i_flags &= ~S_APPEND;
	if (xflags & FS_XFLAG_SYNC)
		inode->i_flags |= S_SYNC;
	else
		inode->i_flags &= ~S_SYNC;
	if (xflags & FS_XFLAG_NOATIME)
		inode->i_flags |= S_NOATIME;
	else
		inode->i_flags &= ~S_NOATIME;
#if 0	/* disabled until the flag switching races are sorted out */
	if (xflags & FS_XFLAG_DAX)
		inode->i_flags |= S_DAX;
	else
		inode->i_flags &= ~S_DAX;
#endif
}

static int
scxfs_ioctl_setattr_xflags(
	struct scxfs_trans	*tp,
	struct scxfs_inode	*ip,
	struct fsxattr		*fa)
{
	struct scxfs_mount	*mp = ip->i_mount;
	uint64_t		di_flags2;

	/* Can't change realtime flag if any extents are allocated. */
	if ((ip->i_d.di_nextents || ip->i_delayed_blks) &&
	    SCXFS_IS_REALTIME_INODE(ip) != (fa->fsx_xflags & FS_XFLAG_REALTIME))
		return -EINVAL;

	/* If realtime flag is set then must have realtime device */
	if (fa->fsx_xflags & FS_XFLAG_REALTIME) {
		if (mp->m_sb.sb_rblocks == 0 || mp->m_sb.sb_rextsize == 0 ||
		    (ip->i_d.di_extsize % mp->m_sb.sb_rextsize))
			return -EINVAL;
	}

	/* Clear reflink if we are actually able to set the rt flag. */
	if ((fa->fsx_xflags & FS_XFLAG_REALTIME) && scxfs_is_reflink_inode(ip))
		ip->i_d.di_flags2 &= ~SCXFS_DIFLAG2_REFLINK;

	/* Don't allow us to set DAX mode for a reflinked file for now. */
	if ((fa->fsx_xflags & FS_XFLAG_DAX) && scxfs_is_reflink_inode(ip))
		return -EINVAL;

	/* diflags2 only valid for v3 inodes. */
	di_flags2 = scxfs_flags2diflags2(ip, fa->fsx_xflags);
	if (di_flags2 && ip->i_d.di_version < 3)
		return -EINVAL;

	ip->i_d.di_flags = scxfs_flags2diflags(ip, fa->fsx_xflags);
	ip->i_d.di_flags2 = di_flags2;

	scxfs_diflags_to_linux(ip);
	scxfs_trans_ichgtime(tp, ip, SCXFS_ICHGTIME_CHG);
	scxfs_trans_log_inode(tp, ip, SCXFS_ILOG_CORE);
	SCXFS_STATS_INC(mp, xs_ig_attrchg);
	return 0;
}

/*
 * If we are changing DAX flags, we have to ensure the file is clean and any
 * cached objects in the address space are invalidated and removed. This
 * requires us to lock out other IO and page faults similar to a truncate
 * operation. The locks need to be held until the transaction has been committed
 * so that the cache invalidation is atomic with respect to the DAX flag
 * manipulation.
 */
static int
scxfs_ioctl_setattr_dax_invalidate(
	struct scxfs_inode	*ip,
	struct fsxattr		*fa,
	int			*join_flags)
{
	struct inode		*inode = VFS_I(ip);
	struct super_block	*sb = inode->i_sb;
	int			error;

	*join_flags = 0;

	/*
	 * It is only valid to set the DAX flag on regular files and
	 * directories on filesystems where the block size is equal to the page
	 * size. On directories it serves as an inherited hint so we don't
	 * have to check the device for dax support or flush pagecache.
	 */
	if (fa->fsx_xflags & FS_XFLAG_DAX) {
		if (!(S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode)))
			return -EINVAL;
		if (!bdev_dax_supported(scxfs_find_bdev_for_inode(VFS_I(ip)),
				sb->s_blocksize))
			return -EINVAL;
	}

	/* If the DAX state is not changing, we have nothing to do here. */
	if ((fa->fsx_xflags & FS_XFLAG_DAX) && IS_DAX(inode))
		return 0;
	if (!(fa->fsx_xflags & FS_XFLAG_DAX) && !IS_DAX(inode))
		return 0;

	if (S_ISDIR(inode->i_mode))
		return 0;

	/* lock, flush and invalidate mapping in preparation for flag change */
	scxfs_ilock(ip, SCXFS_MMAPLOCK_EXCL | SCXFS_IOLOCK_EXCL);
	error = filemap_write_and_wait(inode->i_mapping);
	if (error)
		goto out_unlock;
	error = invalidate_inode_pages2(inode->i_mapping);
	if (error)
		goto out_unlock;

	*join_flags = SCXFS_MMAPLOCK_EXCL | SCXFS_IOLOCK_EXCL;
	return 0;

out_unlock:
	scxfs_iunlock(ip, SCXFS_MMAPLOCK_EXCL | SCXFS_IOLOCK_EXCL);
	return error;

}

/*
 * Set up the transaction structure for the setattr operation, checking that we
 * have permission to do so. On success, return a clean transaction and the
 * inode locked exclusively ready for further operation specific checks. On
 * failure, return an error without modifying or locking the inode.
 *
 * The inode might already be IO locked on call. If this is the case, it is
 * indicated in @join_flags and we take full responsibility for ensuring they
 * are unlocked from now on. Hence if we have an error here, we still have to
 * unlock them. Otherwise, once they are joined to the transaction, they will
 * be unlocked on commit/cancel.
 */
static struct scxfs_trans *
scxfs_ioctl_setattr_get_trans(
	struct scxfs_inode	*ip,
	int			join_flags)
{
	struct scxfs_mount	*mp = ip->i_mount;
	struct scxfs_trans	*tp;
	int			error = -EROFS;

	if (mp->m_flags & SCXFS_MOUNT_RDONLY)
		goto out_unlock;
	error = -EIO;
	if (SCXFS_FORCED_SHUTDOWN(mp))
		goto out_unlock;

	error = scxfs_trans_alloc(mp, &M_RES(mp)->tr_ichange, 0, 0, 0, &tp);
	if (error)
		goto out_unlock;

	scxfs_ilock(ip, SCXFS_ILOCK_EXCL);
	scxfs_trans_ijoin(tp, ip, SCXFS_ILOCK_EXCL | join_flags);
	join_flags = 0;

	/*
	 * CAP_FOWNER overrides the following restrictions:
	 *
	 * The user ID of the calling process must be equal to the file owner
	 * ID, except in cases where the CAP_FSETID capability is applicable.
	 */
	if (!inode_owner_or_capable(VFS_I(ip))) {
		error = -EPERM;
		goto out_cancel;
	}

	if (mp->m_flags & SCXFS_MOUNT_WSYNC)
		scxfs_trans_set_sync(tp);

	return tp;

out_cancel:
	scxfs_trans_cancel(tp);
out_unlock:
	if (join_flags)
		scxfs_iunlock(ip, join_flags);
	return ERR_PTR(error);
}

/*
 * extent size hint validation is somewhat cumbersome. Rules are:
 *
 * 1. extent size hint is only valid for directories and regular files
 * 2. FS_XFLAG_EXTSIZE is only valid for regular files
 * 3. FS_XFLAG_EXTSZINHERIT is only valid for directories.
 * 4. can only be changed on regular files if no extents are allocated
 * 5. can be changed on directories at any time
 * 6. extsize hint of 0 turns off hints, clears inode flags.
 * 7. Extent size must be a multiple of the appropriate block size.
 * 8. for non-realtime files, the extent size hint must be limited
 *    to half the AG size to avoid alignment extending the extent beyond the
 *    limits of the AG.
 *
 * Please keep this function in sync with scxfs_scrub_inode_extsize.
 */
static int
scxfs_ioctl_setattr_check_extsize(
	struct scxfs_inode	*ip,
	struct fsxattr		*fa)
{
	struct scxfs_mount	*mp = ip->i_mount;
	scxfs_extlen_t		size;
	scxfs_fsblock_t		extsize_fsb;

	if (S_ISREG(VFS_I(ip)->i_mode) && ip->i_d.di_nextents &&
	    ((ip->i_d.di_extsize << mp->m_sb.sb_blocklog) != fa->fsx_extsize))
		return -EINVAL;

	if (fa->fsx_extsize == 0)
		return 0;

	extsize_fsb = SCXFS_B_TO_FSB(mp, fa->fsx_extsize);
	if (extsize_fsb > MAXEXTLEN)
		return -EINVAL;

	if (SCXFS_IS_REALTIME_INODE(ip) ||
	    (fa->fsx_xflags & FS_XFLAG_REALTIME)) {
		size = mp->m_sb.sb_rextsize << mp->m_sb.sb_blocklog;
	} else {
		size = mp->m_sb.sb_blocksize;
		if (extsize_fsb > mp->m_sb.sb_agblocks / 2)
			return -EINVAL;
	}

	if (fa->fsx_extsize % size)
		return -EINVAL;

	return 0;
}

/*
 * CoW extent size hint validation rules are:
 *
 * 1. CoW extent size hint can only be set if reflink is enabled on the fs.
 *    The inode does not have to have any shared blocks, but it must be a v3.
 * 2. FS_XFLAG_COWEXTSIZE is only valid for directories and regular files;
 *    for a directory, the hint is propagated to new files.
 * 3. Can be changed on files & directories at any time.
 * 4. CoW extsize hint of 0 turns off hints, clears inode flags.
 * 5. Extent size must be a multiple of the appropriate block size.
 * 6. The extent size hint must be limited to half the AG size to avoid
 *    alignment extending the extent beyond the limits of the AG.
 *
 * Please keep this function in sync with scxfs_scrub_inode_cowextsize.
 */
static int
scxfs_ioctl_setattr_check_cowextsize(
	struct scxfs_inode	*ip,
	struct fsxattr		*fa)
{
	struct scxfs_mount	*mp = ip->i_mount;
	scxfs_extlen_t		size;
	scxfs_fsblock_t		cowextsize_fsb;

	if (!(fa->fsx_xflags & FS_XFLAG_COWEXTSIZE))
		return 0;

	if (!scxfs_sb_version_hasreflink(&ip->i_mount->m_sb) ||
	    ip->i_d.di_version != 3)
		return -EINVAL;

	if (fa->fsx_cowextsize == 0)
		return 0;

	cowextsize_fsb = SCXFS_B_TO_FSB(mp, fa->fsx_cowextsize);
	if (cowextsize_fsb > MAXEXTLEN)
		return -EINVAL;

	size = mp->m_sb.sb_blocksize;
	if (cowextsize_fsb > mp->m_sb.sb_agblocks / 2)
		return -EINVAL;

	if (fa->fsx_cowextsize % size)
		return -EINVAL;

	return 0;
}

static int
scxfs_ioctl_setattr_check_projid(
	struct scxfs_inode	*ip,
	struct fsxattr		*fa)
{
	/* Disallow 32bit project ids if projid32bit feature is not enabled. */
	if (fa->fsx_projid > (uint16_t)-1 &&
	    !scxfs_sb_version_hasprojid32bit(&ip->i_mount->m_sb))
		return -EINVAL;
	return 0;
}

STATIC int
scxfs_ioctl_setattr(
	scxfs_inode_t		*ip,
	struct fsxattr		*fa)
{
	struct fsxattr		old_fa;
	struct scxfs_mount	*mp = ip->i_mount;
	struct scxfs_trans	*tp;
	struct scxfs_dquot	*udqp = NULL;
	struct scxfs_dquot	*pdqp = NULL;
	struct scxfs_dquot	*olddquot = NULL;
	int			code;
	int			join_flags = 0;

	trace_scxfs_ioctl_setattr(ip);

	code = scxfs_ioctl_setattr_check_projid(ip, fa);
	if (code)
		return code;

	/*
	 * If disk quotas is on, we make sure that the dquots do exist on disk,
	 * before we start any other transactions. Trying to do this later
	 * is messy. We don't care to take a readlock to look at the ids
	 * in inode here, because we can't hold it across the trans_reserve.
	 * If the IDs do change before we take the ilock, we're covered
	 * because the i_*dquot fields will get updated anyway.
	 */
	if (SCXFS_IS_QUOTA_ON(mp)) {
		code = scxfs_qm_vop_dqalloc(ip, ip->i_d.di_uid,
					 ip->i_d.di_gid, fa->fsx_projid,
					 SCXFS_QMOPT_PQUOTA, &udqp, NULL, &pdqp);
		if (code)
			return code;
	}

	/*
	 * Changing DAX config may require inode locking for mapping
	 * invalidation. These need to be held all the way to transaction commit
	 * or cancel time, so need to be passed through to
	 * scxfs_ioctl_setattr_get_trans() so it can apply them to the join call
	 * appropriately.
	 */
	code = scxfs_ioctl_setattr_dax_invalidate(ip, fa, &join_flags);
	if (code)
		goto error_free_dquots;

	tp = scxfs_ioctl_setattr_get_trans(ip, join_flags);
	if (IS_ERR(tp)) {
		code = PTR_ERR(tp);
		goto error_free_dquots;
	}

	if (SCXFS_IS_QUOTA_RUNNING(mp) && SCXFS_IS_PQUOTA_ON(mp) &&
	    scxfs_get_projid(ip) != fa->fsx_projid) {
		code = scxfs_qm_vop_chown_reserve(tp, ip, udqp, NULL, pdqp,
				capable(CAP_FOWNER) ?  SCXFS_QMOPT_FORCE_RES : 0);
		if (code)	/* out of quota */
			goto error_trans_cancel;
	}

	scxfs_fill_fsxattr(ip, false, &old_fa);
	code = vfs_ioc_fssetxattr_check(VFS_I(ip), &old_fa, fa);
	if (code)
		goto error_trans_cancel;

	code = scxfs_ioctl_setattr_check_extsize(ip, fa);
	if (code)
		goto error_trans_cancel;

	code = scxfs_ioctl_setattr_check_cowextsize(ip, fa);
	if (code)
		goto error_trans_cancel;

	code = scxfs_ioctl_setattr_xflags(tp, ip, fa);
	if (code)
		goto error_trans_cancel;

	/*
	 * Change file ownership.  Must be the owner or privileged.  CAP_FSETID
	 * overrides the following restrictions:
	 *
	 * The set-user-ID and set-group-ID bits of a file will be cleared upon
	 * successful return from chown()
	 */

	if ((VFS_I(ip)->i_mode & (S_ISUID|S_ISGID)) &&
	    !capable_wrt_inode_uidgid(VFS_I(ip), CAP_FSETID))
		VFS_I(ip)->i_mode &= ~(S_ISUID|S_ISGID);

	/* Change the ownerships and register project quota modifications */
	if (scxfs_get_projid(ip) != fa->fsx_projid) {
		if (SCXFS_IS_QUOTA_RUNNING(mp) && SCXFS_IS_PQUOTA_ON(mp)) {
			olddquot = scxfs_qm_vop_chown(tp, ip,
						&ip->i_pdquot, pdqp);
		}
		ASSERT(ip->i_d.di_version > 1);
		scxfs_set_projid(ip, fa->fsx_projid);
	}

	/*
	 * Only set the extent size hint if we've already determined that the
	 * extent size hint should be set on the inode. If no extent size flags
	 * are set on the inode then unconditionally clear the extent size hint.
	 */
	if (ip->i_d.di_flags & (SCXFS_DIFLAG_EXTSIZE | SCXFS_DIFLAG_EXTSZINHERIT))
		ip->i_d.di_extsize = fa->fsx_extsize >> mp->m_sb.sb_blocklog;
	else
		ip->i_d.di_extsize = 0;
	if (ip->i_d.di_version == 3 &&
	    (ip->i_d.di_flags2 & SCXFS_DIFLAG2_COWEXTSIZE))
		ip->i_d.di_cowextsize = fa->fsx_cowextsize >>
				mp->m_sb.sb_blocklog;
	else
		ip->i_d.di_cowextsize = 0;

	code = scxfs_trans_commit(tp);

	/*
	 * Release any dquot(s) the inode had kept before chown.
	 */
	scxfs_qm_dqrele(olddquot);
	scxfs_qm_dqrele(udqp);
	scxfs_qm_dqrele(pdqp);

	return code;

error_trans_cancel:
	scxfs_trans_cancel(tp);
error_free_dquots:
	scxfs_qm_dqrele(udqp);
	scxfs_qm_dqrele(pdqp);
	return code;
}

STATIC int
scxfs_ioc_fssetxattr(
	scxfs_inode_t		*ip,
	struct file		*filp,
	void			__user *arg)
{
	struct fsxattr		fa;
	int error;

	if (copy_from_user(&fa, arg, sizeof(fa)))
		return -EFAULT;

	error = mnt_want_write_file(filp);
	if (error)
		return error;
	error = scxfs_ioctl_setattr(ip, &fa);
	mnt_drop_write_file(filp);
	return error;
}

STATIC int
scxfs_ioc_getxflags(
	scxfs_inode_t		*ip,
	void			__user *arg)
{
	unsigned int		flags;

	flags = scxfs_di2lxflags(ip->i_d.di_flags);
	if (copy_to_user(arg, &flags, sizeof(flags)))
		return -EFAULT;
	return 0;
}

STATIC int
scxfs_ioc_setxflags(
	struct scxfs_inode	*ip,
	struct file		*filp,
	void			__user *arg)
{
	struct scxfs_trans	*tp;
	struct fsxattr		fa;
	struct fsxattr		old_fa;
	unsigned int		flags;
	int			join_flags = 0;
	int			error;

	if (copy_from_user(&flags, arg, sizeof(flags)))
		return -EFAULT;

	if (flags & ~(FS_IMMUTABLE_FL | FS_APPEND_FL | \
		      FS_NOATIME_FL | FS_NODUMP_FL | \
		      FS_SYNC_FL))
		return -EOPNOTSUPP;

	fa.fsx_xflags = scxfs_merge_ioc_xflags(flags, scxfs_ip2xflags(ip));

	error = mnt_want_write_file(filp);
	if (error)
		return error;

	/*
	 * Changing DAX config may require inode locking for mapping
	 * invalidation. These need to be held all the way to transaction commit
	 * or cancel time, so need to be passed through to
	 * scxfs_ioctl_setattr_get_trans() so it can apply them to the join call
	 * appropriately.
	 */
	error = scxfs_ioctl_setattr_dax_invalidate(ip, &fa, &join_flags);
	if (error)
		goto out_drop_write;

	tp = scxfs_ioctl_setattr_get_trans(ip, join_flags);
	if (IS_ERR(tp)) {
		error = PTR_ERR(tp);
		goto out_drop_write;
	}

	scxfs_fill_fsxattr(ip, false, &old_fa);
	error = vfs_ioc_fssetxattr_check(VFS_I(ip), &old_fa, &fa);
	if (error) {
		scxfs_trans_cancel(tp);
		goto out_drop_write;
	}

	error = scxfs_ioctl_setattr_xflags(tp, ip, &fa);
	if (error) {
		scxfs_trans_cancel(tp);
		goto out_drop_write;
	}

	error = scxfs_trans_commit(tp);
out_drop_write:
	mnt_drop_write_file(filp);
	return error;
}

static bool
scxfs_getbmap_format(
	struct kgetbmap		*p,
	struct getbmapx __user	*u,
	size_t			recsize)
{
	if (put_user(p->bmv_offset, &u->bmv_offset) ||
	    put_user(p->bmv_block, &u->bmv_block) ||
	    put_user(p->bmv_length, &u->bmv_length) ||
	    put_user(0, &u->bmv_count) ||
	    put_user(0, &u->bmv_entries))
		return false;
	if (recsize < sizeof(struct getbmapx))
		return true;
	if (put_user(0, &u->bmv_iflags) ||
	    put_user(p->bmv_oflags, &u->bmv_oflags) ||
	    put_user(0, &u->bmv_unused1) ||
	    put_user(0, &u->bmv_unused2))
		return false;
	return true;
}

STATIC int
scxfs_ioc_getbmap(
	struct file		*file,
	unsigned int		cmd,
	void			__user *arg)
{
	struct getbmapx		bmx = { 0 };
	struct kgetbmap		*buf;
	size_t			recsize;
	int			error, i;

	switch (cmd) {
	case SCXFS_IOC_GETBMAPA:
		bmx.bmv_iflags = BMV_IF_ATTRFORK;
		/*FALLTHRU*/
	case SCXFS_IOC_GETBMAP:
		if (file->f_mode & FMODE_NOCMTIME)
			bmx.bmv_iflags |= BMV_IF_NO_DMAPI_READ;
		/* struct getbmap is a strict subset of struct getbmapx. */
		recsize = sizeof(struct getbmap);
		break;
	case SCXFS_IOC_GETBMAPX:
		recsize = sizeof(struct getbmapx);
		break;
	default:
		return -EINVAL;
	}

	if (copy_from_user(&bmx, arg, recsize))
		return -EFAULT;

	if (bmx.bmv_count < 2)
		return -EINVAL;
	if (bmx.bmv_count > ULONG_MAX / recsize)
		return -ENOMEM;

	buf = kmem_zalloc_large(bmx.bmv_count * sizeof(*buf), 0);
	if (!buf)
		return -ENOMEM;

	error = scxfs_getbmap(SCXFS_I(file_inode(file)), &bmx, buf);
	if (error)
		goto out_free_buf;

	error = -EFAULT;
	if (copy_to_user(arg, &bmx, recsize))
		goto out_free_buf;
	arg += recsize;

	for (i = 0; i < bmx.bmv_entries; i++) {
		if (!scxfs_getbmap_format(buf + i, arg, recsize))
			goto out_free_buf;
		arg += recsize;
	}

	error = 0;
out_free_buf:
	kmem_free(buf);
	return error;
}

STATIC int
scxfs_ioc_getfsmap(
	struct scxfs_inode	*ip,
	struct fsmap_head	__user *arg)
{
	struct scxfs_fsmap_head	xhead = {0};
	struct fsmap_head	head;
	struct fsmap		*recs;
	unsigned int		count;
	__u32			last_flags = 0;
	bool			done = false;
	int			error;

	if (copy_from_user(&head, arg, sizeof(struct fsmap_head)))
		return -EFAULT;
	if (memchr_inv(head.fmh_reserved, 0, sizeof(head.fmh_reserved)) ||
	    memchr_inv(head.fmh_keys[0].fmr_reserved, 0,
		       sizeof(head.fmh_keys[0].fmr_reserved)) ||
	    memchr_inv(head.fmh_keys[1].fmr_reserved, 0,
		       sizeof(head.fmh_keys[1].fmr_reserved)))
		return -EINVAL;

	/*
	 * Use an internal memory buffer so that we don't have to copy fsmap
	 * data to userspace while holding locks.  Start by trying to allocate
	 * up to 128k for the buffer, but fall back to a single page if needed.
	 */
	count = min_t(unsigned int, head.fmh_count,
			131072 / sizeof(struct fsmap));
	recs = kvzalloc(count * sizeof(struct fsmap), GFP_KERNEL);
	if (!recs) {
		count = min_t(unsigned int, head.fmh_count,
				PAGE_SIZE / sizeof(struct fsmap));
		recs = kvzalloc(count * sizeof(struct fsmap), GFP_KERNEL);
		if (!recs)
			return -ENOMEM;
	}

	xhead.fmh_iflags = head.fmh_iflags;
	scxfs_fsmap_to_internal(&xhead.fmh_keys[0], &head.fmh_keys[0]);
	scxfs_fsmap_to_internal(&xhead.fmh_keys[1], &head.fmh_keys[1]);

	trace_scxfs_getfsmap_low_key(ip->i_mount, &xhead.fmh_keys[0]);
	trace_scxfs_getfsmap_high_key(ip->i_mount, &xhead.fmh_keys[1]);

	head.fmh_entries = 0;
	do {
		struct fsmap __user	*user_recs;
		struct fsmap		*last_rec;

		user_recs = &arg->fmh_recs[head.fmh_entries];
		xhead.fmh_entries = 0;
		xhead.fmh_count = min_t(unsigned int, count,
					head.fmh_count - head.fmh_entries);

		/* Run query, record how many entries we got. */
		error = scxfs_getfsmap(ip->i_mount, &xhead, recs);
		switch (error) {
		case 0:
			/*
			 * There are no more records in the result set.  Copy
			 * whatever we got to userspace and break out.
			 */
			done = true;
			break;
		case -ECANCELED:
			/*
			 * The internal memory buffer is full.  Copy whatever
			 * records we got to userspace and go again if we have
			 * not yet filled the userspace buffer.
			 */
			error = 0;
			break;
		default:
			goto out_free;
		}
		head.fmh_entries += xhead.fmh_entries;
		head.fmh_oflags = xhead.fmh_oflags;

		/*
		 * If the caller wanted a record count or there aren't any
		 * new records to return, we're done.
		 */
		if (head.fmh_count == 0 || xhead.fmh_entries == 0)
			break;

		/* Copy all the records we got out to userspace. */
		if (copy_to_user(user_recs, recs,
				 xhead.fmh_entries * sizeof(struct fsmap))) {
			error = -EFAULT;
			goto out_free;
		}

		/* Remember the last record flags we copied to userspace. */
		last_rec = &recs[xhead.fmh_entries - 1];
		last_flags = last_rec->fmr_flags;

		/* Set up the low key for the next iteration. */
		scxfs_fsmap_to_internal(&xhead.fmh_keys[0], last_rec);
		trace_scxfs_getfsmap_low_key(ip->i_mount, &xhead.fmh_keys[0]);
	} while (!done && head.fmh_entries < head.fmh_count);

	/*
	 * If there are no more records in the query result set and we're not
	 * in counting mode, mark the last record returned with the LAST flag.
	 */
	if (done && head.fmh_count > 0 && head.fmh_entries > 0) {
		struct fsmap __user	*user_rec;

		last_flags |= FMR_OF_LAST;
		user_rec = &arg->fmh_recs[head.fmh_entries - 1];

		if (copy_to_user(&user_rec->fmr_flags, &last_flags,
					sizeof(last_flags))) {
			error = -EFAULT;
			goto out_free;
		}
	}

	/* copy back header */
	if (copy_to_user(arg, &head, sizeof(struct fsmap_head))) {
		error = -EFAULT;
		goto out_free;
	}

out_free:
	kmem_free(recs);
	return error;
}

STATIC int
scxfs_ioc_scrub_metadata(
	struct scxfs_inode		*ip,
	void				__user *arg)
{
	struct scxfs_scrub_metadata	scrub;
	int				error;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (copy_from_user(&scrub, arg, sizeof(scrub)))
		return -EFAULT;

	error = scxfs_scrub_metadata(ip, &scrub);
	if (error)
		return error;

	if (copy_to_user(arg, &scrub, sizeof(scrub)))
		return -EFAULT;

	return 0;
}

int
scxfs_ioc_swapext(
	scxfs_swapext_t	*sxp)
{
	scxfs_inode_t     *ip, *tip;
	struct fd	f, tmp;
	int		error = 0;

	/* Pull information for the target fd */
	f = fdget((int)sxp->sx_fdtarget);
	if (!f.file) {
		error = -EINVAL;
		goto out;
	}

	if (!(f.file->f_mode & FMODE_WRITE) ||
	    !(f.file->f_mode & FMODE_READ) ||
	    (f.file->f_flags & O_APPEND)) {
		error = -EBADF;
		goto out_put_file;
	}

	tmp = fdget((int)sxp->sx_fdtmp);
	if (!tmp.file) {
		error = -EINVAL;
		goto out_put_file;
	}

	if (!(tmp.file->f_mode & FMODE_WRITE) ||
	    !(tmp.file->f_mode & FMODE_READ) ||
	    (tmp.file->f_flags & O_APPEND)) {
		error = -EBADF;
		goto out_put_tmp_file;
	}

	if (IS_SWAPFILE(file_inode(f.file)) ||
	    IS_SWAPFILE(file_inode(tmp.file))) {
		error = -EINVAL;
		goto out_put_tmp_file;
	}

	/*
	 * We need to ensure that the fds passed in point to SCXFS inodes
	 * before we cast and access them as SCXFS structures as we have no
	 * control over what the user passes us here.
	 */
	if (f.file->f_op != &scxfs_file_operations ||
	    tmp.file->f_op != &scxfs_file_operations) {
		error = -EINVAL;
		goto out_put_tmp_file;
	}

	ip = SCXFS_I(file_inode(f.file));
	tip = SCXFS_I(file_inode(tmp.file));

	if (ip->i_mount != tip->i_mount) {
		error = -EINVAL;
		goto out_put_tmp_file;
	}

	if (ip->i_ino == tip->i_ino) {
		error = -EINVAL;
		goto out_put_tmp_file;
	}

	if (SCXFS_FORCED_SHUTDOWN(ip->i_mount)) {
		error = -EIO;
		goto out_put_tmp_file;
	}

	error = scxfs_swap_extents(ip, tip, sxp);

 out_put_tmp_file:
	fdput(tmp);
 out_put_file:
	fdput(f);
 out:
	return error;
}

static int
scxfs_ioc_getlabel(
	struct scxfs_mount	*mp,
	char			__user *user_label)
{
	struct scxfs_sb		*sbp = &mp->m_sb;
	char			label[SCXFSLABEL_MAX + 1];

	/* Paranoia */
	BUILD_BUG_ON(sizeof(sbp->sb_fname) > FSLABEL_MAX);

	/* 1 larger than sb_fname, so this ensures a trailing NUL char */
	memset(label, 0, sizeof(label));
	spin_lock(&mp->m_sb_lock);
	strncpy(label, sbp->sb_fname, SCXFSLABEL_MAX);
	spin_unlock(&mp->m_sb_lock);

	if (copy_to_user(user_label, label, sizeof(label)))
		return -EFAULT;
	return 0;
}

static int
scxfs_ioc_setlabel(
	struct file		*filp,
	struct scxfs_mount	*mp,
	char			__user *newlabel)
{
	struct scxfs_sb		*sbp = &mp->m_sb;
	char			label[SCXFSLABEL_MAX + 1];
	size_t			len;
	int			error;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	/*
	 * The generic ioctl allows up to FSLABEL_MAX chars, but SCXFS is much
	 * smaller, at 12 bytes.  We copy one more to be sure we find the
	 * (required) NULL character to test the incoming label length.
	 * NB: The on disk label doesn't need to be null terminated.
	 */
	if (copy_from_user(label, newlabel, SCXFSLABEL_MAX + 1))
		return -EFAULT;
	len = strnlen(label, SCXFSLABEL_MAX + 1);
	if (len > sizeof(sbp->sb_fname))
		return -EINVAL;

	error = mnt_want_write_file(filp);
	if (error)
		return error;

	spin_lock(&mp->m_sb_lock);
	memset(sbp->sb_fname, 0, sizeof(sbp->sb_fname));
	memcpy(sbp->sb_fname, label, len);
	spin_unlock(&mp->m_sb_lock);

	/*
	 * Now we do several things to satisfy userspace.
	 * In addition to normal logging of the primary superblock, we also
	 * immediately write these changes to sector zero for the primary, then
	 * update all backup supers (as scxfs_db does for a label change), then
	 * invalidate the block device page cache.  This is so that any prior
	 * buffered reads from userspace (i.e. from blkid) are invalidated,
	 * and userspace will see the newly-written label.
	 */
	error = scxfs_sync_sb_buf(mp);
	if (error)
		goto out;
	/*
	 * growfs also updates backup supers so lock against that.
	 */
	mutex_lock(&mp->m_growlock);
	error = scxfs_update_secondary_sbs(mp);
	mutex_unlock(&mp->m_growlock);

	invalidate_bdev(mp->m_ddev_targp->bt_bdev);

out:
	mnt_drop_write_file(filp);
	return error;
}

/*
 * Note: some of the ioctl's return positive numbers as a
 * byte count indicating success, such as readlink_by_handle.
 * So we don't "sign flip" like most other routines.  This means
 * true errors need to be returned as a negative value.
 */
long
scxfs_file_ioctl(
	struct file		*filp,
	unsigned int		cmd,
	unsigned long		p)
{
	struct inode		*inode = file_inode(filp);
	struct scxfs_inode	*ip = SCXFS_I(inode);
	struct scxfs_mount	*mp = ip->i_mount;
	void			__user *arg = (void __user *)p;
	int			error;

	trace_scxfs_file_ioctl(ip);

	switch (cmd) {
	case FITRIM:
		return scxfs_ioc_trim(mp, arg);
	case FS_IOC_GETFSLABEL:
		return scxfs_ioc_getlabel(mp, arg);
	case FS_IOC_SETFSLABEL:
		return scxfs_ioc_setlabel(filp, mp, arg);
	case SCXFS_IOC_ALLOCSP:
	case SCXFS_IOC_FREESP:
	case SCXFS_IOC_RESVSP:
	case SCXFS_IOC_UNRESVSP:
	case SCXFS_IOC_ALLOCSP64:
	case SCXFS_IOC_FREESP64:
	case SCXFS_IOC_RESVSP64:
	case SCXFS_IOC_UNRESVSP64:
	case SCXFS_IOC_ZERO_RANGE: {
		scxfs_flock64_t		bf;

		if (copy_from_user(&bf, arg, sizeof(bf)))
			return -EFAULT;
		return scxfs_ioc_space(filp, cmd, &bf);
	}
	case SCXFS_IOC_DIOINFO: {
		struct dioattr	da;
		scxfs_buftarg_t	*target =
			SCXFS_IS_REALTIME_INODE(ip) ?
			mp->m_rtdev_targp : mp->m_ddev_targp;

		da.d_mem =  da.d_miniosz = target->bt_logical_sectorsize;
		da.d_maxiosz = INT_MAX & ~(da.d_miniosz - 1);

		if (copy_to_user(arg, &da, sizeof(da)))
			return -EFAULT;
		return 0;
	}

	case SCXFS_IOC_FSBULKSTAT_SINGLE:
	case SCXFS_IOC_FSBULKSTAT:
	case SCXFS_IOC_FSINUMBERS:
		return scxfs_ioc_fsbulkstat(mp, cmd, arg);

	case SCXFS_IOC_BULKSTAT:
		return scxfs_ioc_bulkstat(mp, cmd, arg);
	case SCXFS_IOC_INUMBERS:
		return scxfs_ioc_inumbers(mp, cmd, arg);

	case SCXFS_IOC_FSGEOMETRY_V1:
		return scxfs_ioc_fsgeometry(mp, arg, 3);
	case SCXFS_IOC_FSGEOMETRY_V4:
		return scxfs_ioc_fsgeometry(mp, arg, 4);
	case SCXFS_IOC_FSGEOMETRY:
		return scxfs_ioc_fsgeometry(mp, arg, 5);

	case SCXFS_IOC_AG_GEOMETRY:
		return scxfs_ioc_ag_geometry(mp, arg);

	case SCXFS_IOC_GETVERSION:
		return put_user(inode->i_generation, (int __user *)arg);

	case SCXFS_IOC_FSGETXATTR:
		return scxfs_ioc_fsgetxattr(ip, 0, arg);
	case SCXFS_IOC_FSGETXATTRA:
		return scxfs_ioc_fsgetxattr(ip, 1, arg);
	case SCXFS_IOC_FSSETXATTR:
		return scxfs_ioc_fssetxattr(ip, filp, arg);
	case SCXFS_IOC_GETXFLAGS:
		return scxfs_ioc_getxflags(ip, arg);
	case SCXFS_IOC_SETXFLAGS:
		return scxfs_ioc_setxflags(ip, filp, arg);

	case SCXFS_IOC_FSSETDM: {
		struct fsdmidata	dmi;

		if (copy_from_user(&dmi, arg, sizeof(dmi)))
			return -EFAULT;

		error = mnt_want_write_file(filp);
		if (error)
			return error;

		error = scxfs_set_dmattrs(ip, dmi.fsd_dmevmask,
				dmi.fsd_dmstate);
		mnt_drop_write_file(filp);
		return error;
	}

	case SCXFS_IOC_GETBMAP:
	case SCXFS_IOC_GETBMAPA:
	case SCXFS_IOC_GETBMAPX:
		return scxfs_ioc_getbmap(filp, cmd, arg);

	case FS_IOC_GETFSMAP:
		return scxfs_ioc_getfsmap(ip, arg);

	case SCXFS_IOC_SCRUB_METADATA:
		return scxfs_ioc_scrub_metadata(ip, arg);

	case SCXFS_IOC_FD_TO_HANDLE:
	case SCXFS_IOC_PATH_TO_HANDLE:
	case SCXFS_IOC_PATH_TO_FSHANDLE: {
		scxfs_fsop_handlereq_t	hreq;

		if (copy_from_user(&hreq, arg, sizeof(hreq)))
			return -EFAULT;
		return scxfs_find_handle(cmd, &hreq);
	}
	case SCXFS_IOC_OPEN_BY_HANDLE: {
		scxfs_fsop_handlereq_t	hreq;

		if (copy_from_user(&hreq, arg, sizeof(scxfs_fsop_handlereq_t)))
			return -EFAULT;
		return scxfs_open_by_handle(filp, &hreq);
	}
	case SCXFS_IOC_FSSETDM_BY_HANDLE:
		return scxfs_fssetdm_by_handle(filp, arg);

	case SCXFS_IOC_READLINK_BY_HANDLE: {
		scxfs_fsop_handlereq_t	hreq;

		if (copy_from_user(&hreq, arg, sizeof(scxfs_fsop_handlereq_t)))
			return -EFAULT;
		return scxfs_readlink_by_handle(filp, &hreq);
	}
	case SCXFS_IOC_ATTRLIST_BY_HANDLE:
		return scxfs_attrlist_by_handle(filp, arg);

	case SCXFS_IOC_ATTRMULTI_BY_HANDLE:
		return scxfs_attrmulti_by_handle(filp, arg);

	case SCXFS_IOC_SWAPEXT: {
		struct scxfs_swapext	sxp;

		if (copy_from_user(&sxp, arg, sizeof(scxfs_swapext_t)))
			return -EFAULT;
		error = mnt_want_write_file(filp);
		if (error)
			return error;
		error = scxfs_ioc_swapext(&sxp);
		mnt_drop_write_file(filp);
		return error;
	}

	case SCXFS_IOC_FSCOUNTS: {
		scxfs_fsop_counts_t out;

		scxfs_fs_counts(mp, &out);

		if (copy_to_user(arg, &out, sizeof(out)))
			return -EFAULT;
		return 0;
	}

	case SCXFS_IOC_SET_RESBLKS: {
		scxfs_fsop_resblks_t inout;
		uint64_t	   in;

		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;

		if (mp->m_flags & SCXFS_MOUNT_RDONLY)
			return -EROFS;

		if (copy_from_user(&inout, arg, sizeof(inout)))
			return -EFAULT;

		error = mnt_want_write_file(filp);
		if (error)
			return error;

		/* input parameter is passed in resblks field of structure */
		in = inout.resblks;
		error = scxfs_reserve_blocks(mp, &in, &inout);
		mnt_drop_write_file(filp);
		if (error)
			return error;

		if (copy_to_user(arg, &inout, sizeof(inout)))
			return -EFAULT;
		return 0;
	}

	case SCXFS_IOC_GET_RESBLKS: {
		scxfs_fsop_resblks_t out;

		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;

		error = scxfs_reserve_blocks(mp, NULL, &out);
		if (error)
			return error;

		if (copy_to_user(arg, &out, sizeof(out)))
			return -EFAULT;

		return 0;
	}

	case SCXFS_IOC_FSGROWFSDATA: {
		scxfs_growfs_data_t in;

		if (copy_from_user(&in, arg, sizeof(in)))
			return -EFAULT;

		error = mnt_want_write_file(filp);
		if (error)
			return error;
		error = scxfs_growfs_data(mp, &in);
		mnt_drop_write_file(filp);
		return error;
	}

	case SCXFS_IOC_FSGROWFSLOG: {
		scxfs_growfs_log_t in;

		if (copy_from_user(&in, arg, sizeof(in)))
			return -EFAULT;

		error = mnt_want_write_file(filp);
		if (error)
			return error;
		error = scxfs_growfs_log(mp, &in);
		mnt_drop_write_file(filp);
		return error;
	}

	case SCXFS_IOC_FSGROWFSRT: {
		scxfs_growfs_rt_t in;

		if (copy_from_user(&in, arg, sizeof(in)))
			return -EFAULT;

		error = mnt_want_write_file(filp);
		if (error)
			return error;
		error = scxfs_growfs_rt(mp, &in);
		mnt_drop_write_file(filp);
		return error;
	}

	case SCXFS_IOC_GOINGDOWN: {
		uint32_t in;

		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;

		if (get_user(in, (uint32_t __user *)arg))
			return -EFAULT;

		return scxfs_fs_goingdown(mp, in);
	}

	case SCXFS_IOC_ERROR_INJECTION: {
		scxfs_error_injection_t in;

		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;

		if (copy_from_user(&in, arg, sizeof(in)))
			return -EFAULT;

		return scxfs_errortag_add(mp, in.errtag);
	}

	case SCXFS_IOC_ERROR_CLEARALL:
		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;

		return scxfs_errortag_clearall(mp);

	case SCXFS_IOC_FREE_EOFBLOCKS: {
		struct scxfs_fs_eofblocks eofb;
		struct scxfs_eofblocks keofb;

		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;

		if (mp->m_flags & SCXFS_MOUNT_RDONLY)
			return -EROFS;

		if (copy_from_user(&eofb, arg, sizeof(eofb)))
			return -EFAULT;

		error = scxfs_fs_eofblocks_from_user(&eofb, &keofb);
		if (error)
			return error;

		sb_start_write(mp->m_super);
		error = scxfs_icache_free_eofblocks(mp, &keofb);
		sb_end_write(mp->m_super);
		return error;
	}

	default:
		return -ENOTTY;
	}
}
