// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2008 Christoph Hellwig.
 * Portions Copyright (C) 2000-2008 Silicon Graphics, Inc.
 */

#include "scxfs.h"
#include "scxfs_shared.h"
#include "scxfs_format.h"
#include "scxfs_log_format.h"
#include "scxfs_da_format.h"
#include "scxfs_inode.h"
#include "scxfs_attr.h"

#include <linux/posix_acl_xattr.h>
#include <linux/xattr.h>


static int
scxfs_xattr_get(const struct xattr_handler *handler, struct dentry *unused,
		struct inode *inode, const char *name, void *value, size_t size)
{
	int xflags = handler->flags;
	struct scxfs_inode *ip = SCXFS_I(inode);
	int error, asize = size;

	/* Convert Linux syscall to SCXFS internal ATTR flags */
	if (!size) {
		xflags |= ATTR_KERNOVAL;
		value = NULL;
	}

	error = scxfs_attr_get(ip, name, (unsigned char **)&value, &asize, xflags);
	if (error)
		return error;
	return asize;
}

void
scxfs_forget_acl(
	struct inode		*inode,
	const char		*name,
	int			xflags)
{
	/*
	 * Invalidate any cached ACLs if the user has bypassed the ACL
	 * interface. We don't validate the content whatsoever so it is caller
	 * responsibility to provide data in valid format and ensure i_mode is
	 * consistent.
	 */
	if (xflags & ATTR_ROOT) {
#ifdef CONFIG_XFS_POSIX_ACL
		if (!strcmp(name, SGI_ACL_FILE))
			forget_cached_acl(inode, ACL_TYPE_ACCESS);
		else if (!strcmp(name, SGI_ACL_DEFAULT))
			forget_cached_acl(inode, ACL_TYPE_DEFAULT);
#endif
	}
}

static int
scxfs_xattr_set(const struct xattr_handler *handler, struct dentry *unused,
		struct inode *inode, const char *name, const void *value,
		size_t size, int flags)
{
	int			xflags = handler->flags;
	struct scxfs_inode	*ip = SCXFS_I(inode);
	int			error;

	/* Convert Linux syscall to SCXFS internal ATTR flags */
	if (flags & XATTR_CREATE)
		xflags |= ATTR_CREATE;
	if (flags & XATTR_REPLACE)
		xflags |= ATTR_REPLACE;

	if (!value)
		return scxfs_attr_remove(ip, (unsigned char *)name, xflags);
	error = scxfs_attr_set(ip, (unsigned char *)name,
				(void *)value, size, xflags);
	if (!error)
		scxfs_forget_acl(inode, name, xflags);

	return error;
}

static const struct xattr_handler scxfs_xattr_user_handler = {
	.prefix	= XATTR_USER_PREFIX,
	.flags	= 0, /* no flags implies user namespace */
	.get	= scxfs_xattr_get,
	.set	= scxfs_xattr_set,
};

static const struct xattr_handler scxfs_xattr_trusted_handler = {
	.prefix	= XATTR_TRUSTED_PREFIX,
	.flags	= ATTR_ROOT,
	.get	= scxfs_xattr_get,
	.set	= scxfs_xattr_set,
};

static const struct xattr_handler scxfs_xattr_security_handler = {
	.prefix	= XATTR_SECURITY_PREFIX,
	.flags	= ATTR_SECURE,
	.get	= scxfs_xattr_get,
	.set	= scxfs_xattr_set,
};

const struct xattr_handler *scxfs_xattr_handlers[] = {
	&scxfs_xattr_user_handler,
	&scxfs_xattr_trusted_handler,
	&scxfs_xattr_security_handler,
#ifdef CONFIG_XFS_POSIX_ACL
	&posix_acl_access_xattr_handler,
	&posix_acl_default_xattr_handler,
#endif
	NULL
};

static void
__scxfs_xattr_put_listent(
	struct scxfs_attr_list_context *context,
	char *prefix,
	int prefix_len,
	unsigned char *name,
	int namelen)
{
	char *offset;
	int arraytop;

	if (context->count < 0 || context->seen_enough)
		return;

	if (!context->alist)
		goto compute_size;

	arraytop = context->count + prefix_len + namelen + 1;
	if (arraytop > context->firstu) {
		context->count = -1;	/* insufficient space */
		context->seen_enough = 1;
		return;
	}
	offset = (char *)context->alist + context->count;
	strncpy(offset, prefix, prefix_len);
	offset += prefix_len;
	strncpy(offset, (char *)name, namelen);			/* real name */
	offset += namelen;
	*offset = '\0';

compute_size:
	context->count += prefix_len + namelen + 1;
	return;
}

static void
scxfs_xattr_put_listent(
	struct scxfs_attr_list_context *context,
	int		flags,
	unsigned char	*name,
	int		namelen,
	int		valuelen)
{
	char *prefix;
	int prefix_len;

	ASSERT(context->count >= 0);

	if (flags & SCXFS_ATTR_ROOT) {
#ifdef CONFIG_XFS_POSIX_ACL
		if (namelen == SGI_ACL_FILE_SIZE &&
		    strncmp(name, SGI_ACL_FILE,
			    SGI_ACL_FILE_SIZE) == 0) {
			__scxfs_xattr_put_listent(
					context, XATTR_SYSTEM_PREFIX,
					XATTR_SYSTEM_PREFIX_LEN,
					XATTR_POSIX_ACL_ACCESS,
					strlen(XATTR_POSIX_ACL_ACCESS));
		} else if (namelen == SGI_ACL_DEFAULT_SIZE &&
			 strncmp(name, SGI_ACL_DEFAULT,
				 SGI_ACL_DEFAULT_SIZE) == 0) {
			__scxfs_xattr_put_listent(
					context, XATTR_SYSTEM_PREFIX,
					XATTR_SYSTEM_PREFIX_LEN,
					XATTR_POSIX_ACL_DEFAULT,
					strlen(XATTR_POSIX_ACL_DEFAULT));
		}
#endif

		/*
		 * Only show root namespace entries if we are actually allowed to
		 * see them.
		 */
		if (!capable(CAP_SYS_ADMIN))
			return;

		prefix = XATTR_TRUSTED_PREFIX;
		prefix_len = XATTR_TRUSTED_PREFIX_LEN;
	} else if (flags & SCXFS_ATTR_SECURE) {
		prefix = XATTR_SECURITY_PREFIX;
		prefix_len = XATTR_SECURITY_PREFIX_LEN;
	} else {
		prefix = XATTR_USER_PREFIX;
		prefix_len = XATTR_USER_PREFIX_LEN;
	}

	__scxfs_xattr_put_listent(context, prefix, prefix_len, name,
				namelen);
	return;
}

ssize_t
scxfs_vn_listxattr(
	struct dentry	*dentry,
	char		*data,
	size_t		size)
{
	struct scxfs_attr_list_context context;
	struct attrlist_cursor_kern cursor = { 0 };
	struct inode	*inode = d_inode(dentry);
	int		error;

	/*
	 * First read the regular on-disk attributes.
	 */
	memset(&context, 0, sizeof(context));
	context.dp = SCXFS_I(inode);
	context.cursor = &cursor;
	context.resynch = 1;
	context.alist = size ? data : NULL;
	context.bufsize = size;
	context.firstu = context.bufsize;
	context.put_listent = scxfs_xattr_put_listent;

	error = scxfs_attr_list_int(&context);
	if (error)
		return error;
	if (context.count < 0)
		return -ERANGE;

	return context.count;
}
