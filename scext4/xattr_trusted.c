// SPDX-License-Identifier: GPL-2.0
/*
 * linux/fs/scext4/xattr_trusted.c
 * Handler for trusted extended attributes.
 *
 * Copyright (C) 2003 by Andreas Gruenbacher, <a.gruenbacher@computer.org>
 */

#include <linux/string.h>
#include <linux/capability.h>
#include <linux/fs.h>
#include "scext4_jbd3.h"
#include "scext4.h"
#include "xattr.h"

static bool
scext4_xattr_trusted_list(struct dentry *dentry)
{
	return capable(CAP_SYS_ADMIN);
}

static int
scext4_xattr_trusted_get(const struct xattr_handler *handler,
		       struct dentry *unused, struct inode *inode,
		       const char *name, void *buffer, size_t size)
{
	return scext4_xattr_get(inode, SCEXT4_XATTR_INDEX_TRUSTED,
			      name, buffer, size);
}

static int
scext4_xattr_trusted_set(const struct xattr_handler *handler,
		       struct dentry *unused, struct inode *inode,
		       const char *name, const void *value,
		       size_t size, int flags)
{
	return scext4_xattr_set(inode, SCEXT4_XATTR_INDEX_TRUSTED,
			      name, value, size, flags);
}

const struct xattr_handler scext4_xattr_trusted_handler = {
	.prefix	= XATTR_TRUSTED_PREFIX,
	.list	= scext4_xattr_trusted_list,
	.get	= scext4_xattr_trusted_get,
	.set	= scext4_xattr_trusted_set,
};
