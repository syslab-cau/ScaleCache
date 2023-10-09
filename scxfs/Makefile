# SPDX-License-Identifier: GPL-2.0
#
# Copyright (c) 2000-2005 Silicon Graphics, Inc.
# All Rights Reserved.
#

ccflags-y += -I $(src)		# needed for trace events
ccflags-y += -I $(src)/libscxfs

ccflags-y += -g

obj-m				+= scxfs.o

# this one should be compiled first, as the tracing macros can easily blow up
scxfs-y				+= scxfs_trace.o

# build the libscxfs code first
scxfs-y				+= $(addprefix libscxfs/, \
				   scxfs_ag.o \
				   scxfs_alloc.o \
				   scxfs_alloc_btree.o \
				   scxfs_attr.o \
				   scxfs_attr_leaf.o \
				   scxfs_attr_remote.o \
				   scxfs_bit.o \
				   scxfs_bmap.o \
				   scxfs_bmap_btree.o \
				   scxfs_btree.o \
				   scxfs_da_btree.o \
				   scxfs_da_format.o \
				   scxfs_defer.o \
				   scxfs_dir2.o \
				   scxfs_dir2_block.o \
				   scxfs_dir2_data.o \
				   scxfs_dir2_leaf.o \
				   scxfs_dir2_node.o \
				   scxfs_dir2_sf.o \
				   scxfs_dquot_buf.o \
				   scxfs_ialloc.o \
				   scxfs_ialloc_btree.o \
				   scxfs_iext_tree.o \
				   scxfs_inode_fork.o \
				   scxfs_inode_buf.o \
				   scxfs_log_rlimit.o \
				   scxfs_ag_resv.o \
				   scxfs_rmap.o \
				   scxfs_rmap_btree.o \
				   scxfs_refcount.o \
				   scxfs_refcount_btree.o \
				   scxfs_sb.o \
				   scxfs_symlink_remote.o \
				   scxfs_trans_inode.o \
				   scxfs_trans_resv.o \
				   scxfs_types.o \
				   )
# scxfs_rtbitmap is shared with libscxfs
scxfs-$(CONFIG_XFS_RT)		+= $(addprefix libscxfs/, \
				   scxfs_rtbitmap.o \
				   )

# highlevel code
scxfs-y				+= scxfs_aops.o \
				   scxfs_attr_inactive.o \
				   scxfs_attr_list.o \
				   scxfs_bmap_util.o \
				   scxfs_bio_io.o \
				   scxfs_buf.o \
				   scxfs_dir2_readdir.o \
				   scxfs_discard.o \
				   scxfs_error.o \
				   scxfs_export.o \
				   scxfs_extent_busy.o \
				   scxfs_file.o \
				   scxfs_filestream.o \
				   scxfs_fsmap.o \
				   scxfs_fsops.o \
				   scxfs_globals.o \
				   scxfs_health.o \
				   scxfs_icache.o \
				   scxfs_ioctl.o \
				   scxfs_iomap.o \
				   scxfs_iops.o \
				   scxfs_inode.o \
				   scxfs_itable.o \
				   scxfs_iwalk.o \
				   scxfs_message.o \
				   scxfs_mount.o \
				   scxfs_mru_cache.o \
				   scxfs_pwork.o \
				   scxfs_reflink.o \
				   scxfs_stats.o \
				   scxfs_super.o \
				   scxfs_symlink.o \
				   scxfs_sysfs.o \
				   scxfs_trans.o \
				   scxfs_xattr.o \
				   kmem.o

# low-level transaction/log code
scxfs-y				+= scxfs_log.o \
				   scxfs_log_cil.o \
				   scxfs_bmap_item.o \
				   scxfs_buf_item.o \
				   scxfs_extfree_item.o \
				   scxfs_icreate_item.o \
				   scxfs_inode_item.o \
				   scxfs_refcount_item.o \
				   scxfs_rmap_item.o \
				   scxfs_log_recover.o \
				   scxfs_trans_ail.o \
				   scxfs_trans_buf.o

# optional features
scxfs-$(CONFIG_XFS_QUOTA)	+= scxfs_dquot.o \
				   scxfs_dquot_item.o \
				   scxfs_trans_dquot.o \
				   scxfs_qm_syscalls.o \
				   scxfs_qm_bhv.o \
				   scxfs_qm.o \
				   scxfs_quotaops.o

# scxfs_rtbitmap is shared with libxfs
scxfs-$(CONFIG_XFS_RT)		+= scxfs_rtalloc.o

scxfs-$(CONFIG_XFS_POSIX_ACL)	+= scxfs_acl.o
scxfs-$(CONFIG_SYSCTL)		+= scxfs_sysctl.o
scxfs-$(CONFIG_COMPAT)		+= scxfs_ioctl32.o
scxfs-$(CONFIG_EXPORTFS_BLOCK_OPS)	+= scxfs_pnfs.o

# online scrub/repair
ifeq ($(CONFIG_XFS_ONLINE_SCRUB),y)

# Tracepoints like to blow up, so build that before everything else

scxfs-y				+= $(addprefix scrub/, \
				   trace.o \
				   agheader.o \
				   alloc.o \
				   attr.o \
				   bmap.o \
				   btree.o \
				   common.o \
				   dabtree.o \
				   dir.o \
				   fscounters.o \
				   health.o \
				   ialloc.o \
				   inode.o \
				   parent.o \
				   refcount.o \
				   rmap.o \
				   scrub.o \
				   symlink.o \
				   )

scxfs-$(CONFIG_XFS_RT)		+= scrub/rtbitmap.o
scxfs-$(CONFIG_XFS_QUOTA)	+= scrub/quota.o

# online repair
ifeq ($(CONFIG_XFS_ONLINE_REPAIR),y)
scxfs-y				+= $(addprefix scrub/, \
				   agheader_repair.o \
				   bitmap.o \
				   repair.o \
				   )
endif
endif

# ScaleCache MM
scxfs-y				+= $(addprefix mm/, \
				   page-writeback.o \
				   filemap.o \
				   memcontrol.o \
				   mempolicy.o \
				   workingset.o \
				   page_alloc.o \
				   vmscan.o \
				   )

# ScaleCache FS
scxfs-y				+= $(addprefix fs/, \
				   buffer.o \
				   fs-writeback.o \
				   $(addprefix iomap/, \
				   buffered-io.o \
				   apply.o \
				   ) \
				   )

# ScaleCache WorkQueue
scxfs-y				+= workqueue.o 

# ScaleCache Concurrent XArray
scxfs-y				+= cc_xarray/cc_xarray.o 


KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
install:
	sudo $(MAKE) -C $(KDIR) M=$(PWD) modules_install
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
