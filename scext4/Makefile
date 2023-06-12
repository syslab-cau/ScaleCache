# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the linux ScaleCache ext4-filesystem routines.
#

obj-m = jbd3/ scext4.o

scext4-y	:= balloc.o bitmap.o block_validity.o dir.o scext4_jbd3.o extents.o \
		extents_status.o file.o fsmap.o fsync.o hash.o ialloc.o \
		indirect.o inline.o inode.o ioctl.o mballoc.o migrate.o \
		mmp.o move_extent.o namei.o page-io.o readpage.o resize.o \
		super.o symlink.o sysfs.o xattr.o xattr_trusted.o xattr_user.o \
		mm/page-writeback.o mm/filemap.o mm/memcontrol.o mm/mempolicy.o \
		mm/workingset.o  mm/page_alloc.o mm/vmscan.o \
		fs/buffer.o fs/fs-writeback.o workqueue.o cc_xarray/cc_xarray.o \
		mm/truncate.o mm/swap.o mm/readahead.o

scext4-m	+= acl.o
scext4-m	+= xattr_security.o
scext4-m	+= verity.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

ccflags-y += -DDEBUG -g

default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
install:
	sudo $(MAKE) -C $(KDIR) M=$(PWD) modules_install
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
