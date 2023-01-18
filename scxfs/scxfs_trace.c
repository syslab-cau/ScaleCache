// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2009, Christoph Hellwig
 * All Rights Reserved.
 */
#include "scxfs.h"
#include "scxfs_fs.h"
#include "scxfs_shared.h"
#include "scxfs_format.h"
#include "scxfs_log_format.h"
#include "scxfs_trans_resv.h"
#include "scxfs_mount.h"
#include "scxfs_defer.h"
#include "scxfs_da_format.h"
#include "scxfs_inode.h"
#include "scxfs_btree.h"
#include "scxfs_da_btree.h"
#include "scxfs_alloc.h"
#include "scxfs_bmap.h"
#include "scxfs_attr.h"
#include "scxfs_trans.h"
#include "scxfs_log_priv.h"
#include "scxfs_buf_item.h"
#include "scxfs_quota.h"
#include "scxfs_dquot_item.h"
#include "scxfs_dquot.h"
#include "scxfs_log_recover.h"
#include "scxfs_filestream.h"
#include "scxfs_fsmap.h"

/*
 * We include this last to have the helpers above available for the trace
 * event implementations.
 */
#define CREATE_TRACE_POINTS
#include "scxfs_trace.h"
