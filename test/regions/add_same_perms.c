/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2018 Andrew Turner
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
 * ("CTSRD"), as part of the DARPA CRASH research programme.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <libmw.h>

#include "regions.h"

static struct region_ctx cb_ctx = {
	.regions = {
		/* 0 */ {
			.addr = 0x100000,
			.size = 0x1000,
			.perms = MW_PERM_ALL,
			.change = MW_REGION_INSERT,
			.have_old = false,
		},
		/* 1 */ {
			.addr = 0xff000,
			.size = 0x1000,
			.perms = MW_PERM_ALL,
			.change = MW_REGION_EXPAND,
			.have_old = true,
			.old_addr = 0x100000,
			.old_size = 0x1000,
			.old_perms = MW_PERM_ALL,
		},
		/* 2 */ {
			.addr = 0x101000,
			.size = 0x1000,
			.perms = MW_PERM_ALL,
			.change = MW_REGION_EXPAND,
			.have_old = true,
			.old_addr = 0xff000,
			.old_size = 0x2000,
			.old_perms = MW_PERM_ALL,
		},
		/* 3 */ {
			.addr = 0x102000,
			.size = 0x1000,
			.perms = MW_PERM_ALL,
			.change = MW_REGION_EXPAND,
			.have_old = true,
			.old_addr = 0xff000,
			.old_size = 0x3000,
			.old_perms = MW_PERM_ALL,
		},
		/* 4 */ {
			.addr = 0xfe000,
			.size = 0x1000,
			.perms = MW_PERM_ALL,
			.change = MW_REGION_EXPAND,
			.have_old = true,
			.old_addr = 0xff000,
			.old_size = 0x4000,
			.old_perms = MW_PERM_ALL,
		},
		/* 5 */ {
			.addr = 0xfd000,
			.size = 0x1000,
			.perms = MW_PERM_ALL,
			.change = MW_REGION_EXPAND,
			.have_old = true,
			.old_addr = 0xfe000,
			.old_size = 0x5000,
			.old_perms = MW_PERM_ALL,
		},
		/* 6 */ {
			.addr = 0xfc000,
			.size = 0x1000,
			.perms = MW_PERM_ALL,
			.change = MW_REGION_EXPAND,
			.have_old = true,
			.old_addr = 0xfd000,
			.old_size = 0x6000,
			.old_perms = MW_PERM_ALL,
		},
		/* 7 */ {
			.addr = 0x103000,
			.size = 0x1000,
			.perms = MW_PERM_ALL,
			.change = MW_REGION_EXPAND,
			.have_old = true,
			.old_addr = 0xfc000,
			.old_size = 0x7000,
			.old_perms = MW_PERM_ALL,
		},
		/* 8 */ {
			.addr = 0x104000,
			.size = 0x1000,
			.perms = MW_PERM_ALL,
			.change = MW_REGION_EXPAND,
			.have_old = true,
			.old_addr = 0xfc000,
			.old_size = 0x8000,
			.old_perms = MW_PERM_ALL,
		},
		/* 9 */ {
			.addr = 0x200000,
			.size = 0x1000,
			.perms = MW_PERM_ALL,
			.change = MW_REGION_INSERT,
			.have_old = false,
		},
		/* 10 */ {
			.addr = 0x1000,
			.size = 0x1000,
			.perms = MW_PERM_ALL,
			.change = MW_REGION_INSERT,
			.have_old = false,
		},
		/* 11 */ {
			.addr = 0x3000,
			.size = 0x1000,
			.perms = MW_PERM_ALL,
			.change = MW_REGION_INSERT,
			.have_old = false,
		},
		/* 12 */ {
			.addr = 0x2000,
			.size = 0x1000,
			.perms = MW_PERM_ALL,
			.change = MW_REGION_EXPAND,
			.have_old = true,
			.old_addr = 0x1000,
			.old_size = 0x1000,
			.old_perms = MW_PERM_ALL,
		},
		/* 13 */ {
			.addr = 0x4000,
			.size = 0xf8000,
			.perms = MW_PERM_ALL,
			.change = MW_REGION_EXPAND,
			.have_old = true,
			.old_addr = 0x1000,
			.old_size = 0x3000,
			.old_perms = MW_PERM_ALL,
		},
		/* 14 */ {
			.addr = 0x0,
			.size = 0x1000,
			.perms = MW_PERM_ALL,
			.change = MW_REGION_EXPAND,
			.have_old = true,
			.old_addr = 0x1000,
			.old_size = 0x104000,
			.old_perms = MW_PERM_ALL,
		},
		/* 15 */ {
			.addr = 0x105000,
			.size = 0xfb000,
			.perms = MW_PERM_ALL,
			.change = MW_REGION_EXPAND,
			.have_old = true,
			.old_addr = 0x0,
			.old_size = 0x105000,
			.old_perms = MW_PERM_ALL,
		},
		/* 16 */ {
			.addr = 0x201000,
			.size = 0xff000,
			.perms = MW_PERM_ALL,
			.change = MW_REGION_EXPAND,
			.have_old = true,
			.old_addr = 0x0,
			.old_size = 0x201000,
			.old_perms = MW_PERM_ALL,
		},
	},
	.count = 17,
};

static void
test_expand(struct mw_region_collection *col, struct region_ctx *ctx)
{
	struct mw_region region;
	bool ret;

	/* Check the initial state is as we expect */
	assert(ctx->cb_count == 1);
	assert(col->region_count == 1);
	assert(col->regions[0].addr == 0x100000);
	assert(col->regions[0].size == 0x1000);

	memset(&region, 0, sizeof(region));

	/* Adding a region overlapping the current region should expand */
	region.addr = 0xff000;
	region.size = 0x3000;
	region.perms = MW_PERM_ALL;
	assert(col->regions[0].addr > region.addr);
	assert(col->regions[0].addr + col->regions[0].size <
	    region.addr + region.size);
	ret = mw_region_collection_add(col, &region);
	assert(ret);
	assert(ctx->cb_count == 3);
	assert(col->region_count == 1);
	assert(col->regions[0].addr == 0xff000);
	assert(col->regions[0].size == 0x3000);

	/* Adding with the same address, but size is larger should expand */
	region.addr = 0xff000;
	region.size = 0x4000;
	region.perms = MW_PERM_ALL;
	assert(col->regions[0].addr == region.addr);
	assert(col->regions[0].addr + col->regions[0].size <
	    region.addr + region.size);
	ret = mw_region_collection_add(col, &region);
	assert(ret);
	assert(ctx->cb_count == 4);
	assert(col->region_count == 1);
	assert(col->regions[0].addr == 0xff000);
	assert(col->regions[0].size == 0x4000);

	/* Adding with the same end address, but size is larger should expand */
	region.addr = 0xfe000;
	region.size = 0x5000;
	region.perms = MW_PERM_ALL;
	assert(col->regions[0].addr > region.addr);
	assert(col->regions[0].addr + col->regions[0].size ==
	    region.addr + region.size);
	ret = mw_region_collection_add(col, &region);
	assert(ret);
	assert(ctx->cb_count == 5);
	assert(col->region_count == 1);
	assert(col->regions[0].addr == 0xfe000);
	assert(col->regions[0].size == 0x5000);
}

static void
test_subset(struct mw_region_collection *col, struct region_ctx *ctx)
{
	struct mw_region region;
	bool ret;

	/* Check the initial state is as we expect */
	assert(ctx->cb_count == 5);
	assert(col->region_count == 1);
	assert(col->regions[0].addr == 0xfe000);
	assert(col->regions[0].size == 0x5000);

	memset(&region, 0, sizeof(region));

	/* A region with the same address, but smaller */
	region.addr = 0xfe000;
	region.size = 0x4000;
	region.perms = MW_PERM_ALL;
	assert(col->regions[0].addr == region.addr);
	assert(col->regions[0].addr + col->regions[0].size >
	    region.addr + region.size);
	ret = mw_region_collection_add(col, &region);
	assert(ret);
	assert(ctx->cb_count == 5);
	assert(col->region_count == 1);
	assert(col->regions[0].addr == 0xfe000);
	assert(col->regions[0].size == 0x5000);

	/* A region with the same end address, but smaller */
	region.addr = 0xff000;
	region.size = 0x4000;
	region.perms = MW_PERM_ALL;
	assert(col->regions[0].addr < region.addr);
	assert(col->regions[0].addr + col->regions[0].size ==
	    region.addr + region.size);
	ret = mw_region_collection_add(col, &region);
	assert(ret);
	assert(ctx->cb_count == 5);
	assert(col->region_count == 1);
	assert(col->regions[0].addr == 0xfe000);
	assert(col->regions[0].size == 0x5000);

	/* A region entirely within the existing region */
	region.addr = 0xfe800;
	region.size = 0x4000;
	region.perms = MW_PERM_ALL;
	assert(col->regions[0].addr < region.addr);
	assert(col->regions[0].addr + col->regions[0].size >
	    region.addr + region.size);
	ret = mw_region_collection_add(col, &region);
	assert(ret);
	assert(ctx->cb_count == 5);
	assert(col->region_count == 1);
	assert(col->regions[0].addr == 0xfe000);
	assert(col->regions[0].size == 0x5000);
}

static void
test_overlap_start(struct mw_region_collection *col, struct region_ctx *ctx)
{
	struct mw_region region;
	bool ret;

	/* Check the initial state is as we expect */
	assert(ctx->cb_count == 5);
	assert(col->region_count == 1);
	assert(col->regions[0].addr == 0xfe000);
	assert(col->regions[0].size == 0x5000);

	memset(&region, 0, sizeof(region));

	/* A region just before the current region */
	region.addr = 0xfd000;
	region.size = 0x1000;
	region.perms = MW_PERM_ALL;
	assert(col->regions[0].addr > region.addr);
	assert(col->regions[0].addr == region.addr + region.size);
	ret = mw_region_collection_add(col, &region);
	assert(ret);
	assert(ctx->cb_count == 6);
	assert(col->region_count == 1);
	assert(col->regions[0].addr == 0xfd000);
	assert(col->regions[0].size == 0x6000);

	/* A region before, but overlapping the current region */
	region.addr = 0xfc000;
	region.size = 0x2000;
	region.perms = MW_PERM_ALL;
	assert(col->regions[0].addr > region.addr);
	assert(col->regions[0].addr < region.addr + region.size);
	assert(col->regions[0].addr + col->regions[0].size >
	    region.addr + region.size);
	ret = mw_region_collection_add(col, &region);
	assert(ret);
	assert(ctx->cb_count == 7);
	assert(col->region_count == 1);
	assert(col->regions[0].addr == 0xfc000);
	assert(col->regions[0].size == 0x7000);
}

static void
test_overlap_end(struct mw_region_collection *col, struct region_ctx *ctx)
{
	struct mw_region region;
	bool ret;

	/* Check the initial state is as we expect */
	assert(ctx->cb_count == 7);
	assert(col->region_count == 1);
	assert(col->regions[0].addr == 0xfc000);
	assert(col->regions[0].size == 0x7000);

	memset(&region, 0, sizeof(region));

	/* A region just before the current region */
	region.addr = 0x103000;
	region.size = 0x1000;
	region.perms = MW_PERM_ALL;
	assert(col->regions[0].addr + col->regions[0].size == region.addr);
	assert(col->regions[0].addr + col->regions[0].size <
	    region.addr + region.size);
	ret = mw_region_collection_add(col, &region);
	assert(ret);
	assert(ctx->cb_count == 8);
	assert(col->region_count == 1);
	assert(col->regions[0].addr == 0xfc000);
	assert(col->regions[0].size == 0x8000);

	/* A region before, but overlapping the current region */
	region.addr = 0x103000;
	region.size = 0x2000;
	region.perms = MW_PERM_ALL;
	assert(col->regions[0].addr + col->regions[0].size > region.addr);
	assert(col->regions[0].addr + col->regions[0].size <
	    region.addr + region.size);
	ret = mw_region_collection_add(col, &region);
	assert(ret);
	assert(ctx->cb_count == 9);
	assert(col->region_count == 1);
	assert(col->regions[0].addr == 0xfc000);
	assert(col->regions[0].size == 0x9000);
}

void
test_add_same_perms(void)
{
	struct mw_region region;
	struct mw_region_collection *col;
	bool ret;

	col = mw_region_collection_alloc(region_cb, &cb_ctx);
	assert(col != NULL);
	assert(col->region_count == 0);
	assert(cb_ctx.cb_count == 0);

	ret = mw_region_collection_add(col, NULL);
	assert(ret);
	assert(cb_ctx.cb_count == 0);
	assert(col->region_count == 0);

	memset(&region, 0, sizeof(region));
	region.addr = 0x100000;
	region.size = 0x1000;
	region.perms = MW_PERM_ALL;
	ret = mw_region_collection_add(col, &region);
	assert(ret);
	assert(cb_ctx.cb_count == 1);
	assert(col->region_count == 1);
	assert(col->regions[0].addr == 0x100000);
	assert(col->regions[0].size == 0x1000);

	/* Adding an identically sized entry should be a nop */
	ret = mw_region_collection_add(col, &region);
	assert(ret);
	/* It shouldn't call the callback for a nop */
	assert(cb_ctx.cb_count == 1);
	assert(col->region_count == 1);
	assert(col->regions[0].addr == 0x100000);
	assert(col->regions[0].size == 0x1000);

	test_expand(col, &cb_ctx);
	test_subset(col, &cb_ctx);
	test_overlap_start(col, &cb_ctx);
	test_overlap_end(col, &cb_ctx);

	assert(cb_ctx.cb_count == 9);
	assert(col->region_count == 1);
	assert(col->regions[0].addr == 0xfc000);
	assert(col->regions[0].size == 0x9000);

	/* Add a region after the current region */
	region.addr = 0x200000;
	region.size = 0x1000;
	region.perms = MW_PERM_ALL;
	assert(col->regions[0].addr + col->regions[0].size < region.addr);
	ret = mw_region_collection_add(col, &region);
	assert(ret);
	assert(cb_ctx.cb_count == 10);
	assert(col->region_count == 2);
	assert(col->regions[0].addr == 0xfc000);
	assert(col->regions[0].size == 0x9000);
	assert(col->regions[1].addr == 0x200000);
	assert(col->regions[1].size == 0x1000);

	/* Add a region before the current regions */
	region.addr = 0x1000;
	region.size = 0x1000;
	region.perms = MW_PERM_ALL;
	assert(col->regions[0].addr > region.addr + region.size);
	ret = mw_region_collection_add(col, &region);
	assert(ret);
	assert(cb_ctx.cb_count == 11);
	assert(col->region_count == 3);
	assert(col->regions[0].addr == 0x1000);
	assert(col->regions[0].size == 0x1000);
	assert(col->regions[1].addr == 0xfc000);
	assert(col->regions[1].size == 0x9000);
	assert(col->regions[2].addr == 0x200000);
	assert(col->regions[2].size == 0x1000);

	/* Add a region between two existing regions */
	region.addr = 0x3000;
	region.size = 0x1000;
	region.perms = MW_PERM_ALL;
	assert(col->regions[0].addr + col->regions[0].size < region.addr);
	assert(col->regions[1].addr > region.addr + region.size);
	ret = mw_region_collection_add(col, &region);
	assert(ret);
	assert(cb_ctx.cb_count == 12);
	assert(col->region_count == 4);
	assert(col->regions[0].addr == 0x1000);
	assert(col->regions[0].size == 0x1000);
	assert(col->regions[1].addr == 0x3000);
	assert(col->regions[1].size == 0x1000);
	assert(col->regions[2].addr == 0xfc000);
	assert(col->regions[2].size == 0x9000);
	assert(col->regions[3].addr == 0x200000);
	assert(col->regions[3].size == 0x1000);

	/* Add a region that overlaps two other regions should merge them */
	region.addr = 0x2000;
	region.size = 0x1000;
	region.perms = MW_PERM_ALL;
	assert(col->regions[0].addr + col->regions[0].size == region.addr);
	assert(col->regions[1].addr == region.addr + region.size);
	ret = mw_region_collection_add(col, &region);
	assert(ret);
	assert(cb_ctx.cb_count == 13);
	assert(col->region_count == 3);
	assert(col->regions[0].addr == 0x1000);
	assert(col->regions[0].size == 0x3000);
	assert(col->regions[1].addr == 0xfc000);
	assert(col->regions[1].size == 0x9000);
	assert(col->regions[2].addr == 0x200000);
	assert(col->regions[2].size == 0x1000);

	/* Add a region partially overlapping two regions */
	region.addr = 0x2000;
	region.size = 0xfc000;
	region.perms = MW_PERM_ALL;
	assert(col->regions[0].addr < region.addr);
	assert(col->regions[0].addr + col->regions[0].size > region.addr);
	assert(col->regions[1].addr < region.addr + region.size);
	assert(col->regions[1].addr + col->regions[1].size >
	    region.addr + region.size);
	ret = mw_region_collection_add(col, &region);
	assert(ret);
	assert(cb_ctx.cb_count == 14);
	assert(col->region_count == 2);
	assert(col->regions[0].addr == 0x1000);
	assert(col->regions[0].size == 0x104000);
	assert(col->regions[1].addr == 0x200000);
	assert(col->regions[1].size == 0x1000);

	/* A region overlapping everything should create a single region */
	region.addr = 0x0;
	region.size = 0x300000;
	region.perms = MW_PERM_ALL;
	assert(col->regions[0].addr > region.addr);
	assert(col->regions[1].addr + col->regions[1].size <
	    region.addr + region.size);
	ret = mw_region_collection_add(col, &region);
	assert(ret);
	assert(cb_ctx.cb_count == 17);
	assert(col->region_count == 1);
	assert(col->regions[0].addr == 0x0);
	assert(col->regions[0].size == 0x300000);

	mw_region_collection_free(col);
}
