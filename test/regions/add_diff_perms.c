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
#include <string.h>

#include <libmw.h>

#include "regions.h"

static int cb_count;

static void
add_diff_cb(void)
{

	cb_count++;
}

static struct mw_region_collection *
alloc_initial_col(void)
{
	struct mw_region region;
	struct mw_region_collection *col;
	bool ret;

	cb_count = 0;
	col = mw_region_collection_alloc(add_diff_cb);
	assert(col != NULL);
	assert(cb_count == 0);
	assert(col->region_count == 0);

	memset(&region, 0, sizeof(region));
	region.addr = 0x100000;
	region.size = 0x1000;
	region.perms = MW_PERM_READ;
	ret = mw_region_collection_add(col, &region);
	assert(ret);
	assert(cb_count == 1);

	return (col);
}

/*
 * Adding these together:
 * +----+
 * | R  |
 * +----+
 * +----+
 * | W  |
 * +----+
 *
 * Should give:
 * +----+
 * | RW |
 * +----+
 */
void
test_diff_perms_samearea(void)
{
	struct mw_region region;
	struct mw_region_collection *col;
	bool ret;

	col = alloc_initial_col();
	assert(col != NULL);
	assert(cb_count == 1);
	assert(col->region_count == 1);
	assert(col->regions[0].addr == 0x100000);
	assert(col->regions[0].size == 0x1000);
	assert(col->regions[0].perms == MW_PERM_READ);

	memset(&region, 0, sizeof(region));
	region.addr = 0x100000;
	region.size = 0x1000;
	region.perms = MW_PERM_WRITE;
	assert(col->regions[0].addr == region.addr);
	assert(col->regions[0].addr + col->regions[0].size ==
	    region.addr + region.size);
	ret = mw_region_collection_add(col, &region);
	assert(ret);
	assert(cb_count == 2);
	assert(col->region_count == 1);
	assert(col->regions[0].addr == 0x100000);
	assert(col->regions[0].size == 0x1000);
	assert(col->regions[0].perms == (MW_PERM_READ | MW_PERM_WRITE));

	mw_region_collection_free(col);
}

/*
 * Test adding a new non-overlapping region at the start of the
 * existing regions works
 *
 * Adding these together:
 *     +---+
 *     | R |
 *     +---+
 * +---+
 * | W |
 * +---+
 *
 * Should give:
 * +---+---+
 * | W | R |
 * +---+---+
 */
static void
test_diff_perms_start(void)
{
	struct mw_region region;
	struct mw_region_collection *col;
	bool ret;

	col = alloc_initial_col();
	assert(col != NULL);
	assert(cb_count == 1);
	assert(col->region_count == 1);
	assert(col->regions[0].addr == 0x100000);
	assert(col->regions[0].size == 0x1000);
	assert(col->regions[0].perms == MW_PERM_READ);

	memset(&region, 0, sizeof(region));
	region.addr = 0xff000;
	region.size = 0x1000;
	region.perms = MW_PERM_WRITE;
	assert(col->regions[0].addr > region.addr);
	assert(col->regions[0].addr + col->regions[0].size >=
	    region.addr + region.size);
	ret = mw_region_collection_add(col, &region);
	assert(ret);
	assert(cb_count == 2);
	assert(col->region_count == 2);
	assert(col->regions[0].addr == 0xff000);
	assert(col->regions[0].size == 0x1000);
	assert(col->regions[0].perms == MW_PERM_WRITE);
	assert(col->regions[1].addr == 0x100000);
	assert(col->regions[1].size == 0x1000);
	assert(col->regions[1].perms == MW_PERM_READ);

	mw_region_collection_free(col);
}

/*
 * Test adding a new region overlapping the start of the existing regions works
 *
 * Adding these together:
 *     +--------+
 *     | R      |
 *     +--------+
 * +--------+
 * | W      |
 * +--------+
 *
 * Should give:
 * +---+----+---+
 * | W | RW | R |
 * +---+----+---+
 */
static void
test_diff_perms_start2(void)
{
	struct mw_region region;
	struct mw_region_collection *col;
	bool ret;

	col = alloc_initial_col();
	assert(col != NULL);
	assert(cb_count == 1);
	assert(col->region_count == 1);
	assert(col->regions[0].addr == 0x100000);
	assert(col->regions[0].size == 0x1000);
	assert(col->regions[0].perms == MW_PERM_READ);

	memset(&region, 0, sizeof(region));
	region.addr = 0xff000;
	region.size = 0x1800;
	region.perms = MW_PERM_WRITE;
	assert(col->regions[0].addr > region.addr);
	assert(col->regions[0].addr + col->regions[0].size >=
	    region.addr + region.size);
	ret = mw_region_collection_add(col, &region);
	assert(ret);
	assert(cb_count == 3);
	assert(col->region_count == 3);
	assert(col->regions[0].addr == 0xff000);
	assert(col->regions[0].size == 0x1000);
	assert(col->regions[0].perms == MW_PERM_WRITE);
	assert(col->regions[1].addr == 0x100000);
	assert(col->regions[1].size == 0x800);
	assert(col->regions[1].perms == (MW_PERM_READ | MW_PERM_WRITE));
	assert(col->regions[2].addr == 0x100800);
	assert(col->regions[2].size == 0x800);
	assert(col->regions[2].perms == MW_PERM_READ);

	mw_region_collection_free(col);
}

/*
 * Test adding a new region overlapping the end of the existing regions works
 *
 * Adding these together:
 *     +--------+
 *     | R      |
 *     +--------+
 *         +--------+
 *         |      W |
 *         +--------+
 *
 * Should give:
 *     +---+----+---+
 *     | R | RW | W |
 *     +---+----+---+
 * Adding this is a nop:
 *      +-------+
 *      | R     |
 *      +-------+
 * Adding this:
 * +------------------+
 * | R                |
 * +------------------+
 * Should result in this:
 * +---+-----+----+---+
 * | R | RWX | RW | R |
 * +---+-----+----+---+
 */
static void
test_diff_perms_end(void)
{
	struct mw_region region;
	struct mw_region_collection *col;
	bool ret;

	col = alloc_initial_col();
	assert(col != NULL);
	assert(cb_count == 1);
	assert(col->region_count == 1);
	assert(col->regions[0].addr == 0x100000);
	assert(col->regions[0].size == 0x1000);
	assert(col->regions[0].perms == MW_PERM_READ);

	memset(&region, 0, sizeof(region));
	region.addr = 0x100800;
	region.size = 0x1800;
	region.perms = MW_PERM_WRITE;
	assert(col->regions[0].addr < region.addr);
	assert(col->regions[0].addr + col->regions[0].size > region.addr);
	assert(col->regions[0].addr + col->regions[0].size <
	    region.addr + region.size);
	ret = mw_region_collection_add(col, &region);
	assert(ret);
	assert(cb_count == 3);
	assert(col->region_count == 3);
	assert(col->regions[0].addr == 0x100000);
	assert(col->regions[0].size == 0x800);
	assert(col->regions[0].perms == MW_PERM_READ);
	assert(col->regions[1].addr == 0x100800);
	assert(col->regions[1].size == 0x800);
	assert(col->regions[1].perms == (MW_PERM_READ | MW_PERM_WRITE));
	assert(col->regions[2].addr == 0x101000);
	assert(col->regions[2].size == 0x1000);
	assert(col->regions[2].perms == MW_PERM_WRITE);

	/* Test adding a region overlapping two regions is a nop */
	region.addr = 0x100000;
	region.size = 0x1000;
	region.perms = MW_PERM_READ;
	assert(col->regions[0].addr == region.addr);
	assert(col->regions[1].addr + col->regions[1].size ==
	    region.addr + region.size);
	ret = mw_region_collection_add(col, &region);
	assert(ret);
	assert(cb_count == 3);
	assert(col->region_count == 3);
	assert(col->regions[0].addr == 0x100000);
	assert(col->regions[0].size == 0x800);
	assert(col->regions[0].perms == MW_PERM_READ);
	assert(col->regions[1].addr == 0x100800);
	assert(col->regions[1].size == 0x800);
	assert(col->regions[1].perms == (MW_PERM_READ | MW_PERM_WRITE));
	assert(col->regions[2].addr == 0x101000);
	assert(col->regions[2].size == 0x1000);
	assert(col->regions[2].perms == MW_PERM_WRITE);

	/* Also if it's slightly smaller */
	region.addr = 0x100100;
	region.size = 0xe00;
	region.perms = MW_PERM_READ;
	assert(col->regions[0].addr < region.addr);
	assert(col->regions[0].addr + col->regions[0].size > region.addr);
	assert(col->regions[1].addr < region.addr + region.size);
	assert(col->regions[1].addr + col->regions[1].size >
	    region.addr + region.size);
	ret = mw_region_collection_add(col, &region);
	assert(ret);
	assert(cb_count == 3);
	assert(col->region_count == 3);
	assert(col->regions[0].addr == 0x100000);
	assert(col->regions[0].size == 0x800);
	assert(col->regions[0].perms == MW_PERM_READ);
	assert(col->regions[1].addr == 0x100800);
	assert(col->regions[1].size == 0x800);
	assert(col->regions[1].perms == (MW_PERM_READ | MW_PERM_WRITE));
	assert(col->regions[2].addr == 0x101000);
	assert(col->regions[2].size == 0x1000);
	assert(col->regions[2].perms == MW_PERM_WRITE);

	mw_region_collection_free(col);
}

/*
 * Adding these together:
 * +----+   +----+
 * | R  |   | R  |
 * +----+   +----+
 * +-------------+
 * |      W      |
 * +-------------+
 *
 * Should give:
 * +----+---+----+
 * | RW | W | RW |
 * +----+---+----+
 */
void
test_diff_perms_gap(void)
{
	struct mw_region region;
	struct mw_region_collection *col;
	bool ret;

	col = alloc_initial_col();
	assert(col != NULL);
	assert(cb_count == 1);
	assert(col->region_count == 1);
	assert(col->regions[0].addr == 0x100000);
	assert(col->regions[0].size == 0x1000);
	assert(col->regions[0].perms == MW_PERM_READ);

	memset(&region, 0, sizeof(region));
	region.addr = 0x102000;
	region.size = 0x1000;
	region.perms = MW_PERM_READ;
	ret = mw_region_collection_add(col, &region);
	assert(ret);
	assert(cb_count == 2);
	assert(col->region_count == 2);
	assert(col->regions[0].addr == 0x100000);
	assert(col->regions[0].size == 0x1000);
	assert(col->regions[0].perms == MW_PERM_READ);
	assert(col->regions[1].addr == 0x102000);
	assert(col->regions[1].size == 0x1000);
	assert(col->regions[1].perms == MW_PERM_READ);

	region.addr = 0x100000;
	region.size = 0x3000;
	region.perms = MW_PERM_WRITE;
	ret = mw_region_collection_add(col, &region);
	assert(ret);
	assert(cb_count == 5);
	assert(col->region_count == 3);
	assert(col->regions[0].addr == 0x100000);
	assert(col->regions[0].size == 0x1000);
	assert(col->regions[0].perms == (MW_PERM_READ | MW_PERM_WRITE));
	assert(col->regions[1].addr == 0x101000);
	assert(col->regions[1].size == 0x1000);
	assert(col->regions[1].perms == MW_PERM_WRITE);
	assert(col->regions[2].addr == 0x102000);
	assert(col->regions[2].size == 0x1000);
	assert(col->regions[2].perms == (MW_PERM_READ | MW_PERM_WRITE));

	mw_region_collection_free(col);
}

/*
 * Adding these together:
 * +--------+   +--------+
 * | R      |   |      R |
 * +--------+   +--------+
 *     +-------------+
 *     |      W      |
 *     +-------------+
 *
 * Should give:
 * +---+----+---+----+---+
 * | R | RW | W | RW | R |
 * +---+----+---+----+---+
 */
void
test_diff_perms_gap2(void)
{
	struct mw_region region;
	struct mw_region_collection *col;
	bool ret;

	col = alloc_initial_col();
	assert(col != NULL);
	assert(cb_count == 1);
	assert(col->region_count == 1);
	assert(col->regions[0].addr == 0x100000);
	assert(col->regions[0].size == 0x1000);
	assert(col->regions[0].perms == MW_PERM_READ);

	memset(&region, 0, sizeof(region));
	region.addr = 0x102000;
	region.size = 0x1000;
	region.perms = MW_PERM_READ;
	ret = mw_region_collection_add(col, &region);
	assert(ret);
	assert(cb_count == 2);
	assert(col->region_count == 2);
	assert(col->regions[0].addr == 0x100000);
	assert(col->regions[0].size == 0x1000);
	assert(col->regions[0].perms == MW_PERM_READ);
	assert(col->regions[1].addr == 0x102000);
	assert(col->regions[1].size == 0x1000);
	assert(col->regions[1].perms == MW_PERM_READ);

	region.addr = 0x100800;
	region.size = 0x2000;
	region.perms = MW_PERM_WRITE;
	assert(col->regions[0].addr < region.addr);
	assert(col->regions[0].addr + col->regions[0].size > region.addr);
	assert(col->regions[1].addr < region.addr + region.size);
	assert(col->regions[1].addr + col->regions[1].size >
	    region.addr + region.size);
	ret = mw_region_collection_add(col, &region);
	assert(ret);
	assert(cb_count == 5);
	assert(col->region_count == 5);
	assert(col->regions[0].addr == 0x100000);
	assert(col->regions[0].size == 0x800);
	assert(col->regions[0].perms == MW_PERM_READ);
	assert(col->regions[1].addr == 0x100800);
	assert(col->regions[1].size == 0x800);
	assert(col->regions[1].perms == (MW_PERM_READ | MW_PERM_WRITE));
	assert(col->regions[2].addr == 0x101000);
	assert(col->regions[2].size == 0x1000);
	assert(col->regions[2].perms == MW_PERM_WRITE);
	assert(col->regions[3].addr == 0x102000);
	assert(col->regions[3].size == 0x800);
	assert(col->regions[3].perms == (MW_PERM_READ | MW_PERM_WRITE));
	assert(col->regions[4].addr == 0x102800);
	assert(col->regions[4].size == 0x800);
	assert(col->regions[4].perms == MW_PERM_READ);

	mw_region_collection_free(col);
}

/*
 * Adding these together:
 * +---+   +---+
 * | R |   | R |
 * +---+   +---+
 *     +---+
 *     | W |
 *     +---+
 *
 * Should give:
 * +---+---+---+
 * | R | W | R |
 * +---+---+---+
 */
void
test_diff_perms_gap3(void)
{
	struct mw_region region;
	struct mw_region_collection *col;
	bool ret;

	col = alloc_initial_col();
	assert(col != NULL);
	assert(cb_count == 1);
	assert(col->region_count == 1);
	assert(col->regions[0].addr == 0x100000);
	assert(col->regions[0].size == 0x1000);
	assert(col->regions[0].perms == MW_PERM_READ);

	memset(&region, 0, sizeof(region));
	region.addr = 0x102000;
	region.size = 0x1000;
	region.perms = MW_PERM_READ;
	ret = mw_region_collection_add(col, &region);
	assert(ret);
	assert(cb_count == 2);
	assert(col->region_count == 2);
	assert(col->regions[0].addr == 0x100000);
	assert(col->regions[0].size == 0x1000);
	assert(col->regions[0].perms == MW_PERM_READ);
	assert(col->regions[1].addr == 0x102000);
	assert(col->regions[1].size == 0x1000);
	assert(col->regions[1].perms == MW_PERM_READ);

	region.addr = 0x101000;
	region.size = 0x1000;
	region.perms = MW_PERM_WRITE;
	ret = mw_region_collection_add(col, &region);
	assert(ret);
	assert(cb_count == 3);
	assert(col->region_count == 3);
	assert(col->regions[0].addr == 0x100000);
	assert(col->regions[0].size == 0x1000);
	assert(col->regions[0].perms == MW_PERM_READ);
	assert(col->regions[1].addr == 0x101000);
	assert(col->regions[1].size == 0x1000);
	assert(col->regions[1].perms == MW_PERM_WRITE);
	assert(col->regions[2].addr == 0x102000);
	assert(col->regions[2].size == 0x1000);
	assert(col->regions[2].perms == MW_PERM_READ);

	mw_region_collection_free(col);
}

void
test_add_diff_perms(void)
{

	test_diff_perms_samearea();
	test_diff_perms_start();
	test_diff_perms_start2();
	test_diff_perms_end();
	test_diff_perms_gap();
	test_diff_perms_gap2();
	test_diff_perms_gap3();
}
