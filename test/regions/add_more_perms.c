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

static struct mw_region_collection *
alloc_initial_col(void)
{
	struct mw_region region;
	struct mw_region_collection *col;
	bool ret;

	col = mw_region_collection_alloc();
	assert(col != NULL);
	assert(col->region_count == 0);

	memset(&region, 0, sizeof(region));
	region.addr = 0x100000;
	region.size = 0x1000;
	region.perms = MW_PERM_READ;
	ret = mw_region_collection_add(col, &region);
	assert(ret);

	return (col);
}

/*
 * Test adding a new region within the existing region is a nop
 *
 * Adding these together:
 *  +---+
 *  | R |
 *  +---+
 * +-----+
 * | RWX |
 * +-----+
 *
 * Should give:
 * +-----+
 * | RWX |
 * +-----+
 */
static void
test_more_perms_superset(void)
{
	struct mw_region region;
	struct mw_region_collection *col;
	bool ret;

	col = alloc_initial_col();
	assert(col != NULL);
	assert(col->region_count == 1);
	assert(col->regions[0].addr == 0x100000);
	assert(col->regions[0].size == 0x1000);
	assert(col->regions[0].perms == MW_PERM_READ);

	memset(&region, 0, sizeof(region));
	region.addr = 0xff000;
	region.size = 0x3000;
	region.perms = MW_PERM_ALL;
	assert(col->regions[0].addr > region.addr);
	assert(col->regions[0].addr + col->regions[0].size <
	    region.addr + region.size);
	ret = mw_region_collection_add(col, &region);
	assert(ret);
	assert(col->region_count == 1);
	assert(col->regions[0].addr == 0xff000);
	assert(col->regions[0].size == 0x3000);
	assert(col->regions[0].perms == MW_PERM_ALL);

	mw_region_collection_free(col);
}

/*
 * Test adding a new region overlapping the start of the existing regions works
 *
 * Adding these together:
 *      +----+
 *      |  R |
 *      +----+
 * +-----+
 * | RWX |
 * +-----+
 *
 * Should give:
 * +-----+---+
 * | RWX | R |
 * +-----+---+
 */
static void
test_more_perms_start(void)
{
	struct mw_region region;
	struct mw_region_collection *col;
	bool ret;

	col = alloc_initial_col();
	assert(col != NULL);
	assert(col->region_count == 1);
	assert(col->regions[0].addr == 0x100000);
	assert(col->regions[0].size == 0x1000);
	assert(col->regions[0].perms == MW_PERM_READ);

	memset(&region, 0, sizeof(region));
	region.addr = 0xff000;
	region.size = 0x1800;
	region.perms = MW_PERM_ALL;
	assert(col->regions[0].addr > region.addr);
	assert(col->regions[0].addr < region.addr + region.size);
	assert(col->regions[0].addr + col->regions[0].size >
	    region.addr + region.size);
	ret = mw_region_collection_add(col, &region);
	assert(ret);
	assert(col->region_count == 2);
	assert(col->regions[0].addr == 0xff000);
	assert(col->regions[0].size == 0x1800);
	assert(col->regions[0].perms == MW_PERM_ALL);
	assert(col->regions[1].addr == 0x100800);
	assert(col->regions[1].size == 0x800);
	assert(col->regions[1].perms == MW_PERM_READ);

	mw_region_collection_free(col);
}

/*
 * Test adding a new region overlapping the end of the existing regions works
 *
 * Adding these together:
 *  +-----+
 *  | R   |
 *  +-----+
 *      +-----+
 *      | RWX |
 *      +-----+
 *
 * Should give:
 *  +---+-----+
 *  | R | RWX |
 *  +---+-----+
 * Adding this:
 *  +---------+
 *  | RWX     |
 *  +---------+
 * Should result in this:
 *  +---------+
 *  | RWX     |
 *  +---------+
 */
static void
test_more_perms_end(void)
{
	struct mw_region region;
	struct mw_region_collection *col;
	bool ret;

	col = alloc_initial_col();
	assert(col != NULL);
	assert(col->region_count == 1);
	assert(col->regions[0].addr == 0x100000);
	assert(col->regions[0].size == 0x1000);
	assert(col->regions[0].perms == MW_PERM_READ);

	memset(&region, 0, sizeof(region));
	region.addr = 0x100800;
	region.size = 0x1800;
	region.perms = MW_PERM_ALL;
	assert(col->regions[0].addr < region.addr);
	assert(col->regions[0].addr + col->regions[0].size > region.addr);
	assert(col->regions[0].addr + col->regions[0].size <
	    region.addr + region.size);
	ret = mw_region_collection_add(col, &region);
	assert(ret);
	assert(col->region_count == 2);
	assert(col->regions[0].addr == 0x100000);
	assert(col->regions[0].size == 0x800);
	assert(col->regions[0].perms == MW_PERM_READ);
	assert(col->regions[1].addr == 0x100800);
	assert(col->regions[1].size == 0x1800);
	assert(col->regions[1].perms == MW_PERM_ALL);

	/* Test adding a region overlapping two regions is a nop */
	region.addr = 0x100000;
	region.size = 0x2000;
	region.perms = MW_PERM_ALL;
	assert(col->regions[0].addr == region.addr);
	assert(col->regions[1].addr + col->regions[1].size ==
	    region.addr + region.size);
	ret = mw_region_collection_add(col, &region);
	assert(ret);
	assert(col->region_count == 1);
	assert(col->regions[0].addr == 0x100000);
	assert(col->regions[0].size == 0x2000);
	assert(col->regions[0].perms == MW_PERM_ALL);

	mw_region_collection_free(col);
}

/*
 * Adding these together:
 * +---+     +---+
 * | R |     | R |
 * +---+     +---+
 * +-------------+
 * |     RWX     |
 * +-------------+
 *
 * Should give:
 * +-------------+
 * | RWX         |
 * +-------------+
 */
void
test_more_perms_gap(void)
{
	struct mw_region region;
	struct mw_region_collection *col;
	bool ret;

	col = alloc_initial_col();
	assert(col != NULL);
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
	assert(col->region_count == 2);
	assert(col->regions[0].addr == 0x100000);
	assert(col->regions[0].size == 0x1000);
	assert(col->regions[0].perms == MW_PERM_READ);
	assert(col->regions[1].addr == 0x102000);
	assert(col->regions[1].size == 0x1000);
	assert(col->regions[1].perms == MW_PERM_READ);

	region.addr = 0x100000;
	region.size = 0x3000;
	region.perms = MW_PERM_ALL;
	ret = mw_region_collection_add(col, &region);
	assert(ret);
	assert(col->region_count == 1);
	assert(col->regions[0].addr == 0x100000);
	assert(col->regions[0].size == 0x3000);
	assert(col->regions[0].perms == MW_PERM_ALL);

	mw_region_collection_free(col);
}

/*
 * Adding these together:
 * +----+   +----+
 * | R  |   |  R |
 * +----+   +----+
 *     +-----+
 *     | RWX |
 *     +-----+
 *
 * Should give:
 * +---+-----+---+
 * | R | RWX | R |
 * +---+-----+---+
 */
void
test_more_perms_gap2(void)
{
	struct mw_region region;
	struct mw_region_collection *col;
	bool ret;

	col = alloc_initial_col();
	assert(col != NULL);
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
	assert(col->region_count == 2);
	assert(col->regions[0].addr == 0x100000);
	assert(col->regions[0].size == 0x1000);
	assert(col->regions[0].perms == MW_PERM_READ);
	assert(col->regions[1].addr == 0x102000);
	assert(col->regions[1].size == 0x1000);
	assert(col->regions[1].perms == MW_PERM_READ);

	region.addr = 0x100800;
	region.size = 0x2000;
	region.perms = MW_PERM_ALL;
	assert(col->regions[0].addr < region.addr);
	assert(col->regions[0].addr + col->regions[0].size > region.addr);
	assert(col->regions[1].addr < region.addr + region.size);
	assert(col->regions[1].addr + col->regions[1].size >
	    region.addr + region.size);

	ret = mw_region_collection_add(col, &region);
	assert(ret);
	assert(col->region_count == 3);
	assert(col->regions[0].addr == 0x100000);
	assert(col->regions[0].size == 0x800);
	assert(col->regions[0].perms == MW_PERM_READ);
	assert(col->regions[1].addr == 0x100800);
	assert(col->regions[1].size == 0x2000);
	assert(col->regions[1].perms == MW_PERM_ALL);
	assert(col->regions[2].addr == 0x102800);
	assert(col->regions[2].size == 0x800);
	assert(col->regions[2].perms == MW_PERM_READ);

	mw_region_collection_free(col);
}

/*
 * Adding these together:
 * +---+     +---+
 * | R |     | R |
 * +---+     +---+
 *     +-----+
 *     | RWX |
 *     +-----+
 *
 * Should give:
 * +---+-----+---+
 * | R | RWX | R |
 * +---+-----+---+
 */
void
test_more_perms_gap3(void)
{
	struct mw_region region;
	struct mw_region_collection *col;
	bool ret;

	col = alloc_initial_col();
	assert(col != NULL);
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
	assert(col->region_count == 2);
	assert(col->regions[0].addr == 0x100000);
	assert(col->regions[0].size == 0x1000);
	assert(col->regions[0].perms == MW_PERM_READ);
	assert(col->regions[1].addr == 0x102000);
	assert(col->regions[1].size == 0x1000);
	assert(col->regions[1].perms == MW_PERM_READ);

	region.addr = 0x101000;
	region.size = 0x1000;
	region.perms = MW_PERM_ALL;
	assert(col->regions[0].addr + col->regions[0].size == region.addr);
	assert(col->regions[1].addr == region.addr + region.size);
	ret = mw_region_collection_add(col, &region);
	assert(ret);
	assert(col->region_count == 3);
	assert(col->regions[0].addr == 0x100000);
	assert(col->regions[0].size == 0x1000);
	assert(col->regions[0].perms == MW_PERM_READ);
	assert(col->regions[1].addr == 0x101000);
	assert(col->regions[1].size == 0x1000);
	assert(col->regions[1].perms == MW_PERM_ALL);
	assert(col->regions[2].addr == 0x102000);
	assert(col->regions[2].size == 0x1000);
	assert(col->regions[2].perms == MW_PERM_READ);

	mw_region_collection_free(col);
}

void
test_add_more_perms(void)
{

	test_more_perms_superset();
	test_more_perms_start();
	test_more_perms_end();
	test_more_perms_gap();
	test_more_perms_gap2();
	test_more_perms_gap3();
}