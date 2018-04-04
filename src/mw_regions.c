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

#include <libmw.h>

#include <assert.h>
#include <limits.h>
#include <stdlib.h>

#define max(a, b) (((a) > (b)) ? (a) : (b))
#define min(a, b) (((a) < (b)) ? (a) : (b))

struct mw_region_collection *
mw_region_collection_alloc(void)
{
	struct mw_region_collection *col;

	col = calloc(1, sizeof(*col));
	if (col == NULL)
		return (NULL);

	return (col);
}

static bool
mw_check_space(struct mw_region_collection *col, unsigned int number)
{
	struct mw_region *tmp;
	unsigned int alloc_count;

	assert(col->region_count <= col->alloc_count);
	if (col->region_count + number < col->alloc_count)
		return (true);

	assert(col->alloc_count < (UINT_MAX - 8));
	alloc_count = col->alloc_count + max(number, 8);
	tmp = realloc(col->regions, alloc_count * sizeof(struct mw_region));
	if (tmp == NULL)
		return (false);
	col->regions = tmp;
	col->alloc_count = alloc_count;
	assert(col->region_count + number < col->alloc_count);

	return (true);
}

/* Count how many regions a given region overlaps */
static unsigned int
mw_count_overlapping(struct mw_region_collection *col, unsigned int start,
    struct mw_region *region)
{
	uintptr_t end;
	unsigned int count;

	assert(start == 0 ||
	    col->regions[start - 1].addr + col->regions[start - 1].size <=
	    region->addr);

	end = region->addr + region->size;
	for (count = 0; start < col->region_count; start++) {
		/* This region ends before the next region begins */
		if (end <= col->regions[start].addr)
			break;
		count++;
	}

	return (count);
}

/*
 * Updates a region to remove up to size bytes from the start.
 * Return true when there is more space in the region.
 */
static bool
mw_consume_region(struct mw_region_collection *col, unsigned int pos,
    struct mw_region *region)
{
	uintptr_t end, reg_end;

	end = col->regions[pos].addr + col->regions[pos].size;
	reg_end = region->addr + region->size;

	if (region->addr < col->regions[pos].addr) {
		assert(reg_end < col->regions[pos].addr);
		region->addr += region->size;
		region->size = 0;
		return (false);
	}

	assert(region->addr >= col->regions[pos].addr);
	assert(region->addr <= end);

	if (reg_end <= end) {
		region->addr += region->size;
		region->size = 0;
		return (false);
	}


	region->size -= end - region->addr;
	region->addr = end;
	assert(region->size > 0);

	return (true);
}

static int
mw_add_region(struct mw_region_collection *col, unsigned int pos,
    struct mw_region *region)
{
	size_t size;
	unsigned int i;

	size = region->size;
	if (pos < col->region_count) {
		size_t max_size;

		max_size = col->regions[pos].addr - region->addr;
		if (max_size < size)
			size = max_size;
	}

	/*
	 * If this region has the same perms as the previous region, and they
	 * are contiguous merge them into a single region.
	 */
	if (pos != 0 && col->regions[pos - 1].perms == region->perms &&
	    col->regions[pos - 1].addr + col->regions[pos - 1].size ==
	    region->addr) {
		col->regions[pos - 1].size += size;
		if (!mw_consume_region(col, pos - 1, region))
			return (-1);
		return (0);
	}

	/* TODO: This should be a memmove */
	for (i = col->region_count; i != pos; i--) {
		col->regions[i] = col->regions[i - 1];
	}
	col->region_count++;
	col->regions[pos] = *region;
	col->regions[pos].size = size;

	if (!mw_consume_region(col, pos, region))
		return (-1);
	return (1);
}

static int
mw_region_extend(struct mw_region_collection *col, unsigned int pos,
    struct mw_region *region)
{
	size_t size;

	assert(region->addr == col->regions[pos].addr + col->regions[pos].size);

	size = region->size;
	if (pos < col->region_count - 1) {
		size_t max_size;

		max_size = col->regions[pos + 1].addr - region->addr;
		if (max_size < size)
			size = max_size;
	}

	col->regions[pos].size += size;
	if (!mw_consume_region(col, pos, region))
		return (-1);
	return (1);
}

/* XXX: Use mw_region_merge_trailing? */
static bool
mw_merge_regions(struct mw_region_collection *col, unsigned int pos,
    struct mw_region *region, bool *merged)
{
	uintptr_t end, new_end;
	unsigned int i;

	*merged = false;
	/* If this is the last position don't merge */
	if (pos >= col->region_count - 1)
		return (true);

	if (col->regions[pos].perms != col->regions[pos + 1].perms)
		return (true);

	end = col->regions[pos].addr + col->regions[pos].size;
	if (end < col->regions[pos + 1].addr)
		return (true);

	assert(col->region_count > 1);
	new_end = col->regions[pos + 1].addr + col->regions[pos + 1].size;
	assert(new_end > end);
	col->regions[pos].size += new_end - end;
	assert(col->regions[pos].addr + col->regions[pos].size == new_end);
	for (i = pos + 1; i < col->region_count - 1; i++)
		col->regions[i] = col->regions[i + 1];
	col->region_count--;
	*merged = true;

	return (mw_consume_region(col, pos, region));
}

typedef enum {
	PERM_SAME,	/* The permissions are the same */
	PERM_SUB,	/* The new permissions are a subset of the current */
	PERM_SUPER,	/* The new permissions are a superset of the current */
	PERM_DIFF,	/* The permissions don't overlap */
} perm_change_t;

static perm_change_t
mw_perm_change(uint64_t cur, uint64_t new)
{
	uint64_t total_perms;

	if (cur == new)
		return (PERM_SAME);

	total_perms = cur | new;
	if (cur == total_perms)
		return (PERM_SUB);
	if (new == total_perms)
		return (PERM_SUPER);
	return (PERM_DIFF);
}

/*
 * Insert a region at pos, updating the other regions as needed.
 * Return true if there is more space at the end of the new region that
 * could be added to the next existing region.
 */
static int
mw_insert_region(struct mw_region_collection *col, unsigned int pos,
    struct mw_region *region)
{
	unsigned int i;

	assert(col->region_count < col->alloc_count);
	assert(region->size > 0);

	/*
	 * This region doesn't overlap the next region if there are no
	 * more regions or the end is before the next region starts.
	 */
	if (pos == col->region_count) {
		assert(region->addr ==
		    col->regions[pos - 1].addr + col->regions[pos - 1].size);
		return (mw_add_region(col, pos, region));
	}
	if (region->addr + region->size < col->regions[pos].addr) {
		return (mw_add_region(col, pos, region));
	}

	assert(pos < col->region_count);
	assert(region->addr <= col->regions[pos].addr + col->regions[pos].size);
	assert(region->addr + region->size >= col->regions[pos].addr);

	/*
	 * There must be some amount of overlap with the existing region.
	 */

	switch(mw_perm_change(col->regions[pos].perms, region->perms)) {
	case PERM_SAME:
		if (region->addr < col->regions[pos].addr) {
			/* The region starts before the current region */
			assert(region->addr + region->size >=
			    col->regions[pos].addr);
			col->regions[pos].size +=
			    col->regions[pos].addr - region->addr;
			col->regions[pos].addr = region->addr;

			if (!mw_consume_region(col, pos, region))
				return (-1);
			return (0);
		} else if (region->addr <
		    col->regions[pos].addr + col->regions[pos].size) {
			if (!mw_consume_region(col, pos, region))
				return (-1);
			return (0);
		}
		return (mw_region_extend(col, pos, region));
	case PERM_SUB:
		if (region->addr < col->regions[pos].addr) {
			/* The region starts before the current region */
			assert(region->addr + region->size >=
			    col->regions[pos].addr);
			return (mw_add_region(col, pos, region));
		} else if (region->addr <
		    col->regions[pos].addr + col->regions[pos].size) {
			if (!mw_consume_region(col, pos, region))
				return (-1);
			return (1);
		}
		return (mw_add_region(col, pos + 1, region));
	case PERM_SUPER:
	case PERM_DIFF:
		if (region->addr < col->regions[pos].addr) {
			/* The region starts before the current region */
			assert(region->addr + region->size >=
			    col->regions[pos].addr);
			return (mw_add_region(col, pos, region));
		} else if (region->addr == col->regions[pos].addr &&
		    region->size >= col->regions[pos].size) {
			bool merged = false;

			col->regions[pos].perms |= region->perms;
			if (pos > 0) {
				if (!mw_merge_regions(col, pos - 1, region,
				    &merged))
					return (-1);
			}
			if (!merged) {
				if (!mw_consume_region(col, pos, region))
					return (-1);
			}
			return (merged ? 0 : 1);
		} else if (region->addr == col->regions[pos].addr) {
			/* Split into 2 regions */
			bool merged;

			assert(region->size < col->regions[pos].size);
			assert(region->addr + region->size <
			    col->regions[pos].addr + col->regions[pos].size);

			/* TODO: This should be a memmove */
			for (i = col->region_count; i != pos; i--) {
				col->regions[i] = col->regions[i - 1];
			}
			col->region_count++;

			col->regions[pos] = *region;
			col->regions[pos].perms =
			    region->perms | col->regions[pos + 1].perms;
			col->regions[pos + 1].addr += region->size;
			col->regions[pos + 1].size -= region->size;

			if (pos > 0) {
				if (!mw_merge_regions(col, pos - 1, region,
				    &merged))
					return (-1);
			}
			if (!mw_consume_region(col, pos, region))
				return (-1);
			assert(0);
		} else if (region->addr <
		    col->regions[pos].addr + col->regions[pos].size) {
			/* Split into 2 regions */
			assert(region->addr > col->regions[pos].addr);

			/* TODO: This should be a memmove */
			for (i = col->region_count; i != pos; i--) {
				col->regions[i] = col->regions[i - 1];
			}
			col->region_count++;

			col->regions[i].size =
			    region->addr - col->regions[pos].addr;
			col->regions[i + 1].size -= col->regions[i].size;
			col->regions[i + 1].addr += col->regions[i].size;
			col->regions[i + 1].perms |= region->perms;
			if (!mw_consume_region(col, pos + 1, region))
				return (-1);
			return (2);
		}
		assert(region->addr ==
		    col->regions[pos].addr + col->regions[pos].size);

		/* TODO: This should be a memmove */
		for (i = col->region_count; i != pos + 1; i--) {
			col->regions[i] = col->regions[i - 1];
		}
		col->region_count++;

		col->regions[pos + 1] = *region;
		if (pos < col->region_count - 2) {
			size_t max_size;

			max_size = col->regions[pos + 2].addr - region->addr;
			if (max_size < region->size)
				col->regions[pos + 1].size = max_size;
		}
		if (!mw_consume_region(col, pos + 1, region))
			return (-1);
		return (1);
	}
	assert(0);
}

static bool
mw_insert(struct mw_region_collection *col, unsigned int pos,
    struct mw_region *region)
{
	unsigned int overlaps;
	struct mw_region r;
	int inc;
	bool merged;

	assert(pos < col->region_count);
	assert(pos == 0 || region->addr >=
	    col->regions[pos - 1].addr + col->regions[pos - 1].size);
	assert(region->addr <= col->regions[pos].addr + col->regions[pos].size);

	overlaps = mw_count_overlapping(col, pos, region);

	/* Is the new region starts before current region */
	if (region->addr < col->regions[pos].addr) {
		overlaps++;
	} else {
		assert(region->addr <=
		    col->regions[pos].addr + col->regions[pos].size);
	}

	if (!mw_check_space(col, overlaps))
		return (false);

	r = *region;
	while ((inc = mw_insert_region(col, pos, &r)) != -1) {
		if (!mw_merge_regions(col, pos, &r, &merged))
			break;
		if (!merged)
			pos += inc;
	}
	mw_merge_regions(col, pos, &r, &merged);
	assert(r.size == 0);

	return (true);
}

bool
mw_region_collection_add(struct mw_region_collection *col,
    struct mw_region *region)
{
	unsigned int i;

	(void)col;

	if (region == NULL)
		return (true);

	assert(col->region_count <= col->alloc_count);

	for (i = 0; i < col->region_count; i++) {
		if (region->addr <= col->regions[i].addr + col->regions[i].size)
			return (mw_insert(col, i, region));
	}

	if (!mw_check_space(col, 1))
		return (false);
	col->regions[i] = *region;
	col->region_count++;
	return (true);
}

void
mw_region_collection_free(struct mw_region_collection *col)
{

	if (col == NULL)
		return;

	free(col->regions);
	free(col);
}
