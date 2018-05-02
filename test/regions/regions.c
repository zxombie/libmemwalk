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

#include <libmw.h>

#include "regions.h"

void
region_cb(int change, const struct mw_region *region,
    const struct mw_region *old, void *ctx)
{
	struct region_ctx *rctx = ctx;

	assert(region != NULL);
	assert(ctx != NULL);
	assert(rctx->cb_count < rctx->count);
	assert(region->addr == rctx->regions[rctx->cb_count].addr);
	assert(region->size == rctx->regions[rctx->cb_count].size);
	assert(region->perms == rctx->regions[rctx->cb_count].perms);
	assert(change == rctx->regions[rctx->cb_count].change);

	if (rctx->regions[rctx->cb_count].have_old) {
		assert(old != NULL);
		assert(old->addr == rctx->regions[rctx->cb_count].old_addr);
		assert(old->size == rctx->regions[rctx->cb_count].old_size);
		assert(old->perms == rctx->regions[rctx->cb_count].old_perms);
	} else {
		assert(old == NULL);
		assert(rctx->regions[rctx->cb_count].old_addr == 0);
		assert(rctx->regions[rctx->cb_count].old_size == 0);
		assert(rctx->regions[rctx->cb_count].old_perms == 0);
	}

	switch (change) {
	case MW_REGION_PERMS:
		assert(old != NULL);
		/* The new region should be no larger */
		assert(old->addr <= region->addr);
		assert(old->addr + old->size >= region->addr + region->size);
		assert(old->size >= region->size);
		assert(old->perms != region->perms);
		break;
	case MW_REGION_INSERT:
		assert(old == NULL);
		break;
	case MW_REGION_EXPAND:
		assert(old != NULL);
		/* The new region should be larger */
		assert(region->addr + region->size == old->addr ||
		    region->addr == old->addr + old->size);
		assert(old->perms == region->perms);
		break;
	default:
		/* We received an invalid change */
		assert(false);
	}

	rctx->cb_count++;
}

int
main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	test_add_same_perms();
	test_add_less_perms();
	test_add_more_perms();
	test_add_diff_perms();

	return (0);
}
