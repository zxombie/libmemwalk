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
#include <mw_os.h>

#include <sys/types.h>
#include <sys/mman.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

struct mw_subcontext {
	struct mw_region *region;
	size_t off;
	size_t len;
	mincore_vec vec[];
};

struct mw_subcontext *
mw_alloc_subcontext(struct mw_region *region)
{
	struct mw_subcontext *subctx;
	size_t page_count;
	int page_size;

	page_size = getpagesize();
	page_count = (region->size + page_size - 1) / page_size;
	subctx = calloc(1, sizeof(*subctx) + page_count);
	if (subctx == NULL)
		return (NULL);

	subctx->region = region;
	subctx->len = page_count;
	if (mincore((caddr_t)region->addr, region->size, subctx->vec) != 0) {
#ifdef __linux__
#if __WORDSIZE != 64
#error This will likely fail on non-64bit architectures
#endif
		/*
		 * The vsyscall memory is in the kernel range so
		 * mincore will fail with ENOMEM.
		 */
		if (errno == ENOMEM && region->addr >= (1ul << 63)) {
			memset(subctx->vec, 1, subctx->len);
			return (subctx);
		}
#endif
		free(subctx);
		return (NULL);
	}

	return (subctx);
}

bool
mw_next_subrange(struct mw_subcontext *subctx, struct mw_region *region)
{
	size_t off;
	int page_size;
	bool found;

	found = false;
	page_size = getpagesize();
	while (subctx->off < subctx->len) {
		off = subctx->off;
		subctx->off++;
		if (subctx->vec[off] != 0) {
			if (!found) {
				region->addr = subctx->region->addr +
				    off * page_size;
				region->size = page_size;
				found = true;
			} else {
				region->size += page_size;
			}
		} else if (found)
			break;
	}

	return (found);
}

void
mw_free_subcontext(struct mw_subcontext* subctx)
{

	if (subctx == NULL)
		return;

	free(subctx);
}
