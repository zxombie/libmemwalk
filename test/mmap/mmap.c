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

#include <sys/mman.h>

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <libmw.h>

#include "../tests.h"

static void
test(int idx)
{
	struct mw_context *ctx;
	struct mw_region region;
	int page_size;
	char *mem;

	page_size = getpagesize();
	mem = mmap(NULL, page_size, tests[idx].prot,
	    MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (mem == MAP_FAILED) {
		perror("mmap");
		exit(1);
	}

	ctx = mw_alloc_context(getpid());
	while (mw_next_range(ctx, &region)) {
		char prot[4], expected_prot[4];

		if (region.addr + region.size <= (uintptr_t)mem)
			continue;
		if (region.addr >= (uintptr_t)mem + page_size)
			continue;

		perm_string(prot, region.perms);
		perm_string(expected_prot, tests[idx].expected);
		printf("%lx - %lx: %s %s\n", region.addr,
		    region.addr + region.size, prot, expected_prot);
		assert(tests[idx].expected == region.perms);
	}
	mw_free_context(ctx);
	munmap(mem, page_size);
}

int
main(int argc, char *argv[])
{
	size_t i;

	(void)argc;
	(void)argv;

	for (i = 0; i < nitems(tests); i++)
		test(i);

	return (0);
}
