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

#include <sys/types.h>
#include <sys/stat.h>
#include <assert.h>
#include <limits.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct mw_context {
	char *buf;
	size_t len;
	FILE *fd;
};

struct mw_context *
mw_alloc_context(pid_t pid)
{
	char file[PATH_MAX];
	struct mw_context *ctx;

	ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL)
		return (NULL);

	snprintf(file, PATH_MAX, "/proc/%d/maps", pid);
	ctx->fd = fopen(file, "r");
	if (ctx->fd == NULL) {
		free(ctx);
		return (NULL);
	}

	/* Allocate the initial working buffer */
	ctx->len = 0;
	ctx->buf = NULL;

	return (ctx);
}

void
mw_free_context(struct mw_context *ctx)
{
	if (ctx == NULL)
		return;

	free(ctx->buf);
	fclose(ctx->fd);
	free(ctx);
}

bool
mw_next_range(struct mw_context *ctx, struct mw_region *region)
{
	char *ptr, *next;

	memset(region, 0, sizeof(*region));

	/* Read the line to be parsed */
	if (getline(&ctx->buf, &ctx->len, ctx->fd) < 0)
		return (false);

	/* Read the start address */
	ptr = ctx->buf;
	region->addr = strtoull(ptr, &next, 16);
	assert(*next = '-');

	/* Skip over the '-' */
	ptr = next + 1;

	/* Read the end address & subtract the start to get the size */
	region->size = strtoull(ptr, &next, 16);
	assert(*next = ' ');
	assert(region->size > region->addr);
	region->size -= region->addr;

	return (true);
}
