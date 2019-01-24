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

#include <err.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <libmw.h>

static void
perm_string(char *buf, uint64_t perms)
{
	buf[0] = buf[1] = buf[2]  = '-';
	buf[3] = '\0';
	if ((perms & MW_PERM_READ) == MW_PERM_READ)
		buf[0] = 'r';
	if ((perms & MW_PERM_WRITE) == MW_PERM_WRITE)
		buf[1] = 'w';
	if ((perms & MW_PERM_EXECUTE) == MW_PERM_EXECUTE)
		buf[2] = 'x';
}

int
main(int argc, char *argv[])
{
	struct mw_context *ctx;
	struct mw_region region;
	int fd1[2], fd2[2];
	pid_t pid;
	char buf = 'a';

	(void)argc;
	(void)argv;

	/* Create two pipes to communicate with the child */
	if (pipe(fd1) < 0)
		errx(1, "Unable to create first pipe");
	if (pipe(fd2) < 0)
		errx(1, "Unable to create second pipe");

	pid = fork();
	switch(pid) {
	case -1:
		errx(1, "Unable to fork");
		break;
	case 0:
		close (fd1[0]);
		close (fd2[1]);
		/* Signal to the parent we are ready */
		write(fd1[1], &buf, 1);
		/* Block waiting for the parent to complete */
		read(fd2[0], &buf, 1);
		break;
	default:
		close (fd1[1]);
		close (fd2[0]);
		read(fd1[0], &buf, 1);
		ctx = mw_alloc_context(pid);
		while (mw_next_range(ctx, &region)) {
			struct mw_subcontext *subctx;
			struct mw_region subregion;
			char perm[4], max_perm[4];

			perm_string(perm, region.perms);
			perm_string(max_perm, region.max_perms);
			printf("%16" PRIxPTR " - %16" PRIxPTR ": %s %s\n",
			    region.addr, region.addr + region.size, perm,
			    max_perm);

			subctx = mw_alloc_subcontext(&region);

			while (mw_next_subrange(subctx, &subregion)) {
				printf("\t%16" PRIxPTR " - %16" PRIxPTR "\n",
				    subregion.addr,
				    subregion.addr + subregion.size);
			}

			mw_free_subcontext(subctx);
		}
		mw_free_context(ctx);
		write(fd2[1], &buf, 1);
	}

	return (0);
}
