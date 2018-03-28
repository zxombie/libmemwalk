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

#define MEM_LEN		(8 * page_size)
#define	MAX_PROT	(PROT_READ | PROT_WRITE | PROT_EXEC)

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

static void
_protect(void *mem, int len, int prot, char *prot_str)
{
	char err_str[128];
	int errno_save, ret;

	assert(len > 0);
	printf("%p %p %s\n", mem, mem + len, prot_str);
	ret = mprotect(mem, len, prot);
	if (ret == -1) {
		errno_save = errno;
		snprintf(err_str, sizeof(err_str), "mprotect: %s", prot_str);
		errno = errno_save;
		perror(err_str);
		exit(1);
	}
}

#define mw_protect(mem, len, prot)	_protect(mem, len, prot, #prot)

int
main(int argc, char *argv[])
{
	struct mw_context *ctx;
	struct mw_region region;
	int page_size, ret;
	char *mem;

	page_size = getpagesize();
	mem = mmap(NULL, MEM_LEN, MAX_PROT, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (mem == MAP_FAILED) {
		perror("mmap");
		exit(1);
	}

	mw_protect(mem + (0 * page_size), page_size, PROT_NONE);
	mw_protect(mem + (1 * page_size), page_size, PROT_READ);
	mw_protect(mem + (2 * page_size), page_size, PROT_WRITE);
	mw_protect(mem + (3 * page_size), page_size, PROT_EXEC);
	mw_protect(mem + (4 * page_size), page_size, PROT_READ | PROT_WRITE);
	mw_protect(mem + (5 * page_size), page_size, PROT_READ | PROT_EXEC);
	mw_protect(mem + (6 * page_size), page_size, PROT_WRITE | PROT_EXEC);
	putchar('\n');

	ctx = mw_alloc_context(getpid());
	while (mw_next_range(ctx, &region)) {
		char prot[4];

		if (region.addr + region.size <= (uintptr_t)mem)
			continue;
		if (region.addr >= (uintptr_t)mem + MEM_LEN)
			continue;

		perm_string(prot, region.perms);
		printf("%lx - %lx: %s\n", region.addr,
		    region.addr + region.size, prot);
	}
	mw_free_context(ctx);

	munmap(mem, MEM_LEN);
	return (0);
}
