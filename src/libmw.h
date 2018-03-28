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

#ifndef _LIBMW_H_
#define _LIBMW_H_

#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

struct mw_context;
struct mw_subcontext;

#define	MW_PERM_READ	(1 << 0)
#define	MW_PERM_WRITE	(1 << 1)
#define	MW_PERM_EXECUTE	(1 << 2)

#define	MW_PERM_ALL	(MW_PERM_READ | MW_PERM_WRITE | MW_PERM_EXECUTE)

struct mw_region {
	uintptr_t	addr;
	size_t		size;
	uint64_t	perms;
	uint64_t	max_perms;
};

struct mw_context *mw_alloc_context(pid_t);
void mw_free_context(struct mw_context *);
bool mw_next_range(struct mw_context *, struct mw_region *);

struct mw_subcontext *mw_alloc_subcontext(struct mw_region *);
void mw_free_subcontext(struct mw_subcontext *);
bool mw_next_subrange(struct mw_subcontext *, struct mw_region *);

#endif
