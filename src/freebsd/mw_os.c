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

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <libprocstat.h>
#include <kvm.h>
#include <stdlib.h>
#include <string.h>

struct mw_context {
	struct procstat *prstat;
	struct kinfo_proc *proc;
	struct kinfo_vmentry *info;
	unsigned int count;
	unsigned int cur;
};

struct mw_context *
mw_alloc_context(pid_t pid)
{
	struct mw_context *ctx;
	unsigned int cnt;

	ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL)
		return (NULL);

	ctx->prstat = procstat_open_sysctl();
	if (ctx->prstat == NULL) {
		free(ctx);
		return (NULL);
	}

	ctx->proc = procstat_getprocs(ctx->prstat, KERN_PROC_PID, pid, &cnt);
	if (cnt == 0) {
		procstat_close(ctx->prstat);
		free(ctx);
		return (NULL);
	}

	ctx->info = procstat_getvmmap(ctx->prstat, ctx->proc, &ctx->count);
	if (ctx->info == NULL) {
		procstat_freeprocs(ctx->prstat, ctx->proc);
		procstat_close(ctx->prstat);
		free(ctx);
		return (NULL);
	}

	ctx->cur = 0;

	return (ctx);
}

void
mw_free_context(struct mw_context *ctx)
{
	if (ctx == NULL)
		return;

	procstat_freeprocs(ctx->prstat, ctx->proc);
	procstat_close(ctx->prstat);
	free(ctx);
}

static uint64_t
mw_freebsd_perms(vm_prot_t prot)
{
	uint64_t perms;

	perms = 0;
	if ((prot & KVME_PROT_READ) != 0)
		perms |= MW_PERM_READ;
	if ((prot & KVME_PROT_WRITE) != 0)
		perms |= MW_PERM_WRITE;
	if ((prot & KVME_PROT_EXEC) != 0)
		perms |= MW_PERM_EXECUTE;

	return (perms);
}

bool
mw_next_range(struct mw_context *ctx, struct mw_region *region)
{

	memset(region, 0, sizeof(*region));
	if (ctx->cur >= ctx->count)
		return (false);

	region->addr = ctx->info[ctx->cur].kve_start;
	region->size = ctx->info[ctx->cur].kve_end -
	    ctx->info[ctx->cur].kve_start;
	region->perms = mw_freebsd_perms(ctx->info[ctx->cur].kve_protection);
	region->max_perms = MW_PERM_ALL;

	ctx->cur++;

	return (true);
}
