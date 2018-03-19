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

#include <stdlib.h>

#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/task.h>

struct mw_context {
	mach_port_t task;
	vm_region_basic_info_data_64_t info;
	mach_vm_address_t addr;
	mach_vm_size_t size;
	bool first;
};

struct mw_context *
mw_alloc_context(pid_t pid)
{
	struct mw_context *ctx;

	ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL)
		return (NULL);

	task_for_pid(mach_task_self(), pid, &ctx->task);
	ctx->addr = 0;
	ctx->size = 1;
	ctx->first = true;

	return (ctx);
}

void
mw_free_context(struct mw_context *ctx)
{
	if (ctx == NULL)
		return;

	free(ctx);
}

bool
mw_next_range(struct mw_context *ctx, struct mw_region *region)
{
	vm_region_basic_info_data_64_t info;
	mach_msg_type_number_t info_cnt;
	mach_port_t object;
	mach_vm_address_t addr;
	mach_vm_size_t size;
	kern_return_t rc;
	bool found = false;

	while (!found) {
		addr = ctx->addr + ctx->size;
		info_cnt = VM_REGION_BASIC_INFO_COUNT_64;
		rc = mach_vm_region(ctx->task, &addr, &size,
		    VM_REGION_BASIC_INFO, (vm_region_info_t)&info, &info_cnt,
		    &object);
		if (rc != KERN_SUCCESS) {
			return (false);
		}
		if (ctx->first || addr != ctx->size + ctx->addr) {
			found = true;
		} else if (info.protection != ctx->info.protection ||
		    info.max_protection != ctx->info.max_protection ||
		    info.inheritance != ctx->info.inheritance ||
		    info.shared != ctx->info.shared ||
		    info.reserved != ctx->info.reserved) {
			found = true;
		}
		if (found) {
			region->addr = addr;
			region-> size = size;
			ctx->addr = addr;
			ctx->size = size;
			ctx->info = info;
			ctx->first = false;
		} else {
			ctx->size += size;
		}
	}

	return (true);
}
