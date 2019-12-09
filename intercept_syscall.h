/*
 * Copyright (C) 2019 Diego Augusto Molina
 * Report bugs or suggest features to <diegoaugustomolina@gmail.com>
 *
 * This file is part of intercept_syscall.
 *
 * intercept_syscall is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 of the License.
 *
 * intercept_syscall is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with intercept_syscall.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

#ifndef _INTERCEPT_SYSCALL_H
#define _INTERCEPT_SYSCALL_H 1

#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <sys/syscall.h>

    /* Architecture-dependant:
     * In which registers are syscall arguments stored
     */
#if defined(CONFIG_X86_32) /* Check arch */
/* See linux/arch/x86/entry/entry_32.S */
#   define SYSC_RG_NR   ORIG_RAX    /* TODO: Is this accurate? */
#   define SYSC_RG_RET  RAX         /* TODO: Is this accurate? */
#   define SYSC_RG_ARG0 EBX
#   define SYSC_RG_ARG1 ECX
#   define SYSC_RG_ARG2 EDX
#   define SYSC_RG_ARG3 ESI
#   define SYSC_RG_ARG4 EDI
#   define SYSC_RG_ARG5 0(%ebp)

#elif defined(CONFIG_X86_64)
/* See linux/arch/x86/entry/entry_64.S */
#   define SYSC_RG_NR   ORIG_RAX
#   define SYSC_RG_RET  RAX
#   define SYSC_RG_ARG0 RDI
#   define SYSC_RG_ARG1 RSI
#   define SYSC_RG_ARG2 RDX
#   define SYSC_RG_ARG3 R10
#   define SYSC_RG_ARG4 R8
#   define SYSC_RG_ARG5 R9

#endif /* Check arch */

    /* Event types */
#define INTERCEPT_EVT_BEFORE 0;
#define INTERCEPT_EVT_AFTER 1;

struct intercept_t {
    int count;
    struct {
        int nr; /* Read <asm/unistd*.h> for more information */
        void (*handler)(struct intercept_t *_i, int idx, int evt, pid_t child);
    } syscall[];
};

    /* Run program passed on argv, intercepting all syscalls in intercept_t and
     * execute their corresponding handlers upon arrival
     */
int intercept(struct intercept_t *_i, int argc, char **argv);

    /* Copy into buf a string pointed by register reg in process child. Returns
     * the number of characters copied, including the null terminator.
     */
int child_get_str(pid_t child, char *buf, int reg);

    /* Internal functions */
static void process_signals(struct intercept_t *_i);
static void wait_for_syscall(struct intercept_t *_i, pid_t *child, int *idx);

#endif /* intercept_syscall.h */

/*                  LAST MODIFIED: 2019-12-08 13:41:37 -03                    */
