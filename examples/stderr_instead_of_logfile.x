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

    /* This will make our implementation more portable across architectures */
#include <sys/syscall.h>
    /* Just for the sake of this example */
#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include "intercept_syscall.h"

#define E_BAD_HANDLER(nr, evt, child) \
{ \
    fprintf(stderr, "[INTERCEPT] Bad syscall handler. Args: %d, %d, %d\n", \
        nr, evt, child); \
    return; \
}

    /* Example syscall handlers */
static void opens_handler(intercept_t *_i, int idx, int evt, pid_t child);
static void close_handler(intercept_t *_i, int idx, int evt, pid_t child);

int main(int argc, char **argv){
    struct intercept_t _i = {
        .count = 2, /* Remember to keep this counter updated */
        .syscall = {

            {
                .nr = __NR_open,
                .handler = &opens_handler
            },

            {
                .nr = __NR_openat,
                .handler = &opens_handler
            }/*,

            {
                .nr = __NR_close,
                .handler = &close_handler
            }*/

        }
    };

    if (argc < 2) return 127;

    return intercept(&_i, argc, argv);
}

static void opens_handler(intercept_t *_i, int idx, int evt, pid_t child){
    char *child_addr, *f, *p;
	long val;
    int reg, i, j;

    if (intercept.syscall[idx].nr == __NR_open)
        reg = SYSCALL_ARG0;
    else if (intercept.syscall[idx].nr == __NR_openat)
        reg = SYSCALL_ARG1;
    else
        E_BAD_HANDLER(idx, evt, child);

    if ( evt == INTERCEPT_EVT_AFTER ){
        if (0){
                /* We set the return value of the open* syscalls to "2", meaning
                 * stderr */
            ptrace(PTRACE_POKEUSER, child, sizeof(long)*SYSC_RG_RET, 2);
        }
        return;
    }

	if (!(f = malloc( sizeof(char)*PATH_MAX ))) return;

    child_addr = (char *) ptrace(PTRACE_PEEKUSER, child, sizeof(long) * reg, 0);

    for (i=0, j=sizeof(long); j==sizeof(long); i++, child_addr+=sizeof(long)) {
  
        val = ptrace(PTRACE_PEEKTEXT, child, child_addr, NULL);
        if (val == -1 && errno != 0) {
            fprintf(stderr, "[INTERCEPT] PTRACE_PEEKTEXT error: %d\n",
                strerror(errno));
            exit(1);
        }
  
        p = (char *) &val;
            /* Copy char by char while counting */
        for (j=0; j<sizeof(long); j++){
            *(f+sizeof(long)*i+j) = *(p+j);
            if ( *(p+j) == '\0' ) break;
        }
    }

    if ( strstr(f, ".log") ){
        //fprintf(stderr, "[INTERCEPT] Denied open(\"%s\"). Using stderr\n", f);
        //ptrace(PTRACE_POKEUSER, child, sizeof(long)*SYSC_RG_NR, -1);
        fprintf(stderr, "[INTERCEPT] Would deny open(\"%s\")\n", f);
    }
    free(f);
}

static void close_handler(intercept_t *_i, int idx, int evt, pid_t child){
    if (intercept.syscall[idx].nr != __NR_close)
        E_BAD_HANDLER(idx, evt, child);

    if ( evt == INTERCEPT_EVT_AFTER ){
        if (0){
                /* We set the return value of the open* syscall to "2", meaning
                 * stderr */
            ptrace(PTRACE_POKEUSER, child, sizeof(long)*SYSC_RG_RET, 2);
        }
        return;
    }
}

/*                  LAST MODIFIED: 2019-12-08 13:14:12 -03                    */
