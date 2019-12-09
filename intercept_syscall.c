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

#define CONFIG_X86_64 1
#include "intercept_syscall.h"

int intercept(struct intercept_t *_i, int argc, char **argv) {
    pid_t pid;
    int status;

    if (argc < 2) return 127;

    if ((pid = fork()) == 0) {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        kill(getpid(), SIGSTOP);
        return execvp(argv[1], argv + 1);
    } else if (pid < 0){
        /* fork failed */
        return 127;
    }

    waitpid(pid, &status, 0);
    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD);
    process_signals(_i);

    return 0;
}

static void process_signals(struct intercept_t *_i) {   
    pid_t child;
    int idx, evt;

    while(1) {
        /* Wait for syscall's start */
        wait_for_syscall(_i, &child, &idx);

        if (child == -1){
            if (0) // TODO: If no more children left
                break;
            /* My child is dead :'( TODO: Do something about it! */
            continue;
        }

        evt = INTERCEPT_EVT_BEFORE; // TODO: or after? How to know?

        /* Do your magic here */
        if (_i->syscall[idx].handler)
            _i->syscall[idx].handler(_i, idx, evt, child);
    }
}

static void wait_for_syscall(struct intercept_t *_i, pid_t *child, int *idx) {
    int status;
    long ptrace_r;

    do {
        ptrace(PTRACE_SYSCALL, *child, 0, 0);
        *child = waitpid(-1, &status, __WALL);

        /* Is it any of our syscalls? */
        if (WIFSTOPPED(status) && WSTOPSIG(status) & 0x80) {
            ptrace_r =
                ptrace(PTRACE_PEEKUSER, *child, sizeof(long)*SYSC_RG_NR, 0);
            for (*idx=0; *idx<_i->count; *idx++)
                if (_i->syscall[*idx].nr == ptrace_r)
                    return;
        }

    } while (! WIFEXITED(status));

    *child = -1;
}

int child_get_str(pid_t child, char *buf, int reg){
    char *child_addr, *p;
	long val;
    int i, j;

    child_addr = (char *) ptrace(PTRACE_PEEKUSER, child, sizeof(long) * reg, 0);

    for (i=0, j=sizeof(long); j==sizeof(long); i++, child_addr+=sizeof(long)) {
  
        val = ptrace(PTRACE_PEEKTEXT, child, child_addr, NULL);
        if (val == -1 && errno != 0) return -1;
  
        p = (char *) &val;
            /* Copy char by char while counting */
        for (j=0; j<sizeof(long); j++){
            *(buf+sizeof(long)*i+j) = *(p+j);
            if ( *(p+j) == '\0' ) break;
        }
    }

    return sizeof(long)*i+j;
}

/*                  LAST MODIFIED: 2019-12-08 13:58:22 -03                    */
