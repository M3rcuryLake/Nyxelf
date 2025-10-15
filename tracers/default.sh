bpftrace -c "$1" -e '
tracepoint:syscalls:sys_enter_execve /pid == cpid/
{
    printf("[+] [EXECVE]\t PID %d (%s) is executing a new program: %s\n",
           pid, comm, str(args->filename));
}

tracepoint:syscalls:sys_enter_clone /pid == cpid/
{
    printf("[+] [CLONE]\t PID %d (%s) is cloning to create a new process.\n",
           pid, comm);
}

tracepoint:syscalls:sys_enter_fork /pid == cpid/
{
    printf("[+] [FORK]\t PID %d (%s) is forking a new child process.\n",
           pid, comm);
}

tracepoint:syscalls:sys_enter_vfork /pid == cpid/
{
    printf("[+] [VFORK]\t PID %d (%s) is creating a vforked child.\n",
           pid, comm);
}

tracepoint:syscalls:sys_enter_open /pid == cpid/
{
    printf("[+] [OPEN]\t PID %d (%s) is opening a file (legacy open).\n",
           pid, comm);
}

tracepoint:syscalls:sys_enter_openat /pid == cpid/
{
    printf("[+] [OPENAT]\t PID %d (%s) is opening file: %s\n",
           pid, comm, str(args->filename));
}

tracepoint:syscalls:sys_enter_read /pid == cpid/
{
    printf("[+] [READ]\t PID %d (%s) is reading %d bytes from fd %d.\n",
           pid, comm, args->count, args->fd);
}

tracepoint:syscalls:sys_enter_write /pid == cpid/
{
    printf("[+] [WRITE]\t PID %d (%s) is writing %d bytes to fd %d.\n",
           pid, comm, args->count, args->fd);
}

tracepoint:syscalls:sys_enter_close /pid == cpid/
{
    printf("[+] [CLOSE]\t PID %d (%s) closed file descriptor %d.\n",
           pid, comm, args->fd);
}

tracepoint:syscalls:sys_enter_unlink /pid == cpid/
{
    printf("[+] [UNLINK]\t PID %d (%s) is unlinking a file (legacy unlink).\n",
           pid, comm);
}

tracepoint:syscalls:sys_enter_unlinkat /pid == cpid/
{
    printf("[+] [UNLINKAT]\t PID %d (%s) is deleting file: %s\n",
           pid, comm, str(args->pathname));
}

tracepoint:syscalls:sys_enter_mkdir /pid == cpid/
{
    printf("[+] [MKDIR]\t PID %d (%s) is creating a new directory (legacy mkdir).\n",
           pid, comm);
}

tracepoint:syscalls:sys_enter_mkdirat /pid == cpid/
{
    printf("[+] [MKDIRAT]\t PID %d (%s) is creating directory: %s\n",
           pid, comm, str(args->pathname));
}

tracepoint:syscalls:sys_enter_rmdir /pid == cpid/
{
    printf("[+] [RMDIR]\t PID %d (%s) is removing directory: %s\n",
           pid, comm, str(args->pathname));
}

tracepoint:syscalls:sys_enter_socket /pid == cpid/
{
    printf("[+] [SOCKET]\t PID %d (%s) created a socket (domain=%d, type=%d).\n",
           pid, comm, args->family, args->type);
}

tracepoint:syscalls:sys_enter_connect /pid == cpid/
{
    printf("[+] [CONNECT]\t PID %d (%s) is connecting socket fd %d.\n",
           pid, comm, args->fd);
}

tracepoint:syscalls:sys_enter_bind /pid == cpid/
{
    printf("[+] [BIND]\t PID %d (%s) is binding socket fd %d.\n",
           pid, comm, args->fd);
}

tracepoint:syscalls:sys_enter_listen /pid == cpid/
{
    printf("[+] [LISTEN]\t PID %d (%s) is listening on socket fd %d.\n",
           pid, comm, args->fd);
}

tracepoint:syscalls:sys_enter_accept /pid == cpid/
{
    printf("[+] [ACCEPT]\t PID %d (%s) is waiting to accept a connection.\n",
           pid, comm);
}

tracepoint:syscalls:sys_enter_accept4 /pid == cpid/
{
    printf("[+] [ACCEPT4]\t PID %d (%s) accepted a connection on fd %d.\n",
           pid, comm, args->fd);
}

tracepoint:syscalls:sys_enter_mmap /pid == cpid/
{
    printf("[+] [MMAP]\t PID %d (%s) is mapping %d bytes of memory.\n",
           pid, comm, args->len);
}

tracepoint:syscalls:sys_enter_kill /pid == cpid/
{
    printf("[+] [KILL]\t PID %d (%s) is sending a signal to PID %d.\n",
           pid, comm, args->pid);
}

tracepoint:syscalls:sys_enter_setuid /pid == cpid/
{
    printf("[+] [SETUID]\t PID %d (%s) changed its UID to %d.\n",
           pid, comm, args->uid);
}

tracepoint:syscalls:sys_enter_ptrace /pid == cpid/
{
    printf("[+] [PTRACE]\t PID %d (%s) invoked ptrace (request=%d).\n",
           pid, comm, args->request);
}

tracepoint:sched:sched_process_fork /pid == cpid/
{
    printf("[+] [FORK]\t PID %d (%s)  forked a new child process with PID %d.\n", pid, comm, args->child_pid);
}

tracepoint:sched:sched_process_exit /pid == cpid/
{
    printf("[+] [EXIT]\t PID %d (%s) exited. Stopping trace.\n", pid, comm);
    exit();
}


/* --- sys_enter probes --- */

/* --- Filesystem / Metadata Probes --- */

/* Cache statistics for a file descriptor */
tracepoint:syscalls:sys_enter_cachestat /pid == cpid/
{
    printf("[+] [CACHESTAT]\t PID %d (%s) is querying cache stats for fd=%u (flags=0x%x)\n",
           pid, comm, args->fd, args->flags);
}

/* Filesystem stats by fd */
tracepoint:syscalls:sys_enter_fstatfs /pid == cpid/
{
    printf("[+] [FSTATFS]\t PID %d (%s) requested filesystem info for fd=%u\n",
           pid, comm, args->fd);
}

/* File status by fd */
tracepoint:syscalls:sys_enter_newfstat /pid == cpid/
{
    printf("[+] [NEWFSTAT]\t PID %d (%s) requested file status for fd=%u\n",
           pid, comm, args->fd);
}

/* File status by path relative to directory fd */
tracepoint:syscalls:sys_enter_newfstatat /pid == cpid/
{
    printf("[+] [NEWFSTATAT]\t PID %d (%s) requested file status for '%s' (dirfd=%d, flags=0x%x)\n",
           pid, comm, str(args->filename), args->dfd, args->flag);
}

/* Symbolic link file status */
tracepoint:syscalls:sys_enter_newlstat /pid == cpid/
{
    printf("[+] [NEWLSTAT]\t PID %d (%s) requested link status for '%s'\n",
           pid, comm, str(args->filename));
}

/* Basic file status by path */
tracepoint:syscalls:sys_enter_newstat /pid == cpid/
{
    printf("[+] [NEWSTAT]\t PID %d (%s) requested file status for '%s'\n",
           pid, comm, str(args->filename));
}

/* Filesystem stats by path */
tracepoint:syscalls:sys_enter_statfs /pid == cpid/
{
    printf("[+] [STATFS]\t PID %d (%s) requested filesystem info for path '%s'\n",
           pid, comm, str(args->pathname));
}

/* Mounted filesystem stats */
tracepoint:syscalls:sys_enter_statmount /pid == cpid/
{
    printf("[+] [STATMOUNT]\t PID %d (%s) queried mount info (buffer size=%zu, flags=0x%x)\n",
           pid, comm, args->bufsize, args->flags);
}

/* Extended file status (statx) */
tracepoint:syscalls:sys_enter_statx /pid == cpid/
{
    printf("[+] [STATX]\t PID %d (%s) requested extended status for '%s' (dirfd=%d, flags=0x%x, mask=0x%x)\n",
           pid, comm, str(args->filename), args->dfd, args->flags, args->mask);
}

/* Legacy filesystem status (ustat) */
tracepoint:syscalls:sys_enter_ustat /pid == cpid/
{
    printf("[+] [USTAT]\t PID %d (%s) requested status for device %u\n",
           pid, comm, args->dev);
}


/* --- sys_exit probes --- */

tracepoint:syscalls:sys_exit_cachestat /pid == cpid/
{
    printf("[+] [CACHESTAT]\t PID %d (%s) returned: %ld\n",
           pid, comm, args->ret);
}

tracepoint:syscalls:sys_exit_fstatfs /pid == cpid/
{
    printf("[+] [FSTATFS]\t PID %d (%s) returned: %ld\n",
           pid, comm, args->ret);
}

tracepoint:syscalls:sys_exit_newfstat /pid == cpid/
{
    printf("[+] [NEWFSTAT]\t PID %d (%s) returned: %ld\n",
           pid, comm, args->ret);
}

tracepoint:syscalls:sys_exit_newfstatat /pid == cpid/
{
    printf("[+] [NEWFSTATAT]\t PID %d (%s) returned: %ld\n",
           pid, comm, args->ret);
}

tracepoint:syscalls:sys_exit_newlstat /pid == cpid/
{
    printf("[+] [NEWLSTAT]\t PID %d (%s) returned: %ld\n",
           pid, comm, args->ret);
}

tracepoint:syscalls:sys_exit_newstat /pid == cpid/
{
    printf("[+] [NEWSTAT]\t PID %d (%s) returned: %ld\n",
           pid, comm, args->ret);
}

tracepoint:syscalls:sys_exit_statfs /pid == cpid/
{
    printf("[+] [STATFS]\t PID %d (%s) returned: %ld\n",
           pid, comm, args->ret);
}

tracepoint:syscalls:sys_exit_statmount /pid == cpid/
{
    printf("[+] [STATMOUNT]\t PID %d (%s) returned: %ld\n",
           pid, comm, args->ret);
}

tracepoint:syscalls:sys_exit_statx /pid == cpid/
{
    printf("[+] [STATX]\t PID %d (%s) returned: %ld\n",
           pid, comm, args->ret);
}

tracepoint:syscalls:sys_exit_ustat /pid == cpid/
{
    printf("[+] [USTAT]\t PID %d (%s) returned: %ld\n",
           pid, comm, args->ret);
}


tracepoint:syscalls:sys_enter_set_tid_address /pid == cpid/
{
    printf("[+] [SET_TID_ADDRESS]\t PID %d (%s) set_tid_address: 0x%lx\n",
           pid, comm, args->tidptr);
}

/* --- Process control --- */

/* wait4 */
tracepoint:syscalls:sys_enter_wait4 /pid == cpid/
{
    printf("[+] [WAIT4]\t PID %d (%s) called wait4 on child PID %d, options=%d\n",
           pid, comm, args->upid, args->options);
}

tracepoint:syscalls:sys_exit_wait4 /pid == cpid/
{
    printf("[+] [WAIT4]\t PID %d (%s) wait4 returned: %ld\n",
           pid, comm, args->ret);
}

/* --- File IO --- */

/* pread64 */
tracepoint:syscalls:sys_enter_pread64 /pid == cpid/
{
    printf("[+] [PREAD64]\t PID %d (%s) reading fd=%u count=%lu offset=%lld\n",
           pid, comm, args->fd, args->count, args->pos);
}

tracepoint:syscalls:sys_exit_pread64 /pid == cpid/
{
    printf("[+] [PREAD64]\t PID %d (%s) read returned %ld bytes\n",
           pid, comm, args->ret);
}

/* pwrite64 */
tracepoint:syscalls:sys_enter_pwrite64 /pid == cpid/
{
    printf("[+] [PWRITE64]\t PID %d (%s) writing fd=%u count=%lu offset=%lld\n",
           pid, comm, args->fd, args->count, args->pos);
}

tracepoint:syscalls:sys_exit_pwrite64 /pid == cpid/
{
    printf("[+] [PWRITE64]\t PID %d (%s) write returned %ld bytes\n",
           pid, comm, args->ret);
}

/* rename */
tracepoint:syscalls:sys_enter_rename /pid == cpid/
{
    printf("[+] [RENAME]\t PID %d (%s) renaming '%s' -> '%s'\n",
           pid, comm, str(args->oldname), str(args->newname));
}

tracepoint:syscalls:sys_exit_rename /pid == cpid/
{
    printf("[+] [RENAME]\t PID %d (%s) rename returned %ld\n",
           pid, comm, args->ret);
}

/* renameat */
tracepoint:syscalls:sys_enter_renameat /pid == cpid/
{
    printf("[+] [RENAMEAT]\t PID %d (%s) renaming dfd_old=%d '%s' -> dfd_new=%d '%s'\n",
           pid, comm, args->olddfd, str(args->oldname), args->newdfd, str(args->newname));
}

tracepoint:syscalls:sys_exit_renameat /pid == cpid/
{
    printf("[+] [RENAMEAT]\t PID %d (%s) renameat returned %ld\n",
           pid, comm, args->ret);
}

/* --- Memory management --- */

/* brk */
tracepoint:syscalls:sys_enter_brk /pid == cpid/
{
    printf("[+] [BRK]\t PID %d (%s) requested new brk at 0x%lx\n",
           pid, comm, args->brk);
}

tracepoint:syscalls:sys_exit_brk /pid == cpid/
{
    printf("[+] [BRK]\t PID %d (%s) brk returned 0x%lx\n",
           pid, comm, args->ret);
}

/* mprotect */
tracepoint:syscalls:sys_enter_mprotect /pid == cpid/
{
    printf("[+] [MPROTECT]\t PID %d (%s) changing memory at 0x%lx, len=%lu, prot=%lu\n",
           pid, comm, args->start, args->len, args->prot);
}

tracepoint:syscalls:sys_exit_mprotect /pid == cpid/
{
    printf("[+] [MPROTECT]\t PID %d (%s) mprotect returned %ld\n",
           pid, comm, args->ret);
}

/* --- Signals --- */

/* kill */
tracepoint:syscalls:sys_enter_kill /pid == cpid/
{
    printf("[+] [KILL]\t PID %d (%s) sending signal %d to PID %d\n",
           pid, comm, args->sig, args->pid);
}

tracepoint:syscalls:sys_exit_kill /pid == cpid/
{
    printf("[+] [KILL]\t PID %d (%s) kill returned %ld\n",
           pid, comm, args->ret);
}

/* tkill */
tracepoint:syscalls:sys_enter_tkill /pid == cpid/
{
    printf("[+] [TKILL]\t PID %d (%s) sending signal %d to PID %d\n",
           pid, comm, args->sig, args->pid);
}

tracepoint:syscalls:sys_exit_tkill /pid == cpid/
{
    printf("[+] [TKILL]\t PID %d (%s) tkill returned %ld\n",
           pid, comm, args->ret);
}

/* tgkill */
tracepoint:syscalls:sys_enter_tgkill /pid == cpid/
{
    printf("[+] [TGKILL]\t PID %d (%s) sending signal %d to TGID %d, PID %d\n",
           pid, comm, args->sig, args->tgid, args->pid);
}

tracepoint:syscalls:sys_exit_tgkill /pid == cpid/
{
    printf("[+] [TGKILL]\t PID %d (%s) tgkill returned %ld\n",
           pid, comm, args->ret);
}

/* --- Process attributes --- */

/* prctl */
tracepoint:syscalls:sys_enter_prctl /pid == cpid/
{
    printf("[+] [PRCTL]\t PID %d (%s) option=%d args=[%lu, %lu, %lu, %lu]\n",
           pid, comm, args->option, args->arg2, args->arg3, args->arg4, args->arg5);
}

tracepoint:syscalls:sys_exit_prctl /pid == cpid/
{
    printf("[+] [PRCTL]\t PID %d (%s) prctl returned %ld\n",
           pid, comm, args->ret);
}

/* --- Time functions --- */

/* gettimeofday */
tracepoint:syscalls:sys_enter_gettimeofday /pid == cpid/
{
    printf("[+] [GETTIMEOFDAY]\t PID %d (%s) requested current time\n", pid, comm);
}

tracepoint:syscalls:sys_exit_gettimeofday /pid == cpid/
{
    printf("[+] [GETTIMEOFDAY]\t PID %d (%s) gettimeofday returned %ld\n", pid, comm, args->ret);
}

/* clock_gettime */
tracepoint:syscalls:sys_enter_clock_gettime /pid == cpid/
{
    printf("[+] [CLOCK_GETTIME]\t PID %d (%s) requested clock %d\n", pid, comm, args->which_clock);
}

tracepoint:syscalls:sys_exit_clock_gettime /pid == cpid/
{
    printf("[+] [CLOCK_GETTIME]\t PID %d (%s) clock_gettime returned %ld\n", pid, comm, args->ret);
}

/* --- File permissions --- */

/* chmod */
tracepoint:syscalls:sys_enter_chmod /pid == cpid/
{
    printf("[+] [CHMOD]\t PID %d (%s) changing permissions of '%s' to 0%o\n",
           pid, comm, str(args->filename), args->mode);
}

tracepoint:syscalls:sys_exit_chmod /pid == cpid/
{
    printf("[+] [CHMOD]\t PID %d (%s) chmod returned %ld\n",
           pid, comm, args->ret);
}

/* fchmod */
tracepoint:syscalls:sys_enter_fchmod /pid == cpid/
{
    printf("[+] [FCHMOD]\t PID %d (%s) changing permissions of fd=%u to 0%o\n",
           pid, comm, args->fd, args->mode);
}

tracepoint:syscalls:sys_exit_fchmod /pid == cpid/
{
    printf("[+] [FCHMOD]\t PID %d (%s) fchmod returned %ld\n",
           pid, comm, args->ret);
}

/* chown */
tracepoint:syscalls:sys_enter_chown /pid == cpid/
{
    printf("[+] [CHOWN]\t PID %d (%s) changing owner of '%s' to UID=%d GID=%d\n",
           pid, comm, str(args->filename), args->user, args->group);
}

tracepoint:syscalls:sys_exit_chown /pid == cpid/
{
    printf("[+] [CHOWN]\t PID %d (%s) chown returned %ld\n",
           pid, comm, args->ret);
}

/* fchown */
tracepoint:syscalls:sys_enter_fchown /pid == cpid/
{
    printf("[+] [FCHOWN]\t PID %d (%s) changing owner of fd=%u to UID=%d GID=%d\n",
           pid, comm, args->fd, args->user, args->group);
}

tracepoint:syscalls:sys_exit_fchown /pid == cpid/
{
    printf("[+] [FCHOWN]\t PID %d (%s) fchown returned %ld\n",
           pid, comm, args->ret);
}

/* fchownat */
tracepoint:syscalls:sys_enter_fchownat /pid == cpid/
{
    printf("[+] [FCHOWNAT]\t PID %d (%s) changing owner of '%s' (dfd=%d) to UID=%d GID=%d, flags=0x%x\n",
           pid, comm, str(args->filename), args->dfd, args->user, args->group, args->flag);
}

tracepoint:syscalls:sys_exit_fchownat /pid == cpid/
{
    printf("[+] [FCHOWNAT]\t PID %d (%s) fchownat returned %ld\n",
           pid, comm, args->ret);
}

kprobe:vfs_read /pid == cpid/
{
    /* @read_map[pid, arg0] = arg2; */
    printf("[+] [VFS READ]\t PID %d (%s) read %d bytes from file_ptr=%p (buf=%p).\n", pid, comm, arg2, arg0, arg1);
}

kprobe:vfs_write /pid == cpid/
{
    /* @write_map[pid, arg0] = arg2; */
    printf("[+] [VFS WRITE]\t PID %d (%s) wrote %d bytes to file_ptr=%p (buf=%p).\n", pid, comm, arg2, arg0, arg1);
}

kprobe:tcp_sendmsg /pid == cpid/
{
    printf("[+] [SENDMSG]\t %s(%d) sent a TCP message.\n", comm, pid);
}

kprobe:tcp_recvmsg /pid == cpid/
{
    printf("[+] [RECVMSG]\t %s(%d) received a TCP message.\n", comm, pid);
}

kprobe:ptrace*
{
    if (pid == cpid) {
        printf("[+] [PTRACE] PID %s(%d) hit probe: %s (process tracing or anti-debug attempt)\n",
               comm, pid, probe);
    }
}


kprobe:commit_creds
{
    if (pid == cpid) {
        printf("[+] [COMMIT CREDS]\t %s(%d) hit probe: %s (process credential modification, may indicate privilege escalation )\n",
               comm, pid, probe);
    }
}

kprobe:prepare_kernel_cred
{
    if (pid == cpid) {
        printf("[+] [PREPARE KERNAL CREDS]\t PID %s(%d) hit probe: %s (setting up new credentials in kernel space)\n",
               comm, pid, probe);
    }
}

kprobe:__x64_sys_nanosleep
{
    if (pid == cpid) {
        printf("[+] [NANOSLEEP]\t PID %s(%d) hit probe: %s (nanosleep syscall, may indicate delay or timing anti-debug)\n",
               comm, pid, probe);
    }
}

kprobe:schedule
{
    if (pid == cpid) {
        printf("[+] [SCHEDULE]\t %s(%d) hit probe: %s (task being scheduled)\n",
               comm, pid, probe);
    }
}


tracepoint:raw_syscalls:sys_enter /pid == cpid/
{
    @syscalls[comm, pid] = count();
    @syscall_types[comm] = count();
}

END
{
    printf("\n=== [+] Syscall Summary by Process ===\n");
    print(@syscalls);

    printf("\n=== [+] Total Syscalls by Command ===\n");
    print(@syscall_types);

    clear(@syscalls);
    clear(@syscall_types);
}'

