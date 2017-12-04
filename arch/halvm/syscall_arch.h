#ifdef X86_64
#define __SYSCALL_LL_E(x) (x)
#define __SYSCALL_LL_O(x) (x)
#else
#define __SYSCALL_LL_E(x) \
((union { long long ll; long l[2]; }){ .ll = x }).l[0], \
((union { long long ll; long l[2]; }){ .ll = x }).l[1]
#define __SYSCALL_LL_O(x) __SYSCALL_LL_E((x))
#endif

#define __NEED_size_t
#include <bits/alltypes.h>

long halvm_syscall_read(int, void*, size_t);
long halvm_syscall_write(long, long, long, long, long, long, long);
long halvm_syscall_open(long, long, long, long, long, long, long);
long halvm_syscall_close(long, long, long, long, long, long, long);
long halvm_syscall_stat(long, long, long, long, long, long, long);
long halvm_syscall_fstat(long, long, long, long, long, long, long);
long halvm_syscall_lstat(long, long, long, long, long, long, long);
long halvm_syscall_poll(long, long, long, long, long, long, long);
long halvm_syscall_lseek(long, long, long, long, long, long, long);
long halvm_syscall_mmap(long, long, long, long, long, long, long);
long halvm_syscall_mprotect(long, long, long, long, long, long, long);
long halvm_syscall_munmap(long, long, long, long, long, long, long);
long halvm_syscall_brk(long, long, long, long, long, long, long);
long halvm_syscall_rt_sigaction(long, long, long, long, long, long, long);
long halvm_syscall_rt_sigprocmask(long, long, long, long, long, long, long);
long halvm_syscall_rt_sigreturn(long, long, long, long, long, long, long);
long halvm_syscall_ioctl(long, long, long, long, long, long, long);
long halvm_syscall_pread64(long, long, long, long, long, long, long);
long halvm_syscall_pwrite64(long, long, long, long, long, long, long);
long halvm_syscall_readv(int, void*, int);
long halvm_syscall_writev(long, long, long, long, long, long, long);
long halvm_syscall_access(long, long, long, long, long, long, long);
long halvm_syscall_pipe(long, long, long, long, long, long, long);
long halvm_syscall_select(long, long, long, long, long, long, long);
long halvm_syscall_sched_yield(long, long, long, long, long, long, long);
long halvm_syscall_mremap(long, long, long, long, long, long, long);
long halvm_syscall_msync(long, long, long, long, long, long, long);
long halvm_syscall_mincore(long, long, long, long, long, long, long);
long halvm_syscall_madvise(long, long, long, long, long, long, long);
long halvm_syscall_shmget(int, size_t, int);
long halvm_syscall_shmat(int, void*, int);
long halvm_syscall_shmctl(int, int, void*);
long halvm_syscall_dup(int);
long halvm_syscall_dup2(int, int);
long halvm_syscall_pause(long, long, long, long, long, long, long);
long halvm_syscall_nanosleep(long, long, long, long, long, long, long);
long halvm_syscall_getitimer(long, long, long, long, long, long, long);
long halvm_syscall_alarm(long, long, long, long, long, long, long);
long halvm_syscall_setitimer(long, long, long, long, long, long, long);
long halvm_syscall_getpid(long, long, long, long, long, long, long);
long halvm_syscall_sendfile(long, long, long, long, long, long, long);
long halvm_syscall_socket(long, long, long, long, long, long, long);
long halvm_syscall_connect(long, long, long, long, long, long, long);
long halvm_syscall_accept(long, long, long, long, long, long, long);
long halvm_syscall_sendto(long, long, long, long, long, long, long);
long halvm_syscall_recvfrom(long, long, long, long, long, long, long);
long halvm_syscall_sendmsg(long, long, long, long, long, long, long);
long halvm_syscall_recvmsg(long, long, long, long, long, long, long);
long halvm_syscall_shutdown(long, long, long, long, long, long, long);
long halvm_syscall_bind(long, long, long, long, long, long, long);
long halvm_syscall_listen(long, long, long, long, long, long, long);
long halvm_syscall_getsockname(long, long, long, long, long, long, long);
long halvm_syscall_getpeername(long, long, long, long, long, long, long);
long halvm_syscall_socketpair(long, long, long, long, long, long, long);
long halvm_syscall_setsockopt(long, long, long, long, long, long, long);
long halvm_syscall_getsockopt(long, long, long, long, long, long, long);
long halvm_syscall_clone(long, long, long, long, long, long, long);
long halvm_syscall_fork(long, long, long, long, long, long, long);
long halvm_syscall_vfork(long, long, long, long, long, long, long);
long halvm_syscall_execve(void*, void*, void*);
long halvm_syscall_exit(long, long, long, long, long, long, long);
long halvm_syscall_wait4(int, int*, int, void*);
long halvm_syscall_kill(long, long, long, long, long, long, long);
long halvm_syscall_uname(long, long, long, long, long, long, long);
long halvm_syscall_semget(long, long, long, long, long, long, long);
long halvm_syscall_semop(long, long, long, long, long, long, long);
long halvm_syscall_semctl(long, long, long, long, long, long, long);
long halvm_syscall_shmdt(const void *);
long halvm_syscall_msgget(int, int);
long halvm_syscall_msgsnd(int, char *, size_t, int);
long halvm_syscall_msgrcv(int, char *, size_t, long);
long halvm_syscall_msgctl(int, int, char *);
long halvm_syscall_fcntl(long, long, long, long, long, long, long);
long halvm_syscall_flock(long, long, long, long, long, long, long);
long halvm_syscall_fsync(long, long, long, long, long, long, long);
long halvm_syscall_fdatasync(long, long, long, long, long, long, long);
long halvm_syscall_truncate(long, long, long, long, long, long, long);
long halvm_syscall_ftruncate(long, long, long, long, long, long, long);
long halvm_syscall_getdents(unsigned int, void *, unsigned int);
long halvm_syscall_getcwd(long, long, long, long, long, long, long);
long halvm_syscall_chdir(long, long, long, long, long, long, long);
long halvm_syscall_fchdir(long, long, long, long, long, long, long);
long halvm_syscall_rename(long, long, long, long, long, long, long);
long halvm_syscall_mkdir(long, long, long, long, long, long, long);
long halvm_syscall_rmdir(long, long, long, long, long, long, long);
long halvm_syscall_creat(long, long, long, long, long, long, long);
long halvm_syscall_link(long, long, long, long, long, long, long);
long halvm_syscall_unlink(long, long, long, long, long, long, long);
long halvm_syscall_symlink(long, long, long, long, long, long, long);
long halvm_syscall_readlink(long, long, long, long, long, long, long);
long halvm_syscall_chmod(long, long, long, long, long, long, long);
long halvm_syscall_fchmod(long, long, long, long, long, long, long);
long halvm_syscall_chown(long, long, long, long, long, long, long);
long halvm_syscall_fchown(long, long, long, long, long, long, long);
long halvm_syscall_lchown(long, long, long, long, long, long, long);
long halvm_syscall_umask(long, long, long, long, long, long, long);
long halvm_syscall_gettimeofday(long, long, long, long, long, long, long);
long halvm_syscall_getrlimit(long, long, long, long, long, long, long);
long halvm_syscall_getrusage(long, long, long, long, long, long, long);
long halvm_syscall_sysinfo(long, long, long, long, long, long, long);
long halvm_syscall_times(long, long, long, long, long, long, long);
long halvm_syscall_ptrace(int, int, void*, void*);
long halvm_syscall_getuid(long, long, long, long, long, long, long);
long halvm_syscall_syslog(long, long, long, long, long, long, long);
long halvm_syscall_getgid(long, long, long, long, long, long, long);
long halvm_syscall_setuid(long, long, long, long, long, long, long);
long halvm_syscall_setgid(long, long, long, long, long, long, long);
long halvm_syscall_geteuid(long, long, long, long, long, long, long);
long halvm_syscall_getegid(long, long, long, long, long, long, long);
long halvm_syscall_setpgid(int, int);
long halvm_syscall_getppid(long, long, long, long, long, long, long);
long halvm_syscall_getpgrp(long, long, long, long, long, long, long);
long halvm_syscall_setsid(void);
long halvm_syscall_setreuid(long, long, long, long, long, long, long);
long halvm_syscall_setregid(long, long, long, long, long, long, long);
long halvm_syscall_getgroups(size_t, int*);
long halvm_syscall_setgroups(size_t, char*);
long halvm_syscall_setresuid(long, long, long, long, long, long, long);
long halvm_syscall_getresuid(long, long, long, long, long, long, long);
long halvm_syscall_setresgid(long, long, long, long, long, long, long);
long halvm_syscall_getresgid(long, long, long, long, long, long, long);
long halvm_syscall_getpgid(long, long, long, long, long, long, long);
long halvm_syscall_setfsuid(int);
long halvm_syscall_setfsgid(int);
long halvm_syscall_getsid(long, long, long, long, long, long, long);
long halvm_syscall_capget(void*, void*);
long halvm_syscall_capset(void*, void*);
long halvm_syscall_rt_sigpending(long, long, long, long, long, long, long);
long halvm_syscall_rt_sigtimedwait(long, long, long, long, long, long, long);
long halvm_syscall_rt_sigqueueinfo(long, long, long, long, long, long, long);
long halvm_syscall_rt_sigsuspend(long, long, long, long, long, long, long);
long halvm_syscall_sigaltstack(long, long, long, long, long, long, long);
long halvm_syscall_utime(long, long, long, long, long, long, long);
long halvm_syscall_mknod(char*, int, int);
long halvm_syscall_uselib(long, long, long, long, long, long, long);
long halvm_syscall_personality(unsigned long);
long halvm_syscall_ustat(long, long, long, long, long, long, long);
long halvm_syscall_statfs(long, long, long, long, long, long, long);
long halvm_syscall_fstatfs(long, long, long, long, long, long, long);
long halvm_syscall_sysfs(long, long, long, long, long, long, long);
long halvm_syscall_getpriority(long, long, long, long, long, long, long);
long halvm_syscall_setpriority(long, long, long, long, long, long, long);
long halvm_syscall_sched_setparam(long, long, long, long, long, long, long);
long halvm_syscall_sched_getparam(long, long, long, long, long, long, long);
long halvm_syscall_sched_setscheduler(long, long, long, long, long, long, long);
long halvm_syscall_sched_getscheduler(long, long, long, long, long, long, long);
long halvm_syscall_sched_get_priority_max(long, long, long, long, long, long, long);
long halvm_syscall_sched_get_priority_min(long, long, long, long, long, long, long);
long halvm_syscall_sched_rr_get_interval(long, long, long, long, long, long, long);
long halvm_syscall_mlock(long, long, long, long, long, long, long);
long halvm_syscall_munlock(long, long, long, long, long, long, long);
long halvm_syscall_mlockall(long, long, long, long, long, long, long);
long halvm_syscall_munlockall(long, long, long, long, long, long, long);
long halvm_syscall_vhangup(void);
long halvm_syscall_modify_ldt(long, long, long, long, long, long, long);
long halvm_syscall_pivot_root(const char *, const char *);
long halvm_syscall__sysctl(long, long, long, long, long, long, long);
long halvm_syscall_prctl(int, unsigned long, unsigned long,
                              unsigned long, unsigned long);
long halvm_syscall_arch_prctl(int, long);
long halvm_syscall_adjtimex(void*);
long halvm_syscall_setrlimit(long, long, long, long, long, long, long);
long halvm_syscall_chroot(const char *);
long halvm_syscall_sync(long, long, long, long, long, long, long);
long halvm_syscall_acct(const char *);
long halvm_syscall_settimeofday(long, long, long, long, long, long, long);
long halvm_syscall_mount(long, long, long, long, long, long, long);
long halvm_syscall_umount2(long, long, long, long, long, long, long);
long halvm_syscall_swapon(const char *, int);
long halvm_syscall_swapoff(const char *);
long halvm_syscall_reboot(long, long, long, long, long, long, long);
long halvm_syscall_sethostname(long, long, long, long, long, long, long);
long halvm_syscall_setdomainname(long, long, long, long, long, long, long);
long halvm_syscall_iopl(int);
long halvm_syscall_ioperm(long, long, long, long, long, long, long);
long halvm_syscall_create_module(long, long, long, long, long, long, long);
long halvm_syscall_init_module(char*, unsigned long, char*);
long halvm_syscall_delete_module(void*, int);
long halvm_syscall_get_kernel_syms(long, long, long, long, long, long, long);
long halvm_syscall_query_module(long, long, long, long, long, long, long);
long halvm_syscall_quotactl(long, long, long, long, long, long, long);
long halvm_syscall_nfsservctl(long, long, long, long, long, long, long);
long halvm_syscall_getpmsg(long, long, long, long, long, long, long);
long halvm_syscall_putpmsg(long, long, long, long, long, long, long);
long halvm_syscall_afs_syscall(long, long, long, long, long, long, long);
long halvm_syscall_tuxcall(long, long, long, long, long, long, long);
long halvm_syscall_security(long, long, long, long, long, long, long);
long halvm_syscall_gettid(long, long, long, long, long, long, long);
long halvm_syscall_readahead(long, long, long, long, long, long, long);
long halvm_syscall_setxattr(long, long, long, long, long, long, long);
long halvm_syscall_lsetxattr(long, long, long, long, long, long, long);
long halvm_syscall_fsetxattr(long, long, long, long, long, long, long);
long halvm_syscall_getxattr(long, long, long, long, long, long, long);
long halvm_syscall_lgetxattr(long, long, long, long, long, long, long);
long halvm_syscall_fgetxattr(long, long, long, long, long, long, long);
long halvm_syscall_listxattr(long, long, long, long, long, long, long);
long halvm_syscall_llistxattr(long, long, long, long, long, long, long);
long halvm_syscall_flistxattr(long, long, long, long, long, long, long);
long halvm_syscall_removexattr(long, long, long, long, long, long, long);
long halvm_syscall_lremovexattr(long, long, long, long, long, long, long);
long halvm_syscall_fremovexattr(long, long, long, long, long, long, long);
long halvm_syscall_tkill(long, long, long, long, long, long, long);
long halvm_syscall_time(long, long, long, long, long, long, long);
long halvm_syscall_futex(long, long, long, long, long, long, long);
long halvm_syscall_sched_setaffinity(long, long, long, long, long, long, long);
long halvm_syscall_sched_getaffinity(long, long, long, long, long, long, long);
long halvm_syscall_set_thread_area(long, long, long, long, long, long, long);
long halvm_syscall_io_setup(long, long, long, long, long, long, long);
long halvm_syscall_io_destroy(long, long, long, long, long, long, long);
long halvm_syscall_io_getevents(long, long, long, long, long, long, long);
long halvm_syscall_io_submit(long, long, long, long, long, long, long);
long halvm_syscall_io_cancel(long, long, long, long, long, long, long);
long halvm_syscall_get_thread_area(long, long, long, long, long, long, long);
long halvm_syscall_lookup_dcookie(long, long, long, long, long, long, long);
long halvm_syscall_epoll_create(long, long, long, long, long, long, long);
long halvm_syscall_epoll_ctl_old(long, long, long, long, long, long, long);
long halvm_syscall_epoll_wait_old(long, long, long, long, long, long, long);
long halvm_syscall_remap_file_pages(char*, size_t, int, size_t, int);
long halvm_syscall_getdents64(unsigned int, void*, unsigned int);
long halvm_syscall_set_tid_address(long, long, long, long, long, long, long);
long halvm_syscall_restart_syscall(long, long, long, long, long, long, long);
long halvm_syscall_semtimedop(long, long, long, long, long, long, long);
long halvm_syscall_fadvise64(long, long, long, long, long, long, long);
long halvm_syscall_timer_create(long, long, long, long, long, long, long);
long halvm_syscall_timer_settime(long, long, long, long, long, long, long);
long halvm_syscall_timer_gettime(long, long, long, long, long, long, long);
long halvm_syscall_timer_getoverrun(long, long, long, long, long, long, long);
long halvm_syscall_timer_delete(long, long, long, long, long, long, long);
long halvm_syscall_clock_settime(long, long, long, long, long, long, long);
long halvm_syscall_clock_gettime(long, long, long, long, long, long, long);
long halvm_syscall_clock_getres(long, long, long, long, long, long, long);
long halvm_syscall_clock_nanosleep(long, long, long, long, long, long, long);
long halvm_syscall_exit_group(long, long, long, long, long, long, long);
long halvm_syscall_epoll_wait(long, long, long, long, long, long, long);
long halvm_syscall_epoll_ctl(long, long, long, long, long, long, long);
long halvm_syscall_tgkill(long, long, long, long, long, long, long);
long halvm_syscall_utimes(long, long, long, long, long, long, long);
long halvm_syscall_vserver(long, long, long, long, long, long, long);
long halvm_syscall_mbind(long, long, long, long, long, long, long);
long halvm_syscall_set_mempolicy(long, long, long, long, long, long, long);
long halvm_syscall_get_mempolicy(long, long, long, long, long, long, long);
long halvm_syscall_mq_open(long, long, long, long, long, long, long);
long halvm_syscall_mq_unlink(long, long, long, long, long, long, long);
long halvm_syscall_mq_timedsend(long, long, long, long, long, long, long);
long halvm_syscall_mq_timedreceive(long, long, long, long, long, long, long);
long halvm_syscall_mq_notify(long, long, long, long, long, long, long);
long halvm_syscall_mq_getsetattr(long, long, long, long, long, long, long);
long halvm_syscall_kexec_load(long, long, long, long, long, long, long);
long halvm_syscall_waitid(int, int, void*, int);
long halvm_syscall_add_key(long, long, long, long, long, long, long);
long halvm_syscall_request_key(long, long, long, long, long, long, long);
long halvm_syscall_keyctl(long, long, long, long, long, long, long);
long halvm_syscall_ioprio_set(long, long, long, long, long, long, long);
long halvm_syscall_ioprio_get(long, long, long, long, long, long, long);
long halvm_syscall_inotify_init(long, long, long, long, long, long, long);
long halvm_syscall_inotify_add_watch(long, long, long, long, long, long, long);
long halvm_syscall_inotify_rm_watch(long, long, long, long, long, long, long);
long halvm_syscall_migrate_pages(long, long, long, long, long, long, long);
long halvm_syscall_openat(long, long, long, long, long, long, long);
long halvm_syscall_mkdirat(long, long, long, long, long, long, long);
long halvm_syscall_mknodat(long, long, long, long, long, long, long);
long halvm_syscall_fchownat(long, long, long, long, long, long, long);
long halvm_syscall_futimesat(long, long, long, long, long, long, long);
long halvm_syscall_newfstatat(long, long, long, long, long, long, long);
long halvm_syscall_unlinkat(long, long, long, long, long, long, long);
long halvm_syscall_renameat(long, long, long, long, long, long, long);
long halvm_syscall_linkat(long, long, long, long, long, long, long);
long halvm_syscall_symlinkat(long, long, long, long, long, long, long);
long halvm_syscall_readlinkat(long, long, long, long, long, long, long);
long halvm_syscall_fchmodat(long, long, long, long, long, long, long);
long halvm_syscall_faccessat(long, long, long, long, long, long, long);
long halvm_syscall_pselect6(long, long, long, long, long, long, long);
long halvm_syscall_ppoll(long, long, long, long, long, long, long);
long halvm_syscall_unshare(int);
long halvm_syscall_set_robust_list(long, long, long, long, long, long, long);
long halvm_syscall_get_robust_list(long, long, long, long, long, long, long);
long halvm_syscall_splice(long, long, long, long, long, long, long);
long halvm_syscall_tee(long, long, long, long, long, long, long);
long halvm_syscall_sync_file_range(long, long, long, long, long, long, long);
long halvm_syscall_vmsplice(long, long, long, long, long, long, long);
long halvm_syscall_move_pages(long, long, long, long, long, long, long);
long halvm_syscall_utimensat(long, long, long, long, long, long, long);
long halvm_syscall_epoll_pwait(long, long, long, long, long, long, long);
long halvm_syscall_signalfd(long, long, long, long, long, long, long);
long halvm_syscall_timerfd_create(long, long, long, long, long, long, long);
long halvm_syscall_eventfd(long, long, long, long, long, long, long);
long halvm_syscall_fallocate(long, long, long, long, long, long, long);
long halvm_syscall_timerfd_settime(long, long, long, long, long, long, long);
long halvm_syscall_timerfd_gettime(long, long, long, long, long, long, long);
long halvm_syscall_accept4(long, long, long, long, long, long, long);
long halvm_syscall_signalfd4(long, long, long, long, long, long, long);
long halvm_syscall_eventfd2(long, long, long, long, long, long, long);
long halvm_syscall_epoll_create1(long, long, long, long, long, long, long);
long halvm_syscall_dup3(int, int, int);
long halvm_syscall_pipe2(long, long, long, long, long, long, long);
long halvm_syscall_inotify_init1(long, long, long, long, long, long, long);
long halvm_syscall_preadv(long, long, long, long, long, long, long);
long halvm_syscall_pwritev(long, long, long, long, long, long, long);
long halvm_syscall_rt_tgsigqueueinfo(long, long, long, long, long, long, long);
long halvm_syscall_perf_event_open(long, long, long, long, long, long, long);
long halvm_syscall_recvmmsg(long, long, long, long, long, long, long);
long halvm_syscall_fanotify_init(long, long, long, long, long, long, long);
long halvm_syscall_fanotify_mark(long, long, long, long, long, long, long);
long halvm_syscall_prlimit64(long, long, long, long, long, long, long);
long halvm_syscall_name_to_handle_at(long, long, long, long, long, long, long);
long halvm_syscall_open_by_handle_at(long, long, long, long, long, long, long);
long halvm_syscall_clock_adjtime(int, void *);
long halvm_syscall_syncfs(long, long, long, long, long, long, long);
long halvm_syscall_sendmmsg(long, long, long, long, long, long, long);
long halvm_syscall_setns(int, int);
long halvm_syscall_getcpu(long, long, long, long, long, long, long);
long halvm_syscall_process_vm_readv(int, void*, unsigned long, void*,
                                    unsigned long, unsigned long);
long halvm_syscall_process_vm_writev(int, void*, unsigned long, void*,
                                     unsigned long, unsigned long);
long halvm_syscall_kcmp(long, long, long, long, long, long, long);
long halvm_syscall_finit_module(long, long, long, long, long, long, long);
long halvm_syscall_sched_setattr(long, long, long, long, long, long, long);
long halvm_syscall_sched_getattr(long, long, long, long, long, long, long);
long halvm_syscall_renameat2(long, long, long, long, long, long, long);
long halvm_syscall_seccomp(long, long, long, long, long, long, long);
long halvm_syscall_getrandom(long, long, long, long, long, long, long);
long halvm_syscall_memfd_create(long, long, long, long, long, long, long);
long halvm_syscall_kexec_file_load(long, long, long, long, long, long, long);
long halvm_syscall_bpf(long, long, long, long, long, long, long);
long halvm_syscall_execveat(long, long, long, long, long, long, long);
long halvm_syscall_userfaultfd(long, long, long, long, long, long, long);
long halvm_syscall_membarrier(long, long, long, long, long, long, long);
long halvm_syscall_mlock2(long, long, long, long, long, long, long);
long halvm_syscall_copy_file_range(long, long, long, long, long, long, long);
long halvm_syscall_preadv2(long, long, long, long, long, long, long);
long halvm_syscall_pwritev2(long, long, long, long, long, long, long);
long halvm_syscall_pkey_mprotect(long, long, long, long, long, long, long);
long halvm_syscall_pkey_alloc(long, long, long, long, long, long, long);
long halvm_syscall_pkey_free(long, long, long, long, long, long, long);
long halvm_syscall_statx(long, long, long, long, long, long, long);

static inline long halvm_syscall(long n,
                                 long a1, long a2, long a3,
                                 long a4, long a5, long a6)
{
  switch(n) {
    case __NR_read:
      return halvm_syscall_read(a1, (void*)a2, a3);
    case __NR_write:
      return halvm_syscall_write(n, a1, a2, a3, a4, a5, a6);
    case __NR_open:
      return halvm_syscall_open(n, a1, a2, a3, a4, a5, a6);
    case __NR_close:
      return halvm_syscall_close(n, a1, a2, a3, a4, a5, a6);
    case __NR_stat:
      return halvm_syscall_stat(n, a1, a2, a3, a4, a5, a6);
    case __NR_fstat:
      return halvm_syscall_fstat(n, a1, a2, a3, a4, a5, a6);
    case __NR_lstat:
      return halvm_syscall_lstat(n, a1, a2, a3, a4, a5, a6);
    case __NR_poll:
      return halvm_syscall_poll(n, a1, a2, a3, a4, a5, a6);
    case __NR_lseek:
      return halvm_syscall_lseek(n, a1, a2, a3, a4, a5, a6);
    case __NR_mmap:
      return halvm_syscall_mmap(n, a1, a2, a3, a4, a5, a6);
    case __NR_mprotect:
      return halvm_syscall_mprotect(n, a1, a2, a3, a4, a5, a6);
    case __NR_munmap:
      return halvm_syscall_munmap(n, a1, a2, a3, a4, a5, a6);
    case __NR_brk:
      return halvm_syscall_brk(n, a1, a2, a3, a4, a5, a6);
    case __NR_rt_sigaction:
      return halvm_syscall_rt_sigaction(n, a1, a2, a3, a4, a5, a6);
    case __NR_rt_sigprocmask:
      return halvm_syscall_rt_sigprocmask(n, a1, a2, a3, a4, a5, a6);
    case __NR_rt_sigreturn:
      return halvm_syscall_rt_sigreturn(n, a1, a2, a3, a4, a5, a6);
    case __NR_ioctl:
      return halvm_syscall_ioctl(n, a1, a2, a3, a4, a5, a6);
    case __NR_pread64:
      return halvm_syscall_pread64(n, a1, a2, a3, a4, a5, a6);
    case __NR_pwrite64:
      return halvm_syscall_pwrite64(n, a1, a2, a3, a4, a5, a6);
    case __NR_readv:
      return halvm_syscall_readv(a1, (void*)a2, a3);
    case __NR_writev:
      return halvm_syscall_writev(n, a1, a2, a3, a4, a5, a6);
    case __NR_access:
      return halvm_syscall_access(n, a1, a2, a3, a4, a5, a6);
    case __NR_pipe:
      return halvm_syscall_pipe(n, a1, a2, a3, a4, a5, a6);
    case __NR_select:
      return halvm_syscall_select(n, a1, a2, a3, a4, a5, a6);
    case __NR_sched_yield:
      return halvm_syscall_sched_yield(n, a1, a2, a3, a4, a5, a6);
    case __NR_mremap:
      return halvm_syscall_mremap(n, a1, a2, a3, a4, a5, a6);
    case __NR_msync:
      return halvm_syscall_msync(n, a1, a2, a3, a4, a5, a6);
    case __NR_mincore:
      return halvm_syscall_mincore(n, a1, a2, a3, a4, a5, a6);
    case __NR_madvise:
      return halvm_syscall_madvise(n, a1, a2, a3, a4, a5, a6);
    case __NR_shmget:
      return halvm_syscall_shmget(a1, a2, a3);
    case __NR_shmat:
      return halvm_syscall_shmat(a1, (void*)a2, a3);
    case __NR_shmctl:
      return halvm_syscall_shmctl(a1, a2, (void*)a3);
    case __NR_dup:
      return halvm_syscall_dup(a1);
    case __NR_dup2:
      return halvm_syscall_dup2(a1, a2);
    case __NR_pause:
      return halvm_syscall_pause(n, a1, a2, a3, a4, a5, a6);
    case __NR_nanosleep:
      return halvm_syscall_nanosleep(n, a1, a2, a3, a4, a5, a6);
    case __NR_getitimer:
      return halvm_syscall_getitimer(n, a1, a2, a3, a4, a5, a6);
    case __NR_alarm:
      return halvm_syscall_alarm(n, a1, a2, a3, a4, a5, a6);
    case __NR_setitimer:
      return halvm_syscall_setitimer(n, a1, a2, a3, a4, a5, a6);
    case __NR_getpid:
      return halvm_syscall_getpid(n, a1, a2, a3, a4, a5, a6);
    case __NR_sendfile:
      return halvm_syscall_sendfile(n, a1, a2, a3, a4, a5, a6);
    case __NR_socket:
      return halvm_syscall_socket(n, a1, a2, a3, a4, a5, a6);
    case __NR_connect:
      return halvm_syscall_connect(n, a1, a2, a3, a4, a5, a6);
    case __NR_accept:
      return halvm_syscall_accept(n, a1, a2, a3, a4, a5, a6);
    case __NR_sendto:
      return halvm_syscall_sendto(n, a1, a2, a3, a4, a5, a6);
    case __NR_recvfrom:
      return halvm_syscall_recvfrom(n, a1, a2, a3, a4, a5, a6);
    case __NR_sendmsg:
      return halvm_syscall_sendmsg(n, a1, a2, a3, a4, a5, a6);
    case __NR_recvmsg:
      return halvm_syscall_recvmsg(n, a1, a2, a3, a4, a5, a6);
    case __NR_shutdown:
      return halvm_syscall_shutdown(n, a1, a2, a3, a4, a5, a6);
    case __NR_bind:
      return halvm_syscall_bind(n, a1, a2, a3, a4, a5, a6);
    case __NR_listen:
      return halvm_syscall_listen(n, a1, a2, a3, a4, a5, a6);
    case __NR_getsockname:
      return halvm_syscall_getsockname(n, a1, a2, a3, a4, a5, a6);
    case __NR_getpeername:
      return halvm_syscall_getpeername(n, a1, a2, a3, a4, a5, a6);
    case __NR_socketpair:
      return halvm_syscall_socketpair(n, a1, a2, a3, a4, a5, a6);
    case __NR_setsockopt:
      return halvm_syscall_setsockopt(n, a1, a2, a3, a4, a5, a6);
    case __NR_getsockopt:
      return halvm_syscall_getsockopt(n, a1, a2, a3, a4, a5, a6);
    case __NR_clone:
      return halvm_syscall_clone(n, a1, a2, a3, a4, a5, a6);
    case __NR_fork:
      return halvm_syscall_fork(n, a1, a2, a3, a4, a5, a6);
    case __NR_vfork:
      return halvm_syscall_vfork(n, a1, a2, a3, a4, a5, a6);
    case __NR_execve:
      return halvm_syscall_execve((void*)a1, (void*)a2, (void*)a3);
    case __NR_exit:
      return halvm_syscall_exit(n, a1, a2, a3, a4, a5, a6);
    case __NR_wait4:
      return halvm_syscall_wait4(a1, (int*)a2, a3, (void*)a4);
    case __NR_kill:
      return halvm_syscall_kill(n, a1, a2, a3, a4, a5, a6);
    case __NR_uname:
      return halvm_syscall_uname(n, a1, a2, a3, a4, a5, a6);
    case __NR_semget:
      return halvm_syscall_semget(n, a1, a2, a3, a4, a5, a6);
    case __NR_semop:
      return halvm_syscall_semop(n, a1, a2, a3, a4, a5, a6);
    case __NR_semctl:
      return halvm_syscall_semctl(n, a1, a2, a3, a4, a5, a6);
    case __NR_shmdt:
      return halvm_syscall_shmdt((const void *)a1);
    case __NR_msgget:
      return halvm_syscall_msgget(a1, a2);
    case __NR_msgsnd:
      return halvm_syscall_msgsnd(a1, (char*)a2, a3, a4);
    case __NR_msgrcv:
      return halvm_syscall_msgrcv(a1, (char*)a2, a3, a4);
    case __NR_msgctl:
      return halvm_syscall_msgctl(a1, a2, (char*)a3);
    case __NR_fcntl:
      return halvm_syscall_fcntl(n, a1, a2, a3, a4, a5, a6);
    case __NR_flock:
      return halvm_syscall_flock(n, a1, a2, a3, a4, a5, a6);
    case __NR_fsync:
      return halvm_syscall_fsync(n, a1, a2, a3, a4, a5, a6);
    case __NR_fdatasync:
      return halvm_syscall_fdatasync(n, a1, a2, a3, a4, a5, a6);
    case __NR_truncate:
      return halvm_syscall_truncate(n, a1, a2, a3, a4, a5, a6);
    case __NR_ftruncate:
      return halvm_syscall_ftruncate(n, a1, a2, a3, a4, a5, a6);
    case __NR_getdents:
      return halvm_syscall_getdents(a1, (void*)a2, a3);
    case __NR_getcwd:
      return halvm_syscall_getcwd(n, a1, a2, a3, a4, a5, a6);
    case __NR_chdir:
      return halvm_syscall_chdir(n, a1, a2, a3, a4, a5, a6);
    case __NR_fchdir:
      return halvm_syscall_fchdir(n, a1, a2, a3, a4, a5, a6);
    case __NR_rename:
      return halvm_syscall_rename(n, a1, a2, a3, a4, a5, a6);
    case __NR_mkdir:
      return halvm_syscall_mkdir(n, a1, a2, a3, a4, a5, a6);
    case __NR_rmdir:
      return halvm_syscall_rmdir(n, a1, a2, a3, a4, a5, a6);
    case __NR_creat:
      return halvm_syscall_creat(n, a1, a2, a3, a4, a5, a6);
    case __NR_link:
      return halvm_syscall_link(n, a1, a2, a3, a4, a5, a6);
    case __NR_unlink:
      return halvm_syscall_unlink(n, a1, a2, a3, a4, a5, a6);
    case __NR_symlink:
      return halvm_syscall_symlink(n, a1, a2, a3, a4, a5, a6);
    case __NR_readlink:
      return halvm_syscall_readlink(n, a1, a2, a3, a4, a5, a6);
    case __NR_chmod:
      return halvm_syscall_chmod(n, a1, a2, a3, a4, a5, a6);
    case __NR_fchmod:
      return halvm_syscall_fchmod(n, a1, a2, a3, a4, a5, a6);
    case __NR_chown:
      return halvm_syscall_chown(n, a1, a2, a3, a4, a5, a6);
    case __NR_fchown:
      return halvm_syscall_fchown(n, a1, a2, a3, a4, a5, a6);
    case __NR_lchown:
      return halvm_syscall_lchown(n, a1, a2, a3, a4, a5, a6);
    case __NR_umask:
      return halvm_syscall_umask(n, a1, a2, a3, a4, a5, a6);
    case __NR_gettimeofday:
      return halvm_syscall_gettimeofday(n, a1, a2, a3, a4, a5, a6);
    case __NR_getrlimit:
      return halvm_syscall_getrlimit(n, a1, a2, a3, a4, a5, a6);
    case __NR_getrusage:
      return halvm_syscall_getrusage(n, a1, a2, a3, a4, a5, a6);
    case __NR_sysinfo:
      return halvm_syscall_sysinfo(n, a1, a2, a3, a4, a5, a6);
    case __NR_times:
      return halvm_syscall_times(n, a1, a2, a3, a4, a5, a6);
    case __NR_ptrace:
      return halvm_syscall_ptrace(a1, a2, (void*)a3, (void*)a4);
    case __NR_getuid:
      return halvm_syscall_getuid(n, a1, a2, a3, a4, a5, a6);
    case __NR_syslog:
      return halvm_syscall_syslog(n, a1, a2, a3, a4, a5, a6);
    case __NR_getgid:
      return halvm_syscall_getgid(n, a1, a2, a3, a4, a5, a6);
    case __NR_setuid:
      return halvm_syscall_setuid(n, a1, a2, a3, a4, a5, a6);
    case __NR_setgid:
      return halvm_syscall_setgid(n, a1, a2, a3, a4, a5, a6);
    case __NR_geteuid:
      return halvm_syscall_geteuid(n, a1, a2, a3, a4, a5, a6);
    case __NR_getegid:
      return halvm_syscall_getegid(n, a1, a2, a3, a4, a5, a6);
    case __NR_setpgid:
      return halvm_syscall_setpgid(a1, a2);
    case __NR_getppid:
      return halvm_syscall_getppid(n, a1, a2, a3, a4, a5, a6);
    case __NR_getpgrp:
      return halvm_syscall_getpgrp(n, a1, a2, a3, a4, a5, a6);
    case __NR_setsid:
      return halvm_syscall_setsid();
    case __NR_setreuid:
      return halvm_syscall_setreuid(n, a1, a2, a3, a4, a5, a6);
    case __NR_setregid:
      return halvm_syscall_setregid(n, a1, a2, a3, a4, a5, a6);
    case __NR_getgroups:
      return halvm_syscall_getgroups(a1, (void*)a2);
    case __NR_setgroups:
      return halvm_syscall_setgroups(a1, (char*)a2);
    case __NR_setresuid:
      return halvm_syscall_setresuid(n, a1, a2, a3, a4, a5, a6);
    case __NR_getresuid:
      return halvm_syscall_getresuid(n, a1, a2, a3, a4, a5, a6);
    case __NR_setresgid:
      return halvm_syscall_setresgid(n, a1, a2, a3, a4, a5, a6);
    case __NR_getresgid:
      return halvm_syscall_getresgid(n, a1, a2, a3, a4, a5, a6);
    case __NR_getpgid:
      return halvm_syscall_getpgid(n, a1, a2, a3, a4, a5, a6);
    case __NR_setfsuid:
      return halvm_syscall_setfsuid(a1);
    case __NR_setfsgid:
      return halvm_syscall_setfsgid(a1);
    case __NR_getsid:
      return halvm_syscall_getsid(n, a1, a2, a3, a4, a5, a6);
    case __NR_capget:
      return halvm_syscall_capget((void*)a1, (void*)a2);
    case __NR_capset:
      return halvm_syscall_capset((void*)a1, (void*)a2);
    case __NR_rt_sigpending:
      return halvm_syscall_rt_sigpending(n, a1, a2, a3, a4, a5, a6);
    case __NR_rt_sigtimedwait:
      return halvm_syscall_rt_sigtimedwait(n, a1, a2, a3, a4, a5, a6);
    case __NR_rt_sigqueueinfo:
      return halvm_syscall_rt_sigqueueinfo(n, a1, a2, a3, a4, a5, a6);
    case __NR_rt_sigsuspend:
      return halvm_syscall_rt_sigsuspend(n, a1, a2, a3, a4, a5, a6);
    case __NR_sigaltstack:
      return halvm_syscall_sigaltstack(n, a1, a2, a3, a4, a5, a6);
    case __NR_utime:
      return halvm_syscall_utime(n, a1, a2, a3, a4, a5, a6);
    case __NR_mknod:
      return halvm_syscall_mknod((char*)a1, a2, a3);
    case __NR_uselib:
      return halvm_syscall_uselib(n, a1, a2, a3, a4, a5, a6);
    case __NR_personality:
      return halvm_syscall_personality(a1);
    case __NR_ustat:
      return halvm_syscall_ustat(n, a1, a2, a3, a4, a5, a6);
    case __NR_statfs:
      return halvm_syscall_statfs(n, a1, a2, a3, a4, a5, a6);
    case __NR_fstatfs:
      return halvm_syscall_fstatfs(n, a1, a2, a3, a4, a5, a6);
    case __NR_sysfs:
      return halvm_syscall_sysfs(n, a1, a2, a3, a4, a5, a6);
    case __NR_getpriority:
      return halvm_syscall_getpriority(n, a1, a2, a3, a4, a5, a6);
    case __NR_setpriority:
      return halvm_syscall_setpriority(n, a1, a2, a3, a4, a5, a6);
    case __NR_sched_setparam:
      return halvm_syscall_sched_setparam(n, a1, a2, a3, a4, a5, a6);
    case __NR_sched_getparam:
      return halvm_syscall_sched_getparam(n, a1, a2, a3, a4, a5, a6);
    case __NR_sched_setscheduler:
      return halvm_syscall_sched_setscheduler(n, a1, a2, a3, a4, a5, a6);
    case __NR_sched_getscheduler:
      return halvm_syscall_sched_getscheduler(n, a1, a2, a3, a4, a5, a6);
    case __NR_sched_get_priority_max:
      return halvm_syscall_sched_get_priority_max(n, a1, a2, a3, a4, a5, a6);
    case __NR_sched_get_priority_min:
      return halvm_syscall_sched_get_priority_min(n, a1, a2, a3, a4, a5, a6);
    case __NR_sched_rr_get_interval:
      return halvm_syscall_sched_rr_get_interval(n, a1, a2, a3, a4, a5, a6);
    case __NR_mlock:
      return halvm_syscall_mlock(n, a1, a2, a3, a4, a5, a6);
    case __NR_munlock:
      return halvm_syscall_munlock(n, a1, a2, a3, a4, a5, a6);
    case __NR_mlockall:
      return halvm_syscall_mlockall(n, a1, a2, a3, a4, a5, a6);
    case __NR_munlockall:
      return halvm_syscall_munlockall(n, a1, a2, a3, a4, a5, a6);
    case __NR_vhangup:
      return halvm_syscall_vhangup();
    case __NR_modify_ldt:
      return halvm_syscall_modify_ldt(n, a1, a2, a3, a4, a5, a6);
    case __NR_pivot_root:
      return halvm_syscall_pivot_root((const char *)a1, (const char *)a2);
    case __NR__sysctl:
      return halvm_syscall__sysctl(n, a1, a2, a3, a4, a5, a6);
    case __NR_prctl:
      return halvm_syscall_prctl(a1, a2, a3, a4, a5);
    case __NR_arch_prctl:
      return halvm_syscall_arch_prctl(a1, a2);
    case __NR_adjtimex:
      return halvm_syscall_adjtimex((void*)a1);
    case __NR_setrlimit:
      return halvm_syscall_setrlimit(n, a1, a2, a3, a4, a5, a6);
    case __NR_chroot:
      return halvm_syscall_chroot((const char *)a1);
    case __NR_sync:
      return halvm_syscall_sync(n, a1, a2, a3, a4, a5, a6);
    case __NR_acct:
      return halvm_syscall_acct((const char*)a1);
    case __NR_settimeofday:
      return halvm_syscall_settimeofday(n, a1, a2, a3, a4, a5, a6);
    case __NR_mount:
      return halvm_syscall_mount(n, a1, a2, a3, a4, a5, a6);
    case __NR_umount2:
      return halvm_syscall_umount2(n, a1, a2, a3, a4, a5, a6);
    case __NR_swapon:
      return halvm_syscall_swapon((const char *)a1, a2);
    case __NR_swapoff:
      return halvm_syscall_swapoff((const char *)a1);
    case __NR_reboot:
      return halvm_syscall_reboot(n, a1, a2, a3, a4, a5, a6);
    case __NR_sethostname:
      return halvm_syscall_sethostname(n, a1, a2, a3, a4, a5, a6);
    case __NR_setdomainname:
      return halvm_syscall_setdomainname(n, a1, a2, a3, a4, a5, a6);
    case __NR_iopl:
      return halvm_syscall_iopl(a1);
    case __NR_ioperm:
      return halvm_syscall_ioperm(n, a1, a2, a3, a4, a5, a6);
    case __NR_create_module:
      return halvm_syscall_create_module(n, a1, a2, a3, a4, a5, a6);
    case __NR_init_module:
      return halvm_syscall_init_module((char*)a1, a2, (char*)a3);
    case __NR_delete_module:
      return halvm_syscall_delete_module((void*)a1, a2);
    case __NR_get_kernel_syms:
      return halvm_syscall_get_kernel_syms(n, a1, a2, a3, a4, a5, a6);
    case __NR_query_module:
      return halvm_syscall_query_module(n, a1, a2, a3, a4, a5, a6);
    case __NR_quotactl:
      return halvm_syscall_quotactl(n, a1, a2, a3, a4, a5, a6);
    case __NR_nfsservctl:
      return halvm_syscall_nfsservctl(n, a1, a2, a3, a4, a5, a6);
    case __NR_getpmsg:
      return halvm_syscall_getpmsg(n, a1, a2, a3, a4, a5, a6);
    case __NR_putpmsg:
      return halvm_syscall_putpmsg(n, a1, a2, a3, a4, a5, a6);
    case __NR_afs_syscall:
      return halvm_syscall_afs_syscall(n, a1, a2, a3, a4, a5, a6);
    case __NR_tuxcall:
      return halvm_syscall_tuxcall(n, a1, a2, a3, a4, a5, a6);
    case __NR_security:
      return halvm_syscall_security(n, a1, a2, a3, a4, a5, a6);
    case __NR_gettid:
      return halvm_syscall_gettid(n, a1, a2, a3, a4, a5, a6);
    case __NR_readahead:
      return halvm_syscall_readahead(n, a1, a2, a3, a4, a5, a6);
    case __NR_setxattr:
      return halvm_syscall_setxattr(n, a1, a2, a3, a4, a5, a6);
    case __NR_lsetxattr:
      return halvm_syscall_lsetxattr(n, a1, a2, a3, a4, a5, a6);
    case __NR_fsetxattr:
      return halvm_syscall_fsetxattr(n, a1, a2, a3, a4, a5, a6);
    case __NR_getxattr:
      return halvm_syscall_getxattr(n, a1, a2, a3, a4, a5, a6);
    case __NR_lgetxattr:
      return halvm_syscall_lgetxattr(n, a1, a2, a3, a4, a5, a6);
    case __NR_fgetxattr:
      return halvm_syscall_fgetxattr(n, a1, a2, a3, a4, a5, a6);
    case __NR_listxattr:
      return halvm_syscall_listxattr(n, a1, a2, a3, a4, a5, a6);
    case __NR_llistxattr:
      return halvm_syscall_llistxattr(n, a1, a2, a3, a4, a5, a6);
    case __NR_flistxattr:
      return halvm_syscall_flistxattr(n, a1, a2, a3, a4, a5, a6);
    case __NR_removexattr:
      return halvm_syscall_removexattr(n, a1, a2, a3, a4, a5, a6);
    case __NR_lremovexattr:
      return halvm_syscall_lremovexattr(n, a1, a2, a3, a4, a5, a6);
    case __NR_fremovexattr:
      return halvm_syscall_fremovexattr(n, a1, a2, a3, a4, a5, a6);
    case __NR_tkill:
      return halvm_syscall_tkill(n, a1, a2, a3, a4, a5, a6);
    case __NR_time:
      return halvm_syscall_time(n, a1, a2, a3, a4, a5, a6);
    case __NR_futex:
      return halvm_syscall_futex(n, a1, a2, a3, a4, a5, a6);
    case __NR_sched_setaffinity:
      return halvm_syscall_sched_setaffinity(n, a1, a2, a3, a4, a5, a6);
    case __NR_sched_getaffinity:
      return halvm_syscall_sched_getaffinity(n, a1, a2, a3, a4, a5, a6);
    case __NR_set_thread_area:
      return halvm_syscall_set_thread_area(n, a1, a2, a3, a4, a5, a6);
    case __NR_io_setup:
      return halvm_syscall_io_setup(n, a1, a2, a3, a4, a5, a6);
    case __NR_io_destroy:
      return halvm_syscall_io_destroy(n, a1, a2, a3, a4, a5, a6);
    case __NR_io_getevents:
      return halvm_syscall_io_getevents(n, a1, a2, a3, a4, a5, a6);
    case __NR_io_submit:
      return halvm_syscall_io_submit(n, a1, a2, a3, a4, a5, a6);
    case __NR_io_cancel:
      return halvm_syscall_io_cancel(n, a1, a2, a3, a4, a5, a6);
    case __NR_get_thread_area:
      return halvm_syscall_get_thread_area(n, a1, a2, a3, a4, a5, a6);
    case __NR_lookup_dcookie:
      return halvm_syscall_lookup_dcookie(n, a1, a2, a3, a4, a5, a6);
    case __NR_epoll_create:
      return halvm_syscall_epoll_create(n, a1, a2, a3, a4, a5, a6);
    case __NR_epoll_ctl_old:
      return halvm_syscall_epoll_ctl_old(n, a1, a2, a3, a4, a5, a6);
    case __NR_epoll_wait_old:
      return halvm_syscall_epoll_wait_old(n, a1, a2, a3, a4, a5, a6);
    case __NR_remap_file_pages:
      return halvm_syscall_remap_file_pages((char*)a1, a2, a3, a4, a5);
    case __NR_getdents64:
      return halvm_syscall_getdents64(a1, (void*)a2, a3);
    case __NR_set_tid_address:
      return halvm_syscall_set_tid_address(n, a1, a2, a3, a4, a5, a6);
    case __NR_restart_syscall:
      return halvm_syscall_restart_syscall(n, a1, a2, a3, a4, a5, a6);
    case __NR_semtimedop:
      return halvm_syscall_semtimedop(n, a1, a2, a3, a4, a5, a6);
    case __NR_fadvise64:
      return halvm_syscall_fadvise64(n, a1, a2, a3, a4, a5, a6);
    case __NR_timer_create:
      return halvm_syscall_timer_create(n, a1, a2, a3, a4, a5, a6);
    case __NR_timer_settime:
      return halvm_syscall_timer_settime(n, a1, a2, a3, a4, a5, a6);
    case __NR_timer_gettime:
      return halvm_syscall_timer_gettime(n, a1, a2, a3, a4, a5, a6);
    case __NR_timer_getoverrun:
      return halvm_syscall_timer_getoverrun(n, a1, a2, a3, a4, a5, a6);
    case __NR_timer_delete:
      return halvm_syscall_timer_delete(n, a1, a2, a3, a4, a5, a6);
    case __NR_clock_settime:
      return halvm_syscall_clock_settime(n, a1, a2, a3, a4, a5, a6);
    case __NR_clock_gettime:
      return halvm_syscall_clock_gettime(n, a1, a2, a3, a4, a5, a6);
    case __NR_clock_getres:
      return halvm_syscall_clock_getres(n, a1, a2, a3, a4, a5, a6);
    case __NR_clock_nanosleep:
      return halvm_syscall_clock_nanosleep(n, a1, a2, a3, a4, a5, a6);
    case __NR_exit_group:
      return halvm_syscall_exit_group(n, a1, a2, a3, a4, a5, a6);
    case __NR_epoll_wait:
      return halvm_syscall_epoll_wait(n, a1, a2, a3, a4, a5, a6);
    case __NR_epoll_ctl:
      return halvm_syscall_epoll_ctl(n, a1, a2, a3, a4, a5, a6);
    case __NR_tgkill:
      return halvm_syscall_tgkill(n, a1, a2, a3, a4, a5, a6);
    case __NR_utimes:
      return halvm_syscall_utimes(n, a1, a2, a3, a4, a5, a6);
    case __NR_vserver:
      return halvm_syscall_vserver(n, a1, a2, a3, a4, a5, a6);
    case __NR_mbind:
      return halvm_syscall_mbind(n, a1, a2, a3, a4, a5, a6);
    case __NR_set_mempolicy:
      return halvm_syscall_set_mempolicy(n, a1, a2, a3, a4, a5, a6);
    case __NR_get_mempolicy:
      return halvm_syscall_get_mempolicy(n, a1, a2, a3, a4, a5, a6);
    case __NR_mq_open:
      return halvm_syscall_mq_open(n, a1, a2, a3, a4, a5, a6);
    case __NR_mq_unlink:
      return halvm_syscall_mq_unlink(n, a1, a2, a3, a4, a5, a6);
    case __NR_mq_timedsend:
      return halvm_syscall_mq_timedsend(n, a1, a2, a3, a4, a5, a6);
    case __NR_mq_timedreceive:
      return halvm_syscall_mq_timedreceive(n, a1, a2, a3, a4, a5, a6);
    case __NR_mq_notify:
      return halvm_syscall_mq_notify(n, a1, a2, a3, a4, a5, a6);
    case __NR_mq_getsetattr:
      return halvm_syscall_mq_getsetattr(n, a1, a2, a3, a4, a5, a6);
    case __NR_kexec_load:
      return halvm_syscall_kexec_load(n, a1, a2, a3, a4, a5, a6);
    case __NR_waitid:
      return halvm_syscall_waitid(a1, a2, (void*)a3, a4);
    case __NR_add_key:
      return halvm_syscall_add_key(n, a1, a2, a3, a4, a5, a6);
    case __NR_request_key:
      return halvm_syscall_request_key(n, a1, a2, a3, a4, a5, a6);
    case __NR_keyctl:
      return halvm_syscall_keyctl(n, a1, a2, a3, a4, a5, a6);
    case __NR_ioprio_set:
      return halvm_syscall_ioprio_set(n, a1, a2, a3, a4, a5, a6);
    case __NR_ioprio_get:
      return halvm_syscall_ioprio_get(n, a1, a2, a3, a4, a5, a6);
    case __NR_inotify_init:
      return halvm_syscall_inotify_init(n, a1, a2, a3, a4, a5, a6);
    case __NR_inotify_add_watch:
      return halvm_syscall_inotify_add_watch(n, a1, a2, a3, a4, a5, a6);
    case __NR_inotify_rm_watch:
      return halvm_syscall_inotify_rm_watch(n, a1, a2, a3, a4, a5, a6);
    case __NR_migrate_pages:
      return halvm_syscall_migrate_pages(n, a1, a2, a3, a4, a5, a6);
    case __NR_openat:
      return halvm_syscall_openat(n, a1, a2, a3, a4, a5, a6);
    case __NR_mkdirat:
      return halvm_syscall_mkdirat(n, a1, a2, a3, a4, a5, a6);
    case __NR_mknodat:
      return halvm_syscall_mknodat(n, a1, a2, a3, a4, a5, a6);
    case __NR_fchownat:
      return halvm_syscall_fchownat(n, a1, a2, a3, a4, a5, a6);
    case __NR_futimesat:
      return halvm_syscall_futimesat(n, a1, a2, a3, a4, a5, a6);
    case __NR_newfstatat:
      return halvm_syscall_newfstatat(n, a1, a2, a3, a4, a5, a6);
    case __NR_unlinkat:
      return halvm_syscall_unlinkat(n, a1, a2, a3, a4, a5, a6);
    case __NR_renameat:
      return halvm_syscall_renameat(n, a1, a2, a3, a4, a5, a6);
    case __NR_linkat:
      return halvm_syscall_linkat(n, a1, a2, a3, a4, a5, a6);
    case __NR_symlinkat:
      return halvm_syscall_symlinkat(n, a1, a2, a3, a4, a5, a6);
    case __NR_readlinkat:
      return halvm_syscall_readlinkat(n, a1, a2, a3, a4, a5, a6);
    case __NR_fchmodat:
      return halvm_syscall_fchmodat(n, a1, a2, a3, a4, a5, a6);
    case __NR_faccessat:
      return halvm_syscall_faccessat(n, a1, a2, a3, a4, a5, a6);
    case __NR_pselect6:
      return halvm_syscall_pselect6(n, a1, a2, a3, a4, a5, a6);
    case __NR_ppoll:
      return halvm_syscall_ppoll(n, a1, a2, a3, a4, a5, a6);
    case __NR_unshare:
      return halvm_syscall_unshare(a1);
    case __NR_set_robust_list:
      return halvm_syscall_set_robust_list(n, a1, a2, a3, a4, a5, a6);
    case __NR_get_robust_list:
      return halvm_syscall_get_robust_list(n, a1, a2, a3, a4, a5, a6);
    case __NR_splice:
      return halvm_syscall_splice(n, a1, a2, a3, a4, a5, a6);
    case __NR_tee:
      return halvm_syscall_tee(n, a1, a2, a3, a4, a5, a6);
    case __NR_sync_file_range:
      return halvm_syscall_sync_file_range(n, a1, a2, a3, a4, a5, a6);
    case __NR_vmsplice:
      return halvm_syscall_vmsplice(n, a1, a2, a3, a4, a5, a6);
    case __NR_move_pages:
      return halvm_syscall_move_pages(n, a1, a2, a3, a4, a5, a6);
    case __NR_utimensat:
      return halvm_syscall_utimensat(n, a1, a2, a3, a4, a5, a6);
    case __NR_epoll_pwait:
      return halvm_syscall_epoll_pwait(n, a1, a2, a3, a4, a5, a6);
    case __NR_signalfd:
      return halvm_syscall_signalfd(n, a1, a2, a3, a4, a5, a6);
    case __NR_timerfd_create:
      return halvm_syscall_timerfd_create(n, a1, a2, a3, a4, a5, a6);
    case __NR_eventfd:
      return halvm_syscall_eventfd(n, a1, a2, a3, a4, a5, a6);
    case __NR_fallocate:
      return halvm_syscall_fallocate(n, a1, a2, a3, a4, a5, a6);
    case __NR_timerfd_settime:
      return halvm_syscall_timerfd_settime(n, a1, a2, a3, a4, a5, a6);
    case __NR_timerfd_gettime:
      return halvm_syscall_timerfd_gettime(n, a1, a2, a3, a4, a5, a6);
    case __NR_accept4:
      return halvm_syscall_accept4(n, a1, a2, a3, a4, a5, a6);
    case __NR_signalfd4:
      return halvm_syscall_signalfd4(n, a1, a2, a3, a4, a5, a6);
    case __NR_eventfd2:
      return halvm_syscall_eventfd2(n, a1, a2, a3, a4, a5, a6);
    case __NR_epoll_create1:
      return halvm_syscall_epoll_create1(n, a1, a2, a3, a4, a5, a6);
    case __NR_dup3:
      return halvm_syscall_dup3(a1, a2, a3);
    case __NR_pipe2:
      return halvm_syscall_pipe2(n, a1, a2, a3, a4, a5, a6);
    case __NR_inotify_init1:
      return halvm_syscall_inotify_init1(n, a1, a2, a3, a4, a5, a6);
    case __NR_preadv:
      return halvm_syscall_preadv(n, a1, a2, a3, a4, a5, a6);
    case __NR_pwritev:
      return halvm_syscall_pwritev(n, a1, a2, a3, a4, a5, a6);
    case __NR_rt_tgsigqueueinfo:
      return halvm_syscall_rt_tgsigqueueinfo(n, a1, a2, a3, a4, a5, a6);
    case __NR_perf_event_open:
      return halvm_syscall_perf_event_open(n, a1, a2, a3, a4, a5, a6);
    case __NR_recvmmsg:
      return halvm_syscall_recvmmsg(n, a1, a2, a3, a4, a5, a6);
    case __NR_fanotify_init:
      return halvm_syscall_fanotify_init(n, a1, a2, a3, a4, a5, a6);
    case __NR_fanotify_mark:
      return halvm_syscall_fanotify_mark(n, a1, a2, a3, a4, a5, a6);
    case __NR_prlimit64:
      return halvm_syscall_prlimit64(n, a1, a2, a3, a4, a5, a6);
    case __NR_name_to_handle_at:
      return halvm_syscall_name_to_handle_at(n, a1, a2, a3, a4, a5, a6);
    case __NR_open_by_handle_at:
      return halvm_syscall_open_by_handle_at(n, a1, a2, a3, a4, a5, a6);
    case __NR_clock_adjtime:
      return halvm_syscall_clock_adjtime(a1, (void*)a2);
    case __NR_syncfs:
      return halvm_syscall_syncfs(n, a1, a2, a3, a4, a5, a6);
    case __NR_sendmmsg:
      return halvm_syscall_sendmmsg(n, a1, a2, a3, a4, a5, a6);
    case __NR_setns:
      return halvm_syscall_setns(a1, a2);
    case __NR_getcpu:
      return halvm_syscall_getcpu(n, a1, a2, a3, a4, a5, a6);
    case __NR_process_vm_readv:
      return halvm_syscall_process_vm_readv(a1,(void*)a2,a3,(void*)a4,a5,a6);
    case __NR_process_vm_writev:
      return halvm_syscall_process_vm_writev(a1,(void*)a2,a3,(void*)a4,a5,a6);
    case __NR_kcmp:
      return halvm_syscall_kcmp(n, a1, a2, a3, a4, a5, a6);
    case __NR_finit_module:
      return halvm_syscall_finit_module(n, a1, a2, a3, a4, a5, a6);
    case __NR_sched_setattr:
      return halvm_syscall_sched_setattr(n, a1, a2, a3, a4, a5, a6);
    case __NR_sched_getattr:
      return halvm_syscall_sched_getattr(n, a1, a2, a3, a4, a5, a6);
    case __NR_renameat2:
      return halvm_syscall_renameat2(n, a1, a2, a3, a4, a5, a6);
    case __NR_seccomp:
      return halvm_syscall_seccomp(n, a1, a2, a3, a4, a5, a6);
    case __NR_getrandom:
      return halvm_syscall_getrandom(n, a1, a2, a3, a4, a5, a6);
    case __NR_memfd_create:
      return halvm_syscall_memfd_create(n, a1, a2, a3, a4, a5, a6);
    case __NR_kexec_file_load:
      return halvm_syscall_kexec_file_load(n, a1, a2, a3, a4, a5, a6);
    case __NR_bpf:
      return halvm_syscall_bpf(n, a1, a2, a3, a4, a5, a6);
    case __NR_execveat:
      return halvm_syscall_execveat(n, a1, a2, a3, a4, a5, a6);
    case __NR_userfaultfd:
      return halvm_syscall_userfaultfd(n, a1, a2, a3, a4, a5, a6);
    case __NR_membarrier:
      return halvm_syscall_membarrier(n, a1, a2, a3, a4, a5, a6);
    case __NR_mlock2:
      return halvm_syscall_mlock2(n, a1, a2, a3, a4, a5, a6);
    case __NR_copy_file_range:
      return halvm_syscall_copy_file_range(n, a1, a2, a3, a4, a5, a6);
    case __NR_preadv2:
      return halvm_syscall_preadv2(n, a1, a2, a3, a4, a5, a6);
    case __NR_pwritev2:
      return halvm_syscall_pwritev2(n, a1, a2, a3, a4, a5, a6);
    case __NR_pkey_mprotect:
      return halvm_syscall_pkey_mprotect(n, a1, a2, a3, a4, a5, a6);
    case __NR_pkey_alloc:
      return halvm_syscall_pkey_alloc(n, a1, a2, a3, a4, a5, a6);
    case __NR_pkey_free:
      return halvm_syscall_pkey_free(n, a1, a2, a3, a4, a5, a6);
    case __NR_statx:
      return halvm_syscall_statx(n, a1, a2, a3, a4, a5, a6);

    default:
      return -22; // EINVAL
  }
}

static inline long __syscall0(long n)
{
  return halvm_syscall(n, 0, 0, 0, 0, 0, 0);
}

static inline long __syscall1(long n, long a1)
{
  return halvm_syscall(n, a1, 0, 0, 0, 0, 0);
}

static inline long __syscall2(long n, long a1, long a2)
{
  return halvm_syscall(n, a1, a2, 0, 0, 0, 0);
}

static inline long __syscall3(long n, long a1, long a2, long a3)
{
  return halvm_syscall(n, a1, a2, a3, 0, 0, 0);
}

static inline long __syscall4(long n, long a1, long a2, long a3,
                                      long a4)
{
  return halvm_syscall(n, a1, a2, a3, a4, 0, 0);
}

static inline long __syscall5(long n, long a1, long a2, long a3,
                                      long a4, long a5)
{
  return halvm_syscall(n, a1, a2, a3, a4, a5, 0);
}

static inline long __syscall6(long n, long a1, long a2, long a3,
                                      long a4, long a5, long a6)
{
  return halvm_syscall(n, a1, a2, a3, a4, a5, a6);
}

int *__errno_location(void);

// #define VDSO_USEFUL
// #define VDSO_CGT_SYM "__vdso_clock_gettime"
// #define VDSO_CGT_VER "LINUX_2.6"
// #define VDSO_GETCPU_SYM "__vdso_getcpu"
// #define VDSO_GETCPU_VER "LINUX_2.6"
