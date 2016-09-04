#ifdef X86_64
#define __SYSCALL_LL_E(x) (x)
#define __SYSCALL_LL_O(x) (x)
#else
#define __SYSCALL_LL_E(x) \
((union { long long ll; long l[2]; }){ .ll = x }).l[0], \
((union { long long ll; long l[2]; }){ .ll = x }).l[1]
#define __SYSCALL_LL_O(x) __SYSCALL_LL_E((x))
#endif

extern long syscall_SYS_getdents();
extern long syscall_SYS_fcntl();
extern long syscall_SYS_openat();
extern long syscall_SYS_msgctl();
extern long syscall_SYS_msgget();
extern long syscall_SYS_msgrcv();
extern long syscall_SYS_msgsnd();
extern long syscall_SYS_semctl();
extern long syscall_SYS_semget();
extern long syscall_SYS_semop();
extern long syscall_SYS_semtimedop();
extern long syscall_SYS_shmat();
extern long syscall_SYS_shmctl();
extern long syscall_SYS_shmdt();
extern long syscall_SYS_shmget();
extern long syscall_SYS_adjtimex();
extern long syscall_SYS_arch_prctl();
extern long syscall_SYS_capset();
extern long syscall_SYS_capget();
extern long syscall_SYS_chroot();
extern long syscall_SYS_clock_adjtime();
extern long syscall_SYS_epoll_ctl();
extern long syscall_SYS_fallocate();
extern long syscall_SYS_fanotify_init();
extern long syscall_SYS_fanotify_mark();
extern long syscall_SYS_flock();
extern long syscall_SYS_inotify_add_watch();
extern long syscall_SYS_inotify_rm_watch();
extern long syscall_SYS_ioperm();
extern long syscall_SYS_iopl();
extern long syscall_SYS_syslog();
extern long syscall_SYS_init_module();
extern long syscall_SYS_delete_module();
extern long syscall_SYS_mount();
extern long syscall_SYS_umount2();
extern long syscall_SYS_personality();
extern long syscall_SYS_pivot_root();
extern long syscall_SYS_ppoll();
extern long syscall_SYS_prctl();
extern long syscall_SYS_prlimit64();
extern long syscall_SYS_process_vm_writev();
extern long syscall_SYS_process_vm_readv();
extern long syscall_SYS_ptrace();
extern long syscall_SYS_quotactl();
extern long syscall_SYS_readahead();
extern long syscall_SYS_reboot();
extern long syscall_SYS_remap_file_pages();
extern long syscall_SYS_sendfile();
extern long syscall_SYS_setfsgid();
extern long syscall_SYS_setfsuid();
extern long syscall_SYS_setgroups();
extern long syscall_SYS_sethostname();
extern long syscall_SYS_setns();
extern long syscall_SYS_settimeofday();
extern long syscall_SYS_splice();
extern long syscall_SYS_swapon();
extern long syscall_SYS_swapoff();
extern long syscall_SYS_sync_file_range();
extern long syscall_SYS_syncfs();
extern long syscall_SYS_sysinfo();
extern long syscall_SYS_tee();
extern long syscall_SYS_timerfd_create();
extern long syscall_SYS_timerfd_settime();
extern long syscall_SYS_timerfd_gettime();
extern long syscall_SYS_unshare();
extern long syscall_SYS_vhangup();
extern long syscall_SYS_vmsplice();
extern long syscall_SYS_wait4();
extern long syscall_SYS_getxattr();
extern long syscall_SYS_lgetxattr();
extern long syscall_SYS_fgetxattr();
extern long syscall_SYS_listxattr();
extern long syscall_SYS_llistxattr();
extern long syscall_SYS_flistxattr();
extern long syscall_SYS_setxattr();
extern long syscall_SYS_lsetxattr();
extern long syscall_SYS_fsetxattr();
extern long syscall_SYS_removexattr();
extern long syscall_SYS_lremovexattr();
extern long syscall_SYS_fremovexattr();
extern long syscall_SYS_getpriority();
extern long syscall_SYS_getresgid();
extern long syscall_SYS_getresuid();
extern long syscall_SYS_getrlimit();
extern long syscall_SYS_getrusage();
extern long syscall_SYS_ioctl();
extern long syscall_SYS_setdomainname();
extern long syscall_SYS_setpriority();
extern long syscall_SYS_uname();
extern long syscall_SYS_madvise();
extern long syscall_SYS_mincore();
extern long syscall_SYS_mlock();
extern long syscall_SYS_mlockall();
extern long syscall_SYS_mmap();
extern long syscall_SYS_mprotect();
extern long syscall_SYS_mremap();
extern long syscall_SYS_msync();
extern long syscall_SYS_munlock();
extern long syscall_SYS_munlockall();
extern long syscall_SYS_munmap();
extern long syscall_SYS_close();
extern long syscall_SYS_mq_notify();
extern long syscall_SYS_mq_open();
extern long syscall_SYS_mq_getsetattr();
extern long syscall_SYS_mq_timedreceive();
extern long syscall_SYS_mq_timedsend();
extern long syscall_SYS_recvmmsg();
extern long syscall_SYS_execve();
extern long syscall_SYS_fork();
extern long syscall_SYS_waitid();
extern long syscall_SYS_sched_setaffinity();
extern long syscall_SYS_sched_get_priority_max();
extern long syscall_SYS_sched_get_priority_min();
extern long syscall_SYS_sched_rr_get_interval();
extern long syscall_SYS_sched_yield();
extern long syscall_SYS_poll();
extern long syscall_SYS_pselect6();
extern long syscall_SYS_select();
extern long syscall_SYS_getitimer();
extern long syscall_SYS_kill();
extern long syscall_SYS_tkill();
extern long syscall_SYS_setitimer();
extern long syscall_SYS_rt_sigaction();
extern long syscall_SYS_sigaltstack();
extern long syscall_SYS_rt_sigpending();
extern long syscall_SYS_rt_sigqueueinfo();
extern long syscall_SYS_rt_sigsuspend();
extern long syscall_SYS_rt_sigtimedwait();
extern long syscall_SYS_chmod();
extern long syscall_SYS_fchmodat();
extern long syscall_SYS_stat();
extern long syscall_SYS_fstatat();
extern long syscall_SYS_lstat();
extern long syscall_SYS_mkdir();
extern long syscall_SYS_mkdirat();
extern long syscall_SYS_mknodat();
extern long syscall_SYS_statfs();
extern long syscall_SYS_fstatfs();
extern long syscall_SYS_umask();
extern long syscall_SYS_readv();
extern long syscall_SYS_lseek();
extern long syscall_SYS_writev();
extern long syscall_SYS_rename();
extern long syscall_SYS_futex();
extern long syscall_SYS_clock_getres();
extern long syscall_SYS_clock_nanosleep();
extern long syscall_SYS_clock_settime();
extern long syscall_SYS_nanosleep();
extern long syscall_SYS_timer_create();
extern long syscall_SYS_timer_getoverrun();
extern long syscall_SYS_timer_gettime();
extern long syscall_SYS_timer_settime();
extern long syscall_SYS_access();
extern long syscall_SYS_acct();
extern long syscall_SYS_chdir();
extern long syscall_SYS_chown();
extern long syscall_SYS_dup();
extern long syscall_SYS_faccessat();
extern long syscall_SYS_fchownat();
extern long syscall_SYS_fdatasync();
extern long syscall_SYS_fsync();
extern long syscall_SYS_ftruncate();
extern long syscall_SYS_getcwd();
extern long syscall_SYS_getgroups();
extern long syscall_SYS_getpgid();
extern long syscall_SYS_getsid();
extern long syscall_SYS_lchown();
extern long syscall_SYS_link();
extern long syscall_SYS_linkat();
extern long syscall_SYS_mknod();
extern long syscall_SYS_pause();
extern long syscall_SYS_pipe();
extern long syscall_SYS_pread();
extern long syscall_SYS_preadv();
extern long syscall_SYS_pwrite();
extern long syscall_SYS_pwritev();
extern long syscall_SYS_read();
extern long syscall_SYS_readlink();
extern long syscall_SYS_readlinkat();
extern long syscall_SYS_renameat();
extern long syscall_SYS_rmdir();
extern long syscall_SYS_setpgid();
extern long syscall_SYS_setsid();
extern long syscall_SYS_symlink();
extern long syscall_SYS_symlinkat();
extern long syscall_SYS_truncate();
extern long syscall_SYS_unlink();
extern long syscall_SYS_unlinkat();
extern long syscall_SYS_write();

extern long syscall__sys_open();
extern long syscall__sys_open_cp();

extern long socketcall_accept();
extern long socketcall_accept4();
extern long socketcall_bind();
extern long socketcall_connect();
extern long socketcall_getpeername();
extern long socketcall_getsockname();
extern long socketcall_getsockopt();
extern long socketcall_listen();
extern long socketcall_recvfrom();
extern long socketcall_recvmsg();
extern long socketcall_sendmsg();
extern long socketcall_sendto();
extern long socketcall_setsockopt();
extern long socketcall_shutdown();
extern long socketcall_socket();
extern long socketcall_socketpair();


#define syscall(n, ...)    syscall_##n(__VA_ARGS__)
#define syscall_cp(n, ...) syscall_##n(__VA_ARGS__)
#define __syscall_cp(n, ...) syscall_##n(__VA_ARGS__)
#define socketcall(nm,...) socketcall_##nm(__VA_ARGS__)
#define socketcall_cp(nm,...) socketcall_##nm(__VA_ARGS__)
#define __SYSCALL_DISP(n,u,...) syscall##n(__VA_ARGS__)

// #define __syscall0(x)             syscall##x()
// #define __syscall1(x,a)           syscall##x(a)
// #define __syscall2(x,a,b)         syscall##x(a,b)
// #define __syscall3(x,a,b,c)       syscall##x(a,b,c)
// #define __syscall4(x,a,b,c,d)     syscall##x(a,b,c,d)
// #define __syscall5(x,a,b,c,d,e)   syscall##x(a,b,c,d,e)
// #define __syscall6(x,a,b,c,d,e,f) syscall##x(a,b,c,d,e,f)

#define DIRECT_SYSCALLS
#define SYSCALL_USE_SOCKETCALL

// #define VDSO_USEFUL
// #define VDSO_CGT_SYM "__vdso_clock_gettime"
// #define VDSO_CGT_VER "LINUX_2.6"
// #define VDSO_GETCPU_SYM "__vdso_getcpu"
// #define VDSO_GETCPU_VER "LINUX_2.6"
