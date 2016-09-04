extern struct pthread *__pthread_self();

#define TP_ADJ(p) (p)

#ifdef __x86_64__
#define MC_PC gregs[REG_RIP]
#else
#define MC_PC gregs[REG_EIP]
#endif
