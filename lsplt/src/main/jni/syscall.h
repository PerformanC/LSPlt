#ifndef LSPLT_SYSCALL_H
#define LSPLT_SYSCALL_H

#include <errno.h>

#include <sys/syscall.h>

#define CHECK_SYSCALL_ERROR(res)                      \
  if ((unsigned long)(res) >= (unsigned long)-4095) { \
    errno = -(long)(res);                             \
                                                      \
    return MAP_FAILED;                                \
  }

#define CHECK_SYSCALL_ERROR_INTEGER(res) \
  if ((unsigned long)(res) >= (unsigned long)-4095) { \
    errno = -(long)(res);                             \
                                                      \
    return -1;                                        \
  }

static __attribute__((always_inline)) inline void *sys_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
  /* INFO: mmap2 syscall requires offset to be in pagesize units */
  if (k_page_size == 0) k_page_size = getpagesize();

  if (offset % k_page_size != 0) {
    errno = EINVAL;

    return MAP_FAILED;
  }

  void *result;

  #if defined(__arm__)
    register long r0 __asm__("r0") = (long)addr;
    register long r1 __asm__("r1") = (long)length;
    register long r2 __asm__("r2") = (long)prot;
    register long r3 __asm__("r3") = (long)flags;
    register long r4 __asm__("r4") = (long)fd;
    register long r5 __asm__("r5") = (long)(offset / k_page_size);
    register long r7 __asm__("r7") = SYS_mmap2;

    __asm__ volatile(
      "svc #0"
      : "+r"(r0)
      : "r"(r1), "r"(r2), "r"(r3), "r"(r4), "r"(r5), "r"(r7)
      : "cc", "memory"
    );

    result = (void *)r0;
  #elif defined(__aarch64__)
    register long x0 __asm__("x0") = (long)addr;
    register long x1 __asm__("x1") = (long)length;
    register long x2 __asm__("x2") = (long)prot;
    register long x3 __asm__("x3") = (long)flags;
    register long x4 __asm__("x4") = (long)fd;
    register long x5 __asm__("x5") = (long)offset;
    register long x8 __asm__("x8") = SYS_mmap;

    __asm__ volatile(
      "svc #0"
      : "+r"(x0)
      : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x8)
      : "cc", "memory"
    );

    result = (void *)x0;
  #elif defined(__i386__)
    __asm__ volatile(
      "pushl %%ebp\n\t"
      "movl %[ofs], %%ebp\n\t"
      "int $0x80\n\t"
      "popl %%ebp"
      : "=a"(result)
      : "a"(SYS_mmap2), "b"(addr), "c"(length), "d"(prot),
      "S"(flags), "D"(fd), [ofs]"g"(offset / k_page_size)
      : "memory", "cc", "ebp"
    );
  #elif defined(__x86_64__)
    register long rdi __asm__("rdi") = (long)addr;
    register long rsi __asm__("rsi") = (long)length;
    register long rdx __asm__("rdx") = (long)prot;
    register long r10 __asm__("r10") = (long)flags;
    register long  r8 __asm__("r8")  = (long)fd;
    register long  r9 __asm__("r9")  = (long)offset;
    register long rax __asm__("rax") = SYS_mmap;

    __asm__ volatile(
      "syscall"
      : "+r"(rax)
      : "r"(rdi), "r"(rsi), "r"(rdx),
        "r"(r10), "r"(r8),  "r"(r9)
      : "rcx", "r11", "cc", "memory"
    );

    result = (void *)rax;
  #elif defined(__riscv)
    __asm__ volatile(
      "mv a0,%[addr]\n"
      "mv a1,%[len]\n"
      "mv a2,%[prot]\n"
      "mv a3,%[flags]\n"
      "mv a4,%[fd]\n"
      "mv a5,%[off]\n"
      "li a7,%[nr]\n"
      "ecall"
      : "=r"(result)
      : [addr]"0"(addr), [len]"r"(length), [prot]"r"(prot),
      [flags]"r"(flags), [fd]"r"(fd), [off]"r"(offset),
      [nr]"i"(SYS_mmap)
      : "a1", "a2", "a3", "a4", "a5", "a7", "cc", "memory"
    );
  #endif

  CHECK_SYSCALL_ERROR(result);

  return result;
}

static __attribute__((always_inline)) inline void *sys_mremap(void *old_address, size_t old_size, size_t new_size, int flags, void *new_address) {
  void *result;

  #if defined(__arm__)
    register long r0 __asm__("r0") = (long)old_address;
    register long r1 __asm__("r1") = (long)old_size;
    register long r2 __asm__("r2") = (long)new_size;
    register long r3 __asm__("r3") = (long)flags;
    register long r4 __asm__("r4") = (long)new_address;
    register long r7 __asm__("r7") = SYS_mremap;

    __asm__ volatile(
      "svc #0"
      : "+r"(r0)
      : "r"(r1), "r"(r2), "r"(r3), "r"(r4), "r"(r7)
      : "cc", "memory"
    );

    result = (void *)r0;
  #elif defined(__aarch64__)
    register long x0 __asm__("x0") = (long)old_address;
    register long x1 __asm__("x1") = (long)old_size;
    register long x2 __asm__("x2") = (long)new_size;
    register long x3 __asm__("x3") = (long)flags;
    register long x4 __asm__("x4") = (long)new_address;
    register long x8 __asm__("x8") = SYS_mremap;

    __asm__ volatile(
      "svc #0"
      : "+r"(x0)
      : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x8)
      : "cc", "memory"
    );

    result = (void *)x0;
  #elif defined(__i386__)
    __asm__ volatile(
      "int $0x80"
      : "=a"(result)
      : "a"(SYS_mremap), "b"(old_address), "c"(old_size),
        "d"(new_size), "S"(flags), "D"(new_address)
      : "memory", "cc"
    );
  #elif defined(__x86_64__)
    register long rdi __asm__("rdi") = (long)old_address;
    register long rsi __asm__("rsi") = (long)old_size;
    register long rdx __asm__("rdx") = (long)new_size;
    register long r10 __asm__("r10") = (long)flags;
    register long  r8 __asm__("r8")  = (long)new_address;
    register long rax __asm__("rax") = SYS_mremap;

    __asm__ volatile(
      "syscall"
      : "+r"(rax)
      : "r"(rdi), "r"(rsi), "r"(rdx),
      "r"(r10), "r"(r8)
      : "rcx", "r11", "cc", "memory"
    );

    result = (void *)rax;
  #elif defined(__riscv)
    __asm__ volatile(
      "mv a0,%[old]\n"
      "mv a1,%[osz]\n"
      "mv a2,%[nsz]\n"
      "mv a3,%[flg]\n"
      "mv a4,%[new]\n"
      "li a7,%[nr]\n"
      "ecall"
      : "=r"(result)
      : [old]"0"(old_address), [osz]"r"(old_size),
        [nsz]"r"(new_size), [flg]"r"(flags),
        [new]"r"(new_address), [nr]"i"(SYS_mremap)
      : "a1", "a2", "a3", "a4", "a7", "cc", "memory"
    );
  #endif

  CHECK_SYSCALL_ERROR(result);

  return result;
}

static __attribute__((always_inline)) inline int sys_munmap(void *addr, size_t length) {
  long result;

  #if defined(__arm__)
    register long r0 __asm__("r0") = (long)addr;
    register long r1 __asm__("r1") = (long)length;
    register long r7 __asm__("r7") = SYS_munmap;

    __asm__ volatile(
      "svc #0"
      : "+r"(r0)
      : "r"(r1), "r"(r7)
      : "cc", "memory"
    );
    result = r0;
  #elif defined(__aarch64__)
    register long x0 __asm__("x0") = (long)addr;
    register long x1 __asm__("x1") = (long)length;
    register long x8 __asm__("x8") = SYS_munmap;

    __asm__ volatile(
      "svc #0"
      : "+r"(x0)
      : "r"(x1), "r"(x8)
      : "cc", "memory"
    );
    result = x0;
  #elif defined(__i386__)
    __asm__ volatile(
      "int $0x80"
      : "=a"(result)
      : "a"(SYS_munmap), "b"(addr), "c"(length)
      : "memory", "cc"
    );
  #elif defined(__x86_64__)
    register long rdi __asm__("rdi") = (long)addr;
    register long rsi __asm__("rsi") = (long)length;
    register long rax __asm__("rax") = SYS_munmap;

    __asm__ volatile(
      "syscall"
      : "+r"(rax)
      : "r"(rdi), "r"(rsi)
      : "rcx", "r11", "cc", "memory"
    );
    result = rax;
  #elif defined(__riscv)
    __asm__ volatile(
      "mv a1, %[len]\n"
      "li a7, %[nr]\n"
      "ecall"
      : "=r"(result)
      : "0"(addr), [len]"r"(length), [nr]"i"(SYS_munmap)
      : "a1", "a7", "cc", "memory"
    );
  #endif

  CHECK_SYSCALL_ERROR_INTEGER(result);

  return (int)result;
}

#endif