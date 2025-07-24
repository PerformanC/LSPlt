#ifndef LSPLT_ELF_UTIL_H
#define LSPLT_ELF_UTIL_H

#include <stdint.h>
#include <stdbool.h>
#include <link.h>

struct Elf {
  ElfW(Addr) base_addr_;
  ElfW(Addr) bias_addr_;

  ElfW(Ehdr) *header_;
  ElfW(Phdr) *program_header_;

  ElfW(Dyn) *dynamic_;  /* INFO: .dynamic */
  ElfW(Word) dynamic_size_;

  const char *dyn_str_;  /* INFO: .dynstr (string-table) */
  ElfW(Sym) *dyn_sym_;   /* INFO: .dynsym (symbol-index to string-table's offset) */

  ElfW(Addr) rel_plt_;  /* INFO: .rel.plt or .rela.plt */
  ElfW(Word) rel_plt_size_;

  ElfW(Addr) rel_dyn_;  /* INFO: .rel.dyn or .rela.dyn */
  ElfW(Word) rel_dyn_size_;

  ElfW(Addr) rel_android_;  /* INFO: android compressed rel or rela */
  ElfW(Word) rel_android_size_;

  /* INFO: for ELF hash */
  uint32_t *bucket_;
  uint32_t bucket_count_;
  uint32_t *chain_;

  /* INFO: append for GNU hash */
  uint32_t sym_offset_;
  ElfW(Addr) *bloom_;
  uint32_t bloom_size_;
  uint32_t bloom_shift_;

  bool is_use_rela_;
  bool valid_;
};

void elfutil_init(struct Elf *elf, uintptr_t base_addr);

size_t elfutil_find_plt_addr(const struct Elf *elf, const char *name, uintptr_t **out_addrs);

#endif /* LSPLT_ELF_UTIL_H */