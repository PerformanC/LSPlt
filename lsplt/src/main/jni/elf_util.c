#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "logging.h"

#include "elf_util.h"

#if defined(__arm__)
  #define ELF_R_GENERIC_JUMP_SLOT R_ARM_JUMP_SLOT  /* INFO: .rel.plt */
  #define ELF_R_GENERIC_GLOB_DAT R_ARM_GLOB_DAT    /* INFO: .rel.dyn */
  #define ELF_R_GENERIC_ABS R_ARM_ABS32            /* INFO: .rel.dyn */
#elif defined(__aarch64__)
  #define ELF_R_GENERIC_JUMP_SLOT R_AARCH64_JUMP_SLOT
  #define ELF_R_GENERIC_GLOB_DAT R_AARCH64_GLOB_DAT
  #define ELF_R_GENERIC_ABS R_AARCH64_ABS64
#elif defined(__i386__)
  #define ELF_R_GENERIC_JUMP_SLOT R_386_JMP_SLOT
  #define ELF_R_GENERIC_GLOB_DAT R_386_GLOB_DAT
  #define ELF_R_GENERIC_ABS R_386_32
#elif defined(__x86_64__)
  #define ELF_R_GENERIC_JUMP_SLOT R_X86_64_JUMP_SLOT
  #define ELF_R_GENERIC_GLOB_DAT R_X86_64_GLOB_DAT
  #define ELF_R_GENERIC_ABS R_X86_64_64
#elif defined(__riscv)
  #define ELF_R_GENERIC_JUMP_SLOT R_RISCV_JUMP_SLOT
  #define ELF_R_GENERIC_GLOB_DAT R_RISCV_64
  #define ELF_R_GENERIC_ABS R_RISCV_64
#endif

#ifdef __LP64__
  #define ELF_R_SYM(info) ELF64_R_SYM(info)
  #define ELF_R_TYPE(info) ELF64_R_TYPE(info)
#else
  #define ELF_R_SYM(info) ELF32_R_SYM(info)
  #define ELF_R_TYPE(info) ELF32_R_TYPE(info)
#endif

static void *offset_of(ElfW(Ehdr) *head, ElfW(Off) off) {
  return (void *)(uintptr_t)head + off;
}

static bool set_by_offset(ElfW(Addr) *ptr, ElfW(Addr) base, ElfW(Addr) bias, ElfW(Addr) off) {
  ElfW(Addr) val = bias + off;

  if (val >= base) {
    *ptr = val;

    return true;
  }

  LOGE("Failed to set pointer: base=0x%" PRIxPTR ", bias=0x%" PRIxPTR ", off=0x%" PRIxPTR ", val=0x%" PRIxPTR, (uintptr_t)base, (uintptr_t)bias, (uintptr_t)off, (uintptr_t)val);

  *ptr = 0;

  return false;
}

void elfutil_init(struct Elf *elf, uintptr_t base_addr) {
  elf->header_ = (ElfW(Ehdr) *)base_addr;
  elf->base_addr_ = base_addr;

  /* INFO: check magic */
  if (0 != memcmp(elf->header_->e_ident, ELFMAG, SELFMAG)) return;

  /* INFO: check class (64/32) */
  #ifdef __LP64__
    if (ELFCLASS64 != elf->header_->e_ident[EI_CLASS]) return;
  #else
    if (ELFCLASS32 != elf->header_->e_ident[EI_CLASS]) return;
  #endif

  /* INFO: check endian (little/big) */
  if (ELFDATA2LSB != elf->header_->e_ident[EI_DATA]) return;

  /* INFO: check version */
  if (EV_CURRENT != elf->header_->e_ident[EI_VERSION]) return;

  /* INFO: check type */
  if (ET_EXEC != elf->header_->e_type && ET_DYN != elf->header_->e_type) return;

  /* INFO: check machine */
  #if defined(__arm__)
    if (EM_ARM != elf->header_->e_machine) return;
  #elif defined(__aarch64__)
    if (EM_AARCH64 != elf->header_->e_machine) return;
  #elif defined(__i386__)
    if (EM_386 != elf->header_->e_machine) return;
  #elif defined(__x86_64__)
    if (EM_X86_64 != elf->header_->e_machine) return;
  #elif defined(__riscv)
    if (EM_RISCV != elf->header_->e_machine) return;
  #else
    LOGE("Unsupported architecture: %s", ELF_MACHINE_NAME(elf->header_->e_machine));

    return;
  #endif

  if (elf->header_->e_version != EV_CURRENT) {
    LOGE("Unsupported ELF version: %d", elf->header_->e_version);

    elf->valid_ = false;

    return;
  }

  elf->program_header_ = offset_of(elf->header_, elf->header_->e_phoff);

  uintptr_t ph_off = (uintptr_t)elf->program_header_;
  for (int i = 0; i < elf->header_->e_phnum; i++, ph_off += elf->header_->e_phentsize) {
    ElfW(Phdr) *program_header = (ElfW(Phdr) *)ph_off;

    if (program_header->p_type == PT_LOAD && program_header->p_offset == 0) {
      if (elf->base_addr_ < program_header->p_vaddr) continue;

      elf->bias_addr_ = elf->base_addr_ - program_header->p_vaddr;
    } else if (program_header->p_type == PT_DYNAMIC) {
      elf->dynamic_ = (ElfW(Dyn) *)program_header->p_vaddr;
      elf->dynamic_size_ = program_header->p_memsz;
    }
  }

  if (!elf->dynamic_ || !elf->bias_addr_) {
    LOGE("Failed to find dynamic section or bias address in ELF header");

    elf->valid_ = false;

    return;
  }

  elf->dynamic_ = (ElfW(Dyn) *)(elf->bias_addr_ + (uintptr_t)elf->dynamic_);

  for (ElfW(Dyn) *dynamic = elf->dynamic_, *dynamic_end = elf->dynamic_ + (elf->dynamic_size_ / sizeof(dynamic[0])); dynamic < dynamic_end; ++dynamic) {
    switch (dynamic->d_tag) {
      case DT_NULL: {
        dynamic = dynamic_end;

        break;
      }
      case DT_STRTAB: {
        if (!set_by_offset((ElfW(Addr) *)&elf->dyn_str_, elf->base_addr_, elf->bias_addr_, dynamic->d_un.d_ptr)) return;

        break;
      }
      case DT_SYMTAB: {
        if (!set_by_offset((ElfW(Addr) *)&elf->dyn_sym_, elf->base_addr_, elf->bias_addr_, dynamic->d_un.d_ptr)) return;

        break;
      }
      case DT_PLTREL: {
        elf->is_use_rela_ = dynamic->d_un.d_val == DT_RELA;

        break;
      }
      case DT_JMPREL: {
        if (!set_by_offset((ElfW(Addr) *)&elf->rel_plt_, elf->base_addr_, elf->bias_addr_, dynamic->d_un.d_ptr)) return;

        break;
      }
      case DT_PLTRELSZ: {
        elf->rel_plt_size_ = dynamic->d_un.d_val;

        break;
      }
      case DT_REL:
      case DT_RELA: {
        if (!set_by_offset((ElfW(Addr) *)&elf->rel_dyn_, elf->base_addr_, elf->bias_addr_, dynamic->d_un.d_ptr)) return;

        break;
      }
      case DT_RELSZ:
      case DT_RELASZ: {
        elf->rel_dyn_size_ = dynamic->d_un.d_val;

        break;
      }
      case DT_ANDROID_REL:
      case DT_ANDROID_RELA: {
        if (!set_by_offset((ElfW(Addr) *)&elf->rel_android_, elf->base_addr_, elf->bias_addr_, dynamic->d_un.d_ptr)) return;

        break;
      }
      case DT_ANDROID_RELSZ:
      case DT_ANDROID_RELASZ: {
        elf->rel_android_size_ = dynamic->d_un.d_val;

        break;
      }
      case DT_HASH: {
        if (elf->bloom_) continue;

        ElfW(Word) *raw = (ElfW(Word) *)(elf->bias_addr_ + dynamic->d_un.d_ptr);
        elf->bucket_count_ = raw[0];
        elf->bucket_ = raw + 2;
        elf->chain_ = elf->bucket_ + elf->bucket_count_;

        break;
      }
      case DT_GNU_HASH: {
        ElfW(Word) *raw = (ElfW(Word) *)(elf->bias_addr_ + dynamic->d_un.d_ptr);
        elf->bucket_count_ = raw[0];
        elf->sym_offset_ = raw[1];
        elf->bloom_size_ = raw[2];
        elf->bloom_shift_ = raw[3];
        elf->bloom_ = (ElfW(Addr) *)(raw + 4);
        elf->bucket_ = (uint32_t *)(elf->bloom_ + elf->bloom_size_);
        elf->chain_ = elf->bucket_ + elf->bucket_count_ - elf->sym_offset_;
        // elf->is_use_gnu_hash_ = true;

        break;
      }
      default: break;
    }
  }

  if (0 != elf->rel_android_) {
    const char *rel = (const char *)elf->rel_android_;
    if (elf->rel_android_size_ < 4 || rel[0] != 'A' || rel[1] != 'P' || rel[2] != 'S' || rel[3] != '2')
      return;

    elf->rel_android_ += 4;
    elf->rel_android_size_ -= 4;
  }

  elf->valid_ = true;
}

static uint32_t elfutil_gnu_lookup(const struct Elf *elf, const char *name) {
  static uint32_t kBloomMaskBits = sizeof(ElfW(Addr) *) * 8;
  static uint32_t kInitialHash = 5381;
  static uint32_t kHashShift = 5;

  if (!elf->bucket_ || !elf->bloom_ || !elf->bloom_size_) return 0;

  uint32_t hash = kInitialHash;
  for (int i = 0; name[i]; i++) {
    hash += (hash << kHashShift) + name[i];
  }

  ElfW(Addr) bloom_word = elf->bloom_[(hash / kBloomMaskBits) % elf->bloom_size_];
  uintptr_t mask = 0 | (uintptr_t)1 << (hash % kBloomMaskBits) | (uintptr_t)1 << ((hash >> elf->bloom_shift_) % kBloomMaskBits);
  if ((mask & bloom_word) == mask) {
    int idx = elf->bucket_[hash % elf->bucket_count_];
    const char *strings = elf->dyn_str_;

    do {
      if ((uint32_t)idx >= elf->sym_offset_) break;

      ElfW(Sym) *sym = elf->dyn_sym_ + idx;
      if (((elf->chain_[idx] ^ hash) >> 1) == 0 && strcmp(name, strings + sym->st_name) == 0)
        return idx;
    } while ((elf->chain_[idx++] & 1) == 0);
  }

  return 0;
}

static uint32_t elfutil_elf_lookup(const struct Elf *elf, const char *name) {
  static uint32_t kHashMask = 0xf0000000;
  static uint32_t kHashShift = 24;
  uint32_t hash = 0;
  uint32_t tmp;

  if (!elf->bucket_ || elf->bloom_) return 0;

  for (int i = 0; name[i]; i++) {
    hash = (hash << 4) + name[i];
    tmp = hash & kHashMask;
    hash ^= tmp;
    hash ^= tmp >> kHashShift;
  }

  const char *strings = elf->dyn_str_;
  for (int idx = elf->bucket_[hash % elf->bucket_count_]; idx != 0; idx = elf->chain_[idx]) {
    ElfW(Sym) *sym = elf->dyn_sym_ + idx;
    if (strcmp(name, strings + sym->st_name) == 0) {
      return idx;
    }
  }

  return 0;
}

static uint32_t elfutil_linear_lookup(const struct Elf *elf, const char *name) {
  if (!elf->dyn_sym_ || !elf->sym_offset_) return 0;

  for (uint32_t idx = 0; idx < elf->sym_offset_; idx++) {
    ElfW(Sym) *sym = elf->dyn_sym_ + idx;

    if (strcmp(name, elf->dyn_str_ + sym->st_name) == 0) return idx;
  }

  return 0;
}

static void elfutil_looper(const struct Elf *elf, uint32_t idx, const void *rel_ptr, const ElfW(Word) rel_size,
                           bool is_plt, uintptr_t **res, size_t *res_size) {
  const void *rel_end = (const void *)((uintptr_t)rel_ptr + rel_size);

  size_t rel_entry_size = elf->is_use_rela_ ? sizeof(ElfW(Rela)) : sizeof(ElfW(Rel));
  for (const char *p = (const char *)rel_ptr; p < (const char *)rel_end; p += rel_entry_size) {
    ElfW(Xword) r_info   = elf->is_use_rela_ ? ((const ElfW(Rela) *)p)->r_info : ((const ElfW(Rel) *)p)->r_info;
    ElfW(Addr)  r_offset = elf->is_use_rela_ ? ((const ElfW(Rela) *)p)->r_offset : ((const ElfW(Rel) *)p)->r_offset;
    uint32_t    r_sym    = ELF_R_SYM(r_info);
    uint32_t    r_type   = ELF_R_TYPE(r_info);

    if (r_sym != idx) continue;
    if (is_plt && r_type != ELF_R_GENERIC_JUMP_SLOT) continue;
    if (!is_plt && (r_type != ELF_R_GENERIC_ABS && r_type != ELF_R_GENERIC_GLOB_DAT)) continue;

    uintptr_t addr = elf->bias_addr_ + r_offset;
    if (addr > elf->base_addr_) {
      uintptr_t *new_res = (uintptr_t *)realloc(*res, (*res_size + 1) * sizeof(uintptr_t));
      if (!new_res) {
        LOGE("Failed to allocate memory for PLT addresses");

        free(*res);
        *res = NULL;
        *res_size = 0;

        return;
      }

      *res = new_res;
      (*res)[*res_size] = addr;
      (*res_size)++;
    }

    if (is_plt) break;
  }
}

size_t elfutil_find_plt_addr(const struct Elf *elf, const char *name, uintptr_t **out_addrs) {
  if (!elf->valid_ || out_addrs == NULL) return 0;

  uint32_t idx = elfutil_gnu_lookup(elf, name);
  if (!idx) idx = elfutil_elf_lookup(elf, name);
  if (!idx) idx = elfutil_linear_lookup(elf, name);
  if (!idx) return 0;

  *out_addrs = NULL;
  size_t count = 0;

  elfutil_looper(elf, idx, (void *)elf->rel_plt_,     elf->rel_plt_size_,     true,  out_addrs, &count);
  elfutil_looper(elf, idx, (void *)elf->rel_dyn_,     elf->rel_dyn_size_,     false, out_addrs, &count);
  elfutil_looper(elf, idx, (void *)elf->rel_android_, elf->rel_android_size_, false, out_addrs, &count);

  return count;
}

static void elfutil_looper_by_prefix(const struct Elf *elf, const void *rel_ptr, const ElfW(Word) rel_size,
                                     bool is_plt, const char *name_prefix, size_t prefix_len,
                                     uintptr_t **res, size_t *res_size) {
  if (!rel_ptr || rel_size == 0 || !elf->dyn_sym_ || !elf->dyn_str_) return;

  const void *rel_end = (const void *)((uintptr_t)rel_ptr + rel_size);
  size_t rel_entry_size = elf->is_use_rela_ ? sizeof(ElfW(Rela)) : sizeof(ElfW(Rel));

  for (const char *p = (const char *)rel_ptr; p < (const char *)rel_end; p += rel_entry_size) {
    ElfW(Xword) r_info   = elf->is_use_rela_ ? ((const ElfW(Rela) *)p)->r_info : ((const ElfW(Rel) *)p)->r_info;
    ElfW(Addr)  r_offset = elf->is_use_rela_ ? ((const ElfW(Rela) *)p)->r_offset : ((const ElfW(Rel) *)p)->r_offset;
    uint32_t    r_sym    = ELF_R_SYM(r_info);
    uint32_t    r_type   = ELF_R_TYPE(r_info);

    if (is_plt && r_type != ELF_R_GENERIC_JUMP_SLOT) continue;
    if (!is_plt && (r_type != ELF_R_GENERIC_ABS && r_type != ELF_R_GENERIC_GLOB_DAT)) continue;

    ElfW(Sym) *sym = elf->dyn_sym_ + r_sym;
    if (!sym || sym->st_name == 0) continue;

    const char *sym_name = elf->dyn_str_ + sym->st_name;
    if (!sym_name || strncmp(sym_name, name_prefix, prefix_len) != 0) continue;

    LOGD("Found symbol by prefix: %s", sym_name);

    uintptr_t addr = elf->bias_addr_ + r_offset;
    if (addr <= elf->base_addr_) continue;

    uintptr_t *new_res = (uintptr_t *)realloc(*res, (*res_size + 1) * sizeof(uintptr_t));
    if (!new_res) {
      LOGE("Failed to allocate memory for PLT addresses");

      free(*res);
      *res = NULL;
      *res_size = 0;

      return;
    }

    *res = new_res;
    (*res)[*res_size] = addr;
    (*res_size)++;
  }
}

size_t elfutil_find_plt_addr_by_prefix(const struct Elf *elf, const char *name_prefix, uintptr_t **out_addrs) {
  if (!elf->valid_ || out_addrs == NULL) return 0;

  size_t prefix_len = strlen(name_prefix);

  size_t count = 0;
  uintptr_t *res = NULL;

  elfutil_looper_by_prefix(elf, (void *)elf->rel_plt_,     elf->rel_plt_size_,     true,  name_prefix, prefix_len, &res, &count);
  elfutil_looper_by_prefix(elf, (void *)elf->rel_dyn_,     elf->rel_dyn_size_,     false, name_prefix, prefix_len, &res, &count);
  elfutil_looper_by_prefix(elf, (void *)elf->rel_android_, elf->rel_android_size_, false, name_prefix, prefix_len, &res, &count);

  *out_addrs = res;

  return count;
}
