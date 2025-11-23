#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <inttypes.h>
#include <ctype.h>
#include <limits.h>

#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/sysmacros.h>

#include <unistd.h>
#include <pthread.h>
#include <wait.h>

#include "elf_util.h"
#include "logging.h"

#include "lsplt.h"

struct lsplt_register_info {
  dev_t dev;
  ino_t inode;

  uintptr_t offset_range_start;
  uintptr_t offset_range_end;

  char *symbol;
  bool is_prefix;

  void *callback;
  void **backup;
};

struct lsplt_register_infos {
  struct lsplt_register_info *infos;
  size_t length;
};

struct lsplt_hook_entry {
  uintptr_t addr;
  uintptr_t backup;
};

struct lsplt_hook_entries {
  struct lsplt_hook_entry *entries;
  size_t length;
};

struct lsplt_hook_info {
  struct lsplt_map_entry map;
  struct lsplt_hook_entries hooks;

  uintptr_t backup_region;
  struct Elf elf;
  bool self;
};

struct lsplt_hook_infos {
  struct lsplt_hook_info *infos;
  size_t length;
};

static pthread_mutex_t g_hook_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct lsplt_register_infos *g_register_info_list = NULL;
static struct lsplt_hook_infos *g_hook_infos = NULL;

static uintptr_t k_page_size = 0;
#include "syscall.h"

static inline char *page_start(uintptr_t addr) {
  if (k_page_size == 0) k_page_size = getpagesize();

  return (char *)(addr / k_page_size * k_page_size);
}

static inline char *page_end(uintptr_t addr) {
  if (k_page_size == 0) k_page_size = getpagesize();

  return (char *)((addr / k_page_size * k_page_size) + k_page_size);
}

static inline void *lsplt_memcpy(void *dst, const void *src, size_t len) {
  unsigned char *d = (unsigned char *)dst;
  const unsigned char *s = (const unsigned char *)src;

  while (len--) *d++ = *s++;

  return dst;
}

static bool hook_info_match(const struct lsplt_hook_info *info, const struct lsplt_register_info *reg) {
  return reg->dev == info->map.dev && reg->inode == info->map.inode &&
         info->map.offset >= reg->offset_range_start &&
         info->map.offset < reg->offset_range_end;
}

static void free_hook_info_content(struct lsplt_hook_info *info) {
  free(info->map.path);
  free(info->hooks.entries);

  memset(info, 0, sizeof(struct lsplt_hook_info));
}

static void free_hook_infos(struct lsplt_hook_infos *infos) {
  for (size_t i = 0; i < infos->length; ++i) {
    free_hook_info_content(&infos->infos[i]);
  }

  free(infos->infos);
  free(infos);
}

static int compare_hook_infos_desc(const void *a, const void *b) {
  const struct lsplt_hook_info *info_a = (const struct lsplt_hook_info *)a;
  const struct lsplt_hook_info *info_b = (const struct lsplt_hook_info *)b;

  if (info_a->map.start < info_b->map.start) return 1;
  if (info_a->map.start > info_b->map.start) return -1;

  return 0;
}

static struct lsplt_hook_infos *scan_and_create_hook_infos(struct lsplt_map_info *maps) {
  struct lsplt_hook_infos *new_infos = calloc(1, sizeof(struct lsplt_hook_infos));
  if (!new_infos) {
    PLOGE("allocate memory for hook infos");

    return NULL;
  }

  static ino_t self_inode = 0;
  static dev_t self_dev = 0;

  if (self_inode == 0) {
    uintptr_t self_addr = (uintptr_t)__builtin_return_address(0);

    for (size_t i = 0; i < maps->length; ++i) {
      struct lsplt_map_entry map = maps->maps[i];

      if (self_addr < map.start || self_addr >= map.end) continue;

      self_inode = map.inode;
      self_dev = map.dev;

      LOGV("self inode = %lu", self_inode);

      break;
    }
  }

  #define ISNT_VALID_LIBRARY(map) \
    (!map->is_private || !(map->perms & PROT_READ) || map->path == NULL || map->path[0] == '[')

  size_t infos_length = 0;
  for (size_t i = 0; i < maps->length; ++i) {
    struct lsplt_map_entry *map = &maps->maps[i];
    if (ISNT_VALID_LIBRARY(map))
      continue;

    infos_length++;
  }

  new_infos->infos = calloc(infos_length, sizeof(struct lsplt_hook_info));
  if (!new_infos->infos) {
    LOGE("Failed to allocate memory for hook infos");

    free(new_infos);

    return NULL;
  }

  for (size_t i = 0; i < maps->length; i++) {
    struct lsplt_map_entry *map = &maps->maps[i];
    if (ISNT_VALID_LIBRARY(map))
      continue;

    struct lsplt_hook_info *info = &new_infos->infos[new_infos->length++];
    info->map = *map;
    info->map.path = strdup(map->path);
    if (!info->map.path) {
      LOGE("Failed to duplicate map path");

      free_hook_infos(new_infos);

      return NULL;
    }

    info->self = (map->inode == self_inode && map->dev == self_dev);
  }

  #undef ISNT_VALID_LIBRARY

  qsort(new_infos->infos, new_infos->length, sizeof(struct lsplt_hook_info), compare_hook_infos_desc);

  return new_infos;
}

static bool filter_hook_infos(struct lsplt_hook_infos *infos) {
  size_t write_idx = 0;
  for (size_t read_idx = 0; read_idx < infos->length; read_idx++) {
    struct lsplt_hook_info *info = &infos->infos[read_idx];
    bool matched = false;

    for (size_t i = 0; i < g_register_info_list->length; i++) {
      struct lsplt_register_info *reg = &g_register_info_list->infos[i];
      if (!reg->symbol || !hook_info_match(info, reg)) continue;

      matched = true;

      break;
    }

    if (matched) {
      LOGV("Match hook info %s:%lu %" PRIxPTR " %" PRIxPTR "-%" PRIxPTR,
           info->map.path, info->map.inode, info->map.start,
           info->map.end, info->map.offset);

      if (write_idx != read_idx) {
        infos->infos[write_idx] = infos->infos[read_idx];
        memset(&infos->infos[read_idx], 0, sizeof(struct lsplt_hook_info));
      }

      write_idx++;
    } else {
      free_hook_info_content(info);
    }
  }

  if (write_idx == 0) {
    LOGV("No hook infos matched, freeing");

    free(infos->infos);
    infos->infos = NULL;
    infos->length = 0;

    return false;
  }

  /* INFO: Resize immediatly to the needed size to avoid keeping
             using too much memory unnecessarily. */
  struct lsplt_hook_info *tmp_infos = realloc(infos->infos, write_idx * sizeof(struct lsplt_hook_info));
  if (!tmp_infos) {
    /* INFO: If it fails, it doesn't necessarily cause issues, it will just bloat
             the structure. */
    PLOGE("reallocate memory for hook infos");
  } else {
    infos->infos = tmp_infos;
  }

  infos->length = write_idx;

  return true;
}

static bool copy_hook_info_content(struct lsplt_hook_info *dest, const struct lsplt_hook_info *src) {
  *dest = *src;

  dest->map.path = strdup(src->map.path);
  if (!dest->map.path) {
    LOGE("Failed to duplicate map path");

    return false;
  }

  if (src->hooks.length > 0) {
    dest->hooks.entries = malloc(src->hooks.length * sizeof(struct lsplt_hook_entry));
    if (!dest->hooks.entries) {
      LOGE("Failed to allocate memory for hook entries copy");

      if (dest->map.path) free(dest->map.path);

      return false;
    }

    memcpy(dest->hooks.entries, src->hooks.entries, src->hooks.length * sizeof(struct lsplt_hook_entry));
    dest->hooks.length = src->hooks.length;
  }

  return true;
}

static bool merge_hook_infos(struct lsplt_hook_infos *new_infos, struct lsplt_hook_infos *old_infos) {
  for (size_t i = 0; i < old_infos->length; ++i) {
    struct lsplt_hook_info *old_info = &old_infos->infos[i];
    bool found_in_new = false;

    for (size_t j = 0; j < new_infos->length; ++j) {
      if (new_infos->infos[j].map.start != old_info->map.start) continue;

      free_hook_info_content(&new_infos->infos[j]);
      if (!copy_hook_info_content(&new_infos->infos[j], old_info)) {
        LOGE("Failed to deep copy hook info during merge");

        return false;
      }

      found_in_new = true;

      break;
    }

    if (!found_in_new) {
      struct lsplt_hook_info *tmp_infos = realloc(new_infos->infos, (new_infos->length + 1) * sizeof(struct lsplt_hook_info));
      if (!tmp_infos) {
        PLOGE("reallocate for merging hooks infos");

        return false;
      }
      new_infos->infos = tmp_infos;

      if (!copy_hook_info_content(&new_infos->infos[new_infos->length], old_info)) {
        LOGE("Failed to deep copy new hook info during merge");

        return false;
      }
      new_infos->length++;
    }
  }

  /* INFO: If any information was added or updated, the list is out of order */
  qsort(new_infos->infos, new_infos->length, sizeof(struct lsplt_hook_info), compare_hook_infos_desc);

  return true;
}

static bool do_hook_addr(struct lsplt_hook_infos *infos, uintptr_t addr, uintptr_t callback, uintptr_t *backup);

struct hook_symbol_info {
  void **addresses;
  size_t length;

  void *callback;
  void *backup;
};

static bool do_hooks_for_all_registered(struct lsplt_hook_infos *infos) {
  bool overall_res = true;

  struct hook_symbol_info *symbol_addresses = NULL;
  size_t symbol_addresses_length = 0;

  for (size_t i = 0; i < infos->length; ++i) {
    struct lsplt_hook_info *info = &infos->infos[i];

    for (size_t j = 0; j < g_register_info_list->length; ++j) {
      struct lsplt_register_info *reg = &g_register_info_list->infos[j];
      if (!reg->symbol) continue;

      if (info->map.offset != reg->offset_range_start || !hook_info_match(info, reg))
        continue;

      bool is_to_restore = false;
      if (g_hook_infos) for (size_t j = 0; j < g_hook_infos->length; ++j) {
        struct lsplt_hook_info *hook_info = &g_hook_infos->infos[j];

        for (size_t k = 0; k < hook_info->hooks.length; ++k) {
          struct lsplt_hook_entry *hook_entry = &hook_info->hooks.entries[k];

          if (hook_entry->backup == (uintptr_t)reg->callback) {
            LOGV("Restoring %s from %p via cached address", reg->symbol, (void *)hook_entry->addr);

            is_to_restore = true;

            overall_res = do_hook_addr(infos, hook_entry->addr, hook_entry->backup, NULL) && overall_res;

            break;
          }
        }
      }

      if (!info->elf.base_addr_ && !is_to_restore)
        elfutil_init(&info->elf, info->map.start);

      if (info->elf.valid_ && !is_to_restore) {
        uintptr_t *addrs = NULL;
        size_t addrs_length;
        if (!reg->is_prefix) addrs_length = elfutil_find_plt_addr(&info->elf, reg->symbol, &addrs);
        else addrs_length = elfutil_find_plt_addr_by_prefix(&info->elf, reg->symbol, &addrs);

        if (addrs_length == 0) {
          LOGE("Failed to find PLT address for %s in %s", reg->symbol, info->map.path);

          overall_res = false;

          free(addrs);
          addrs = NULL;

          goto delete_reg;
        }

        struct hook_symbol_info *tmp_symbol_addresses = realloc(symbol_addresses,
                                                                (symbol_addresses_length + 1) * sizeof(*symbol_addresses));
        if (!tmp_symbol_addresses) {
          PLOGE("allocate memory for symbol addresses");

          overall_res = false;

          free(addrs);
          addrs = NULL;

          goto delete_reg;
        }

        symbol_addresses = tmp_symbol_addresses;

        struct hook_symbol_info *sym_addr = &symbol_addresses[symbol_addresses_length++];
        sym_addr->addresses = (void **)addrs;
        sym_addr->length = addrs_length;
        sym_addr->callback = reg->callback;
        sym_addr->backup = reg->backup;
      }

      free(reg->symbol);
      reg->symbol = NULL;

      continue;

    delete_reg:
      free(reg->symbol);
      reg->symbol = NULL;

      if (j < g_register_info_list->length - 1) {
        memmove(&g_register_info_list->infos[j], &g_register_info_list->infos[j + 1],
                (g_register_info_list->length - j - 1) * sizeof(struct lsplt_register_info));
      }

      if (g_register_info_list->length > 0) {
        memset(&g_register_info_list->infos[g_register_info_list->length - 1], 0,
               sizeof(struct lsplt_register_info));
        g_register_info_list->length--;
      }

      if (j != 0) j--;

      break;
    }
  }

  if (overall_res) {
    for (size_t i = 0; i < symbol_addresses_length; ++i) {
      struct hook_symbol_info *sym_info = &symbol_addresses[i];

      for (size_t j = 0; j < sym_info->length; ++j) {
        overall_res = do_hook_addr(infos, (uintptr_t)sym_info->addresses[j], (uintptr_t)sym_info->callback, (uintptr_t *)sym_info->backup) && overall_res;
      }
    }
  }

  for (size_t i = 0; i < symbol_addresses_length; ++i) {
    free(symbol_addresses[i].addresses);
  }

  free(symbol_addresses);

  return overall_res;
}

static bool do_hook_addr(struct lsplt_hook_infos *infos, uintptr_t addr, uintptr_t callback, uintptr_t *backup) {
  LOGV("Hooking %p", (void *)addr);

  struct lsplt_hook_info *info = NULL;
  /* INFO because the array is sorted descending, the first match is the correct one */
  for (size_t i = 0; i < infos->length; i++) {
    if (addr < infos->infos[i].map.start || addr >= infos->infos[i].map.end) continue;

    info = &infos->infos[i];

    break;
  }

  if (!info) {
    LOGE("No hook info found for address %p", (void *)addr);

    return false;
  }

  const size_t len = info->map.end - info->map.start;

  if (!info->backup_region && !info->self) {
    void *backup_addr = sys_mmap(NULL, len, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
    LOGD("Backup %p to %p", (void *)info->map.start, backup_addr);

    if (backup_addr == MAP_FAILED) {
      LOGE("Failed to allocate backup region for %p", (void *)info->map.start);

      return false;
    }

    void *new_addr = sys_mremap((void *)info->map.start, len, len, MREMAP_FIXED | MREMAP_MAYMOVE, backup_addr);
    if (new_addr == MAP_FAILED || new_addr != backup_addr) {
      LOGE("Failed to remap %p to backup %p", (void *)info->map.start, backup_addr);
  
      sys_munmap(backup_addr, len);

      return false;
    }

    new_addr = sys_mmap((void *)info->map.start, len, PROT_READ | PROT_WRITE | info->map.perms, MAP_PRIVATE | MAP_FIXED | MAP_ANON, -1, 0);
    if (new_addr == MAP_FAILED) {
      void *restore_addr = sys_mremap(backup_addr, len, len, MREMAP_FIXED | MREMAP_MAYMOVE, (void *)info->map.start);
      if (restore_addr == MAP_FAILED || restore_addr != (void *)info->map.start) {
        return false;
      }

      LOGE("Failed to remap %p to original %p", backup_addr, (void *)info->map.start);

      return false;
    }

    lsplt_memcpy((void *)info->map.start, backup_addr, len);
    info->backup_region = (uintptr_t)backup_addr;
  }

  if (info->self && !(info->map.perms & PROT_WRITE)) {
    mprotect((void *)info->map.start, len, info->map.perms | PROT_WRITE);
    info->map.perms |= PROT_WRITE;
  }

  uintptr_t *target_addr = (uintptr_t *)addr;
  uintptr_t original_addr = *target_addr;

  if (original_addr != callback) {
    *target_addr = callback;
    if (backup) *backup = original_addr;

    __builtin___clear_cache(page_start(addr), page_end(addr));
  }

  ssize_t hook_idx = -1;
  for (size_t i = 0; i < info->hooks.length; i++) {
    if (info->hooks.entries[i].addr != addr) continue;

    hook_idx = i;

    break;
  }

  if (hook_idx != -1) {
    if (callback == info->hooks.entries[hook_idx].backup) {
      info->hooks.length--;
      if (hook_idx < (ssize_t)info->hooks.length)
        memmove(&info->hooks.entries[hook_idx], &info->hooks.entries[hook_idx + 1], (info->hooks.length - hook_idx) * sizeof(struct lsplt_hook_entry));
    }
  } else {
    info->hooks.length++;
    struct lsplt_hook_entry *tmp_entries = realloc(info->hooks.entries, info->hooks.length * sizeof(struct lsplt_hook_entry));
    if (!tmp_entries) {
      LOGE("Failed to allocate memory for hook entries");

      return false;
    }
    info->hooks.entries = tmp_entries;

    info->hooks.entries[info->hooks.length - 1].addr = addr;
    info->hooks.entries[info->hooks.length - 1].backup = original_addr;
  }

  if (info->hooks.length == 0 && info->backup_region != 0 && !info->self) {
    LOGD("Restore %p from %p", (void *)info->map.start, (void *)info->backup_region);

    void *new_addr = sys_mremap((void *)info->backup_region, len, len, MREMAP_FIXED | MREMAP_MAYMOVE, (void *)info->map.start);
    if (new_addr == MAP_FAILED || (uintptr_t)new_addr != info->map.start) {
      LOGF("Failed to remap backup region %p to original %p", (void *)info->backup_region, (void *)info->map.start);

      return false;
    }

    info->backup_region = 0;
  }

  return true;
}

static ssize_t write_fd(int fd, int sendfd) {
  char cmsgbuf[CMSG_SPACE(sizeof(int))];
  char buf[1] = { 0 };

  struct iovec iov = {
    .iov_base = buf,
    .iov_len = 1
  };

  struct msghdr msg = {
    .msg_iov = &iov,
    .msg_iovlen = 1,
    .msg_control = cmsgbuf,
    .msg_controllen = sizeof(cmsgbuf)
  };

  struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_len = CMSG_LEN(sizeof(int));
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;

  memcpy(CMSG_DATA(cmsg), &sendfd, sizeof(int));

  ssize_t ret = sendmsg(fd, &msg, 0);
  if (ret == -1) {
    LOGE("sendmsg: %s\n", strerror(errno));

    return -1;
  }

  return ret;
}

static int read_fd(int fd) {
  char cmsgbuf[CMSG_SPACE(sizeof(int))];

  int cnt = 1;
  struct iovec iov = {
    .iov_base = &cnt,
    .iov_len = sizeof(cnt)
  };

  struct msghdr msg = {
    .msg_iov = &iov,
    .msg_iovlen = 1,
    .msg_control = cmsgbuf,
    .msg_controllen = sizeof(cmsgbuf)
  };

  ssize_t ret = recvmsg(fd, &msg, MSG_WAITALL);
  if (ret == -1) {
    LOGE("recvmsg: %s\n", strerror(errno));

    return -1;
  }

  struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
  if (cmsg == NULL) {
    LOGE("CMSG_FIRSTHDR: %s\n", strerror(errno));

    return -1;
  }

  int sendfd;
  memcpy(&sendfd, CMSG_DATA(cmsg), sizeof(int));

  return sendfd;
}

struct lsplt_map_info *lsplt_scan_maps(const char *pid) {
  int sockets[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) < 0) {
    LOGE("Failed to create socket pair for lsplt_scan_maps");

    return NULL;
  }

  int ppid = syscall(SYS_clone, SIGCHLD, 0);
  if (ppid == -1) {
    LOGE("Failed to clone process for lsplt_scan_maps");

    close(sockets[0]);
    close(sockets[1]);

    return NULL;
  }

  if (ppid == 0) {
    close(sockets[0]);

    char path[64];
    snprintf(path, sizeof(path), "/proc/%s/maps", pid);

    int maps_file = open(path, O_RDONLY | O_CLOEXEC);
    if (maps_file < 0) {
      LOGE("Failed to open %s in lsplt_scan_maps", path);

      uint8_t can_kill_myself = 0;
      if (TEMP_FAILURE_RETRY(write(sockets[1], &can_kill_myself, sizeof(can_kill_myself))) < 0) {
        LOGE("Failed to write to socket in lsplt_scan_maps");
      }

      goto scan_children_fail;
    }

    if (write_fd(sockets[1], maps_file) < 0) {
      LOGE("Failed to write file descriptor to socket in lsplt_scan_maps");

      goto post_open_scan_children_fail;
    }

    /* INFO: Wait for the parent process to finish reading */
    uint8_t can_kill_myself = 1;
    if (TEMP_FAILURE_RETRY(read(sockets[1], &can_kill_myself, sizeof(can_kill_myself))) < 0) {
      LOGE("Failed to read from socket in lsplt_scan_maps");

      goto post_open_scan_children_fail;
    }

    close(maps_file);
    close(sockets[1]);

    _exit(EXIT_SUCCESS);

    post_open_scan_children_fail:
      close(maps_file);
    scan_children_fail:
      close(sockets[1]);

      _exit(EXIT_FAILURE);
  }

  close(sockets[1]);

  int fd = read_fd(sockets[0]);
  if (fd < 0) {
    LOGE("Failed to read file descriptor from socket in lsplt_scan_maps");

    close(sockets[0]);

    return NULL;
  }

  FILE *fp = fdopen(fd, "r");
  if (!fp) {
    LOGE("Failed to open file descriptor as FILE in lsplt_scan_maps");

    close(fd);
    close(sockets[0]);

    return NULL;
  }

  struct lsplt_map_info *info_array = calloc(1, sizeof(struct lsplt_map_info));
  if (!info_array) {
    PLOGE("allocate memory for lsplt_map_info");

    close(fd);
    close(sockets[0]);

    return NULL;
  }

  size_t infos_capacity = 2;
  info_array->maps = malloc(infos_capacity * sizeof(struct lsplt_map_entry));
  if (!info_array->maps) {
    PLOGE("allocate memory for maps in lsplt_scan_maps");

    free(info_array);

    close(fd);
    close(sockets[0]);

    return NULL;
  }
  info_array->length = 0;

  char line[1024];
  while (fgets(line, sizeof(line), fp) != NULL) {
    line[strlen(line) - 1] = '\0';

    uintptr_t start, end, offset;
    unsigned int dev_major, dev_minor;
    ino_t inode;
    char perms[5] = { 0 };
    int path_off;

    if (sscanf(line, "%" PRIxPTR "-%" PRIxPTR " %4s %" PRIxPTR " %x:%x %lu %n",
               &start, &end, perms, &offset, &dev_major, &dev_minor, &inode, &path_off) != 7) {
      continue;
    }

    uint8_t perms_bit = 0;
    if (perms[0] == 'r') perms_bit |= PROT_READ;
    if (perms[1] == 'w') perms_bit |= PROT_WRITE;
    if (perms[2] == 'x') perms_bit |= PROT_EXEC;

    while (isspace((unsigned char)line[path_off]))
      path_off++;

    char *path_str = strdup(line + path_off);
    if (!path_str) {
      PLOGE("allocate memory for map path in lsplt_scan_maps");

      goto cleanup_maps;
    }

    if (info_array->length >= infos_capacity) {
      infos_capacity *= 2;
      struct lsplt_map_entry *tmp_maps = realloc(info_array->maps, infos_capacity * sizeof(struct lsplt_map_entry));
      if (!tmp_maps) {
        PLOGE("reallocate memory for maps in lsplt_scan_maps");

        goto cleanup_maps_and_path;
      }
      info_array->maps = tmp_maps;
    }

    struct lsplt_map_entry new_map = {
      .start = start,
      .end = end,
      .perms = perms_bit,
      .is_private = (perms[3] == 'p'),
      .offset = offset,
      .dev = makedev(dev_major, dev_minor),
      .inode = inode,
      .path = path_str
    };

    info_array->maps[info_array->length++] = new_map;

    continue;

    cleanup_maps_and_path:
      free(path_str);
    cleanup_maps:
      for (size_t i = 0; i < info_array->length; i++) {
        free(info_array->maps[i].path);
      }
      free(info_array->maps);
      free(info_array);

      fclose(fp);
      close(sockets[0]);

      waitpid(ppid, NULL, 0);

      return NULL;
  }

  fclose(fp);

  /* INFO: Notify the children process that we are done */
  uint8_t can_kill_itself = 1;
  if (TEMP_FAILURE_RETRY(write(sockets[0], &can_kill_itself, sizeof(can_kill_itself))) < 0) {
    LOGE("Failed to write to socket in lsplt_scan_maps");

    goto cleanup_maps;
  }

  close(sockets[0]);

  /* INFO: Resize to the actual size */
  struct lsplt_map_entry *tmp_maps = realloc(info_array->maps, info_array->length * sizeof(struct lsplt_map_entry));
  if (!tmp_maps)
    PLOGE("reallocate memory for maps in lsplt_scan_maps");

  if (tmp_maps) info_array->maps = tmp_maps;
  /* INFO: This waitpid ensures that we only resume code execution once the child dies,
            or the child process will become zombie as shown in /proc/<child_pid>/status */
  waitpid(ppid, NULL, 0);

  return info_array;
}

void lsplt_free_maps(struct lsplt_map_info *maps) {
  for (size_t i = 0; i < maps->length; i++) {
    free(maps->maps[i].path);
  }

  free(maps->maps);
  free(maps);
}

bool lsplt_register_hook_internal(dev_t dev, ino_t inode, uintptr_t offset, size_t size,
                                  const char *symbol, bool is_prefix, void *callback, void **backup) {
  if (dev == 0 || inode == 0 || !symbol || symbol[0] == '\0' || !callback) {
    LOGE("Invalid parameters for lsplt_register_hook_internal: dev=%lu, inode=%lu, symbol=%s, callback=%p",
         (unsigned long)dev, (unsigned long)inode, symbol ? symbol : "NULL", callback);

    return false;
  }

  pthread_mutex_lock(&g_hook_mutex);
  if (!g_register_info_list) {
    g_register_info_list = calloc(1, sizeof(struct lsplt_register_infos));
    if (!g_register_info_list) {
      PLOGE("allocate memory for register info list");

      pthread_mutex_unlock(&g_hook_mutex);

      return false;
    }
  }

  struct lsplt_register_info *tmp_list = realloc(g_register_info_list->infos, (g_register_info_list->length + 1) * sizeof(struct lsplt_register_info));
  if (!tmp_list) {
    PLOGE("reallocate memory for register info list");

    pthread_mutex_unlock(&g_hook_mutex);

    return false;
  }
  g_register_info_list->infos = tmp_list;
  g_register_info_list->length++;

  struct lsplt_register_info *new_node = &g_register_info_list->infos[g_register_info_list->length - 1];

  new_node->symbol = strdup(symbol);
  if (!new_node->symbol) {
    LOGE("Failed to duplicate symbol string: %s", symbol);

    g_register_info_list->length--;
    memset(new_node, 0, sizeof(struct lsplt_register_info));

    pthread_mutex_unlock(&g_hook_mutex);

    return false;
  }

  new_node->is_prefix = is_prefix;
  new_node->dev = dev;
  new_node->inode = inode;
  new_node->offset_range_start = offset;
  new_node->offset_range_end = offset + size;
  new_node->callback = callback;
  new_node->backup = backup;

  pthread_mutex_unlock(&g_hook_mutex);

  LOGV("RegisterHook %lu %s%s", new_node->inode, new_node->symbol, new_node->is_prefix ? " (prefix)" : "");

  return true;
}

bool lsplt_register_hook(dev_t dev, ino_t inode, const char *symbol, void *callback, void **backup) {
  return lsplt_register_hook_internal(dev, inode, 0, UINTPTR_MAX, symbol, false, callback, backup);
}

bool lsplt_register_hook_by_prefix(dev_t dev, ino_t inode, const char *symbol_prefix, void *callback, void **backup) {
  return lsplt_register_hook_internal(dev, inode, 0, UINTPTR_MAX, symbol_prefix, true, callback, backup);
}

bool lsplt_register_hook_with_offset(dev_t dev, ino_t inode, uintptr_t offset, size_t size,
                                     const char *symbol, void *callback, void **backup) {
  return lsplt_register_hook_internal(dev, inode, offset, size, symbol, false, callback, backup);
}

bool lsplt_commit_hook_manual(struct lsplt_map_info *maps) {
  pthread_mutex_lock(&g_hook_mutex);
  if (!g_register_info_list) {
    LOGE("No hooks registered");

    pthread_mutex_unlock(&g_hook_mutex);

    return true;
  }

  struct lsplt_hook_infos *new_hook_infos = scan_and_create_hook_infos(maps);
  if (!new_hook_infos) {
    LOGE("Failed to scan and create hook infos");

    pthread_mutex_unlock(&g_hook_mutex);

    return false;
  }

  if (!filter_hook_infos(new_hook_infos)) {
    LOGE("No hook infos matched, freeing");

    free_hook_infos(new_hook_infos);
    pthread_mutex_unlock(&g_hook_mutex);

    return false;
  }

  if (g_hook_infos && !merge_hook_infos(new_hook_infos, g_hook_infos)) {
    LOGE("Failed to merge hook infos");

    free_hook_infos(new_hook_infos);
    pthread_mutex_unlock(&g_hook_mutex);

    return false;
  }

  bool result = do_hooks_for_all_registered(new_hook_infos);

  if (g_hook_infos) free_hook_infos(g_hook_infos);
  g_hook_infos = new_hook_infos;

  pthread_mutex_unlock(&g_hook_mutex);

  return result;
}

bool lsplt_commit_hook(void) {
  struct lsplt_map_info *maps = lsplt_scan_maps("self");
  if (!maps) {
    LOGE("Failed to scan maps for self");

    return false;
  }

  if (!lsplt_commit_hook_manual(maps)) {
    LOGE("Failed to commit hooks");

    lsplt_free_maps(maps);

    return false;
  }

  lsplt_free_maps(maps);

  return true;
}

bool invalidate_backups(void) {
  pthread_mutex_lock(&g_hook_mutex);

  if (!g_hook_infos) {
    pthread_mutex_unlock(&g_hook_mutex);

    return true;
  }

  bool res = true;
  for (size_t i = 0; i < g_hook_infos->length; i++) {
    struct lsplt_hook_info *info = &g_hook_infos->infos[i];
    if (!info->backup_region) continue;

    for(size_t j = 0; j < info->hooks.length; j++) {
      info->hooks.entries[j].backup = *(uintptr_t*)info->hooks.entries[j].addr;
    }

    size_t len = info->map.end - info->map.start;
    void *new_addr = sys_mremap((void *)info->backup_region, len, len, MREMAP_FIXED | MREMAP_MAYMOVE, (void *)info->map.start);
    if (new_addr == MAP_FAILED || (uintptr_t)new_addr != info->map.start) {
      LOGF("Failed to remap backup region %p to original %p", (void *)info->backup_region, (void *)info->map.start);

      res = false;

      continue;
    }

    if (mprotect(page_start(info->map.start), len, info->map.perms | PROT_WRITE) == 0) {
      for (size_t j = 0; j < info->hooks.length; j++) {
        *(uintptr_t*)info->hooks.entries[j].addr = info->hooks.entries[j].backup;
      }

      mprotect(page_start(info->map.start), len, info->map.perms);
    }

    info->backup_region = 0;
  }

  pthread_mutex_unlock(&g_hook_mutex);

  return res;
}

void lsplt_free_resources(void) {
  pthread_mutex_lock(&g_hook_mutex);

  if (g_hook_infos) {
    free_hook_infos(g_hook_infos);
    g_hook_infos = NULL;
  }

  if (g_register_info_list) {
    for (size_t i = 0; i < g_register_info_list->length; i++) {
      if (!g_register_info_list->infos[i].symbol) continue;

      free(g_register_info_list->infos[i].symbol);
    }
    free(g_register_info_list->infos);

    free(g_register_info_list);
    g_register_info_list = NULL;
  }

  pthread_mutex_unlock(&g_hook_mutex);

  LOGV("Hooks freed");
}
