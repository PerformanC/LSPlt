#include "include/lsplt.hpp"

#include <sys/mman.h>
#include <sys/sysmacros.h>

#include <array>
#include <cinttypes>
#include <list>
#include <map>
#include <mutex>
#include <vector>

#include "elf_util.hpp"
#include "logging.hpp"
#include "syscall.hpp"

namespace {
const uintptr_t kPageSize = getpagesize();

inline auto PageStart(uintptr_t addr) {
    return reinterpret_cast<char *>(addr / kPageSize * kPageSize);
}

inline auto PageEnd(uintptr_t addr) {
    return reinterpret_cast<char *>(reinterpret_cast<uintptr_t>(PageStart(addr)) + kPageSize);
}

struct RegisterInfo {
    dev_t dev;
    ino_t inode;
    std::pair<uintptr_t, uintptr_t> offset_range;
    std::string symbol;
    void *callback;
    void **backup;
};

struct HookInfo : public lsplt::MapInfo {
    std::map<uintptr_t, uintptr_t> hooks;
    uintptr_t backup;
    std::unique_ptr<Elf> elf;
    bool self;
    [[nodiscard]] bool Match(const RegisterInfo &info) const {
        return info.dev == dev && info.inode == inode && offset >= info.offset_range.first &&
               offset < info.offset_range.second;
    }
};

class HookInfos : public std::map<uintptr_t, HookInfo, std::greater<>> {
public:
    static auto ScanHookInfo(std::vector<lsplt::MapInfo> maps) {
        static ino_t kSelfInode = 0;
        static dev_t kSelfDev = 0;
        HookInfos info;

        if (kSelfInode == 0) {
            auto self = reinterpret_cast<uintptr_t>(__builtin_return_address(0));
            for (auto &map : maps) {
                if (self >= map.start && self < map.end) {
                    kSelfInode = map.inode;
                    kSelfDev = map.dev;
                    LOGV("self inode = %lu", kSelfInode);
                    break;
                }
            }
        }
        for (auto &map : maps) {
            // we basically only care about r-?p entry
            // and for offset == 0 it's an ELF header
            // and for offset != 0 it's what we hook
            // both of them should not be xom
            if (!map.is_private || !(map.perms & PROT_READ) || map.path.empty() ||
                map.path[0] == '[') {
                continue;
            }
            auto start = map.start;
            const bool self = map.inode == kSelfInode && map.dev == kSelfDev;
            info.emplace(start, HookInfo{{std::move(map)}, {}, 0, nullptr, self});
        }
        return info;
    }

    // filter out ignored
    void Filter(const std::list<RegisterInfo> &register_info) {
        for (auto iter = begin(); iter != end();) {
            const auto &info = iter->second;
            bool matched = false;
            for (const auto &reg : register_info) {
                if (info.Match(reg)) {
                    matched = true;
                    break;
                }
            }
            if (matched) {
                LOGV("Match hook info %s:%lu %" PRIxPTR " %" PRIxPTR "-%" PRIxPTR,
                     iter->second.path.data(), iter->second.inode, iter->second.start,
                     iter->second.end, iter->second.offset);
                ++iter;
            } else {
                iter = erase(iter);
            }
        }
    }

    void Merge(HookInfos &old) {
        // merge with old map info
        for (auto &info : old) {
            if (info.second.backup) {
                erase(info.second.backup);
            }
            if (auto iter = find(info.first); iter != end()) {
                iter->second = std::move(info.second);
            } else if (info.second.backup) {
                emplace(info.first, std::move(info.second));
            }
        }
    }

    bool DoHook(uintptr_t addr, uintptr_t callback, uintptr_t *backup) {
        LOGV("Hooking %p", reinterpret_cast<void *>(addr));
        auto iter = lower_bound(addr);
        if (iter == end()) return false;
        // iter.first < addr
        auto &info = iter->second;
        if (info.end <= addr) return false;
        const auto len = info.end - info.start;
        if (!info.backup && !info.self) {
            // let os find a suitable address
            auto *backup_addr = sys_mmap(nullptr, len, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
            LOGD("Backup %p to %p", reinterpret_cast<void *>(addr), backup_addr);
            if (backup_addr == MAP_FAILED) return false;
            if (auto *new_addr =
                    sys_mremap(reinterpret_cast<void *>(info.start), len, len,
                               MREMAP_FIXED | MREMAP_MAYMOVE | MREMAP_DONTUNMAP, backup_addr);
                new_addr == MAP_FAILED || new_addr != backup_addr) {
                new_addr = sys_mremap(reinterpret_cast<void *>(info.start), len, len,
                           MREMAP_FIXED | MREMAP_MAYMOVE, backup_addr);
                if (new_addr == MAP_FAILED || new_addr != backup_addr) {
                    return false;
                }
                LOGD("Backup with MREMAP_DONTUNMAP failed, tried without it");
            }
            if (auto *new_addr = sys_mmap(reinterpret_cast<void *>(info.start), len,
                                          PROT_READ | PROT_WRITE | info.perms,
                                          MAP_PRIVATE | MAP_FIXED | MAP_ANON, -1, 0);
                new_addr == MAP_FAILED) {
                return false;
            }
            for (uintptr_t src = reinterpret_cast<uintptr_t>(backup_addr), dest = info.start,
                           end = info.start + len;
                 dest < end; src += kPageSize, dest += kPageSize) {
                memcpy(reinterpret_cast<void *>(dest), reinterpret_cast<void *>(src), kPageSize);
            }
            info.backup = reinterpret_cast<uintptr_t>(backup_addr);
        }
        if (info.self) {
            // self hooking, no need backup since we are always dirty
            if (!(info.perms & PROT_WRITE)) {
                info.perms |= PROT_WRITE;
                mprotect(reinterpret_cast<void *>(info.start), len, info.perms);
            }
        }
        auto *the_addr = reinterpret_cast<uintptr_t *>(addr);
        auto the_backup = *the_addr;
        if (*the_addr != callback) {
            *the_addr = callback;
            if (backup) *backup = the_backup;
            __builtin___clear_cache(PageStart(addr), PageEnd(addr));
        }
        if (auto hook_iter = info.hooks.find(addr); hook_iter != info.hooks.end()) {
            if (hook_iter->second == callback) info.hooks.erase(hook_iter);
        } else {
            info.hooks.emplace(addr, the_backup);
        }
        if (info.hooks.empty() && !info.self) {
            LOGD("Restore %p from %p", reinterpret_cast<void *>(info.start),
                 reinterpret_cast<void *>(info.backup));
            // Note that we have to always use sys_mremap here,
            // see
            // https://cs.android.com/android/_/android/platform/bionic/+/4200e260d266fd0c176e71fbd720d0bab04b02db
            if (auto *new_addr =
                    sys_mremap(reinterpret_cast<void *>(info.backup), len, len,
                               MREMAP_FIXED | MREMAP_MAYMOVE, reinterpret_cast<void *>(info.start));
                new_addr == MAP_FAILED || reinterpret_cast<uintptr_t>(new_addr) != info.start) {
                return false;
            }
            info.backup = 0;
        }
        return true;
    }

    bool DoHook(std::list<RegisterInfo> &register_info) {
        bool res = true;
        for (auto info_iter = rbegin(); info_iter != rend(); ++info_iter) {
            auto &info = info_iter->second;
            for (auto iter = register_info.begin(); iter != register_info.end();) {
                const auto &reg = *iter;
                if (info.offset != iter->offset_range.first || !info.Match(reg)) {
                    ++iter;
                    continue;
                }
                if (!info.elf) info.elf = std::make_unique<Elf>(info.start);
                if (info.elf && info.elf->Valid()) {
                    LOGD("Hooking %s", iter->symbol.data());
                    for (auto addr : info.elf->FindPltAddr(reg.symbol)) {
                        res = DoHook(addr, reinterpret_cast<uintptr_t>(reg.callback),
                                     reinterpret_cast<uintptr_t *>(reg.backup)) &&
                              res;
                    }
                }
                iter = register_info.erase(iter);
            }
        }
        return res;
    }

    bool InvalidateBackup() {
        bool all_successful = true;

        for (auto it = this->begin(); it != this->end(); ++it) {
            HookInfo &info = it->second;
            const auto len = info.end - info.start;

            LOGD("Processing restoration for %s (0x%" PRIxPTR "-0x%" PRIxPTR ", inode %lu)",
                 info.path.data(), info.start, info.end, info.inode);

            if (!info.hooks.empty()) {
                if (!info.self && !( (PROT_READ | PROT_WRITE | info.perms) & PROT_WRITE) && !(info.perms & PROT_WRITE))
                    LOGW("Memory region %s for non-self hook might not be writable as expected for restoration", info.path.c_str());

                for (auto const& [hooked_addr, original_value] : info.hooks) {
                    if (hooked_addr < info.start || hooked_addr >= info.end) {
                        LOGE("Hooked address %p is outside the current map region %s (%p-%p). Skipping restoration for this entry",
                            (void *)hooked_addr, info.path.c_str(), (void *)info.start, (void *)info.end);

                        all_successful = false;

                        continue;
                    }

                    auto *target_ptr = reinterpret_cast<uintptr_t *>(hooked_addr);
                    if (*target_ptr != original_value) {
                        *target_ptr = original_value;
                        __builtin___clear_cache(PageStart(hooked_addr), PageEnd(hooked_addr));

                        LOGV("Restored original value at %p to %p in %s",
                             (void *)hooked_addr, (void *)original_value, info.path.c_str());
                    }
                }
            }

            if (info.backup != 0 && !info.self) {
                LOGD("Restoring original memory segment for %s from backup location %p",
                     info.path.c_str(), (void *)info.backup);

                if (auto *restored_addr = sys_mremap(reinterpret_cast<void *>(info.backup), len, len,
                                   MREMAP_FIXED | MREMAP_MAYMOVE, reinterpret_cast<void *>(info.start));
                    restored_addr == MAP_FAILED || reinterpret_cast<uintptr_t>(restored_addr) != info.start) {

                    LOGE("sys_mremap failed to restore %s from backup %p (errno %d). Original pages potentially lost",
                         info.path.c_str(), (void *)info.backup, errno);

                    all_successful = false;

                    if (sys_munmap(reinterpret_cast<void *>(info.backup), len) != 0 && errno != EINVAL)
                        LOGE("Failed to munmap orphaned backup region %p for %s (errno %d)", (void *)info.backup, info.path.c_str(), errno);
                } else {
                    LOGD("Successfully restored original mapping for %s. Backup location %p is now invalid/moved",
                         info.path.c_str(), (void *)info.backup);
                }

                info.backup = 0;
            } else if (info.self && !info.hooks.empty()) {
                lsplt::MapInfo& original_map_details = static_cast<lsplt::MapInfo&>(info);
                if (info.perms != original_map_details.perms) {
                    if (mprotect(reinterpret_cast<void *>(info.start), len, original_map_details.perms) == 0) {
                        LOGV("Restored original permissions for self-hooked region %s", info.path.c_str());

                        info.perms = original_map_details.perms;
                    } else {
                        LOGW("Failed to restore original permissions for self-hooked region %s (errno %d)", info.path.c_str(), errno);

                        all_successful = false;
                    }
                }
            }
        }

        this->clear();

        return all_successful;
    }
};

std::mutex hook_mutex;
std::list<RegisterInfo> register_info;
HookInfos hook_info;
}  // namespace

namespace lsplt::inline v2 {
[[maybe_unused]] std::vector<MapInfo> MapInfo::Scan(std::string_view pid) {
    constexpr static auto kPermLength = 5;
    constexpr static auto kMapEntry = 7;
    std::vector<MapInfo> info;
    auto path = "/proc/" + std::string{pid} + "/maps";
    auto maps = std::unique_ptr<FILE, decltype(&fclose)>{fopen(path.c_str(), "r"), &fclose};
    if (maps) {
        char *line = nullptr;
        size_t len = 0;
        ssize_t read;
        while ((read = getline(&line, &len, maps.get())) > 0) {
            line[read - 1] = '\0';
            uintptr_t start = 0;
            uintptr_t end = 0;
            uintptr_t off = 0;
            ino_t inode = 0;
            unsigned int dev_major = 0;
            unsigned int dev_minor = 0;
            std::array<char, kPermLength> perm{'\0'};
            int path_off;
            if (sscanf(line, "%" PRIxPTR "-%" PRIxPTR " %4s %" PRIxPTR " %x:%x %lu %n%*s", &start,
                       &end, perm.data(), &off, &dev_major, &dev_minor, &inode,
                       &path_off) != kMapEntry) {
                continue;
            }
            while (path_off < read && isspace(line[path_off])) path_off++;
            auto &ref = info.emplace_back(start, end, 0, perm[3] == 'p', off,
                                          static_cast<dev_t>(makedev(dev_major, dev_minor)), inode,
                                          line + path_off);
            if (perm[0] == 'r') ref.perms |= PROT_READ;
            if (perm[1] == 'w') ref.perms |= PROT_WRITE;
            if (perm[2] == 'x') ref.perms |= PROT_EXEC;
        }
        free(line);
    }
    return info;
}

[[maybe_unused]] bool RegisterHook(dev_t dev, ino_t inode, std::string_view symbol, void *callback,
                                   void **backup) {
    if (dev == 0 || inode == 0 || symbol.empty() || !callback) return false;

    const std::unique_lock lock(hook_mutex);
    static_assert(std::numeric_limits<uintptr_t>::min() == 0);
    static_assert(std::numeric_limits<uintptr_t>::max() == -1);
    [[maybe_unused]] const auto &info = register_info.emplace_back(
        dev, inode,
        std::pair{std::numeric_limits<uintptr_t>::min(), std::numeric_limits<uintptr_t>::max()},
        std::string{symbol}, callback, backup);

    LOGV("RegisterHook %lu %s", info.inode, info.symbol.data());
    return true;
}

[[maybe_unused]] bool RegisterHook(dev_t dev, ino_t inode, uintptr_t offset, size_t size,
                                   std::string_view symbol, void *callback, void **backup) {
    if (dev == 0 || inode == 0 || symbol.empty() || !callback) return false;

    const std::unique_lock lock(hook_mutex);
    static_assert(std::numeric_limits<uintptr_t>::min() == 0);
    static_assert(std::numeric_limits<uintptr_t>::max() == -1);
    [[maybe_unused]] const auto &info = register_info.emplace_back(
        dev, inode, std::pair{offset, offset + size}, std::string{symbol}, callback, backup);

    LOGV("RegisterHook %lu %" PRIxPTR "-%" PRIxPTR " %s", info.inode, info.offset_range.first,
         info.offset_range.second, info.symbol.data());
    return true;
}

[[maybe_unused]] bool CommitHook(std::vector<lsplt::MapInfo> &maps) {
    const std::unique_lock lock(hook_mutex);
    if (register_info.empty()) return true;

    auto new_hook_info = HookInfos::ScanHookInfo(maps);
    if (new_hook_info.empty()) return false;

    new_hook_info.Filter(register_info);

    new_hook_info.Merge(hook_info);
    // update to new map info
    hook_info = std::move(new_hook_info);

    return hook_info.DoHook(register_info);
}

[[gnu::destructor]] [[maybe_unused]] bool InvalidateBackup() {
    const std::unique_lock lock(hook_mutex);
    return hook_info.InvalidateBackup();
}
}  // namespace lsplt::inline v2
