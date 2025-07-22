#ifndef LSPLT_H
#define LSPLT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

struct lsplt_map_entry {
  uintptr_t start;
  uintptr_t end;
  int perms;
  bool is_private;
  uintptr_t offset;
  dev_t dev;
  ino_t inode;
  char *path;
};

struct lsplt_map_info {
  struct lsplt_map_entry *maps;
  size_t length;
};

/**
 * @brief Scans the memory maps for a given process.
 *
 * @param pid The process ID to scan. Use "self" for the current process.
 * @param map_count Out parameter to store the number of map entries found.
 * 
 * @return A dynamically allocated array of lsplt_map_info structs. The caller is
 *         responsible for freeing the array and the 'path' string within each struct.
 */
struct lsplt_map_info *lsplt_scan_maps(const char *pid);

/**
 * @brief Frees the memory allocated for a map info array.
 *
 * @param maps The array of map info structs to free.
 * @param map_count The number of elements in the array.
 */
void lsplt_free_maps(struct lsplt_map_info *maps);

/**
 * @brief Registers a function hook for a specific symbol within a library,
 *        matching the entire library regardless of its loaded offset.
 *
 * @param dev The device ID of the library's file system.
 * @param inode The inode number of the library file.
 * @param symbol The name of the symbol to hook (e.g., in the PLT).
 * @param callback The function to be called instead of the original symbol.
 * @param backup A pointer to store the address of the original function. Can be NULL.
 * 
 * @return True on success, false on failure.
 */
bool lsplt_register_hook(dev_t dev, ino_t inode, const char *symbol, void *callback, void **backup);

/**
 * @brief Registers a function hook for a specific symbol within a defined offset range
 *        of a library.
 *
 * @param dev The device ID of the library's file system.
 * @param inode The inode number of the library file.
 * @param offset The starting file offset of the segment to search within.
 * @param size The size of the segment.
 * @param symbol The name of the symbol to hook.
 * @param callback The function to be called instead of the original symbol.
 * @param backup A pointer to store the address of the original function. Can be NULL.
 * 
 * @return True on success, false on failure.
 */
bool lsplt_register_hook_with_offset(dev_t dev, ino_t inode, uintptr_t offset, size_t size,
                                     const char *symbol, void *callback, void **backup);

/**
 * @brief Applies all registered hooks with manual scan of maps.
 *
 * This function scans the current process's memory maps and applies any pending
 * hooks that match the loaded libraries.
 * 
 * @param maps The memory map information of the current process.
 *
 * @return True if all hooks were applied successfully, false otherwise.
 */
bool lsplt_commit_hook_manual(struct lsplt_map_info *maps);

/**
 * @brief Applies all registered hooks.
 *
 * This function scans the current process's memory maps and applies any pending
 * hooks that match the loaded libraries.
 * 
 * @param maps The memory map information of the current process.
 *
 * @return True if all hooks were applied successfully, false otherwise.
 */
bool lsplt_commit_hook();

/**
 * @brief Invalidates all backups created by the hooks.
 * 
 * This function will restore the original function addresses
 * from the backups and invalidate them.
 * 
 * @return True if the backups were invalidated successfully, false otherwise.
 */
bool invalidate_backups();

/**
 * @brief Frees all resources allocated by the library.
 * 
 * This function should be called to clean up any resources allocated
 * during the usage of the lsplt library, except for the maps themselves.
 * 
 * @return void
 */
void lsplt_free_resources();

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* LSPLT_H */