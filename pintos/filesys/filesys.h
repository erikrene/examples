#ifndef FILESYS_FILESYS_H
#define FILESYS_FILESYS_H

#include <stdbool.h>
#include <limits.h>
#include "filesys/off_t.h"
#include "devices/block.h"
#include "threads/synch.h"
#include "filesys/directory.h"

/* Sectors of system file inodes. */
#define FREE_MAP_SECTOR 0 /* Free map file inode sector. */
#define ROOT_DIR_SECTOR 1 /* Root directory file inode sector. */

#define NUM_CACHE_BLOCKS 64
#define bitnum(n) (31 - __builtin_clz(n))

struct fdt_entry {
    struct dir* dir;
    struct file* file;
};

/* Block device that contains the file system. */
extern struct block* fs_device;
extern void *buffer_cache_blocks[NUM_CACHE_BLOCKS];
extern int64_t dirty_bits;

/* Global filesystem lock. */
extern struct lock fs_lock;
extern struct lock buffer_cache_lock;
extern int64_t valid_bits;

void filesys_init(bool format);
void filesys_done(void);
bool filesys_create(const char* name, off_t initial_size);
struct file* filesys_open(const char* name);
bool filesys_remove(const char* name);

int buffer_cache_find_sector(block_sector_t);
int buffer_cache_allocate_sector(block_sector_t);
int buffer_cache_find_or_allocate_sector(block_sector_t);
int buffer_cache_get_sector(block_sector_t);
void buffer_cache_flush(void);

struct dir* get_last_dir(const char* path);
struct dir* get_second_to_last_dir(char* path);
bool create_helper(struct dir* dir, const char* path, uint32_t index, off_t initial_size);
struct inode* open_helper(struct dir* dir, const char* path, uint32_t index);
bool mkdir_helper(char* path, struct dir** dir, char** file_name);

#endif /* filesys/filesys.h */
