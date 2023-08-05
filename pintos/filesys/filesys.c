#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include <stdlib.h>



struct lock fs_lock; /* Global filesystem lock */
struct lock buffer_cache_lock;

char buffer_cache_space[NUM_CACHE_BLOCKS << 9];
void *buffer_cache_blocks[NUM_CACHE_BLOCKS];
block_sector_t sector_indices[NUM_CACHE_BLOCKS];
int64_t dirty_bits;
int64_t valid_bits;
int64_t access_bits;
int clock_hand;


/* Partition that contains the file system. */
struct block* fs_device;

static void do_format(void);
static int get_next_part(char part[NAME_MAX + 1], const char** srcp);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void filesys_init(bool format) {
    lock_init(&fs_lock);
    lock_init(&buffer_cache_lock);
    for (int i = 0; i < NUM_CACHE_BLOCKS; i++) {
        buffer_cache_blocks[i] = (void *) (buffer_cache_space + (i << 9));
    }
    valid_bits = 0;
    clock_hand = 0;

    fs_device = block_get_role(BLOCK_FILESYS);
    if (fs_device == NULL)
        PANIC("No file system device found, can't initialize file system.");

    inode_init();
    free_map_init();

    if (format)
        do_format();

    free_map_open();

    /* Set cwd for initial process to the filesystem root */
    struct process* pcb = thread_current()->pcb;
    pcb->cwd = dir_open_root();
    pcb->cwd->inode->data.is_dir = true;
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void filesys_done(void) {
    free_map_close();
    buffer_cache_flush();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool filesys_create(const char* name, off_t initial_size) {
    struct dir* dir;
    if (name[0] == '/') {
      dir = dir_open_root();
      name++;
    } else {
      dir = dir_reopen(thread_current()->pcb->cwd);
    }

    return create_helper(dir, name, 0, initial_size);
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file* filesys_open(const char* name) {
    struct dir* dir;
    if (name[0] == '/') {
      dir = dir_open_root();
      name++;
    } else {
      dir = dir_reopen(thread_current()->pcb->cwd);
    }

    struct inode* inode = open_helper(dir, name, 0);
    return file_open(inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool filesys_remove(const char* name) {
    char* file_to_remove;
    struct dir* dir;
    bool success = mkdir_helper((char*) name, &dir, &file_to_remove);
    if (!success)
        return false;

    /* Disallow if dir has entries other than . and .. */
    struct inode* inode;
    if (dir_lookup(dir, file_to_remove, &inode)) {
        if (inode->data.is_dir) {
            struct dir* dir_to_remove = dir_open(inode);

            char dir_name[NAME_MAX + 1];
            while (success) {
                success = dir_readdir(dir_to_remove, dir_name);
                if (!success) {
                    break;
                }
                if (strcmp(dir_name, ".") == 0 || strcmp(dir_name, "..") == 0) {
                    continue;
                } else {
                    /* dir has something in it besides . and .., block remove */
                    dir_close(dir_to_remove);
                    dir_close(dir);
                    return false;
                }
            }

            dir_close(dir_to_remove);
        } else {
            inode_close(inode);
        }
    }


    success = dir != NULL && dir_remove(dir, file_to_remove);
    dir_close(dir);

    return success;
}

/* Formats the file system. */
static void do_format(void) {
    printf("Formatting file system...");
    free_map_create();
    if (!dir_create("", ROOT_DIR_SECTOR, 16))
        PANIC("root directory creation failed");
    free_map_close();
    printf("done.\n");
}

int buffer_cache_find_sector(block_sector_t sector_idx) {
    // ASSERT(lock_held_by_current_thread(&fs_lock));
    int64_t mask = 1;
    for (int i = 0; i < NUM_CACHE_BLOCKS; i++) {
        if ((valid_bits & mask) != 0 && sector_indices[i] == sector_idx) {
            access_bits |= mask;
            return i;
        }
        mask <<= 1;
    }
    return -1;
}

int buffer_cache_allocate_sector(block_sector_t sector_idx) {
    // ASSERT(lock_held_by_current_thread(&fs_lock));
    access_bits &= valid_bits;
    int mask = 1 << clock_hand;

    int old_access_bits = access_bits;
    access_bits += mask;
    mask = access_bits & ~old_access_bits;
    if (mask == 0) {
        old_access_bits = access_bits;
        access_bits++;
        mask = access_bits & ~old_access_bits;
    }
    clock_hand = bitnum(mask);
    int cache_block_num = clock_hand;

    if ((valid_bits & dirty_bits & mask) != 0) {
        block_write(fs_device, sector_indices[cache_block_num], buffer_cache_blocks[cache_block_num]);
    }
    sector_indices[cache_block_num] = sector_idx;
    valid_bits |= mask;
    dirty_bits &= ~mask;
    access_bits |= mask;
    return cache_block_num;
}

int buffer_cache_find_or_allocate_sector(block_sector_t sector_idx) {
    int result = buffer_cache_find_sector(sector_idx);
    if (result != -1) {
        return result;
    } else {
        return buffer_cache_allocate_sector(sector_idx);
    }
}

int buffer_cache_get_sector(block_sector_t sector_idx) {
    int result = buffer_cache_find_sector(sector_idx);
    if (result != -1) {
        return result;
    } else {
        result = buffer_cache_allocate_sector(sector_idx);
        block_read(fs_device, sector_idx, buffer_cache_blocks[result]);
        return result;
    }
}

void buffer_cache_flush(void) {
    int64_t mask = 1;
    dirty_bits &= valid_bits;
    for (int i = 0; i < NUM_CACHE_BLOCKS; i++) {
        if ((dirty_bits & mask) != 0) {
            block_write(fs_device, sector_indices[i], buffer_cache_blocks[i]);
        }
        mask <<= 1;
    }
    dirty_bits = 0;
}

/* Extracts a file name part from *SRCP into PART, and updates *SRCP so that the
   next call will return the next file name part. Returns 1 if successful, 0 at
   end of string, -1 for a too-long file name part. */
static int get_next_part(char part[NAME_MAX + 1], const char** srcp) {
    const char* src = *srcp;
    char* dst = part;

    /* Skip leading slashes.  If it's all slashes, we're done. */
    while (*src == '/')
        src++;
    if (*src == '\0')
        return 0;

    /* Copy up to NAME_MAX character from SRC to DST.  Add null terminator. */
    while (*src != '/' && *src != '\0') {
        if (dst < part + NAME_MAX)
            *dst++ = *src;
        else
            return -1;
        src++;
    }
    *dst = '\0';

    /* Advance source pointer. */
    *srcp = src;
    return 1;
}

struct dir* get_last_dir(const char* path) {
    struct dir* dir;
    if (path[0] == '/') {
        dir = dir_open_root();
    } else {
        dir = dir_reopen(thread_current()->pcb->cwd);
    }
    char part[NAME_MAX + 1];
    int valid = 0;
    struct inode* inode;
    while ((valid = get_next_part(part, &path))) {
        if (dir_lookup(dir, part, &inode)) {
            dir_close(dir);
            dir = dir_open(inode);
        } else {
            /* Path doesn't exist, close current dir and return NULL */
            dir_close(dir);
            return NULL;
        }
    }

    if (valid == -1) {
        dir_close(dir);
        return NULL;
    }

    return dir;
}

bool create_helper(struct dir* dir, const char* path, uint32_t index, off_t initial_size) {
    if (dir == NULL || dir->inode->removed) {
        return false;
    }
    for (uint32_t i = index; i < strlen(path); i++) {
        if (path[i] == '/') {
            /* Update dir and recursive call, then break and return */
            char new_dir_name[NAME_MAX + 1]; 
            strlcpy(new_dir_name, path + index, i - index + 1);
            struct inode* inode;
            if (dir_lookup(dir, new_dir_name, &inode)) {
                dir_close(dir);
                dir = dir_open(inode);
            } else {
                dir_close(dir);
                return false;
            }
            return create_helper(dir, path, i + 1, initial_size);
        }
    }

    /* Make file in cur_dir */
    block_sector_t inode_sector = 0;
    bool success = dir != NULL;
    if (success) {
        lock_acquire(&free_map_lock);
            success = free_map_allocate(1, &inode_sector);
        lock_release(&free_map_lock);
        if (success) {
            char absolutePath[496];
            snprintf(absolutePath, strlen(dir->inode->data.name) + strlen(path+index) + 2, "%s/%s", dir->inode->data.name, path+index);
            if (inode_create(absolutePath, inode_sector, initial_size) && dir_add(dir, path + index, inode_sector)) {
                success = true;
            } else {
                success = false;
                lock_acquire(&free_map_lock);
                    free_map_release(inode_sector, 1);
                lock_release(&free_map_lock);
            }
        }
    }
    dir_close(dir);
    return success;
}

struct inode* open_helper(struct dir* dir, const char* path, uint32_t index) {
    if (dir == NULL || dir->inode->removed) {
        return NULL;
    }
    for (uint32_t i = index; i < strlen(path); i++) {
        if (path[i] == '/') {
            /* Update dir and recursive call, then break and return */
            char new_dir_name[NAME_MAX + 1]; 
            strlcpy(new_dir_name, path + index, i - index + 1);
            struct inode* inode;
            if (dir_lookup(dir, new_dir_name, &inode)) {
                dir_close(dir);
                dir = dir_open(inode);
            } else {
                dir_close(dir);
                return NULL;
            }
            return open_helper(dir, path, i + 1);
        }
    }

    struct inode* inode;
    if (dir != NULL)
        dir_lookup(dir, path + index, &inode);
    dir_close(dir);
    return inode;
}

struct dir* get_second_to_last_dir(char* path) {
    int last_slash = -1;
    for (int i = 0; i < (int) strlen(path); i++) {
        if (path[i] == '/')
        last_slash = i;
    }
    if (last_slash <= 0)
        return dir_open_root();
    path[last_slash] = '\0';
    return get_last_dir((const char*) path);
}

bool mkdir_helper(char* path, struct dir** dir, char** file_name) {
    int last_slash = -1;
    for (int i = 0; i < (int) strlen(path); i++) {
        if (path[i] == '/')
            last_slash = i;
    }
    if (last_slash == -1) {
        *dir = dir_reopen(thread_current()->pcb->cwd);
        *file_name = path;
    } else if (last_slash == 0) {
        *dir = dir_open_root();
        *file_name = path + 1;
    } else {
        path[last_slash] = '\0';
        *dir = get_last_dir(path);
        *file_name = path + last_slash + 1;
    }
    return true;
}