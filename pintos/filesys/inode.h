#ifndef FILESYS_INODE_H
#define FILESYS_INODE_H

#include <stdbool.h>
#include "filesys/off_t.h"
#include "devices/block.h"
#include "threads/synch.h"
#include "lib/kernel/list.h"

struct bitmap;

struct indirect_block {
    block_sector_t blocks[128];
};

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk {
    off_t length;         /* File size in bytes. */
    unsigned magic;       /* Magic number. */

    block_sector_t direct_pointers[122];
    block_sector_t indirect_pointer;
    block_sector_t doubly_indirect_pointer;
    
    char* name; /* Not used. */
    bool is_dir;
};

/* In-memory inode. */
struct inode {
    struct list_elem elem;  /* Element in inode list. */
    block_sector_t sector;  /* Sector number of disk location. */
    int open_cnt;           /* Number of openers. */
    bool removed;           /* True if deleted, false otherwise. */
    int deny_write_cnt;     /* 0: writes ok, >0: deny writes. */
    struct inode_disk data; /* Inode content. */

    struct lock access_lock;    /* Lock to prevent concurrent access of inode data. */
    struct lock directory_lock; /* Lock to prevent concurrent use of inode as a directory. */
};

void inode_init(void);
bool inode_create(char* absolutePath, block_sector_t, off_t);
struct inode* inode_open(block_sector_t);
struct inode* inode_reopen(struct inode*);
block_sector_t inode_get_inumber(const struct inode*);
void inode_close(struct inode*);
void inode_remove(struct inode*);
off_t inode_read_at(struct inode*, void*, off_t size, off_t offset);
off_t inode_write_at(struct inode*, const void*, off_t size, off_t offset);
void inode_deny_write(struct inode*);
void inode_allow_write(struct inode*);
off_t inode_length(const struct inode*);
bool inode_resize(struct inode_disk* id, off_t size);
bool inode_deallocate(struct inode_disk *id);
bool inode_is_dir(struct inode* inode);

#endif /* filesys/inode.h */
