#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"
#include <stdint.h>
#include "filesys/filesys.h"

// At most 8MB can be allocated to the stack
// These defines will be used in Project 2: Multithreading
#define MAX_STACK_PAGES (1 << 11)
#define MAX_THREADS 127
#define MAX_FD_NUM 32 /* Max number of active file descriptors */

/* PIDs and TIDs are the same type. PID should be
   the TID of the main thread of the process */
typedef tid_t pid_t;

/* Thread functions (Project 2: Multithreading) */
typedef void (*pthread_fun)(void*);
typedef void (*stub_fun)(pthread_fun, void*);

/* The process control block for a given process. Since
   there can be multiple threads per process, we need a separate
   PCB from the TCB. All TCBs in a process will have a pointer
   to the PCB, and the PCB will have a pointer to the main thread
   of the process, which is `special`. */


enum {
    UNKNOWN,            /* Parent has neither exited nor waited */
    WAITING,            /* Parent is actively waiting */
    EXITED              /* Parent has exited */
};

typedef struct child_data {
    pid_t pid;                                  /* PID of child process */
    struct lock elem_modification_lock;         /* Synchronization of concurrent read/writes to child_data */
    int parent_status;                          /* Status of the parent described by the enums above */
    int exit_code;                              /* Exit code of child process */
    bool has_exited;                            /* Whether child has exited */
    struct list_elem elem;
} child_data_t;

struct process {
    /* Owned by process.c. */
    uint32_t* pagedir;                          /* Page directory. */
    char process_name[32];                      /* Name of the main thread */
    struct thread* main_thread;                 /* Pointer to main thread */

    struct process *parent_process;             /* Pointer to parent process */
    struct list child_processes;                /* List of struct child_data shared with child processes */

    struct child_data *start_process_result;    /* The child_data of the result of process_execute, NULL if start_process fails*/
    struct semaphore start_process_sema;        /* Semaphore that ensures child PCB is initialized before parent finishes exec */
    struct semaphore wait_sema;                 /* Semaphore that ensures child finishes executing before parent finishes wait */

    child_data_t *child_info;                   /* Shared data struct with parent. See child_data struct above */

    struct fdt_entry* fdt[MAX_FD_NUM];               /* File descriptor table for this process */
    struct file* executable;                    /* Executable that is being run by this process */

    struct dir* cwd;
};




bool setup_pcb(void);
void userprog_init(void);

pid_t process_execute(const char* file_name);
int process_wait(pid_t);
void process_exit(int);
void process_activate(void);

bool is_main_thread(struct thread*, struct process*);
pid_t get_pid(struct process*);

tid_t pthread_execute(stub_fun, pthread_fun, void*);
tid_t pthread_join(tid_t);
void pthread_exit(void);
void pthread_exit_main(void);

#endif /* userprog/process.h */
