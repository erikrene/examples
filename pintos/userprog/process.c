#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"


// #define is_executable(file) (stat(file, &sb) == 0 && (sb.st_mode & S_IXUSR))

static thread_func start_process NO_RETURN;
static thread_func start_pthread NO_RETURN;
static bool load(const char *executable, const char *file_name, void (**eip)(void), void** esp);
bool setup_thread(void (**eip)(void), void** esp);


/* Helper function that sets up PCB that can also be called by normal processes */
bool setup_pcb(void) {
    /* Allocate process control block
        It is imoprtant that this is a call to calloc and not malloc,
        so that t->pcb->pagedir is guaranteed to be NULL (the kernel's
        page directory) when t->pcb is assigned, because a timer interrupt
        can come at any time and activate our pagedir */
    // Ensure that timer_interrupt() -> schedule() -> process_activate()
    // does not try to activate our uninitialized pagedir

    /* Note, calloc innately sets parent pointer to NULL */
    struct process *p = thread_current()->pcb = calloc(sizeof(struct process), 1);
    bool success = p != NULL;

    if (success) {
        /* Initialize parent-child data in process */
        list_init(&(p->child_processes));
        sema_init(&(p->start_process_sema), 0);
        sema_init(&(p->wait_sema), 0);

        /* Initialize fdt */
        fdt_init(p);
    }
    return success;
}

/* Initializes user programs in the system by ensuring the main
   thread has a minimal PCB so that it can execute and wait for
   the first user process. Any additions to the PCB should be also
   initialized here if main needs those members */
void userprog_init(void) {
  bool success = setup_pcb();

  /* Kill the kernel if we did not succeed */
  ASSERT(success);
}

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   process id, or TID_ERROR if the thread cannot be created. */
pid_t process_execute(const char* file_name) {
    char* fn_copy;
    struct process *parent = thread_current()->pcb;
    struct thread *t;

    /* Make a copy of FILE_NAME.
        Otherwise there's a race between the caller and load(). */
    fn_copy = malloc((strlen(file_name) + 1) * sizeof(char));
    if (fn_copy == NULL)
        return TID_ERROR;
    strlcpy(fn_copy, file_name, strlen(file_name) + 1);

    /* Create a new thread to execute FILE_NAME. */
    /* Obtain the executable name */
    char *copy = malloc(strlen(file_name) + 1);
    if (copy == NULL) {
        free(fn_copy);
        return TID_ERROR;
    }
    memcpy(copy, file_name, strlen(file_name) + 1);
    char *executable = strtok_r(copy, " ", &copy);

    void *aux[3] = {parent, executable, fn_copy};
    pid_t tid = thread_create(executable, PRI_DEFAULT, start_process, (void *) aux);

    if (tid == TID_ERROR) {
        free(executable);
        free(fn_copy);
    } else {
        /* Wait for child to finish initializing PCB*/
        sema_down(&parent->start_process_sema);
        if (parent->start_process_result) {
            /* Add child data to list of child processes. It is ok if child has
                already exited because parent still has pointer to valid data */
            list_push_back(&parent->child_processes, &parent->start_process_result->elem);
        } else {
            return TID_ERROR;
        }
    }
    return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void start_process(void* aux) {
    struct process *parent = (struct process *) ((void **) aux)[0];
    char *executable = (char *) ((void **) aux)[1];
    char *file_name = (char*) ((void **) aux)[2];
    struct thread* t = thread_current();


    struct intr_frame if_;
    bool success, pcb_success;
    success = pcb_success = setup_pcb();

    /* Initialize process control block */
    if (success) {
        // Set the pointer to the parent process
        t->pcb->parent_process = parent;

        // Setup child data 
        child_data_t *child = malloc(sizeof(child_data_t));
        success = child != NULL;
        if (success) {
            *child = (child_data_t) {
                .pid = t->tid,
                .elem_modification_lock = {0},
                .parent_status = UNKNOWN,
                .exit_code = 0,
                .has_exited = false,
                .elem = {0}
            };
            lock_init(&child->elem_modification_lock);
            parent->start_process_result = t->pcb->child_info = child;

            // Continue initializing the PCB as normal
            t->pcb->main_thread = t;
            strlcpy(t->pcb->process_name, t->name, sizeof t->name);

            /* Set cwd to parent's cwd */
            t->pcb->cwd = parent->cwd;
        } else {
            struct process* pcb_to_free = t->pcb;
            t->pcb = NULL;
            free(pcb_to_free);
        }
    }

    /* Initialize interrupt frame and load executable. */
    if (success) {
        memset(&if_, 0, sizeof if_);
        if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
        if_.cs = SEL_UCSEG;
        if_.eflags = FLAG_IF | FLAG_MBS;
        success = load(executable, file_name, &if_.eip, &if_.esp);

        // Avoid race where PCB is freed before t->pcb is set to NULL
        // If this happens, then an unfortuantely timed timer interrupt
        // can try to activate the pagedir, but it is now freed memory
        if (!success) {
            struct process* pcb_to_free = t->pcb;
            t->pcb = NULL;
            free(pcb_to_free->child_info);
            free(pcb_to_free);
        }
    }

    /* Clean up. Exit on failure or jump to userspace */
    free(executable);
    free(file_name);
    if (!success) {
        parent->start_process_result = NULL;
        sema_up(&parent->start_process_sema);
        thread_exit();
    } else {
        sema_up(&parent->start_process_sema);
    }

    /* Start the user process by simulating a return from an
        interrupt, implemented by intr_exit (in
        threads/intr-stubs.S).  Because intr_exit takes all of its
        arguments on the stack in the form of a `struct intr_frame',
        we just point the stack pointer (%esp) to our stack frame
        and jump to it. */
    asm volatile("movl %0, %%esp; fsave 48(%%esp); jmp intr_exit" : : "g"(&if_) : "memory");
    NOT_REACHED();
}

/* Waits for process with PID child_pid to die and returns its exit status.
   If it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If child_pid is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given PID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int process_wait(pid_t child_pid) {
    struct process *parent = thread_current()->pcb;

    /* Beyond process_execute -> start_process, the parent is the only one who can add/delete
        list elements so there are no list iteration synchronization issues. Searches through
        list of children to check if a child PID. The first time wait is called, the child is
        removed after the exit code is acquired so child missing covers both cases of child_pid
        not a child and wait already called. */
    struct list_elem *e = list_begin(&parent->child_processes);
    child_data_t *cd;
    while (e != list_end(&parent->child_processes) && (cd = list_entry(e, child_data_t, elem))->pid != child_pid) {
        e = list_next(e);
    }

    /* If child_pid is not present in list of children then error */
    if (e == list_end(&parent->child_processes)) {
        return -1;
    } else {
        lock_acquire(&cd->elem_modification_lock);
        if (cd->has_exited) {
            /* If child already exited, no contest for modification of list element, can read
                return code after releasing the lock */
            lock_release(&cd->elem_modification_lock);
        } else {
            /* Else, set waiting to true. Release the lock and wait for the child to exit */
            cd->parent_status = WAITING;
            lock_release(&cd->elem_modification_lock);
            sema_down(&parent->wait_sema);
        }
        int result = cd->exit_code;

        /* On the first call to wait, remove the child from the list so wait cannot be called twice */
        list_remove(e);
        free(cd);

        return result;
    }
}

/* Free the current process's resources. */
void process_exit(int exit_code) {
    struct process* cur = thread_current()->pcb;
    printf("%s: exit(%d)\n", cur->process_name, exit_code);

    uint32_t* pd;
    /* If this thread does not have a PCB, don't worry */
    if (cur == NULL) {
        thread_exit();
        NOT_REACHED();
    }

    /* Update the parent process that the child has exited */
    struct process *parent = cur->parent_process;
    child_data_t *cd = cur->child_info;

    /* Acquire a lock */
    lock_acquire(&cd->elem_modification_lock);
    /* Checks if parent has exited */
    if (cd->parent_status != EXITED) {
        /* If parent has not exited, alert that child has exited and update exit code */
        cd->has_exited = true;
        cd->exit_code = exit_code;
        /* If parent is waiting, release lock and up the semaphore */
        if (cd->parent_status == WAITING) {
            lock_release(&cd->elem_modification_lock);
            sema_up(&parent->wait_sema);
        /* Else release the lock */
        } else {
            lock_release(&cd->elem_modification_lock);
        }
    /* If parent has exited, no need for shared data, just free */
    } else {
        free(cd);
    }

    /* Update all children processes that the parent no longer exists */
    struct list_elem *e;
    while (!list_empty(&cur->child_processes)) {
        /* Must use list_pop because if free, then cannot use list_next on elem */
        e = list_pop_front(&cur->child_processes);
        cd = list_entry(e, child_data_t, elem);
        /* Acquire the lock */
        lock_acquire(&cd->elem_modification_lock);
        /* If child has exited, just free */
        if (cd->has_exited) {
            free(cd);
        } else {
        /* Else, alert child that parent has exited, release the lock */
            cd->parent_status = EXITED;
            lock_release(&cd->elem_modification_lock);
        }
    }

    /* Close all file descriptors */
    struct fdt_entry* entry;
    for (int i = 2; i < MAX_FD_NUM; i++) {
        entry = cur->fdt[i];
        if (entry == NULL)
            continue;
        if (entry->file != NULL) {
            file_close(entry->file);
        } else if (entry->dir != NULL) {
            dir_close(entry->dir);
        }
    }

    /* Allow writes to the executable file now that the process is exiting */
    file_close(cur->executable);

    /* Destroy the current process's page directory and switch back
        to the kernel-only page directory. */
    pd = cur->pagedir;
    if (pd != NULL) {
        /* Correct ordering here is crucial.  We must set
            cur->pcb->pagedir to NULL before switching page directories,
            so that a timer interrupt can't switch back to the
            process page directory.  We must activate the base page
            directory before destroying the process's page
            directory, or our active page directory will be one
            that's been freed (and cleared). */
        cur->pagedir = NULL;
        pagedir_activate(NULL);
        pagedir_destroy(pd);
    }

    /* Free the PCB of this process and kill this thread
        Avoid race where PCB is freed before t->pcb is set to NULL
        If this happens, then an unfortuantely timed timer interrupt
        can try to activate the pagedir, but it is now freed memory */
    thread_current()->pcb = NULL;
    free(cur);

    thread_exit();
}

/* Sets up the CPU for running user code in the current
   thread. This function is called on every context switch. */
void process_activate(void) {
    struct process* p = thread_current()->pcb;

    /* Activate thread's page tables. */
    if (p != NULL && p->pagedir != NULL)
        pagedir_activate(p->pagedir);
    else
        pagedir_activate(NULL);

    /* Set thread's kernel stack for use in processing interrupts.
        This does nothing if this is not a user process. */
    tss_update();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32 /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32 /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32 /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16 /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr {
    unsigned char e_ident[16];
    Elf32_Half e_type;
    Elf32_Half e_machine;
    Elf32_Word e_version;
    Elf32_Addr e_entry;
    Elf32_Off e_phoff;
    Elf32_Off e_shoff;
    Elf32_Word e_flags;
    Elf32_Half e_ehsize;
    Elf32_Half e_phentsize;
    Elf32_Half e_phnum;
    Elf32_Half e_shentsize;
    Elf32_Half e_shnum;
    Elf32_Half e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr {
    Elf32_Word p_type;
    Elf32_Off p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL 0           /* Ignore. */
#define PT_LOAD 1           /* Loadable segment. */
#define PT_DYNAMIC 2        /* Dynamic linking info. */
#define PT_INTERP 3         /* Name of dynamic loader. */
#define PT_NOTE 4           /* Auxiliary info. */
#define PT_SHLIB 5          /* Reserved. */
#define PT_PHDR 6           /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

static bool setup_stack(void** esp, const char *file_name);
static bool validate_segment(const struct Elf32_Phdr*, struct file*);
static bool load_segment(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool load(const char *executable, const char* file_name, void (**eip)(void), void** esp) {
    struct thread* t = thread_current();
    struct Elf32_Ehdr ehdr;
    struct file* file = NULL;
    off_t file_ofs;
    bool success = false;
    int i;

    /* Allocate and activate page directory. */
    t->pcb->pagedir = pagedir_create();
    if (t->pcb->pagedir == NULL)
        goto done;
    process_activate();

    /* Open executable file. */
    file = filesys_open(executable);
    if (file == NULL) {
        printf("load: %s: open failed\n", executable);
        goto done;
    }

    /* Deny writes to executable of active process and track the executable for this process */
    t->pcb->executable = file;
    file_deny_write(file);

    /* Read and verify executable header. */
    if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr ||
            memcmp(ehdr.e_ident, "\177ELF\1\1\1", 7) || ehdr.e_type != 2 || ehdr.e_machine != 3 ||
            ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Elf32_Phdr) || ehdr.e_phnum > 1024) {
        printf("load: %s: error loading executable\n", executable);
        goto done;
    }

    /* Read program headers. */
    file_ofs = ehdr.e_phoff;
    for (i = 0; i < ehdr.e_phnum; i++) {
        struct Elf32_Phdr phdr;

        if (file_ofs < 0 || file_ofs > file_length(file))
            goto done;
        file_seek(file, file_ofs);

        if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)
            goto done;
        file_ofs += sizeof phdr;
        switch (phdr.p_type) {
            case PT_NULL:
            case PT_NOTE:
            case PT_PHDR:
            case PT_STACK:
            default:
                /* Ignore this segment. */
                break;
            case PT_DYNAMIC:
            case PT_INTERP:
            case PT_SHLIB:
                goto done;
            case PT_LOAD:
            if (validate_segment(&phdr, file)) {
                bool writable = (phdr.p_flags & PF_W) != 0;
                uint32_t file_page = phdr.p_offset & ~PGMASK;
                uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
                uint32_t page_offset = phdr.p_vaddr & PGMASK;
                uint32_t read_bytes, zero_bytes;
                if (phdr.p_filesz > 0) {
                    /* Normal segment.
                            Read initial part from disk and zero the rest. */
                    read_bytes = page_offset + phdr.p_filesz;
                    zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
                } else {
                    /* Entirely zero.
                            Don't read anything from disk. */
                    read_bytes = 0;
                    zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
                }
                if (!load_segment(file, file_page, (void*)mem_page, read_bytes, zero_bytes, writable))
                    goto done;
            } else
                goto done;
            break;
        }
    }

    /* Set up stack. */
    if (!setup_stack(esp, file_name))
        goto done;

    /* Start address. */
    *eip = (void (*)(void))ehdr.e_entry;

    success = true;

done:
    /* We arrive here whether the load is successful or not. */
    return success;
}

/* load() helpers. */

static bool install_page(void* upage, void* kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool validate_segment(const struct Elf32_Phdr* phdr, struct file* file) {
    /* p_offset and p_vaddr must have the same page offset. */
    if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
        return false;

    /* p_offset must point within FILE. */
    if (phdr->p_offset > (Elf32_Off)file_length(file))
        return false;

    /* p_memsz must be at least as big as p_filesz. */
    if (phdr->p_memsz < phdr->p_filesz)
        return false;

    /* The segment must not be empty. */
    if (phdr->p_memsz == 0)
        return false;

    /* The virtual memory region must both start and end within the
        user address space range. */
    if (!is_user_vaddr((void*)phdr->p_vaddr))
        return false;
    if (!is_user_vaddr((void*)(phdr->p_vaddr + phdr->p_memsz)))
        return false;

    /* The region cannot "wrap around" across the kernel virtual
        address space. */
    if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
        return false;

    /* Disallow mapping page 0.
        Not only is it a bad idea to map page 0, but if we allowed
        it then user code that passed a null pointer to system calls
        could quite likely panic the kernel by way of null pointer
        assertions in memcpy(), etc. */
    if (phdr->p_vaddr < PGSIZE)
        return false;

    /* It's okay. */
    return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool load_segment(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable) {
    ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
    ASSERT(pg_ofs(upage) == 0);
    ASSERT(ofs % PGSIZE == 0);

    file_seek(file, ofs);
    while (read_bytes > 0 || zero_bytes > 0) {
        /* Calculate how to fill this page.
            We will read PAGE_READ_BYTES bytes from FILE
            and zero the final PAGE_ZERO_BYTES bytes. */
        size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;

        /* Get a page of memory. */
        uint8_t* kpage = palloc_get_page(PAL_USER);
        if (kpage == NULL)
            return false;

        /* Load this page. */
        if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes) {
            palloc_free_page(kpage);
            return false;
        }
        memset(kpage + page_read_bytes, 0, page_zero_bytes);

        /* Add the page to the process's address space. */
        if (!install_page(upage, kpage, writable)) {
            palloc_free_page(kpage);
            return false;
        }

        /* Advance. */
        read_bytes -= page_read_bytes;
        zero_bytes -= page_zero_bytes;
        upage += PGSIZE;
    }
    return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool setup_stack(void **esp, const char *file_name) {
    uint8_t* kpage;
    bool success = false;

    kpage = palloc_get_page(PAL_USER | PAL_ZERO);
    if (kpage != NULL) {
        success = install_page(((uint8_t*)PHYS_BASE) - PGSIZE, kpage, true);
        if (success) {
            /* Computation of stack memory requirements */
            int argc = 0, capacity = 1;
            char *token, *save_ptr = malloc(strlen(file_name) + 1);
            if (save_ptr == NULL) {
                palloc_free_page(kpage);
                return false;
            }
            char *save_ptr_cpy = save_ptr;

            /* Make a copy of file_name for tokenization */
            strlcpy(save_ptr, file_name, strlen(file_name) + 1);

            /* Keep track of cumulative lengths of tokens to allow copying to stack */
            uint32_t *cumulative_lengths = malloc(sizeof(int)), cumulative_length = 0;
            if (cumulative_lengths == NULL) {
                palloc_free_page(kpage);
                free(save_ptr);
                return false;
            }
            char **tokens = malloc(sizeof(char *));
            if (tokens == NULL) {
                palloc_free_page(kpage);
                free(save_ptr);
                free(cumulative_lengths);
                return false;
            }

            /* Iterate through tokens using strtok_r */
            while ((token = strtok_r(save_ptr, " ", &save_ptr))) {
                if (argc + 1 > capacity) {
                    capacity <<= 1;
                    cumulative_lengths = realloc(cumulative_lengths, capacity * sizeof(int));
                    tokens = realloc(tokens, capacity * sizeof(char *));
                }
                cumulative_lengths[argc] = cumulative_length;
                tokens[argc] = token;
                cumulative_length += (strlen(token) + 1);

                argc++;
            }

            /* Add space for arg pointers, argc, argv, padding, and return address */
            uint32_t memreq = sizeof(int) + sizeof(char **) + (argc + 1) * sizeof(char *) + cumulative_length;
            uint32_t padding = -memreq & 0xF;
            memreq += (padding + 4);

            /* Lower stack pointer */
            *esp = PHYS_BASE - memreq;


            /* Loading arguments onto the stack */
            void **stack_ptr = (void **) *esp;

            /* Fake return address */
            *(stack_ptr++) = NULL;

            /* argc and argv */
            *stack_ptr = (void *) argc;
            *(stack_ptr + 1) = (void *) (stack_ptr + 2);
            stack_ptr += 2;

            char *args_start = (char *) (stack_ptr) + (argc + 1) * sizeof(char *);
            memset(args_start, 0, padding);

            /* For each argument copy its token onto the appropriate address and load the address onto the stack */
            args_start += padding;
            for (int i = 0; i < argc; i++) {
                char *arg_ptr = args_start + cumulative_lengths[i];
                strlcpy(arg_ptr, tokens[i], strlen(tokens[i]) + 1);
                stack_ptr[i] = (void *) arg_ptr;
            }
            stack_ptr[argc] = NULL;

            /* Free memory used for computations */
            free(save_ptr_cpy);
            free(cumulative_lengths);
            free(tokens);
        } else {
            palloc_free_page(kpage);
        }
    }
    return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool install_page(void* upage, void* kpage, bool writable) {
    struct thread* t = thread_current();

    /* Verify that there's not already a page at that virtual
        address, then map our page there. */
    return (pagedir_get_page(t->pcb->pagedir, upage) == NULL &&
            pagedir_set_page(t->pcb->pagedir, upage, kpage, writable));
}

/* Returns true if t is the main thread of the process p */
bool is_main_thread(struct thread* t, struct process* p) { return p->main_thread == t; }

/* Gets the PID of a process */
pid_t get_pid(struct process* p) { return (pid_t)p->main_thread->tid; }

/* Creates a new stack for the thread and sets up its arguments.
   Stores the thread's entry point into *EIP and its initial stack
   pointer into *ESP. Handles all cleanup if unsuccessful. Returns
   true if successful, false otherwise.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. You may find it necessary to change the
   function signature. */
bool setup_thread(void (**eip)(void) UNUSED, void** esp UNUSED) { return false; }

/* Starts a new thread with a new user stack running SF, which takes
   TF and ARG as arguments on its user stack. This new thread may be
   scheduled (and may even exit) before pthread_execute () returns.
   Returns the new thread's TID or TID_ERROR if the thread cannot
   be created properly.

   This function will be implemented in Project 2: Multithreading and
   should be similar to process_execute (). For now, it does nothing.
   */
tid_t pthread_execute(stub_fun sf UNUSED, pthread_fun tf UNUSED, void* arg UNUSED) { return -1; }

/* A thread function that creates a new user thread and starts it
   running. Responsible for adding itself to the list of threads in
   the PCB.

   This function will be implemented in Project 2: Multithreading and
   should be similar to start_process (). For now, it does nothing. */
static void start_pthread(void* exec_ UNUSED) {}

/* Waits for thread with TID to die, if that thread was spawned
   in the same process and has not been waited on yet. Returns TID on
   success and returns TID_ERROR on failure immediately, without
   waiting.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
tid_t pthread_join(tid_t tid UNUSED) { return -1; }

/* Free the current thread's resources. Most resources will
   be freed on thread_exit(), so all we have to do is deallocate the
   thread's userspace stack. Wake any waiters on this thread.

   The main thread should not use this function. See
   pthread_exit_main() below.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
void pthread_exit(void) {}

/* Only to be used when the main thread explicitly calls pthread_exit.
   The main thread should wait on all threads in the process to
   terminate properly, before exiting itself. When it exits itself, it
   must terminate the process in addition to all necessary duties in
   pthread_exit.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
void pthread_exit_main(void) {}
