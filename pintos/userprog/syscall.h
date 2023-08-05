#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>


bool validate_space_func(void *, size_t);
bool validate_string_func(char *);

void syscall_init(void);

#endif /* userprog/syscall.h */
