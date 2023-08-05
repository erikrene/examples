#ifndef DEVICES_INPUT_H
#define DEVICES_INPUT_H

#include <stdbool.h>
#include <stdint.h>
#include "threads/synch.h"

static struct lock input_lock;

void input_init(void);
void input_putc(uint8_t);
uint8_t input_getc(void);
bool input_full(void);

#endif /* devices/input.h */
