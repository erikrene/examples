/* Opens the same file twice, then closes the second file descriptor.
   Then, checks that the first file descriptor is still valid. */

#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"
#include "tests/userprog/sample.inc"

void test_main(void) {
  int fd = open("sample.txt");
  seek(fd, 0xFF);
  char buf[420];
  int result = read(fd, buf, 1);
  msg("%d", result);
}
