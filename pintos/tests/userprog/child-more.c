/* Child process run by wait-not-child test.
   Executes child-simple process. */

#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"

int main(void) {
  test_name = "child-more";
  
  pid_t pid = exec("child-simple");
  wait(pid);
  return pid;
}
