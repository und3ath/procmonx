#include <cstdio>

#include "test_util.h"

int test_append_log();
int test_string_pool();
int test_protocol();
int test_flags();
int test_pairer();
int test_filter();
int test_store();
int test_pid_names();
int test_pml();

int main() {
  int fails = 0;
  fails += test_append_log();
  fails += test_string_pool();
  fails += test_protocol();
  fails += test_flags();
  fails += test_pairer();
  fails += test_filter();
  fails += test_store();
  fails += test_pid_names();
  fails += test_pml();
  if (fails == 0) {
    std::printf("ALL TESTS PASSED\n");
    return 0;
  }
  std::printf("%d CHECK(s) FAILED\n", fails);
  return 1;
}
