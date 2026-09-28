add_executable(pmx_tests
  main.cpp
  test_append_log.cpp
  test_string_pool.cpp
  test_protocol.cpp
  test_flags.cpp
  test_pairer.cpp
  test_filter.cpp
  test_store.cpp
  test_pid_names.cpp
  test_pml.cpp
  test_spool.cpp
  test_writers.cpp
)
target_link_libraries(pmx_tests PRIVATE pmx_core)
add_test(NAME pmx_tests COMMAND pmx_tests)
