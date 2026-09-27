add_library(pmx_core STATIC
  pmx/string_pool.cpp
  pmx/driver/port_client.cpp
  pmx/driver/driver_controller.cpp
  pmx/enrich/process_table.cpp
  pmx/enrich/pairer.cpp
  pmx/enrich/pid_names.cpp
  pmx/decode.cpp
  pmx/filter.cpp
  pmx/filter_json.cpp
  pmx/filter_pmc.cpp
  pmx/store.cpp
  pmx/pml.cpp
  pmx/pml_read.cpp
  pmx/etw/net_trace.cpp
)

target_include_directories(pmx_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(pmx_core PUBLIC fltlib advapi32 ws2_32)
target_compile_features(pmx_core PUBLIC cxx_std_20)
