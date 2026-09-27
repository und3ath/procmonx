add_executable(pmx main.cpp cli_common.cpp)
target_link_libraries(pmx PRIVATE pmx_core shell32)
set_target_properties(pmx PROPERTIES OUTPUT_NAME "pmx")

# The CLI loads the minifilter by an absolute NT path; defaultSysPath expects it
# in a `procmon\` dir next to pmx.exe. Copy the .sys files there so a freshly
# built tree can install/load the driver without extra setup.
set(PMX_DRIVER_SRC "${CMAKE_SOURCE_DIR}/procmon")
add_custom_command(TARGET pmx POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:pmx>/procmon"
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
          "${PMX_DRIVER_SRC}/PROCMON25.SYS" "$<TARGET_FILE_DIR:pmx>/procmon/"
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
          "${PMX_DRIVER_SRC}/PROCMON24.SYS" "$<TARGET_FILE_DIR:pmx>/procmon/"
  COMMENT "Copying Procmon minifilter next to pmx.exe")
