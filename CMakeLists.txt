cmake_minimum_required(VERSION 3.25)
project(procmonx VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(PMX_BUILD_TESTS "Build unit tests" ON)
option(PMX_BUILD_GUI "Build Qt GUI (requires Qt 6)" OFF)

if(MSVC)
  add_compile_options(/W4 /permissive- /utf-8 /Zc:__cplusplus /MP)
  add_compile_definitions(UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0A00)
endif()

add_subdirectory(src/core)
add_subdirectory(src/cli)

if(PMX_BUILD_GUI)
  add_subdirectory(src/gui)
endif()

if(PMX_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
