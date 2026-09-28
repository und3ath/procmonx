cmake_minimum_required(VERSION 3.25)

# Before project(): its compiler check links gdi32 and would die with a bare
# LNK1104. A partial SDK (e.g. 10.0.28000.0) lacks these import libs.
if(DEFINED ENV{WindowsSdkDir} AND DEFINED ENV{WindowsSDKLibVersion})
  set(_pmx_sdk_lib "$ENV{WindowsSdkDir}Lib/$ENV{WindowsSDKLibVersion}um/x64")
  foreach(_lib gdi32 fltlib)
    if(NOT EXISTS "${_pmx_sdk_lib}/${_lib}.lib")
      message(FATAL_ERROR "Windows SDK $ENV{WindowsSDKLibVersion} has no ${_lib}.lib. "
        "Use build.cmd, or run: vcvars64.bat 10.0.26100.0")
    endif()
  endforeach()
endif()

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
