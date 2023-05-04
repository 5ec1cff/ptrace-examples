cmake_minimum_required(VERSION 3.22.1)
enable_language(ASM)
project("pt_injector")

find_package(cxx REQUIRED CONFIG)

include_directories(include)

add_library(inject-lib SHARED inject-lib.cpp)
target_link_libraries(inject-lib log cxx::cxx)

add_executable(libinjector.so inject.cpp elf_util.cpp pmparser.c ptrace_utils.cpp trace.cpp)
target_link_libraries(libinjector.so log cxx::cxx)

if(ANDROID_ABI STREQUAL "armeabi-v7a")
    message("current abi is armeabi-v7a")
    add_executable(libshellcode.so shellcode/armeabi-v7a.s)
    target_link_libraries(libshellcode.so -nostdlib -static)
endif()

add_executable(libbkpt.so shellcode/breakpoint.c)
target_link_libraries(libbkpt.so -nostdlib -static)
