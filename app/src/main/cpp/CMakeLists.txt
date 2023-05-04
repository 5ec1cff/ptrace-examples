cmake_minimum_required(VERSION 3.22.1)
project("pt_injector")

find_package(cxx REQUIRED CONFIG)

include_directories(include)

add_library(inject-lib SHARED inject-lib.cpp)
target_link_libraries(inject-lib log cxx::cxx)

add_executable(libinjector.so inject.cpp elf_util.cpp pmparser.c ptrace_utils.cpp trace.cpp)
target_link_libraries(libinjector.so log cxx::cxx)
