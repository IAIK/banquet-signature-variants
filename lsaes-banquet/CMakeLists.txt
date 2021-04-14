cmake_minimum_required (VERSION 3.12)
project (banquet C CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 17) 

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Choose the type of build." FORCE)
endif()

include(CheckCXXCompilerFlag)


add_compile_options("-Wall")

add_subdirectory(keccak)

set(BANQUET_SRCS
  aes.cpp
  banquet.cpp
  banquet_instances.cpp
  field.cpp
  tree.cpp
  tape.cpp
  randomness.c
  )

CHECK_CXX_COMPILER_FLAG(-mpclmul COMPILER_HAS_M_PCLMUL)
CHECK_CXX_COMPILER_FLAG(-msse2 COMPILER_HAS_M_SSE2)
CHECK_CXX_COMPILER_FLAG(-msse4 COMPILER_HAS_M_SSE4)
CHECK_CXX_COMPILER_FLAG(-maes COMPILER_HAS_M_AES)
if (COMPILER_HAS_M_PCLMUL AND COMPILER_HAS_M_SSE2 AND COMPILER_HAS_M_SSE4 AND COMPILER_HAS_M_AES)
  add_compile_options(-mpclmul -msse2 -msse4 -maes)
else()
  message(
    ERROR
    "compiler does not have at least one of flag (pclmul, sse2, sse4, aes) which are needed"  )
endif()

add_library(banquet_static STATIC ${BANQUET_SRCS})
target_link_libraries(banquet_static PUBLIC keccak) 

add_library(bench_utils STATIC tools/bench_utils.cpp tools/bench_timing.cpp)
add_executable(bench tools/bench.cpp)
add_executable(bench_free tools/bench_free.cpp)
target_link_libraries(bench banquet_static bench_utils)
target_link_libraries(bench_free banquet_static bench_utils)
