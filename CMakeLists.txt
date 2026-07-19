cmake_minimum_required(VERSION 3.18)

# BLAKE3 1.8.5's CMake project enables CXX and ASM even when its optional TBB
# support is disabled, so those languages must be available to consume its
# upstream target without patching the dependency.
project(blind_mss LANGUAGES C CXX ASM)

if(NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

if(NOT APPLE AND NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
  message(FATAL_ERROR "blind-mss currently supports macOS and Linux")
endif()
if(APPLE AND CMAKE_OSX_DEPLOYMENT_TARGET AND
   CMAKE_OSX_DEPLOYMENT_TARGET VERSION_LESS "10.12")
  message(FATAL_ERROR "blind-mss requires macOS 10.12 or newer for getentropy")
endif()
include(CheckSymbolExists)
check_symbol_exists(getentropy "sys/random.h" BLIND_MSS_HAVE_GETENTROPY)
if(NOT BLIND_MSS_HAVE_GETENTROPY)
  message(FATAL_ERROR "getentropy is required for cryptographic randomness")
endif()

set(BLIND_MSS_N "4" CACHE STRING "Number of KKW parties")
set_property(CACHE BLIND_MSS_N PROPERTY STRINGS
  4 8 12 16 20 24 28 32 64 128 256)
set(BLIND_MSS_GRIND_W "16" CACHE STRING "Fiat-Shamir grinding bits")
set_property(CACHE BLIND_MSS_GRIND_W PROPERTY STRINGS 0 16 24)
set(BLIND_MSS_SEC "128" CACHE STRING "Security target")
set_property(CACHE BLIND_MSS_SEC PROPERTY STRINGS 128 256)
set(BLIND_MSS_BENCH_ITERS "100" CACHE STRING "Benchmark iterations")
set(BLIND_MSS_PIPELINE_ITERS "100" CACHE STRING "Pipeline benchmark iterations")

set(_blind_mss_supported_n 4 8 12 16 20 24 28 32 64 128 256)
if(NOT BLIND_MSS_N IN_LIST _blind_mss_supported_n)
  message(FATAL_ERROR "BLIND_MSS_N must be one of: ${_blind_mss_supported_n}")
endif()
if(NOT BLIND_MSS_GRIND_W MATCHES "^(0|16|24)$")
  message(FATAL_ERROR "BLIND_MSS_GRIND_W must be 0, 16, or 24")
endif()
if(NOT BLIND_MSS_SEC MATCHES "^(128|256)$")
  message(FATAL_ERROR "BLIND_MSS_SEC must be 128 or 256")
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  set(_blind_mss_native_default ON)
else()
  set(_blind_mss_native_default OFF)
endif()
option(BLIND_MSS_NATIVE_ARCH "Tune blind-mss code for the build machine"
       ${_blind_mss_native_default})

include(FetchContent)
FetchContent_Declare(
  blake3
  GIT_REPOSITORY https://github.com/BLAKE3-team/BLAKE3.git
  GIT_TAG        93a431c78a52d7ccf0f366f106467f5070e6075e
  SOURCE_SUBDIR  c
)
set(BLAKE3_USE_TBB OFF CACHE BOOL "" FORCE)
set(BLAKE3_FETCH_TBB OFF CACHE BOOL "" FORCE)
set(BLAKE3_EXAMPLES OFF CACHE BOOL "" FORCE)
set(BLAKE3_TESTING OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(blake3)

# Homebrew's libomp is keg-only. Modern FindOpenMP understands AppleClang's
# flags once its package root is visible, while callers can always override
# OpenMP_ROOT explicitly for a non-Homebrew installation.
if(APPLE AND NOT OpenMP_ROOT)
  find_program(BREW_EXECUTABLE brew)
  if(BREW_EXECUTABLE)
    execute_process(
      COMMAND "${BREW_EXECUTABLE}" --prefix libomp
      OUTPUT_VARIABLE _blind_mss_libomp_root
      OUTPUT_STRIP_TRAILING_WHITESPACE
      ERROR_QUIET
      RESULT_VARIABLE _blind_mss_brew_result)
    if(_blind_mss_brew_result EQUAL 0 AND EXISTS "${_blind_mss_libomp_root}")
      set(OpenMP_ROOT "${_blind_mss_libomp_root}" CACHE PATH
          "Root of the OpenMP installation")
    endif()
  endif()
endif()
find_package(OpenMP REQUIRED COMPONENTS C)

add_library(blindmss STATIC
  src/xmss.c
  src/shared.c
  src/circuits.c
  src/MPC_prove_functions.c
  src/MPC_verify_functions.c
  src/gf128.c
  src/commitment.c
  src/blake3_th.c
  src/blake3_keyed_xof.c
  src/randombytes.c
  src/kkw_prove.c
  src/kkw_verify.c
)
add_library(blindmss::blindmss ALIAS blindmss)
set_target_properties(blindmss PROPERTIES OUTPUT_NAME blindmss)
target_include_directories(blindmss PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>)
target_compile_definitions(blindmss PUBLIC
  N_PARTIES=${BLIND_MSS_N}
  GRIND_W=${BLIND_MSS_GRIND_W}
  SEC_TARGET=${BLIND_MSS_SEC})
target_link_libraries(blindmss
  PUBLIC OpenMP::OpenMP_C
  PRIVATE BLAKE3::blake3)
if(UNIX)
  target_link_libraries(blindmss PUBLIC m)
endif()

function(blind_mss_apply_project_options target)
  target_compile_options(${target} PRIVATE
    $<$<COMPILE_LANG_AND_ID:C,GNU,Clang,AppleClang>:
      -Wall;-Wextra;-Werror;-Wno-array-parameter>
    $<$<COMPILE_LANG_AND_ID:C,Clang,AppleClang>:-Wno-gnu-folding-constant>)
  if(BLIND_MSS_NATIVE_ARCH AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_compile_options(${target} PRIVATE -march=native)
  endif()
endfunction()
blind_mss_apply_project_options(blindmss)

include(CTest)
if(BUILD_TESTING)
  set(_blind_mss_tests
    test_blake3
    test_blake3_keyed_xof
    test_randombytes
    test_xmss
    test_circuit
    test_roundtrip
    test_leaf
    test_e2e)
  foreach(test_name IN LISTS _blind_mss_tests)
    add_executable(${test_name} "src/tests/${test_name}.c")
    target_link_libraries(${test_name} PRIVATE blindmss::blindmss)
    blind_mss_apply_project_options(${test_name})
    add_test(NAME ${test_name} COMMAND ${test_name})
    set_tests_properties(${test_name} PROPERTIES TIMEOUT 1800)
  endforeach()
  # This test directly exercises the upstream public API and therefore needs
  # its public include directory in addition to blindmss's link dependency.
  target_link_libraries(test_blake3_keyed_xof PRIVATE BLAKE3::blake3)

  add_custom_target(check
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
    DEPENDS ${_blind_mss_tests}
    USES_TERMINAL)
endif()

add_executable(bench_bin src/bench.c)
target_link_libraries(bench_bin PRIVATE blindmss::blindmss)
target_compile_definitions(bench_bin PRIVATE
  BENCH_ITERS=${BLIND_MSS_BENCH_ITERS})
blind_mss_apply_project_options(bench_bin)

add_executable(bench_pipeline_bin src/bench_pipeline.c)
target_link_libraries(bench_pipeline_bin PRIVATE blindmss::blindmss)
target_compile_definitions(bench_pipeline_bin PRIVATE
  PIPELINE_ITERS=${BLIND_MSS_PIPELINE_ITERS})
blind_mss_apply_project_options(bench_pipeline_bin)
