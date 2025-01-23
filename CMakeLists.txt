# stolen from relic, ATM we do not need any newer features
cmake_minimum_required(VERSION 3.1)
set(PRIVACY_PASS "1")
set(GVRF_OPT "0")
project(GVRF)
message("Source directory: ${CMAKE_SOURCE_DIR}")

### RELIC START ###
# Configure relic
option(DEBUG "Relic: Build with debugging support" off)
option(PROFL "Relic: Build with profiling support" off)
option(CHECK "Relic: Build with error-checking support" on)
option(VERBS "Relic: Build with detailed error messages" on)
option(OVERH "Relic: Build with overhead estimation" off)
option(DOCUM "Relic: Build documentation" off)
option(STRIP "Relic: Build only the selected algorithms" off)
option(QUIET "Relic: Build with printing disabled" off)
option(COLOR "Relic: Build with colored output" on)
option(BIGED "Relic: Build with big-endian support" off)
option(SHLIB "Relic: Build shared library" off)                             # Do not build a shared library
option(STLIB "Relic: Build static library" on)
option(STBIN "Relic: Build static binaries" off)
option(AMALG "Relic: Build amalgamation" off)
# Number of tests and benchmarks
set(TESTS "0" CACHE STRING "Relic: Number of times each test is ran.")      # Do not build tests
set(BENCH "0" CACHE STRING "Relic: Number of times each benchmark is ran.") # Do not build benchmarks
# Choose the memory-allocation policy.
set(ALLOC "AUTO" CACHE STRING "Relic: Allocation policy")
#Using gmp-sec as default arithmetic backend
set(ARITH "gmp-sec")
if (PRIVACY_PASS)
  message("PP")
  set(FP_PRIME 256)
  set(MD_METHD "SH256")
  set(FP_QNRES off)
  set(EC_ENDOM off)
  set(TIMER "CYCLE")
  set(RAND "UDEV")
  set(FP_METHD "INTEG;INTEG;INTEG;MONTY;JMPDS;JMPDS;SLIDE")
  set(TIMER "CYCLE")
  set(RAND "UDEV")
  set(EP_METHD "JACOB;LWNAF;COMBS;INTER;SSWUM")
  set(ENV{COMP} "-O3 -funroll-loops -fomit-frame-pointer -finline-small-functions -march=native -mtune=native")
  # Use optimized code for x64
else()
  if (GVRF_OPT)
    #Using a faster backend for GVRF. Does not seem to work with P-256, even if the suggestion of the error message is impleented
    set(ARITH "x64-asm-6l")
  endif()
  message("test")
  set(FP_PRIME 381)
  set(MD_METHD "SH384")
  set(FP_QNRES on)
  set(FP_METHD "INTEG;INTEG;INTEG;MONTY;JMPDS;JMPDS;SLIDE")
  set(FPX_METHD "INTEG;INTEG;LAZYR")
  set(TIMER "CYCLE")
  set(RAND "UDEV")
  set(WSIZE 64)
  set(FP_METHD "INTEG;INTEG;INTEG;MONTY;JMPDS;JMPDS;SLIDE")
  set(EP_METHD "JACOB;LWNAF;COMBS;INTER;SWIFT")
  set(ENV{COMP} "-O3 -funroll-loops -fomit-frame-pointer -finline-small-functions -march=native -mtune=native")
# Use optimized code for x64
  set(FP_PMERS off)
  set(EP_PLAIN off)
  set(EP_SUPER off)
  set(PP_METHD="LAZYR;OATEP")
endif()

link_directories(/usr/lib/x86_64-linux-gnu/libgmpxx.a)
find_library(LIB_GMP gmp)
if(NOT LIB_GMP)
  message(FATAL_ERROR "gmp library not found")
endif()
set(CMAKE_C_FLAGS_TEMP "${CMAKE_C_FLAGS}")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
#set(DEBUG "SET_THIS_TO_SOMETHING_FOR_RELIC")
#TODO USE ALLOC DYNAMIC WITH SANITIZERS
#set(ALLOC "DYNAMIC")
add_subdirectory("${CMAKE_SOURCE_DIR}/lib/relic" "${CMAKE_BINARY_DIR}/relic_build" EXCLUDE_FROM_ALL)
target_include_directories(relic_s INTERFACE "${CMAKE_BINARY_DIR}/relic_build/include/")
#unset(ALLOC)
#unset(DEBUG)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS_TEMP}")
### RELIC END ###

if (PRIVACY_PASS)
  set(RELIC_PROJ_NAME "ep")
  add_subdirectory("./src/crypto/ep_group" "${CMAKE_BINARY_DIR}/ep_build")
else()
  set(RELIC_PROJ_NAME "pairing")
  add_subdirectory("./src/crypto/bilinear_group" "${CMAKE_BINARY_DIR}/pairing_build")
endif()
set(Boost_USE_STATIC_LIBS ON)
find_package(Boost REQUIRED COMPONENTS system thread)
set(OPENSSL_USE_STATIC_LIBS TRUE)

find_package(OpenSSL REQUIRED)
add_executable(gvrf "")
target_compile_options(gvrf PUBLIC
  "-Wall"
  "-Wextra"
  "-Wpedantic"
  "-Wno-conversion"
  "-Wno-sign-conversion"
  "-Wno-sign-compare"
  "${OpenMP_CXX_FLAGS}"
  "$<$<CONFIG:Debug>:-g3>"
  "$<$<BOOL:${USE_PROFILE}>:-pg>"
  "$<$<CONFIG:Debug>:-Og>"
  "$<$<CONFIG:Release>:-Ofast>"
  "-g"
  "$<$<BOOL:${PRIVACY_PASS}>:-DPRIVACY_PASS>"
)
target_link_options(gvrf PUBLIC
  "-pthread"
)
set_property(TARGET gvrf PROPERTY CXX_STANDARD 23)
set_property(TARGET gvrf PROPERTY C_STANDARD 99)

include(src/CMakeLists.txt)
target_include_directories(gvrf PUBLIC inc/ ${Boost_INCLUDE_DIRS})
target_link_libraries(gvrf PUBLIC ${RELIC_PROJ_NAME} gmpxx gmp PRIVATE OpenSSL::SSL OpenSSL::Crypto Boost::system Boost::thread -lcrypto -lz -ldl -pthread -static-libgcc)