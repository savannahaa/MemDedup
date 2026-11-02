cmake_minimum_required(VERSION 3.16)
project(MemDedup VERSION 0.1.0 LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
if(POLICY CMP0144)
  cmake_policy(SET CMP0144 NEW)
endif()
if(POLICY CMP0167)
  cmake_policy(SET CMP0167 OLD)
endif()
find_package(Boost 1.71 REQUIRED)
find_package(OpenSSL 1.1.1 REQUIRED COMPONENTS Crypto)
find_package(Threads REQUIRED)
if(APPLE AND Boost_VERSION_STRING VERSION_LESS "1.81")
  add_compile_definitions(_LIBCPP_ENABLE_CXX17_REMOVED_UNARY_BINARY_FUNCTION)
endif()

add_library(blake3_portable STATIC
  third_party/blake3/c/blake3.c
  third_party/blake3/c/blake3_dispatch.c
  third_party/blake3/c/blake3_portable.c)
target_include_directories(blake3_portable PUBLIC third_party/blake3/c)
target_compile_definitions(blake3_portable PRIVATE
  BLAKE3_NO_SSE2 BLAKE3_NO_SSE41 BLAKE3_NO_AVX2 BLAKE3_NO_AVX512 BLAKE3_USE_NEON=0)

add_library(memdedup STATIC
  src/bucket.cpp
  src/dedup_protocol.cpp
  src/key_exchange.cpp
  src/network.cpp
  src/record.cpp
  src/update_protocol.cpp)
add_library(MemDedup::memdedup ALIAS memdedup)
target_include_directories(memdedup PUBLIC include ${Boost_INCLUDE_DIRS}
                                   PRIVATE include/memdedup)
target_link_libraries(memdedup PUBLIC blake3_portable OpenSSL::Crypto Threads::Threads)
