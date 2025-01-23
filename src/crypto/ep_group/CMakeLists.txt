add_library(ep
  STATIC
    ep.cpp
    serializer.cpp
    deserializer.cpp
)

# Relic does not check for libgmp if using it, and due to some c/c++ incompatibilities,
# we also need to include libgmp directly
find_library(LIB_GMP gmp)
if(NOT LIB_GMP)
  message(FATAL_ERROR "gmp library not found")
endif()

target_include_directories(ep
  PUBLIC
    "${PROJECT_SOURCE_DIR}/inc/crypto/ep_group"
    "${PROJECT_SOURCE_DIR}/inc/concurrency/"

  PRIVATE
    "${PROJECT_SOURCE_DIR}/lib/relic/include/"
)
target_link_libraries(ep PUBLIC gmp
  PRIVATE relic_s  
)