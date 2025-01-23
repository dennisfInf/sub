target_sources(gvrf
  PRIVATE
    "${CMAKE_CURRENT_LIST_DIR}/main.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/config.cpp"
)

include(${CMAKE_CURRENT_LIST_DIR}/crypto/CMakeLists.txt)
include(${CMAKE_CURRENT_LIST_DIR}/networking/CMakeLists.txt)
