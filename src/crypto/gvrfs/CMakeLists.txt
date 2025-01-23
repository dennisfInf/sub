target_sources(gvrf
  PRIVATE
    "${CMAKE_CURRENT_LIST_DIR}/client.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/server.cpp"

)
include(${CMAKE_CURRENT_LIST_DIR}/sps_eq/CMakeLists.txt)
