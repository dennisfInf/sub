
if (PRIVACY_PASS)
  target_sources(gvrf
    PRIVATE
      "${CMAKE_CURRENT_LIST_DIR}/PPClient.cpp"
  )
else()
  target_sources(gvrf
  PRIVATE
    "${CMAKE_CURRENT_LIST_DIR}/GVRFClient.cpp"
  )
endif()