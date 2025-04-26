include_directories ("${PROJECT_SOURCE_DIR}/src/include"
  "${PROJECT_SOURCE_DIR}/src")

add_library (ksap23 
  grp_key.c grp_key.h 
  mgr_key.c mgr_key.h 
  mem_key.c mem_key.h 
  signature.c signature.h 
  setup.c 
  join_mem.c join_mgr.c 
  sign.c 
  verify.c
  nizk.c nizk.h
  open.c
  judge.c
  proof.c proof.h 
  gml.c gml.h)

target_include_directories (ksap23 PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries (ksap23 PRIVATE ${OPENSSL_LIBRARIES})
