cmake_minimum_required (VERSION 3.1)
project (kms_message
   LANGUAGES C
   VERSION 0.0.1
   DESCRIPTION
   "Library to parse and generate AWS Key Management Service (KMS) messages"
)

set (CMAKE_C_STANDARD 90)

include (CheckCCompilerFlag)
# All targets obey visibility, not just library targets.
cmake_policy (SET CMP0063 NEW)
set (CMAKE_C_VISIBILITY_PRESET hidden)
add_library (
   kms_message SHARED
   src/hexlify.c
   src/hexlify.h
   src/kms_crypto.c
   src/kms_crypto.h
   src/kms_kv_list.c
   src/kms_kv_list.h
   src/kms_message/kms_message.h
   src/kms_message/kms_request.h
   src/kms_request.c
   src/kms_request_str.c
   src/kms_request_str.h
)

include (FindOpenSSL)
target_link_libraries(kms_message "${OPENSSL_LIBRARIES}")
target_include_directories(kms_message PRIVATE "${OPENSSL_INCLUDE_DIR}")

set_target_properties (kms_message PROPERTIES
   SOVERSION 0
   OUTPUT_NAME "kms_message"
   PREFIX "lib"
   INTERFACE_kms_message_MAJOR_VERSION 0
)

target_compile_definitions (kms_message PRIVATE KMS_MSG_COMPILATION)
set_property (TARGET kms_message APPEND PROPERTY
   COMPATIBLE_INTERFACE_STRING kms_message_MAJOR_VERSION
)

include (CMakePackageConfigHelpers)
install (TARGETS kms_message
   EXPORT kms_message_targets
   LIBRARY DESTINATION lib
   ARCHIVE DESTINATION lib
   RUNTIME DESTINATION bin
   INCLUDES DESTINATION include
)

install (
   FILES
   src/kms_message/kms_message.h
   src/kms_message/kms_request.h
   DESTINATION include/kms_message
   COMPONENT Devel
)

include (CMakePackageConfigHelpers)
write_basic_package_version_file (
   "${CMAKE_CURRENT_BINARY_DIR}/kms_message/kms_message-config-version.cmake"
   VERSION 0.0.1
   COMPATIBILITY AnyNewerVersion
)

export (EXPORT kms_message_targets
   FILE "${CMAKE_CURRENT_BINARY_DIR}/kms_message/kms_message_targets.cmake"
)

configure_file (cmake/kms_message-config.cmake
   "${CMAKE_CURRENT_BINARY_DIR}/kms_message/kms_message-config.cmake"
   COPYONLY
)

set (ConfigPackageLocation lib/cmake/kms_message)
install (EXPORT kms_message_targets
   FILE kms_message_targets.cmake
   DESTINATION ${ConfigPackageLocation}
)

install (
   FILES
   cmake/kms_message-config.cmake
   "${CMAKE_CURRENT_BINARY_DIR}/kms_message/kms_message-config-version.cmake"
   DESTINATION ${ConfigPackageLocation}
   COMPONENT Devel
)

# pkg-config.
set (PKG_CONFIG_LIBDIR "\${prefix}/lib")
set (PKG_CONFIG_INCLUDEDIR "\${prefix}/include")
set (PKG_CONFIG_LIBS "-L\${libdir} -lkms_message")
set (PKG_CONFIG_CFLAGS "-I\${includedir}")
configure_file (
   "${CMAKE_CURRENT_SOURCE_DIR}/cmake/libkms_message.pc.in"
   "${CMAKE_CURRENT_BINARY_DIR}/libkms_message.pc"
)

install (
   FILES "${CMAKE_BINARY_DIR}/libkms_message.pc"
   DESTINATION lib/pkgconfig
)

add_executable (
   test_kms_request
   src/hexlify.c
   src/kms_kv_list.c
   test/test_kms_request.c
)

target_link_libraries (test_kms_request kms_message)
target_include_directories (test_kms_request PRIVATE ${PROJECT_SOURCE_DIR})
