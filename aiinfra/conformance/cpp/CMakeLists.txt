cmake_minimum_required(VERSION 3.20)

project(cph_ccse_cpp_conformance VERSION 0.1.0 LANGUAGES CXX)

find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)

option(CPH_CCSE_ENFORCE_LOCKED_TOOLCHAIN
  "Require the WS0.1a compiler and OpenSSL versions" OFF)
if(CPH_CCSE_ENFORCE_LOCKED_TOOLCHAIN)
  if(NOT CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR
     NOT CMAKE_CXX_COMPILER_VERSION VERSION_EQUAL "15.2.0")
    message(FATAL_ERROR "WS0.1a requires GNU C++ 15.2.0")
  endif()
  if(NOT OpenSSL_VERSION VERSION_EQUAL "3.5.5")
    message(FATAL_ERROR "WS0.1a requires OpenSSL 3.5.5")
  endif()
endif()

add_executable(cph_ccse_conformance
  src/ccse.cpp
  src/main.cpp
)

target_compile_features(cph_ccse_conformance PRIVATE cxx_std_20)
set_target_properties(cph_ccse_conformance PROPERTIES
  CXX_EXTENSIONS OFF
)
target_include_directories(cph_ccse_conformance PRIVATE src)
target_compile_options(cph_ccse_conformance PRIVATE
  -Wall
  -Wextra
  -Wpedantic
  -Wconversion
  -Wsign-conversion
  -Werror
)
target_link_libraries(cph_ccse_conformance PRIVATE
  OpenSSL::Crypto
  ${CMAKE_DL_LIBS}
)

enable_testing()
add_test(
  NAME ccse_v1_shared_vectors
  COMMAND cph_ccse_conformance
    ${CMAKE_CURRENT_SOURCE_DIR}/../../ccse/testdata/ccse_v1_ed25519_positive.json
    ${CMAKE_CURRENT_SOURCE_DIR}/../../ccse/testdata/ccse_v1_negative.json
)
