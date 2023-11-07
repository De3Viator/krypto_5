cmake_minimum_required(VERSION 3.26)
project(krypto_5)

set(CMAKE_CXX_STANDARD 23)
set(OpenSSL_ROOT_DIR "${CMAKE_SOURCE_DIR}/openssl")
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})
set(SOURCE_FILES main.cpp
)
add_executable(krypto_5 ${SOURCE_FILES})
target_link_libraries(krypto_5 OpenSSL::Crypto)
