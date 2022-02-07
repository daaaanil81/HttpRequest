cmake_minimum_required(VERSION 3.10)

# set the project name
project(HttpRequest VERSION 1.0)

set(THIRD_PARTY_PATH "${PROJECT_SOURCE_DIR}/third_party")
set(OPENSSL_LIB_PATH "${THIRD_PARTY_PATH}/openssl/lib/")
set(OPENSSL_INCLUDE_PATH "${THIRD_PARTY_PATH}/openssl")

include_directories("${PROJECT_SOURCE_DIR}/include"
		    "${OPENSSL_INCLUDE_PATH}")

file(GLOB SOURCES "${PROJECT_SOURCE_DIR}/examples/*.cpp")

# add the executable
add_executable(http_request ${SOURCES})

# add openssl library
target_link_libraries(http_request -L${OPENSSL_LIB_PATH})

target_link_libraries(http_request -lcrypto)
target_link_libraries(http_request -lssl)

# specify the C++ standard
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED True)
