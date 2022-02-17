cmake_minimum_required(VERSION 3.10)

# Set the project name
project(HttpRequest VERSION 1.0)

# Specify the C++ standard
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Third party
set(THIRD_PARTY_PATH "${PROJECT_SOURCE_DIR}/third_party")

# OPENSSL
set(OPENSSL_LIB_PATH "${THIRD_PARTY_PATH}/openssl/lib/")
set(OPENSSL_INCLUDE_PATH "${THIRD_PARTY_PATH}/openssl")

# Source http example
file(GLOB HTTP_EXAMPLE_SOURCES "${PROJECT_SOURCE_DIR}/examples/*.cpp")

# Add the http example executable
add_executable(http_example ${HTTP_EXAMPLE_SOURCES})

target_include_directories(http_example PUBLIC
	"${PROJECT_SOURCE_DIR}/include"
	"${OPENSSL_INCLUDE_PATH}")

# Add openssl library
target_link_libraries(http_example -L${OPENSSL_LIB_PATH})
target_link_libraries(http_example -lcrypto)
target_link_libraries(http_example -lssl)


# Source http test server
set(HTTP_SERVER_DIR "${PROJECT_SOURCE_DIR}/test_server")

add_custom_target(http_server ALL
	COMMAND go build -o ${PROJECT_BINARY_DIR}/
	WORKING_DIRECTORY ${HTTP_SERVER_DIR}
	COMMENT "Build test http server")

add_custom_target(clean_all
	COMMAND ${CMAKE_BUILD_TOOL} clean
	COMMAND rm ${PROJECT_BINARY_DIR}/test_server
	COMMENT "Clean All")
