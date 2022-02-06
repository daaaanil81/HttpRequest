cmake_minimum_required(VERSION 3.10)

# set the project name
project(HttpRequest VERSION 1.0)

include_directories("${PROJECT_SOURCE_DIR}/include")

file(GLOB SOURCES "${PROJECT_SOURCE_DIR}/examples/*.cpp")

# add the executable
add_executable(http_request ${SOURCES})

# specify the C++ standard
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED True)
