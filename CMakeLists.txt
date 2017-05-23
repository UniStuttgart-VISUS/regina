cmake_minimum_required(VERSION 3.4)

project(regina)

set(HEADERS src/log.h src/per_thread_t.h src/trace_ref_t.h src/fileio.h src/abstract_fileio.h)
set(SOURCES src/regina.cpp src/fileio.cpp)

add_library(regina SHARED ${SOURCES} ${HEADERS})

find_package(DynamoRIO)
if (NOT DynamoRIO_FOUND)
  message(FATAL_ERROR "DynamoRIOpackage required to build")
endif(NOT DynamoRIO_FOUND)

configure_DynamoRIO_client(regina)
use_DynamoRIO_extension(regina drmgr)
use_DynamoRIO_extension(regina drreg)
use_DynamoRIO_extension(regina drutil)
use_DynamoRIO_extension(regina drsyms)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /MT")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /Ox")