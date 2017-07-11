cmake_minimum_required(VERSION 3.4)

# Project.
project(regina)

# Update DynamoRIO submodule.
set(DYNAMORIO_DIR "${CMAKE_CURRENT_SOURCE_DIR}/dynamorio")
execute_process(
	COMMAND git submodule update --init ${DYNAMORIO_DIR}
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

# Build DynamoRIO.
include(ExternalProject)
ExternalProject_Add(dynamorio-module
	PREFIX dr
	SOURCE_DIR ${DYNAMORIO_DIR}
    INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/exports
	CMAKE_ARGS
		-DCMAKE_CXX_STANDARD=98
		-DDISABLE_WARNINGS=ON
        -DDEBUG=OFF
		-DBUILD_DOCS=OFF
		-DBUILD_DRSTATS=OFF
		-DBUILD_SAMPLES=OFF
		-DBUILD_TESTS=OFF
        -DCMAKE_INSTALL_PREFIX=${CMAKE_CURRENT_BINARY_DIR}/exports)

# Try to find DynamoRIO.
list(APPEND CMAKE_PREFIX_PATH "${CMAKE_CURRENT_BINARY_DIR}/exports")
find_package(DynamoRIO) #TODO: silence this guy!

# REGINA target.
if(NOT DynamoRIO_FOUND)
	# Rerun cmake during initial build.
	add_custom_target(regina ${CMAKE_COMMAND} ${CMAKE_SOURCE_DIR} DEPENDS dynamorio-module)
else()
	# Our real target.
	file(GLOB_RECURSE SOURCES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
		"src/*.cpp" "src/*.h")
	add_compile_options("/MT")
	add_library(regina SHARED ${SOURCES})
	add_dependencies(regina dynamorio-module)
	if(DynamoRIO_FOUND)
		configure_DynamoRIO_client(regina)
		use_DynamoRIO_extension(regina drmgr)
		use_DynamoRIO_extension(regina drreg)
		use_DynamoRIO_extension(regina drutil)
		use_DynamoRIO_extension(regina drsyms)
	endif()
endif()
