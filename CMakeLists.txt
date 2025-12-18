cmake_minimum_required(VERSION 3.20)

project(IDA_Fusion)

set(CMAKE_CXX_STANDARD 20)

# Add cmake modules directory to module path
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

# Find IDA SDK (will auto-download if not present)
find_package(IDASDK REQUIRED)

# Create the plugin
add_library(IDA_Fusion SHARED
        src/plugin.cpp
        src/signature.cpp
)

# Set output name to match IDA plugin naming convention
if (CMAKE_SIZEOF_VOID_P EQUAL 8)
    set_target_properties(IDA_Fusion PROPERTIES OUTPUT_NAME "IDA_Fusion64")
else ()
    set_target_properties(IDA_Fusion PROPERTIES OUTPUT_NAME "IDA_Fusion32")
endif ()

# Output DLL to parent directory (one level up from _build)
# The presets configure binaryDir as build/x64-release/_build, so we output to ..
get_filename_component(OUTPUT_DIR "${CMAKE_BINARY_DIR}/.." ABSOLUTE)
set_target_properties(IDA_Fusion PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${OUTPUT_DIR}"
        LIBRARY_OUTPUT_DIRECTORY "${OUTPUT_DIR}"
        ARCHIVE_OUTPUT_DIRECTORY "${OUTPUT_DIR}"
        RUNTIME_OUTPUT_DIRECTORY_DEBUG "${OUTPUT_DIR}"
        RUNTIME_OUTPUT_DIRECTORY_RELEASE "${OUTPUT_DIR}"
        LIBRARY_OUTPUT_DIRECTORY_DEBUG "${OUTPUT_DIR}"
        LIBRARY_OUTPUT_DIRECTORY_RELEASE "${OUTPUT_DIR}"
        ARCHIVE_OUTPUT_DIRECTORY_DEBUG "${OUTPUT_DIR}"
        ARCHIVE_OUTPUT_DIRECTORY_RELEASE "${OUTPUT_DIR}"
        PDB_OUTPUT_DIRECTORY "${OUTPUT_DIR}"
)

# Include directories
target_include_directories(IDA_Fusion PRIVATE
        include
        ${IDASDK_INCLUDE_DIRS}
)

# Preprocessor definitions
target_compile_definitions(IDA_Fusion PRIVATE __IDP__)

# Platform-specific definitions
if (WIN32)
    target_compile_definitions(IDA_Fusion PRIVATE __NT__)
elseif (APPLE)
    target_compile_definitions(IDA_Fusion PRIVATE __MAC__)
elseif (UNIX)
    target_compile_definitions(IDA_Fusion PRIVATE __LINUX__)
endif ()

# Add architecture-specific definitions
if (CMAKE_SIZEOF_VOID_P EQUAL 8)
    target_compile_definitions(IDA_Fusion PRIVATE __X64__ __EA64__)
else ()
    target_compile_definitions(IDA_Fusion PRIVATE __X86__ __EA32__)
endif ()

# Link libraries
if (IDASDK_LIBRARIES)
    target_link_libraries(IDA_Fusion PRIVATE ${IDASDK_LIBRARIES})
else ()
    # If no IDA library found, the plugin will link against IDA at runtime
    # This is common for 32-bit builds where libraries aren't provided
    message(STATUS "No IDA library found - symbols will be resolved by IDA at runtime")

    # For MSVC, we need to tell the linker to allow unresolved externals
    # since they'll be provided by IDA when the plugin loads
    if (MSVC)
        target_link_options(IDA_Fusion PRIVATE /FORCE:UNRESOLVED)
    endif ()
endif ()

# Tests (only for x64 builds to avoid complexity)
if (CMAKE_SIZEOF_VOID_P EQUAL 8)
    enable_testing()
    add_executable(fusion_tests tests/test_signature.cpp)
    target_include_directories(fusion_tests PRIVATE include tests)
    target_compile_definitions(fusion_tests PRIVATE IDA_SDK_VERSION=900)
    add_test(NAME fusion_tests COMMAND fusion_tests)
endif ()