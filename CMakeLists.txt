cmake_minimum_required(VERSION 3.20)

project(IDA_Fusion)

set(CMAKE_CXX_STANDARD 20)

# Add cmake modules directory to module path
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

# Find IDA SDK (will auto-download if not present)
find_package(IDASDK REQUIRED)

# Create the plugin
add_library(IDA_Fusion SHARED src/main.cpp)

# Set output name to match IDA plugin naming convention
if(IDASDK_ARCH STREQUAL "64")
    set_target_properties(IDA_Fusion PROPERTIES OUTPUT_NAME "IDA_Fusion64")
else()
    set_target_properties(IDA_Fusion PROPERTIES OUTPUT_NAME "IDA_Fusion")
endif()

# Include directories
target_include_directories(IDA_Fusion PRIVATE
    include
    ${IDASDK_INCLUDE_DIRS}
)

# Preprocessor definitions
target_compile_definitions(IDA_Fusion PRIVATE
    __NT__
    __IDP__
)

# Add architecture-specific definitions
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    target_compile_definitions(IDA_Fusion PRIVATE __X64__ __EA64__)
else()
    target_compile_definitions(IDA_Fusion PRIVATE __EA32__)
endif()

# Link libraries
if(IDASDK_LIBRARIES)
    target_link_libraries(IDA_Fusion PRIVATE ${IDASDK_LIBRARIES})
endif()