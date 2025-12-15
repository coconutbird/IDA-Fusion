# FindIDASDK.cmake
# Finds or downloads the IDA SDK from GitHub
#
# This module defines:
#  IDASDK_FOUND - System has IDA SDK
#  IDASDK_INCLUDE_DIRS - The IDA SDK include directories
#  IDASDK_LIBRARIES - The libraries needed to use IDA SDK
#  IDASDK_LIBRARY_DIRS - The library directories

include(FetchContent)

# Check if IDA SDK is already available locally
if(DEFINED IDA_SDK_DIR AND EXISTS "${IDA_SDK_DIR}")
    message(STATUS "Using local IDA SDK at ${IDA_SDK_DIR}")
    set(ida_sdk_SOURCE_DIR "${IDA_SDK_DIR}")
else()
    # Automatically download IDA SDK from GitHub
    message(STATUS "Downloading IDA SDK from GitHub...")

    FetchContent_Declare(
        ida_sdk
        GIT_REPOSITORY https://github.com/HexRaysSA/ida-sdk.git
        GIT_TAG main
    )

    FetchContent_MakeAvailable(ida_sdk)

    message(STATUS "IDA SDK downloaded to ${ida_sdk_SOURCE_DIR}")
endif()

set(IDA_SDK_DIR "${ida_sdk_SOURCE_DIR}")

# Detect architecture (32-bit or 64-bit)
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(IDA_ARCH "64")
    set(IDA_LIB_ARCH "x64")
else()
    set(IDA_ARCH "32")
    set(IDA_LIB_ARCH "x86")
endif()

# IDA SDK include directories
# The GitHub SDK has a different structure: src/include instead of include
if(EXISTS "${IDA_SDK_DIR}/src/include")
    set(IDASDK_INCLUDE_DIRS "${IDA_SDK_DIR}/src/include")
elseif(EXISTS "${IDA_SDK_DIR}/include")
    set(IDASDK_INCLUDE_DIRS "${IDA_SDK_DIR}/include")
else()
    message(FATAL_ERROR "Could not find IDA SDK include directory in ${IDA_SDK_DIR}")
endif()

# IDA SDK library directory (adjust based on your SDK structure)
# Try both src/lib and lib directories
set(IDASDK_LIBRARY_DIRS "")

if(WIN32)
    # Try src/lib first (GitHub SDK structure)
    if(EXISTS "${IDA_SDK_DIR}/src/lib/x64_win_vc_${IDA_LIB_ARCH}")
        set(IDASDK_LIBRARY_DIRS "${IDA_SDK_DIR}/src/lib/x64_win_vc_${IDA_LIB_ARCH}")
    elseif(EXISTS "${IDA_SDK_DIR}/src/lib/x64_win_vc_64")
        set(IDASDK_LIBRARY_DIRS "${IDA_SDK_DIR}/src/lib/x64_win_vc_64")
    elseif(EXISTS "${IDA_SDK_DIR}/src/lib")
        set(IDASDK_LIBRARY_DIRS "${IDA_SDK_DIR}/src/lib")
    # Try lib directory (standard SDK structure)
    elseif(EXISTS "${IDA_SDK_DIR}/lib/x64_win_vc_${IDA_LIB_ARCH}")
        set(IDASDK_LIBRARY_DIRS "${IDA_SDK_DIR}/lib/x64_win_vc_${IDA_LIB_ARCH}")
    elseif(EXISTS "${IDA_SDK_DIR}/lib/x64_win_vc_64")
        set(IDASDK_LIBRARY_DIRS "${IDA_SDK_DIR}/lib/x64_win_vc_64")
    elseif(EXISTS "${IDA_SDK_DIR}/lib")
        set(IDASDK_LIBRARY_DIRS "${IDA_SDK_DIR}/lib")
    endif()
elseif(UNIX AND NOT APPLE)
    if(EXISTS "${IDA_SDK_DIR}/src/lib/x64_linux_gcc_${IDA_LIB_ARCH}")
        set(IDASDK_LIBRARY_DIRS "${IDA_SDK_DIR}/src/lib/x64_linux_gcc_${IDA_LIB_ARCH}")
    elseif(EXISTS "${IDA_SDK_DIR}/src/lib")
        set(IDASDK_LIBRARY_DIRS "${IDA_SDK_DIR}/src/lib")
    elseif(EXISTS "${IDA_SDK_DIR}/lib/x64_linux_gcc_${IDA_LIB_ARCH}")
        set(IDASDK_LIBRARY_DIRS "${IDA_SDK_DIR}/lib/x64_linux_gcc_${IDA_LIB_ARCH}")
    elseif(EXISTS "${IDA_SDK_DIR}/lib")
        set(IDASDK_LIBRARY_DIRS "${IDA_SDK_DIR}/lib")
    endif()
elseif(APPLE)
    if(EXISTS "${IDA_SDK_DIR}/src/lib/x64_mac_gcc_${IDA_LIB_ARCH}")
        set(IDASDK_LIBRARY_DIRS "${IDA_SDK_DIR}/src/lib/x64_mac_gcc_${IDA_LIB_ARCH}")
    elseif(EXISTS "${IDA_SDK_DIR}/src/lib")
        set(IDASDK_LIBRARY_DIRS "${IDA_SDK_DIR}/src/lib")
    elseif(EXISTS "${IDA_SDK_DIR}/lib/x64_mac_gcc_${IDA_LIB_ARCH}")
        set(IDASDK_LIBRARY_DIRS "${IDA_SDK_DIR}/lib/x64_mac_gcc_${IDA_LIB_ARCH}")
    elseif(EXISTS "${IDA_SDK_DIR}/lib")
        set(IDASDK_LIBRARY_DIRS "${IDA_SDK_DIR}/lib")
    endif()
endif()

# Find IDA library
find_library(IDASDK_LIBRARIES
    NAMES ida
    PATHS "${IDASDK_LIBRARY_DIRS}"
    NO_DEFAULT_PATH
)

if(NOT IDASDK_LIBRARIES)
    message(WARNING "IDA library not found in ${IDASDK_LIBRARY_DIRS}. Linking may fail.")
endif()

# Handle standard arguments
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(IDASDK
    REQUIRED_VARS IDASDK_INCLUDE_DIRS
    FOUND_VAR IDASDK_FOUND
)

# Export variables
set(IDASDK_ARCH ${IDA_ARCH})

message(STATUS "IDA SDK Directory: ${IDA_SDK_DIR}")
message(STATUS "IDA Include Directory: ${IDASDK_INCLUDE_DIRS}")
message(STATUS "IDA Library Directory: ${IDASDK_LIBRARY_DIRS}")
message(STATUS "IDA Library: ${IDASDK_LIBRARIES}")
message(STATUS "IDA Architecture: ${IDASDK_ARCH}")

mark_as_advanced(
    IDA_SDK_DIR
    IDASDK_INCLUDE_DIRS
    IDASDK_LIBRARIES
    IDASDK_LIBRARY_DIRS
    IDASDK_ARCH
)

