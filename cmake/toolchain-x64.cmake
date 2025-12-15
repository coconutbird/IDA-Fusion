# Toolchain file for Windows x64 (64-bit)

set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR AMD64)

# Force 64-bit build
set(CMAKE_SIZEOF_VOID_P 8)

# Set architecture-specific flags
if(MSVC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /arch:AVX" CACHE STRING "" FORCE)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /arch:AVX" CACHE STRING "" FORCE)
endif()

