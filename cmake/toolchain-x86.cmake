# Toolchain file for Windows x86 (32-bit)

set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR X86)

# Force 32-bit build
set(CMAKE_SIZEOF_VOID_P 4)

# Set architecture-specific flags
if(MSVC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /arch:SSE2" CACHE STRING "" FORCE)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /arch:SSE2" CACHE STRING "" FORCE)
endif()

