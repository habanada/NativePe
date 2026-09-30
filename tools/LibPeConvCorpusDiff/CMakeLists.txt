cmake_minimum_required(VERSION 3.20)

project(LibPeConvCorpusDiff LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(LIBPECONV_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../libpeconv"
    CACHE PATH "Path to the libpeconv repository")

if(NOT EXISTS "${LIBPECONV_DIR}/libpeconv/CMakeLists.txt")
    message(FATAL_ERROR
        "libpeconv was not found. Expected: ${LIBPECONV_DIR}/libpeconv/CMakeLists.txt")
endif()

add_subdirectory(
    "${LIBPECONV_DIR}/libpeconv"
    "${CMAKE_BINARY_DIR}/libpeconv-build"
)

add_executable(LibPeConvCorpus
    LibPeConvCorpus.cpp
)

target_include_directories(LibPeConvCorpus PRIVATE
    "${LIBPECONV_DIR}/libpeconv/include"
)

target_link_libraries(LibPeConvCorpus PRIVATE
    libpeconv
    bcrypt
)

if(MSVC)
    target_compile_definitions(LibPeConvCorpus PRIVATE
        _CRT_SECURE_NO_WARNINGS
        NOMINMAX
    )
endif()

add_executable(LibPeConvProcessDump
    ProcessDump/LibPeConvProcessDump.cpp
)

target_include_directories(LibPeConvProcessDump PRIVATE
    "${LIBPECONV_DIR}/libpeconv/include"
)

target_link_libraries(LibPeConvProcessDump PRIVATE
    libpeconv
    bcrypt
)

if(MSVC)
    target_compile_definitions(LibPeConvProcessDump PRIVATE
        _CRT_SECURE_NO_WARNINGS
        NOMINMAX
    )
endif()
