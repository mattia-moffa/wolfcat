cmake_minimum_required(VERSION 4.0)

project(wolfcat)

add_executable(wolfcat src/main.c src/client.c src/server.c)
target_include_directories(wolfcat PRIVATE include)

find_package(wolfssl QUIET)
if(wolfssl_FOUND)
    target_link_libraries(wolfcat PRIVATE wolfssl::wolfssl)
else()
    message(STATUS "The WolfSSL CMake module was not found. Falling back to manual search.")

    if(NOT DEFINED WOLFSSL_ROOT)
        set(WOLFSSL_ROOT $ENV{WOLFSSL_ROOT})
    endif()

    find_library(WOLFSSL_LIB wolfssl
        HINTS ${WOLFSSL_ROOT}
        PATH_SUFFIXES lib lib64
    )

    find_path(WOLFSSL_INCLUDE_DIR wolfssl/ssl.h
        HINTS ${WOLFSSL_ROOT}
        PATH_SUFFIXES include include/wolfssl
    )

    if(WOLFSSL_LIB AND WOLFSSL_INCLUDE_DIR)
        message(STATUS "Using WolfSSL from: ${WOLFSSL_LIB} ${WOLFSSL_INCLUDE_DIR}")
        target_include_directories(wolfcat PRIVATE ${WOLFSSL_INCLUDE_DIR})
        target_link_libraries(wolfcat PRIVATE ${WOLFSSL_LIB})
    else()
        message(STATUS "WolfSSL not found. Set WOLFSSL_ROOT or install it to a system path.")
    endif()
endif()

install(TARGETS wolfcat RUNTIME DESTINATION bin)
