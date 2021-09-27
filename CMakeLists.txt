cmake_minimum_required(VERSION 3.13)

project(wakaama C)

# Enable "test" target
if (CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    enable_testing()
endif()

if(DTLS_MBEDTLS)
    message("Skipping tests")
else()
    message("Adding tests")
    add_subdirectory(tests)
endif()

add_subdirectory(examples)
