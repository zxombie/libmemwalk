cmake_minimum_required (VERSION 2.8.11)

set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS} -Wall -Wextra -Werror")

add_subdirectory (src)
add_subdirectory (test)
