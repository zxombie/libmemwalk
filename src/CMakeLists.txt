if (APPLE)
	set (OS_DIR apple)
elseif (CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
	set (OS_DIR freebsd)
	set (OS_LIBS procstat)
elseif (CMAKE_SYSTEM_NAME STREQUAL "Linux")
	set (OS_DIR linux)
else ()
	message (FATAL_ERROR "Unsupported Operating System")
endif ()

add_library (mw
    ${OS_DIR}/mw_os.c
    mw_subwalk.c
)
target_include_directories (mw PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ${OS_DIR})
target_link_libraries (mw LINK_PRIVATE ${OS_LIBS})
