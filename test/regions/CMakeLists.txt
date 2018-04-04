
add_executable (regions
    regions.c
    add_diff_perms.c
    add_less_perms.c
    add_more_perms.c
    add_same_perms.c
)

target_link_libraries (regions LINK_PUBLIC mw)
