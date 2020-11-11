add_library (bar SHARED
    bar.cpp
)
add_custom_command (TARGET bar
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_BINARY_DIR}/libbar.so ${CMAKE_BINARY_DIR}/libbar.so
)

add_library (foo SHARED
    foo.cpp
)
target_link_directories (foo PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
)
target_link_libraries(foo
    libbar.so
)
add_custom_command (TARGET foo
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_BINARY_DIR}/libfoo.so ${CMAKE_BINARY_DIR}/libfoo.so
)
add_dependencies(foo bar)

add_executable (main.out
    main.cpp
)
target_link_directories (main.out PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
)
target_link_libraries(main.out
    libfoo.so
)
add_custom_command (TARGET main.out
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_BINARY_DIR}/main.out ${CMAKE_BINARY_DIR}/main.out
)
