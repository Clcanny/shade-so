add_library (foo SHARED
    foo.cpp
)

add_executable (main.out
    main.cpp
)
target_link_directories (main.out PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
)
target_link_libraries(main.out
    libfoo.so
)
