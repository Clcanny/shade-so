set (CMAKE_CXX_STANDARD 17)

add_executable (merge.out
    const.cpp
    sec_malloc_mgr.cpp
    handle_lazy_binding_sym_op.cpp
    main.cpp
    patch_rip_insts.cpp
    validate_format.cpp
    handle_code_op.cpp
    relocate_jump_slot_entry.cpp
    handle_strict_binding_sym_op.cpp
    operator.cpp
    handle_init_fini_op.cpp
    handle_global_data_op.cpp
)
target_include_directories (merge.out PRIVATE
    ${PROJECT_SOURCE_DIR}
    ${SPDLOG_INSTALL_DIR}/include
    # ${LIEF_INSTALL_DIR}/include
    ${ZYDIS_INSTALL_DIR}/include
)
target_link_directories (merge.out PRIVATE
    ${SPDLOG_INSTALL_DIR}/lib
    # ${LIEF_INSTALL_DIR}/lib
    ${ZYDIS_INSTALL_DIR}/lib
)
target_link_libraries(merge.out
    libLIEF.a
    libZydis.a
    pthread
)
# add_dependencies (merge.out spdlog zydis)
add_custom_command (TARGET merge.out
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_BINARY_DIR}/merge.out ${CMAKE_BINARY_DIR}/merge.out
)
