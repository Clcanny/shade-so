add_executable (merge.out
    const.cpp
    extend_section.cpp
    handle_lazy_symbol_binding.cpp
    main.cpp
    patch_rip_insts.cpp
    validate_format.cpp
)
target_link_libraries(merge.out
    libLIEF.a
    libZydis.a
)
target_include_directories (merge.out PRIVATE
    ${PROJECT_SOURCE_DIR}
    ${SPDLOG_INSTALL_DIR}/include
    ${LIEF_INSTALL_DIR}/include
    ${ZYDIS_INSTALL_DIR}/include
)
target_link_directories (merge.out PRIVATE
    ${SPDLOG_INSTALL_DIR}/lib
    ${LIEF_INSTALL_DIR}/lib
    ${ZYDIS_INSTALL_DIR}/lib
)
