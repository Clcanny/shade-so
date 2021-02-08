cmake_minimum_required (VERSION 3.18.4)
project (shade-so)

include(ProcessorCount)
ProcessorCount(N)

include (ExternalProject)
set (THIRDPARTY_DIR         ${CMAKE_CURRENT_BINARY_DIR}/thirdparty)
set (THIRDPARTY_INSTALL_DIR ${THIRDPARTY_DIR}/install)

set (SPDLOG_INSTALL_DIR ${THIRDPARTY_INSTALL_DIR}/spdlog)
ExternalProject_Add (
    spdlog
    PREFIX         ${THIRDPARTY_DIR}
    GIT_REPOSITORY https://github.com/gabime/spdlog.git
    GIT_TAG        a51b4856377a71f81b6d74b9af459305c4c644f8
    CMAKE_ARGS     -DCMAKE_INSTALL_PREFIX=${SPDLOG_INSTALL_DIR}
)

set (LIEF_INSTALL_DIR ${THIRDPARTY_INSTALL_DIR}/lief)
ExternalProject_Add (
    lief
    PREFIX         ${THIRDPARTY_DIR}
    GIT_REPOSITORY https://github.com/Clcanny/LIEF
    GIT_TAG        devMaster
    INSTALL_DIR    ${LIEF_INSTALL_DIR}
    BUILD_COMMAND  make -j${N}
)

set (ZYDIS_INSTALL_DIR ${THIRDPARTY_INSTALL_DIR}/zydis)
ExternalProject_Add (
    zydis
    PREFIX         ${THIRDPARTY_DIR}
    GIT_REPOSITORY https://github.com/zyantific/zydis.git
    GIT_TAG        ba9431cf143f89f29343d0c3d737935545627367
    INSTALL_DIR    ${ZYDIS_INSTALL_DIR}
)

add_subdirectory (src)
