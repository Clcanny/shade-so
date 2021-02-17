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
    CMAKE_ARGS     -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} -DCMAKE_INSTALL_PREFIX=${SPDLOG_INSTALL_DIR} -USPDLOG_HEADER_ONLY
)

# set (LIEF_INSTALL_DIR ${THIRDPARTY_INSTALL_DIR}/lief)
# ExternalProject_Add (
#     lief
#     PREFIX         ${THIRDPARTY_DIR}
#     GIT_REPOSITORY https://github.com/Clcanny/LIEF
#     GIT_TAG        devMaster
#     CMAKE_ARGS     -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} -DCMAKE_INSTALL_PREFIX=${LIEF_INSTALL_DIR} -DLIEF_PYTHON_API=OFF -DLIEF_PE=OFF -DLIEF_MACHO=OFF -DLIEF_OAT=OFF -DLIEF_DEX=OFF -DLIEF_VDEX=OFF -DLIEF_LOGGING=OFF -DLIEF_LOGGING_DEBUG=OFF
#     BUILD_COMMAND  make -j${N}
# )

set (ZYDIS_INSTALL_DIR ${THIRDPARTY_INSTALL_DIR}/zydis)
ExternalProject_Add (
    zydis
    PREFIX          ${THIRDPARTY_DIR}
    GIT_REPOSITORY  https://github.com/zyantific/zydis.git
    GIT_TAG         ba9431cf143f89f29343d0c3d737935545627367
    CMAKE_ARGS      -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} -DCMAKE_INSTALL_PREFIX=${ZYDIS_INSTALL_DIR}
    INSTALL_COMMAND make install
)

add_subdirectory (src)
add_subdirectory (tests)

add_custom_target (tests
    ALL rm -f modified-main.out
    COMMAND ./merge.out
    COMMAND chmod u+x modified-main.out
    COMMAND ./modified-main.out
    DEPENDS merge.out foo main.out
)
