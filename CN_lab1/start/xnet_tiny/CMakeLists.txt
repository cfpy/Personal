cmake_minimum_required(VERSION 3.7)
project(xnet)

LINK_DIRECTORIES(
    ${PROJECT_SOURCE_DIR}/../lib/npcap/Lib/x64          # win64使用
    #${PROJECT_SOURCE_DIR}/lib/npcap/Lib/             # win32使用
)


# 给visual studio编译器使用的宏，Enable GCC debug
add_definitions(-D_CRT_SECURE_NO_WARNINGS)
add_compile_options(-g)

include_directories(
        ${PROJECT_SOURCE_DIR}
        ${PROJECT_SOURCE_DIR}/../lib/npcap/Include    
        ${PROJECT_SOURCE_DIR}/src/xnet_app
        ${PROJECT_SOURCE_DIR}/src/xnet_tiny
        ${PROJECT_SOURCE_DIR}/../lib/xnet
)

add_executable(${PROJECT_NAME} ../lib/xnet/pcap_device.c src/app.c)
add_subdirectory(src/xnet_tiny)
add_subdirectory(src/xnet_app)

add_definitions(-DNET_DRIVER_PCAP)    # use pcap



target_link_libraries(${PROJECT_NAME} xnet_tiny xnet_app ${PROJECT_SOURCE_DIR}/../lib/npcap/Lib/x64/wpcap.lib  Ws2_32)

target_compile_definitions(xnet PRIVATE UNICODE _UNICODE)


