#include <string.h>
#include <stdlib.h>
#include "pcap_device.h"
#include "xnet_tiny.h"
#include <time.h>
#include <windows.h>

static pcap_t * pcap;

// pcap所用的网卡
const char * ip_str = "192.168.19.1";      // 根据实际电脑上存在的网卡地址进行修改
const char my_mac_addr[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};

static LARGE_INTEGER g_freq;

void init_qpc(void) {
    QueryPerformanceFrequency(&g_freq);  // 每秒多少“tick”
}

const xnet_time_t xsys_get_time(void){
    return (xnet_time_t)(clock()/CLOCKS_PER_SEC);
}

const xnet_time_t xsys_get_time_ms(void){
    return (xnet_time_t)(clock());
}

uint64_t get_time_us(void) {
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);  // 当前 tick 值
    // 转换为微秒： tick / freq * 1e6
    return (uint64_t)(now.QuadPart * 1000000ULL / g_freq.QuadPart);
}


/**
 * 初始化网络驱动
 * @return 0成功，其它失败
 */
xnet_err_t xnet_driver_open (uint8_t * mac_addr) {
    memcpy(mac_addr, my_mac_addr, sizeof(my_mac_addr));
    pcap = pcap_device_open(ip_str, mac_addr, 1);
    if (pcap == (pcap_t *)0) {
        exit(-1);
    }
    return XNET_ERR_OK;
}

/**
 * 发送数据
 * @param frame 数据起始地址
 * @param size 数据长度
 * @return 0 - 成功，其它失败
 */
xnet_err_t xnet_driver_send (xnet_packet_t * packet) {
    return pcap_device_send(pcap, packet->data, packet->size);
}

/**
 * 读取数据
 * @param frame 数据存储位置
 * @param size 数据长度
 * @return 0 - 成功，其它失败
 */
xnet_err_t xnet_driver_read (xnet_packet_t ** packet) {
    uint16_t size;
    xnet_packet_t * r_packet = xnet_alloc_for_read(XNET_CFG_PACKET_MAX_SIZE);

    size = pcap_device_read(pcap, r_packet->data, XNET_CFG_PACKET_MAX_SIZE);
    if (size) {
        r_packet->size = size;
        *packet = r_packet;
        return XNET_ERR_OK;
    }

    return XNET_ERR_IO;
}
