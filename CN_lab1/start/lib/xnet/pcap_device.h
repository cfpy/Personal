#ifndef PCAP_DRIVER_H
#define PCAP_DRIVER_H 

#include <pcap.h>
#include <stdint.h>

// 主-次版本号
#define NPCAP_VERSION_M             0
#define NPCAP_VERSION_N             9986

typedef void (*irq_handler_t)(void* arg, uint8_t is_rx, const uint8_t* data, uint32_t size);

pcap_t* pcap_device_open(const char* ip, const uint8_t *mac_addr, uint8_t poll_mode);
void pcap_device_close(pcap_t* pcap);
uint32_t pcap_device_send(pcap_t* pcap, const uint8_t* buffer, uint32_t length);
uint32_t pcap_device_read(pcap_t* pcap, uint8_t* buffer, uint32_t length);

#endif //PCAP_DRIVER_H
