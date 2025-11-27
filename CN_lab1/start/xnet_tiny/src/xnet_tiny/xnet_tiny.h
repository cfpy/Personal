#ifndef XNET_TINY_H
#define XNET_TINY_H

#include <stdint.h>

#define XNET_CFG_PACKET_MAX_SIZE        1516        // 收发数据包的最大大小

#pragma pack(1)

#define XNET_MAC_ADDR_SIZE              6           // MAC地址长度

#define XNET_IPV4_ADDR_SIZE             4           // 4字节

// ARP 表的大小（最多缓存 512 个条目）
#define XARP_TABLE_SIZE                 512

// ARP 表项状态
#define XARP_ENTRY_FREE                 0           // 空闲
#define XARP_ENTRY_OK                   1           // 解析成功
#define XARP_ENTRY_RESOLVING            2           // 正在解析（等待 ARP 应答）

// ARP 定时器周期：每 1 秒扫描一遍 ARP 表
#define XARP_TIMER_PERIOD               1

// ARP 报文硬件类型：以太网
#define XARP_HW_ETHER                   0x1
// ARP 操作码：请求 / 响应
#define XARP_REQUEST                    0x1
#define XARP_REPLY                      0x2

// ARP 参数配置：表项有效时间、挂起时间、最大重试次数
#define XARP_CFG_ENTRY_OK_TMO           (5)         // OK 状态下有效 5s
#define XARP_CFG_ENTRY_PENDING_TMO      (1)         // Pending 状态等待 1s
#define XARP_CFG_MAX_RETRIES            4           // 最多重发 4 次

#define XNET_CFG_NETIF_IP               {192,168,19,100}

// IP 协议常量
#define XNET_VERSION_IPV4               4           // IPv4
#define XNET_IP_DEFAULT_TTL             64          // 默认 TTL

// ICMP 类型 & 代码 常量
#define XICMP_TYPE_ECHO_REQUEST         8           // 请求
#define XICMP_TYPE_ECHO_REPLY           0           // 回复
#define XICMP_TYPE_UNREACH              3           // 目标不可达
#define XICMP_TYPE_TIME_EXCEED          11          // 超时

// ICMP 不可达代码
#define XICMP_CODE_NET_UNREACH          0
#define XICMP_CODE_HOST_UNREACH         1
#define XICMP_CODE_PRO_UNREACH          2
#define XICMP_CODE_PORT_UNREACH         3 

// 用于带宽测试的 payload 长度数组和元素个数（在 ping.c 里定义）
extern uint16_t payload_len_list[1000]; 
extern uint16_t pay_cnt;

typedef uint32_t xnet_time_t; //时间类型

// 一些时间相关的系统接口，由其它 .c 提供实现
const xnet_time_t xsys_get_time(void);      // 返回单位为 1s 的系统时间
const xnet_time_t xsys_get_time_ms(void);   // 返回毫秒级时间
void init_qpc(void);                        // 初始化高精度计时器
uint64_t get_time_us(void);                 // 获取微秒级时间（用于 RTT）
void print_statistics(void);                // 打印 ping 统计
void print_jitters(void);                   // 打印 RTT/抖动
void print_and_save_bandwidth(void);        // 打印+导出带宽
void export_and_plot_jitter(void);          // 导出抖动数据

typedef union _xipaddr_t
{
    uint8_t array[XNET_IPV4_ADDR_SIZE]; //按照字节
    uint32_t addr;
    /* data */
} xipaddr_t;

void print_ip(xipaddr_t* ip);

typedef struct _xarp_entry_t
{
    xipaddr_t ipaddr;                     // IP 地址
    uint8_t macaddr[XNET_MAC_ADDR_SIZE];  // 对应 MAC
    uint8_t state;                        // 状态：FREE/OK/RESOLVING
    uint16_t tmo;                         // 剩余有效时间
    uint8_t retry_cnt;                    // 剩余重试次数
} xarp_entry_t;

typedef struct _xarp_packet_t
{
    //硬件类型和协议类型
    uint16_t hardware_type;
    uint16_t protocal_type;
    //硬件地址长+协议地址长
    uint8_t hw_addr_len;
    uint8_t proto_addr_len;
    //请求/响应
    uint16_t opcode; //1 = REQUEST, 2 = REPLY
    //发送包硬件地址
    uint8_t sender_hw_addr[XNET_MAC_ADDR_SIZE];
    //发送包协议地址
    uint8_t sender_proto_addr[XNET_IPV4_ADDR_SIZE];
    //接收方硬件地址
    uint8_t target_hw_addr[XNET_MAC_ADDR_SIZE];
    //接收方协议地址
    uint8_t target_proto_addr[XNET_IPV4_ADDR_SIZE];

    /* data */
}xarp_packet_t;


/**
 * IP数据包结构
 */
typedef struct _xip_hdr_t
{
    //首部长度和版本
    uint8_t ver_ihl;
    //服务类型
    uint8_t type_of_service;
    //总长度
    uint16_t total_len;
    //标识符
    uint16_t id;
    //标志 + 片偏移
    uint16_t flag_fragment;
    //生存时间
    uint8_t time_to_live;
    //协议
    uint8_t proto;
    // 头部校验和
    uint16_t hdr_checksum;
    //源ip地址
    xipaddr_t src;
    //目的ip地址
    xipaddr_t dest;
    /* data */
}xip_hdr_t;

/**
 * ICMP 报文头结构
 */
typedef struct _xicmp_hdr_t
{
    //类型
    uint8_t type;
    //代码
    uint8_t code;
    //校验和
    uint16_t checksum;
    //标识符
    uint16_t id;
    //序列号
    uint16_t sequence_num;

    /* data */
}xicmp_hdr_t;



/**
 * 以太网数据帧格式：RFC894
 */
typedef struct _xether_hdr_t {
    uint8_t dest[XNET_MAC_ADDR_SIZE];           // 目标mac地址
    uint8_t src[XNET_MAC_ADDR_SIZE];            // 源mac地址
    uint16_t protocol;                          // 上层协议类型（IP/ARP）
}xether_hdr_t;

#pragma pack()

typedef enum _xnet_err_t {
    XNET_ERR_OK = 0,
    XNET_ERR_IO = -1,
}xnet_err_t;

/**
 * 网络数据结构
 */
typedef struct _xnet_packet_t{
    uint16_t size;                              // 有效数据长度
    uint8_t * data;                             // 有效数据起始指针
    uint8_t payload[XNET_CFG_PACKET_MAX_SIZE];  // 真正的存储空间
}xnet_packet_t;

xnet_packet_t * xnet_alloc_for_send(uint16_t data_size);
xnet_packet_t * xnet_alloc_for_read(uint16_t data_size);

xnet_err_t xnet_driver_open (uint8_t * mac_addr);
xnet_err_t xnet_driver_send (xnet_packet_t * packet);
xnet_err_t xnet_driver_read (xnet_packet_t ** packet);

typedef enum _xnet_protocol_t {
    XNET_PROTOCOL_ARP = 0x0806,     // ARP
    XNET_PROTOCOL_IP  = 0x0800,     // IP
    XNET_PROTOCOL_ICMP = 0x01       // ICMP（在 IP 头 proto 字段里）
}xnet_protocol_t;


// 存储最近一次收到的“结果型 ICMP”报文（给 xicmp_receive 用）
typedef struct {
    int         valid;       // 是否有效
    xipaddr_t   src_ip;      // 源 IP
    xicmp_hdr_t icmp_hdr;    // ICMP 头部内容
} xicmp_last_t;

// 协议栈对外 API
void xnet_init (void);                               // 整体初始化
void xnet_poll(void);                                // 轮询
int xnet_check_tmo(xnet_time_t* time, uint32_t sec); // 超时检测工具

// ARP 相关接口
void xarp_init(void);
void xarp_poll(void);
void xarp_in(xnet_packet_t* packet);
xnet_err_t xarp_make_request(const xipaddr_t * ipaddr);
xnet_err_t xarp_make_response(xarp_packet_t* arp_recv);

// IP 相关接口
void xip_init(void);
void xip_in(xnet_packet_t* packet);
xnet_err_t xip_out(xnet_protocol_t protocol, xipaddr_t* dest_ip, xnet_packet_t* packet);

// ICMP 相关接口
void xicmp_init(void);
void xicmp_in(xipaddr_t* src_ip, xnet_packet_t* packet);
xnet_err_t xicmp_echo_request(xipaddr_t* target_ip, uint16_t id, uint16_t seq, uint8_t* payload, uint16_t payload_len);
static xnet_err_t reply_icmp_request(xicmp_hdr_t* icmp_hdr, xipaddr_t* src_ip, xnet_packet_t* packet); // 仅在实现文件中使用
xnet_err_t xicmp_dest_unreach(uint8_t code, xip_hdr_t* ip_hdr);

// ping 模块回调(通知)
void ping_on_reply(xicmp_hdr_t* icmp, xipaddr_t* src_ip, xnet_packet_t* packet);

// ARP 表维护
static void update_arp_table(uint8_t* src_ip, uint8_t* mad_addr);
int find_entry(uint8_t* src_ip);

// ping / 带 payload 的 ping
void ping_run(xipaddr_t *dst, uint16_t seq);
void ping_run_payload(xipaddr_t* dst, uint16_t seq, uint8_t* payload, uint16_t payload_len); //用于测试带宽

// traceroute 相关接口
void traceroute(xipaddr_t* dst, uint8_t max_hops);
void traceroute_send(xipaddr_t* dest_ip, uint16_t id, uint16_t seq, uint8_t ttl);
int xicmp_receive(xipaddr_t *src_ip, xicmp_hdr_t *icmp, uint32_t timeout_ms);

// 网络工具函数
static int ip_same_net(const xipaddr_t *a, const xipaddr_t *b, const xipaddr_t *mask); //无用

xnet_err_t xarp_make_response_non_back(void);
static xnet_err_t ethernet_out_to(xnet_protocol_t protocol, const uint8_t *mac_addr, xnet_packet_t * packet);
void print_arp_table(void);

// 全局网络配置变量（在 .c 里定义）
extern xipaddr_t netif_netmask;   // 子网掩码
extern xipaddr_t netif_gateway;   // 默认网关

#endif // XNET_TINY_H

