#include <string.h>
#include "xnet_tiny.h"
#include "stdio.h"

#define min(a, b)               ((a) > (b) ? (b) : (a))

static uint8_t netif_mac[XNET_MAC_ADDR_SIZE];                   // mac地址
static xnet_packet_t tx_packet, rx_packet; 
static xarp_entry_t arp_table[XARP_TABLE_SIZE];                     // 接收与发送缓冲区
static xnet_time_t arp_timer; //arp扫描定时
static const xipaddr_t netif_ipaddr = XNET_CFG_NETIF_IP; //设置的本协议栈ip
static const uint8_t ether_broadcast[] = {0xff,0xff,0xff,0xff,0xff,0xff}; 
static const uint8_t ip_broadcast[] = {0xff,0xff,0xff,0xff};
static uint8_t ip_ttl = XNET_IP_DEFAULT_TTL; //ip默认ttl
static xicmp_last_t g_icmp_last;  //最近收到的一次ICMP

#define swap_order16(v)   ((((v) & 0xFF) << 8) | (((v) >> 8) & 0xFF))
#define xipaddr_is_equal_buf(addr, buf)   (memcmp((addr)->array, (buf), XNET_IPV4_ADDR_SIZE) == 0)  //ip匹配不匹配

xipaddr_t netif_netmask = { .array = {255,255,255,0} };
xipaddr_t netif_gateway = { .array = {192,168,19,1} };  //没用到

void xip_set_ttl(uint8_t ttl)
{
    ip_ttl = ttl;
}

/**
 * 分配一个网络数据包用于发送数据
 * @param data_size 数据空间大小
 * @return 分配得到的包结构
 */
xnet_packet_t * xnet_alloc_for_send(uint16_t data_size) {
    // 从tx_packet的后端往前分配，因为前边要预留作为各种协议的头部数据存储空间
    tx_packet.data = tx_packet.payload + XNET_CFG_PACKET_MAX_SIZE - data_size;
    tx_packet.size = data_size;
    return &tx_packet;
}

/**
 * 分配一个网络数据包用于读取
 * @param data_size 数据空间大小
 * @return 分配得到的数据包
 */
xnet_packet_t * xnet_alloc_for_read(uint16_t data_size) {
    // 从最开始进行分配，用于最底层的网络数据帧读取
    rx_packet.data = rx_packet.payload;
    rx_packet.size = data_size;
    return &rx_packet;
}

/**
 * 为发包添加一个头部
 * @param packet 待处理的数据包
 * @param header_size 增加的头部大小
 */
static void add_header(xnet_packet_t *packet, uint16_t header_size) {
    packet->data -= header_size;
    packet->size += header_size;
}

/**
 * 为接收向上处理移去头部
 * @param packet 待处理的数据包
 * @param header_size 移去的头部大小
 */
static void remove_header(xnet_packet_t *packet, uint16_t header_size) {
    packet->data += header_size;
    packet->size -= header_size;
}

/**
 * 将包的长度截断为size大小
 * @param packet 待处理的数据包
 * @param size 最终大小
 */
static void truncate_packet(xnet_packet_t *packet, uint16_t size) {
    packet->size = min(packet->size, size);
}

/**
 * 以太网初始化
 * @return 初始化结果
 */
static xnet_err_t ethernet_init (void) {
    xnet_err_t err = xnet_driver_open(netif_mac);
    if (err < 0) return err;
    xarp_make_response_non_back();
    // xipaddr_t vm = { {192, 168, 19, 66} }; 
    // xarp_make_request(&vm);
    return XNET_ERR_OK;
}


xnet_err_t xarp_make_response_non_back(void)
{
    xnet_packet_t* pkt = xnet_alloc_for_send(sizeof(xarp_packet_t));
    xarp_packet_t* packet = (xarp_packet_t*)pkt->data;
    packet->hardware_type = swap_order16(XARP_HW_ETHER);
    packet->protocal_type = swap_order16(XNET_PROTOCOL_IP);
    packet->hw_addr_len = XNET_MAC_ADDR_SIZE;
    packet->proto_addr_len = XNET_IPV4_ADDR_SIZE;
    packet->opcode = swap_order16(XARP_REQUEST);
    memcpy(packet->sender_hw_addr, netif_mac, XNET_MAC_ADDR_SIZE);
    memcpy(packet->sender_proto_addr, netif_ipaddr.array, XNET_IPV4_ADDR_SIZE);
    memset(packet->target_hw_addr, 0, XNET_MAC_ADDR_SIZE);
    memcpy(packet->target_proto_addr, netif_ipaddr.array, XNET_IPV4_ADDR_SIZE);
    ethernet_out_to(XNET_PROTOCOL_ARP, ether_broadcast, pkt);
    return XNET_ERR_OK;
}

/**
 * 发送一个以太网数据帧
 * @param protocol 上层数据协议，IP或ARP
 * @param mac_addr 目标网卡的mac地址
 * @param packet 待发送的数据包
 * @return 发送结果
 */
static xnet_err_t ethernet_out_to(xnet_protocol_t protocol, const uint8_t *mac_addr, xnet_packet_t * packet) {
    xether_hdr_t* ether_hdr;

    // 添加头部
    add_header(packet, sizeof(xether_hdr_t));
    ether_hdr = (xether_hdr_t*)packet->data;
    memcpy(ether_hdr->dest, mac_addr, XNET_MAC_ADDR_SIZE);
    memcpy(ether_hdr->src, netif_mac, XNET_MAC_ADDR_SIZE);
    ether_hdr->protocol = swap_order16(protocol);

    // 数据发送
    return xnet_driver_send(packet);
}

/**
 * 以太网数据帧输入输出
 * @param packet 待处理的包
 */
static void ethernet_in (xnet_packet_t * packet) {
    // 至少要比头部数据大
    if (packet->size <= sizeof(xether_hdr_t)) {
        return;
    }

    // 往上分解到各个协议处理
    xether_hdr_t* hdr = (xether_hdr_t*)packet->data;
    if ((memcmp(hdr->dest, netif_mac, XNET_MAC_ADDR_SIZE)!=0) && (memcmp(hdr->dest, ether_broadcast, XNET_MAC_ADDR_SIZE)!=0))
        return;
    // 去掉以太网头，把剩余数据交给上层协议（ARP/IP）
    packet->data += sizeof(xether_hdr_t);
    packet->size -= sizeof(xether_hdr_t);
    switch (swap_order16(hdr->protocol)) {
        case XNET_PROTOCOL_ARP:
            xarp_in(packet);
            break;
        case XNET_PROTOCOL_IP: {
            xip_in(packet);
            break;
        }
    }
}

/**
 * 查询网络接口，看看是否有数据包，有则进行处理
 */
static void ethernet_poll (void) {
    xnet_packet_t * packet;

    if (xnet_driver_read(&packet) == XNET_ERR_OK) {
        // 正常情况下，在此打个断点，全速运行
        // 然后在对方端ping 192.168.254.2，会停在这里
        ethernet_in(packet);
    }
}

/**
 * 协议栈的初始化
 */
void xnet_init (void) {
    init_qpc();  // 初始化高精度计时器（给 get_time_us 用）
    ethernet_init();
    xarp_init();
    xip_init();
    xicmp_init();
}

void xarp_poll(void){
    if(xnet_check_tmo(&arp_timer, XARP_TIMER_PERIOD)){
        for (int i=0;i<XARP_TABLE_SIZE;i++)
        {
            switch (arp_table[i].state)
            {
                case XARP_ENTRY_RESOLVING:
                    if (arp_table[i].tmo > 0)
                    {
                        arp_table[i].tmo--;
                    }
                    else
                    {
                        if (arp_table[i].retry_cnt == 0)
                        {
                            arp_table[i].state = XARP_ENTRY_FREE;
                        }
                        else{
                            xarp_make_request(&arp_table[i].ipaddr);
                            arp_table[i].retry_cnt--;
                            arp_table[i].tmo = XARP_CFG_ENTRY_PENDING_TMO;
                        }
                    }
                    break;
                case XARP_ENTRY_OK: 
                    if (arp_table[i].tmo > 0)
                    {
                        arp_table[i].tmo--;
                    }
                    else
                    {
                        xarp_make_request(&arp_table[i].ipaddr);
                        arp_table[i].state = XARP_ENTRY_RESOLVING;
                        arp_table[i].tmo = XARP_CFG_ENTRY_PENDING_TMO;
                        arp_table[i].retry_cnt = XARP_CFG_MAX_RETRIES;
                    }
                    break;//超时，重新请求
            }
        }
    }
}

/**
 * 轮询处理数据包，并在协议栈中处理
 */
void xnet_poll(void) {
    ethernet_poll();
    xarp_poll();
}

/** 
 * @brief 检查是否超时
 * @param time 前一时间
 * @param sec 预期超时时间，值为0时，表示获取当前时间
 * @return 0-未超时，1-超时
 */
int xnet_check_tmo(xnet_time_t* time, uint32_t sec)
{
    xnet_time_t curr = xsys_get_time();
    if(sec==0)
    {
        *time = curr;
        return 0;
    }
    if (curr - *time >= sec)
    {
        *time = curr;
        return 1;
    }
    else
    {
        return 0;
    }
}


void xarp_init(void){
    // arp_entry.state = XARP_ENTRY_FREE;
    int i;
    for (i=0; i<XARP_TABLE_SIZE; i++)
    {
        arp_table[i].state = XARP_ENTRY_FREE;
    }
    xnet_check_tmo(&arp_timer, 0);  //获取当前时间
}

xnet_err_t xarp_make_request(const xipaddr_t * ipaddr)
{
    xnet_packet_t* pkt = xnet_alloc_for_send(sizeof(xarp_packet_t));
    xarp_packet_t* packet = (xarp_packet_t*)pkt->data;
    packet->hardware_type = swap_order16(XARP_HW_ETHER);
    packet->protocal_type = swap_order16(XNET_PROTOCOL_IP); //要查的地址类型
    packet->hw_addr_len = XNET_MAC_ADDR_SIZE;
    packet->proto_addr_len = XNET_IPV4_ADDR_SIZE;
    packet->opcode = swap_order16(XARP_REQUEST);
    memcpy(packet->sender_hw_addr, netif_mac, XNET_MAC_ADDR_SIZE);
    memcpy(packet->sender_proto_addr, netif_ipaddr.array, XNET_IPV4_ADDR_SIZE);
    memset(packet->target_hw_addr, 0, XNET_MAC_ADDR_SIZE);
    memcpy(packet->target_proto_addr, ipaddr->array, XNET_IPV4_ADDR_SIZE);
    ethernet_out_to(XNET_PROTOCOL_ARP, ether_broadcast, pkt);
    return XNET_ERR_OK;
}


/** 
 * @brief 发送和ARP响应包
 * @param arp_recv 收到的ARP请求包
 * @return 发送结果
 */
xnet_err_t xarp_make_response(xarp_packet_t* arp_recv)
{
    xnet_packet_t* pkt = xnet_alloc_for_send(sizeof(xarp_packet_t));
    xarp_packet_t* packet = (xarp_packet_t*)pkt->data;
    packet->hardware_type = swap_order16(XARP_HW_ETHER);
    packet->protocal_type = swap_order16(XNET_PROTOCOL_IP);
    packet->hw_addr_len = XNET_MAC_ADDR_SIZE;
    packet->proto_addr_len = XNET_IPV4_ADDR_SIZE;
    packet->opcode = swap_order16(XARP_REPLY);
    memcpy(packet->sender_hw_addr, netif_mac, XNET_MAC_ADDR_SIZE);
    memcpy(packet->sender_proto_addr, netif_ipaddr.array, XNET_IPV4_ADDR_SIZE);
    memcpy(packet->target_hw_addr, arp_recv->sender_hw_addr, XNET_MAC_ADDR_SIZE);
    memcpy(packet->target_proto_addr, arp_recv->sender_proto_addr, XNET_IPV4_ADDR_SIZE);
    ethernet_out_to(XNET_PROTOCOL_ARP, arp_recv->sender_hw_addr, pkt);
    return XNET_ERR_OK;
}

/** 
 * ARP输入处理
 * @param packet 输入的ARP包
 */
void xarp_in(xnet_packet_t * packet){
    //获取arp是请求包还是响应包
    xarp_packet_t* arp = (xarp_packet_t*) packet->data;
    uint16_t op = arp->opcode;
    //包的合法性检查 判断硬件类型
    if (swap_order16(arp->hardware_type)!=XARP_HW_ETHER)
        return;
    //只处理发给自己的请求或响应包
    if (!xipaddr_is_equal_buf(&netif_ipaddr, arp->target_proto_addr))
        return;
    //根据操作码进行不同的处理
    switch(swap_order16(op)){
        case XARP_REQUEST:
            xarp_make_response(arp);
            update_arp_table(arp->sender_proto_addr, arp->sender_hw_addr);
            break;
        case XARP_REPLY:
            update_arp_table(arp->sender_proto_addr, arp->sender_hw_addr);
            break;
    }
}

/** 
 * @brief 更新ARP表项
 * @param src_ip 表项的源ip地址
 * @param mac_addr 表项的MAC地址
 * @return 无
 */
static void update_arp_table(uint8_t* src_ip, uint8_t* mac_addr)
{
    int res_index = find_entry(src_ip);
    memcpy(arp_table[res_index].ipaddr.array, src_ip, XNET_IPV4_ADDR_SIZE);
    memcpy(arp_table[res_index].macaddr, mac_addr, XNET_MAC_ADDR_SIZE);
    arp_table[res_index].state = XARP_ENTRY_OK;
    arp_table[res_index].tmo = XARP_CFG_ENTRY_OK_TMO;
    arp_table[res_index].retry_cnt = XARP_CFG_MAX_RETRIES;
}

/** 
 * @brief 查找空闲的ARP表项
 * @param src_ip 表项的源ip地址
 * @return 如果此表项已经存在，返回其索引
 *         如果此表项不存在，但是有空闲表项，返回第一个空闲表项的索引
 *         如果没有空闲表项，则根据LRU算法返回一个表项的索引
 */
int find_entry(uint8_t* src_ip)
{
    int exist_index = -1;  // 已存在条目
    int free_index = -1;   // 第一个空闲条目的索引
    int lru_index = 0;     // LRU 条目的索引
    uint16_t lru_tmo = 0xffff;      // 当前认为最“老”的剩余时间
    for(int i=0;i<XARP_TABLE_SIZE;i++)
    {
        if (arp_table[i].state != XARP_ENTRY_FREE)
        {
            // 如果 IP 一样，说明条目已存在
            if (memcmp(arp_table[i].ipaddr.array, src_ip, XNET_IPV4_ADDR_SIZE) == 0)
            {
                exist_index = i;
                break;
            }
            // 否则维护一个 LRU 候选：tmo 越小，认为越老
            if (arp_table[i].state == XARP_ENTRY_OK)
            {
                if(arp_table[i].tmo < lru_tmo)
                {
                    lru_tmo = arp_table[i].tmo;
                    lru_index = i;
                }
            }
        }
        else 
        {
            // 记录第一个发现的 FREE 条目
            if(free_index == -1)
            {
                free_index = i;
            }
        }
    }
    if(exist_index != -1){
        return exist_index;
    }
    else if(free_index != -1){
        return free_index;
    }
    else{
        return lru_index;
    }
}

/** 
 * @brief 校验和处理
 * @param len 数据区的长度，以字节为单位
 * @param pre_sum 累加的之前的值，用于多次调用checksum对不同的数据区计算出一个校验和
 * @param complement 是否取反
 * @return 校验和
 */
static uint16_t checksum16(uint16_t* buf, uint16_t len, uint16_t pre_sum, int complement){
    uint16_t before_add = 0;
    // 按 16 位（2 字节）为单位累加
    for(int i=0;i<len/2;i++)
    {
        before_add = pre_sum;
        pre_sum += buf[i]; 
        // 处理 16bit 溢出：如果发生进位，则再加 1
        if ((pre_sum < buf[i]) && (pre_sum < before_add))
        {
            pre_sum++;
        }
    }
    if(complement)
    {
        pre_sum = ~pre_sum;
    }
    return pre_sum;
}



/** 
 * @brief IP层的输入处理
 * @param packet 待处理的包
 * @return 无
 */
void xip_in(xnet_packet_t* packet)
{
    xip_hdr_t* ip = (xip_hdr_t*)packet->data;
    //定义局部变量：总长度、头部长度、原始校验和、源IP地址
    uint16_t total_len = swap_order16(ip->total_len);
    uint8_t ihl_bytes = (ip->ver_ihl & 0xF)*4;
    uint8_t version = 0xF & ((ip->ver_ihl & 0xF0) >> 4);
    uint16_t ori_checksum;
    xipaddr_t src_ip;
    //IP头部解析和验证
    if(version != XNET_VERSION_IPV4)    // 必须是 IPv4
    {
        return;
    }
    if(packet->size < ihl_bytes)        // 实际包长不能小于头部长度
    {
        return;
    }
    if(total_len > packet->size)        // 声明总长度不能大于实际收到长度
        return;
    if(ihl_bytes < 20)                  // IPv4 头部至少 20 字节
        return;
    if(total_len < ihl_bytes)           // 总长不能比头长还小
        return;
    //完整性验证
    ori_checksum = ip->hdr_checksum;
    ip->hdr_checksum = 0;
    if(ori_checksum != checksum16((uint16_t*)ip, ihl_bytes, 0, 1))
        return;
    ip->hdr_checksum = ori_checksum;
    //目标地址过滤，只收发给本机或广播的 IP

    if((memcmp(ip->dest.array, netif_ipaddr.array, XNET_IPV4_ADDR_SIZE)!=0) && (memcmp(ip->dest.array, ip_broadcast, XNET_IPV4_ADDR_SIZE)!=0))
        return;
    //协议分发处理，完成ICMP协议处理
    if(ip->proto == XNET_PROTOCOL_ICMP)
    {
        //去头
        packet->data += ihl_bytes;
        packet->size = total_len - ihl_bytes;
        xicmp_in(&ip->src, packet); //total_len-ihl_bytes
    }
    else{
        xicmp_dest_unreach(XICMP_CODE_PRO_UNREACH, ip);  //协议不可达
    }

}

/** 
 * @brief IP层的输出处理
 * @param protocol 上层数据协议，ICMP或TCP或UDP
 * @param dest_ip 目标IP地址
 * @param packet 待发送的数据包
 * @return 发送结果
 */
xnet_err_t xip_out(xnet_protocol_t protocol, xipaddr_t* dest_ip, xnet_packet_t* packet)
{
    //无意义
    xipaddr_t next_hop;
    // 1. 先决定“下一跳 IP”
    if (ip_same_net(dest_ip, &netif_ipaddr, &netif_netmask)) {
        // 同一网段：下一跳就是对方本身
        next_hop = *dest_ip;
    } else {
        // 不同网段：下一跳是默认网关
        next_hop = netif_gateway;
    }


    xip_hdr_t* ip_hdr;
    add_header(packet, sizeof(xip_hdr_t));
    ip_hdr = (xip_hdr_t*)packet->data;
    memcpy(ip_hdr->dest.array, dest_ip->array, XNET_IPV4_ADDR_SIZE);
    memcpy(ip_hdr->src.array, netif_ipaddr.array, XNET_IPV4_ADDR_SIZE);
    ip_hdr->proto = protocol;
    ip_hdr->ver_ihl = (XNET_VERSION_IPV4 << 4) | (sizeof(xip_hdr_t)/4); //ihl一个表示四字节
    ip_hdr->flag_fragment = 0;
    ip_hdr->id = 0;
    ip_hdr->total_len = swap_order16(packet->size);
    ip_hdr->time_to_live = ip_ttl; //64                    
    ip_hdr->type_of_service = 0;
    ip_hdr->hdr_checksum = 0;
    ip_hdr->hdr_checksum = checksum16((uint16_t*)ip_hdr, sizeof(xip_hdr_t), 0, 1);
   
    int index = find_entry(next_hop.array); //一般能查到，因为ping前会先发arp，并且反向的话在应用层设置了先初始化并监听一段时间后再ping
    if (arp_table[index].state == XARP_ENTRY_OK)
    {
        // 找到则直接通过以太网发出去
        return ethernet_out_to(XNET_PROTOCOL_IP, arp_table[index].macaddr, packet);
    }
    else
    {
        // 没找到则发 ARP 请求，然后返回 IO 错误
        xarp_make_request(dest_ip);
        return XNET_ERR_IO;
    }
}


/** 
 * @brief 处理ICMP报文
 * @param src_ip 收到的ICMP报文的源IP地址
 * @param packet 收到的ICMP报文的完整数据包
 * @return 无
 */
void xicmp_in(xipaddr_t* src_ip, xnet_packet_t* packet)
{
    xicmp_hdr_t* icmp = (xicmp_hdr_t*)packet->data;
    if(packet->size < sizeof(xicmp_hdr_t))
        return;

     // 把“结果类”ICMP（Echo Reply/Time Exceed/Unreach）写入 g_icmp_last，供 xicmp_receive 使用
    if (icmp->type == XICMP_TYPE_ECHO_REPLY      ||   // 目标主机
    icmp->type == XICMP_TYPE_TIME_EXCEED      ||   // 中间路由器 TTL 超时
    icmp->type == XICMP_TYPE_UNREACH)               // 目的不可达
    {           // 各种不可达
        g_icmp_last.src_ip   = *src_ip;
        g_icmp_last.icmp_hdr = *icmp;
        g_icmp_last.valid    = 1;
    }

    // Echo Request：别人 ping 我 -> 回一个 Echo Reply
    if(icmp->type==XICMP_TYPE_ECHO_REQUEST && icmp->code==0)
        reply_icmp_request(icmp, src_ip, packet);
    // Echo Reply：别人对我发的 ping 的回应 -> 通知 ping 模块打印
    if(icmp->type==XICMP_TYPE_ECHO_REPLY && icmp->code==0)
    {
        ping_on_reply(icmp, src_ip, packet);
    }
    if (icmp->type == XICMP_TYPE_TIME_EXCEED) {
        printf("来自路由器 %d.%d.%d.%d 的 ICMP TTL 超时报文\n",
               src_ip->array[0], src_ip->array[1],
               src_ip->array[2], src_ip->array[3]);
        return;
    }
    if (icmp->type == XICMP_TYPE_UNREACH) {
        printf("目标不可达：来自 %d.%d.%d.%d，code = %d\n",
               src_ip->array[0], src_ip->array[1],
               src_ip->array[2], src_ip->array[3],
               icmp->code);
        return;
    }
}

/** 
 * @brief 发送ICMP ECHO响应，即回应ping请求
 * @param icmp_hdr 收到的ICMP请求报文的头部
 * @param src_ip 收到的ICMP请求报文的源IP地址
 * @param packet 收到的ICMP请求报文的完整数据包
 * @return 发送结果
 */
static xnet_err_t reply_icmp_request(xicmp_hdr_t* icmp_hdr, xipaddr_t* src_ip, xnet_packet_t* packet)
{
    xnet_packet_t*pkt = xnet_alloc_for_send(packet->size);
    memcpy(pkt->data, packet->data, packet->size); //直接拷贝原来的包在基础上修改
    xicmp_hdr_t* icmp = (xicmp_hdr_t*)pkt->data;
    icmp->type = XICMP_TYPE_ECHO_REPLY;
    icmp->checksum = 0;
    icmp->checksum = checksum16((uint16_t*)icmp, pkt->size, 0, 1);
    xip_out(XNET_PROTOCOL_ICMP, src_ip, pkt);
    return XNET_ERR_OK;
}

/** 
 * @brief 发送ICMP目的不可达报文，根据RFC-792规范生成ICMP目的不可达报文
 * @param code ICMP目的不可达代码（如网络不可达、主机不可达、端口不可达等等）
 * @param ip_hdr 触发该ICMP报文的原始IP数据包头部
 * @return 错误代码，成功返回XNET_ERR_OK
 */
xnet_err_t xicmp_dest_unreach(uint8_t code, xip_hdr_t* ip_hdr)
{
    // ICMP 不可达报文携带：ICMP 头 + 原 IP 头 + 原负载前 8 字节
    xnet_packet_t* pkt = xnet_alloc_for_send(sizeof(xicmp_hdr_t) + (ip_hdr->ver_ihl & 0xF)*4 + 8);
    xicmp_hdr_t* icmp = (xicmp_hdr_t*)pkt->data;

    icmp->code = code;
    icmp->type = XICMP_TYPE_UNREACH;
    icmp->checksum = 0;
    icmp->id = 0;
    icmp->sequence_num = 0;
    // ICMP 数据部分：拷贝原 IP 头 + 前 8 字节负载
    uint8_t* start = pkt->data + sizeof(xicmp_hdr_t);
    memcpy(start, (uint8_t*)ip_hdr, (ip_hdr->ver_ihl & 0xF)*4 + 8);

    icmp->checksum = checksum16((uint16_t*)icmp, pkt->size, 0, 1);
    // 发送到原 IP 的 src 地址
    return xip_out(XNET_PROTOCOL_ICMP, &ip_hdr->src, pkt);
}

void xip_init(void)
{

}

void xicmp_init(void)
{

}

/**
 * @brief 发送一个 ICMP Echo Request（ping）
 * @param target_ip   目标 IP
 * @param id          标识符
 * @param seq         序列号
 * @param payload     负载数据指针
 * @param payload_len 负载数据长度
 */
xnet_err_t xicmp_echo_request(xipaddr_t* target_ip, uint16_t id, uint16_t seq, uint8_t* payload, uint16_t payload_len)
{
    // 分配 ICMP 头 + payload 的空间
    xnet_packet_t* pkt = xnet_alloc_for_send(sizeof(xicmp_hdr_t) + payload_len);
    xicmp_hdr_t* icmp_hdr = (xicmp_hdr_t*)pkt->data;
    // 填写 ICMP Echo Request 头
    icmp_hdr->type = XICMP_TYPE_ECHO_REQUEST;
    icmp_hdr->code = 0;
    icmp_hdr->id = id;
    icmp_hdr->sequence_num = seq;
    // 拷贝 payload
    uint8_t* start = (uint8_t*)(icmp_hdr + sizeof(xicmp_hdr_t));
    memcpy(start, payload, payload_len);

    icmp_hdr->checksum = 0;
    icmp_hdr->checksum = checksum16((uint16_t*)icmp_hdr, pkt->size, 0, 1);

    return xip_out(XNET_PROTOCOL_ICMP, target_ip, pkt);
}

/**
 * @brief traceroute 发送一个带指定 TTL 的 Echo Request
 */
void traceroute_send(xipaddr_t *dest_ip, uint16_t id, uint16_t seq, uint8_t ttl)
{
    // 申请一个用于发送的包，只放一个ICMP头就够了
    xnet_packet_t *packet = xnet_alloc_for_send(sizeof(xicmp_hdr_t));
    xicmp_hdr_t *icmp = (xicmp_hdr_t *)packet->data;

    // 填ICMP头
    icmp->type = XICMP_TYPE_ECHO_REQUEST;
    icmp->code = 0;
    icmp->id   = swap_order16(id);   
    icmp->sequence_num  = swap_order16(seq);  
    icmp->checksum = 0;
    icmp->checksum = checksum16((uint16_t *)icmp, packet->size, 0, 1);

    xip_set_ttl(ttl);

    xip_out(XNET_PROTOCOL_ICMP, dest_ip, packet);
}

/**
 * @brief 应用层阻塞等待一个 ICMP 报文（供 traceroute/ping 使用）
 * @param src_ip   收到报文的源 IP
 * @param icmp     ICMP 头部内容
 * @param timeout_ms 等待超时时间（毫秒）
 * @return 1=收到报文；0=超时
 */
int xicmp_receive(xipaddr_t *src_ip, xicmp_hdr_t *icmp, uint32_t timeout_ms)
{
    uint32_t start = xsys_get_time_ms();    // 你自己的获取当前毫秒函数

    while ((xsys_get_time_ms() - start) < timeout_ms) {
        // 如果 g_icmp_last 有有效数据，就取出来返回
        if (g_icmp_last.valid) {
            *src_ip = g_icmp_last.src_ip;
            *icmp   = g_icmp_last.icmp_hdr;
            g_icmp_last.valid = 0;
            return 1;
        }
        // 没有数据的话继续轮询协议栈，等数据进来
        xnet_poll();   
    }
    // 超时
    return 0;   // 超时
}

//无用
/**
 * @brief 判断两个 IP 是否处于同一网段
 * @param a    IP 地址 A
 * @param b    IP 地址 B
 * @param mask 子网掩码
 * @return 1 = 同网段；0 = 不同网段
 */
static int ip_same_net(const xipaddr_t *a, const xipaddr_t *b, const xipaddr_t *mask)
{
    for (int i = 0; i < 4; i++) {
        if ( (a->array[i] & mask->array[i]) != (b->array[i] & mask->array[i]) ) {
            return 0;
        }
    }
    return 1;
}

// 打印当前 ARP 表内容，方便调试
void print_arp_table(void)
{
    printf("===== ARP Table =====\n");
    printf("Idx  State        IP              MAC                TMO  Retry\n");

    for (int i = 0; i < XARP_TABLE_SIZE; i++) {
        xarp_entry_t *e = &arp_table[i];   // 取出第 i 个表项

        // 如果你只想看“有用的”条目，可以跳过 FREE 的：
        if (e->state == XARP_ENTRY_FREE) {
            continue;
        }

        // 把状态转成文字，打印好看一点
        const char *state_str;
        switch (e->state) {
        case XARP_ENTRY_FREE:      state_str = "FREE";      break;
        case XARP_ENTRY_OK:        state_str = "OK";        break;
        case XARP_ENTRY_RESOLVING: state_str = "RESOLVING"; break;
        default:                   state_str = "UNKNOWN";   break;
        }

        printf("%3d  %-10s  %3d.%3d.%3d.%3d  "
               "%02X:%02X:%02X:%02X:%02X:%02X  "
               "%4u  %3u\n",
               i,
               state_str,
               e->ipaddr.array[0],
               e->ipaddr.array[1],
               e->ipaddr.array[2],
               e->ipaddr.array[3],
               e->macaddr[0],
               e->macaddr[1],
               e->macaddr[2],
               e->macaddr[3],
               e->macaddr[4],
               e->macaddr[5],
               e->tmo,
               e->retry_cnt);
    }

    printf("======================\n");
}

