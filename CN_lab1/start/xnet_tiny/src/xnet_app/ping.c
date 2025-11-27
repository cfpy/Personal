#include "ping.h"
#include "stdio.h"
#include "xnet_tiny.h" 
#include "windows.h"

// 不同 payload 长度列表，用于带宽测量时发不同大小的 ICMP 报文
uint16_t payload_len_list[] = {64,256,512,1024};
// 列表中有效的元素个数
uint16_t pay_cnt = 4;
// traceroute 虚拟拓扑里的一跳：包含一个 IP 和一个可选描述
typedef struct {
    xipaddr_t ip;      // 这一跳的 IP 地址
    const char* name;  // 这一跳的名字（可选，用来打印说明）
} xtrace_hop_t;

// 虚拟路径：前两跳是虚拟路由器，最后一跳是真目标
static const xtrace_hop_t g_virtual_hops[] = {
    { .ip = { .array = {192,168,196,1} }, "本机网关(虚拟)" },
    { .ip = { .array = {10,0,0,1}      }, "运营商路由(虚拟)" },
};

// 虚拟路径中包含多少个虚拟 hop（这里是 2）
#define VIRTUAL_HOP_COUNT   (sizeof(g_virtual_hops) / sizeof(g_virtual_hops[0]))


void print_ip(xipaddr_t* ip)
{
    printf("%d.%d.%d.%d", ip->array[0], ip->array[1], ip->array[2], ip->array[3]);
}

// ping 会话上下文，用来记录当前一次 ping 的 id/seq 和时间信息
static struct {
    uint16_t id;          // 本次 ping 使用的标识符（一般固定）
    uint16_t seq;         // 当前正在发送的序号
    uint64_t send_time;   // 发送时间（微秒）
    uint64_t rtt;         // 本次往返时间（微秒）
} ping_ctx;

// 每个 seq 对应一条统计信息
typedef struct {
    uint64_t rtt;         // 收到应答时的 RTT
    int transmitted;      // 是否发送过（1=发送过）
    int received;         // 是否收到过应答（1=收到）
} statistic;

// 保存很多次 ping 的统计信息（最多 1000 个 seq）
statistic statistics[1000];
// 已经发送的包数量（统计方便）
int sta_cnt = 0;
// 已经收到的包数量
int rec_cnt = 0;

// 1. 获取 RTT 最大值
uint64_t get_rtt_max(statistic *stats, int count) {
    uint64_t max_val = 0;          // 默认从 0 开始

    for (int i = 0; i < count; i++) {
        // 只统计“已经收到应答”的包
        if (stats[i].received) {
            if (stats[i].rtt > max_val) {
                max_val = stats[i].rtt;   // 找到更大的就更新
            }
        }
    }
    return max_val;
}

// 2. 获取 RTT 最小值
uint64_t get_rtt_min(statistic *stats, int count) {
    // 先给一个极大值，后面找最小值时用
    uint64_t min_val = (uint64_t)-1;  // 等价于 UINT64_MAX
    int valid_pkt_cnt = 0;            // 统计真正收到的包个数

    for (int i = 0; i < count; i++) {
        if (stats[i].received) {      // 只统计收到应答的
            if (stats[i].rtt < min_val) {
                min_val = stats[i].rtt;   // 更新最小值
            }
            valid_pkt_cnt++;          // 记录收到包的数量
        }
    }

    // 如果一个包都没收到，返回 0，避免返回初始的超大值
    if (valid_pkt_cnt == 0) {
        return 0;
    }
    return min_val;
}

// 3. 获取 RTT 平均值
double get_rtt_avg(statistic *stats, int count) {
    uint64_t sum = 0;         // RTT 累加和
    int valid_pkt_cnt = 0;    // 收到包的个数

    for (int i = 0; i < count; i++) {
        if (stats[i].received) {
            sum += stats[i].rtt;
            valid_pkt_cnt++;
        }
    }

    // 防止除以 0
    if (valid_pkt_cnt == 0) {
        return 0.0;
    }

    // 强转为 double 再除，保留小数精度
    return (double)sum / valid_pkt_cnt;
}

double get_jitter_avg(statistic *stats, int count) {
    // 如果包的数量少于2个，无法计算差值，抖动为0
    if (count < 2) return 0.0;

    double total_jitter = 0;        // 所有差值的累加
    int valid_jitter_pairs = 0;     // 有效的“相邻对”数量

    // 从第 1 个包开始遍历（和第 i-1 个包比较）
    for (int i = 1; i < count; i++) {
        
        // 关键逻辑：只有当当前包和前一个包都收到时，才能计算“相邻索引”的抖动
        if (stats[i].received && stats[i-1].received) {
            uint64_t rtt_curr = stats[i].rtt;
            uint64_t rtt_prev = stats[i-1].rtt;
            uint64_t diff;

            // 计算绝对值 |rtt_curr - rtt_prev|
            if (rtt_curr >= rtt_prev) {
                diff = rtt_curr - rtt_prev;
            } else {
                diff = rtt_prev - rtt_curr;
            }

            total_jitter += (double)diff;
            valid_jitter_pairs++;
        }
    }

    // 如果没有有效的相邻对（比如丢包严重，或者只收到了第1个和第3个，中间第2个丢了），防止除以0
    if (valid_jitter_pairs == 0) {
        return 0.0;
    }

    return total_jitter / valid_jitter_pairs;
}


// 初始化一次 ping 会话上下文
void ping_session_init(uint16_t seq) {
    ping_ctx.id = 6;           // 固定用 6 作为 ping id（随便取）
    ping_ctx.seq = seq;        // 当前 seq
    ping_ctx.send_time = 0;    // 发送时间在真正发之前填
    ping_ctx.rtt = 0;          // RTT 初始为 0
}


void ping_run(xipaddr_t* dst, uint16_t seq)
{

    ping_session_init(seq);
    uint8_t pay[2] = {6,6};
    ping_ctx.send_time = get_time_us();
    xnet_err_t err =  xicmp_echo_request(dst, ping_ctx.id, seq, pay, 2);
    statistics[seq].transmitted = 1;
    // 在统计表里标记这个 seq 已经发送
    sta_cnt++;
}

void ping_run_payload(xipaddr_t* dst, uint16_t seq, uint8_t* payload, uint16_t payload_len) //为带宽测试服务
{
    ping_session_init(seq);
    ping_ctx.send_time = get_time_us();
    xnet_err_t err =  xicmp_echo_request(dst, ping_ctx.id, seq, payload, payload_len);
    statistics[seq].transmitted = 1;
    sta_cnt++;
}

void ping_on_reply(xicmp_hdr_t* icmp, xipaddr_t* src_ip, xnet_packet_t* packet)
{
    // 只处理属于当前会话（id 相同）的应答
    if(icmp->id != ping_ctx.id) return;
    // 只处理当前 seq 的应答
    if(icmp->sequence_num != ping_ctx.seq) return;

    uint64_t now = get_time_us();
    // printf("now: %d\n", now);
    ping_ctx.rtt = now - ping_ctx.send_time;
    // printf("send: %d\n", ping_ctx.send_time);

    printf("Reply from %d.%d.%d.%d: seq=%d time=%dus payload=%d byte(s)\n", 
    src_ip->array[0], src_ip->array[1], src_ip->array[2], 
    src_ip->array[3], icmp->sequence_num, ping_ctx.rtt, packet->size-sizeof(xicmp_hdr_t));

    // 在统计数据里记录：这个 seq 收到了应答
    statistics[icmp->sequence_num].received = 1;
    statistics[icmp->sequence_num].rtt = ping_ctx.rtt;
    rec_cnt++;
}

void print_statistics(void)
{
    printf("\n");
    printf("-----Ping statistics------\n");
    printf("%d packets transmitted. %d received. %.2f%% loss.\n",
       sta_cnt, rec_cnt, (sta_cnt - rec_cnt)*100.0/(float)sta_cnt);
    printf("rtt min/avg/max = %llu/%.2f/%llu us\n", 
           get_rtt_min(statistics, sta_cnt),
           get_rtt_avg(statistics, sta_cnt),
           get_rtt_max(statistics, sta_cnt)
    );
}

void print_jitters(void)
{
    printf("\n");
    printf("平均RTT：%.2f us，平均抖动：%.2f us\n", get_rtt_avg(statistics, sta_cnt), get_jitter_avg(statistics, sta_cnt));
}

void print_and_save_bandwidth(void)
{
    // 1. 打开文件
    FILE *fp = fopen("C:/Users/19145/Desktop/CN_lab1/visualization/data/bandwidth_data.csv", "w");
    if (fp == NULL) {
        printf("Error: Cannot create csv file.\n");
        return;
    }

    // 2. 写入表头
    // CSV 的规则很简单：用逗号隔开列，用换行隔开行
    fprintf(fp, "payload,bandwidth\n");

    printf("\n");
    for (int i=0;i<pay_cnt;i++)
    {
        double result = 8.0*1000*payload_len_list[i]/statistics[i].rtt;
        printf("Payload %d bytes: %.2f kbps\n", payload_len_list[i], result);
        fprintf(fp, "%d,%.2f\n", payload_len_list[i], result);
    }
    fclose(fp);
    printf("CSV data exported successfully.\n");
}

void export_and_plot_jitter(void) {
    // 1. 打开/创建 CSV 文件
    FILE *fp = fopen("C:/Users/19145/Desktop/CN_lab1/visualization/data/jitter_data.csv", "w");
    if (fp == NULL) {
        printf("Error: Cannot open file for writing.\n");
        return;
    }

    // 2. 写入表头 (Header)
    // 格式：Sequence,RTT,Jitter
    fprintf(fp, "seq,rtt,jitter\n");

    // 3. 遍历所有统计项
    for (int i = 0; i < sta_cnt; i++) {
        // 当前包的抖动值，默认 0
        double jitter_val = 0;
        // 从第 1 个开始可以和前一个比较
        if (i > 0 && statistics[i].received && statistics[i-1].received) {
            // 计算相邻两个 RTT 的差值
            long long diff = (long long)statistics[i].rtt - (long long)statistics[i-1].rtt;
            jitter_val = (diff > 0) ? (double)diff : -(double)diff;
        }

        // 只写已接收的包
        if (statistics[i].received) {
            fprintf(fp, "%d,%llu,%.2f\n", 
                    i, 
                    statistics[i].rtt, 
                    jitter_val);
        }
    }

    // 4. 关闭文件
    fclose(fp);
    printf("Data exported to jitter_data.csv\n");

    // 5. 调用 Python 脚本 (系统调用)
    // 注意：确保你的电脑安装了 python 并且在环境变量里
    // printf("Launching visualization...\n");
    // system("python plot_jitter.py"); 
}

// traceroute：前几跳打印虚拟拓扑，后面用真实 ICMP 做探测
void traceroute(xipaddr_t *dest_ip, uint8_t max_hops)
{
    uint16_t id = 0x1234;                    // traceroute 全程使用的 ICMP id
    uint8_t new_max_hops = VIRTUAL_HOP_COUNT + max_hops; // 虚拟跳数 + 真正探测跳数

    for (uint8_t ttl = 1; ttl <= new_max_hops; ttl++) {
        printf("%2d  ", ttl);

        // 1) 前面几跳（ttl <= VIRTUAL_HOP_COUNT）：直接打印虚拟拓扑
        if (ttl <= VIRTUAL_HOP_COUNT) {
            const xtrace_hop_t *hop = &g_virtual_hops[ttl - 1];
            printf("%d.%d.%d.%d  %s\n",
                   hop->ip.array[0], hop->ip.array[1],
                   hop->ip.array[2], hop->ip.array[3],
                   hop->name ? hop->name : "");
            continue;   // 不发包，打印完这一跳直接下一跳
        }

        // 2) 真正的探测：发送带特定 TTL 的 Echo Request
        traceroute_send(dest_ip, id, ttl, ttl);

        // 用来接收返回的 ICMP 信息
        xipaddr_t hop_ip;
        xicmp_hdr_t icmp_hdr;

        // 阻塞最多 2000ms 等一个 ICMP 报文
        if (xicmp_receive(&hop_ip, &icmp_hdr, 2000)) {
            // a) Time Exceeded：说明中途路由器 TTL 用完
            if (icmp_hdr.type == XICMP_TYPE_TIME_EXCEED) {
                printf("%d.%d.%d.%d  TTL exceeded\n",
                       hop_ip.array[0], hop_ip.array[1],
                       hop_ip.array[2], hop_ip.array[3]);
            }
            // b) Echo Reply：说明已经到达目标主机
            else if (icmp_hdr.type == XICMP_TYPE_ECHO_REPLY && icmp_hdr.code == 0) {
                printf("%d.%d.%d.%d  到达目标\n",
                       hop_ip.array[0], hop_ip.array[1],
                       hop_ip.array[2], hop_ip.array[3]);
                break;  // traceroute 结束
            }
            // c) Destination Unreachable：目标不可达
            else if (icmp_hdr.type == XICMP_TYPE_UNREACH) {
                printf("%d.%d.%d.%d  目标不可达 (code=%d)\n",
                       hop_ip.array[0], hop_ip.array[1],
                       hop_ip.array[2], hop_ip.array[3],
                       icmp_hdr.code);
                break;
            }
            // d) 其它类型，简单打印出来方便调试
            else {
                printf("%d.%d.%d.%d  收到其它 ICMP type=%d code=%d\n",
                       hop_ip.array[0], hop_ip.array[1],
                       hop_ip.array[2], hop_ip.array[3],
                       icmp_hdr.type, icmp_hdr.code);
            }
        } else {
            // 超时时，打印 *
            printf("* 请求超时\n");
        }
    }
}

