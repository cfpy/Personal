#include <stdio.h>
#include "xnet_tiny.h"
#include <time.h>
#include <stdlib.h>
#include <string.h>

int main (void) {
    system("chcp 65001");
    print_arp_table();
    xnet_init();

    printf("xnet running\n");

    // 启动后先跑一小段时间，让 ARP 等初始化流程先走一轮
    double duration = 0.3;              // 持续 0.3 秒
    time_t start_time = time(NULL);     // 当前时间
    while (difftime(time(NULL), start_time) < duration) {
        xnet_poll();                    // 轮询协议栈：收包、ARP 定时等
    }

    int choice;
    int running = 1;

    while (running) {

        xipaddr_t dst = {192,168,19,66};
        int pkt_num = 8;

        printf("\n=== ICMP工具集 ===\n");
        printf("1. Ping测试\n");
        printf("2. Traceroute测试\n");
        printf("3. 带宽估算\n");
        printf("4. 抖动测量\n");
        printf("5. 正常运行监听\n");
        printf("6. 退出\n");
        printf("7. 打印arp表\n");
        printf("\n请选择功能 (1-7): ");


        // 读取用户输入
        // 检查 scanf 的返回值，防止用户输入非数字导致死循环
        if (scanf("%d", &choice) != 1) {
            // 清除输入缓冲区中的错误字符
            while (getchar() != '\n'); 
            printf("输入无效，请输入数字 1-5。\n");
            continue;
        }

        // 处理回车符，防止影响后续的字符串输入
        while (getchar() != '\n'); 

        switch (choice) {
            case 1:

                printf("\nPinging ");
                print_ip(&dst);
                printf(" with %d packets:\n\n",pkt_num);
                for (uint16_t i=0;i<pkt_num;i++)
                {
                    ping_run(&dst, i);
                    // 发完之后给协议栈 2 秒时间去收回包
                    double duration = 2;
                    time_t start_time = time(NULL);
                    while (difftime(time(NULL), start_time) < duration) {
                        xnet_poll();
                    }
                }
                print_statistics();
                break;
            case 2:
                uint8_t max_hops = 8;
                traceroute(&dst, max_hops);
                break;
            case 3:
                uint8_t payload[8195];
                memset(payload, 6, sizeof(payload));
                printf("\n开始基于ICMP的带宽测量：");
                print_ip(&dst);
                printf("\n");
                for (uint16_t i=0;i<pay_cnt;i++)
                {
                    ping_run_payload(&dst, i, payload, payload_len_list[i]);
                    double duration = 0.5;
                    time_t start_time = time(NULL);
                    while (difftime(time(NULL), start_time) < duration) {
                        xnet_poll();
                    }
                }
                print_and_save_bandwidth();
                break;
            case 4:
                printf("\n开始基于ICMP的抖动测量：");
                print_ip(&dst);
                printf("\n");
                for (uint16_t i=0;i<pkt_num;i++)
                {
                    ping_run(&dst, i);
                    double duration = 0.5;
                    time_t start_time = time(NULL);
                    while (difftime(time(NULL), start_time) < duration) {
                        xnet_poll();
                    }
                }
                print_jitters();
                export_and_plot_jitter();
                break;
            case 5: {
                // 记录上一次打印 ARP 表的时间（毫秒）
                uint32_t last = xsys_get_time_ms();

                while (1) {
                    // 让协议栈持续跑：收包、ARP 定时等
                    xnet_poll();

                    // 当前时间（毫秒）
                    uint32_t now = xsys_get_time_ms();

                    // 如果距离上次打印已经超过 10 秒（10000ms）
                    if (now - last >= 1000) {
                        print_arp_table();   // 打印一次 ARP 表
                        last = now;          // 更新“上一次打印时间”
                    }
                }
                break;
            }    
            case 6:
                printf("正在退出程序...\n");
                running = 0;
                break;
            case 7:
                print_arp_table();
                break;
            default:
                printf("无效选项，请重新选择。\n");
                break;
        }

        if (running) {
            printf("\n按回车键返回主菜单...");
            getchar(); // 等待用户按键
        }
    }
    return 0;
}
