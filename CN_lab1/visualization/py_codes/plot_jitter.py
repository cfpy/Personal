import pandas as pd
import matplotlib.pyplot as plt

# 1. 读取 C 语言生成的 CSV 文件
try:
    df = pd.read_csv("C:/Users/19145/Desktop/CN_lab1/visualization/data/jitter_data.csv")
except FileNotFoundError:
    print("Error: jitter_data.csv not found.")
    exit()

# 2. 设置画布风格
# plt.style.use('ggplot')
fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 8)) # 2行1列的子图

# --- 上图：RTT 变化 ---
ax1.plot(df['seq'], df['rtt'], marker='o', linestyle='-', color='blue', label='RTT (ms)')
avg_rtt = df['rtt'].mean()
ax1.axhline(y=avg_rtt, color='red', linestyle='--', label=f'Avg RTT: {avg_rtt:.2f} ms')

ax1.set_title('ICMP Network Quality - RTT Variation')
ax1.set_ylabel('Round Trip Time (ms)')
ax1.legend()
ax1.grid(True, linestyle='--', alpha=0.7)

# --- 下图：Jitter 变化 ---
# 过滤掉第一行(因为第一个包没有抖动)
jitter_data = df.iloc[1:] 

ax2.bar(jitter_data['seq'], jitter_data['jitter'], color='orange', alpha=0.7, label='Jitter (ms)')
avg_jitter = jitter_data['jitter'].mean()
ax2.axhline(y=avg_jitter, color='purple', linestyle='--', label=f'Avg Jitter: {avg_jitter:.2f} ms')

ax2.set_title('Jitter Variation')
ax2.set_xlabel('Packet Sequence')
ax2.set_ylabel('Jitter (ms)')
ax2.legend()
ax2.grid(True, linestyle='--', alpha=0.7)

# 3. 显示图表
plt.tight_layout()
plt.show()