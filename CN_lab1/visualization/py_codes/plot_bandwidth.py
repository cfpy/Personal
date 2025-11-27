import pandas as pd
import matplotlib.pyplot as plt

try:
    df = pd.read_csv("C:/Users/19145/Desktop/CN_lab1/visualization/data/bandwidth_data.csv")
except FileNotFoundError:
    exit()

plt.style.use('seaborn-v0_8-whitegrid')
fig, ax = plt.subplots(figsize=(8, 6))

# 画柱状图
bars = ax.bar(df['payload'].astype(str), df['bandwidth'], color='skyblue', edgecolor='black')

# --- 【关键修改】 ---
# 1. 先清除当前样式自带的默认网格
ax.grid(False) 

# 2. 重新设置网格：
# axis='y' 表示只显示 Y 轴的网格（即横线），去掉了竖线
# linestyle='--' 表示虚线
# alpha=0.7 设置透明度，让网格线不要太抢眼
ax.yaxis.grid(True, linestyle='--', alpha=0.7)
# ------------------

# 在柱子上标数值
for bar in bars:
    height = bar.get_height()
    ax.text(bar.get_x() + bar.get_width()/2., height + 1,
            f'{height:.2f} kbps',
            ha='center', va='bottom')

ax.set_title('ICMP Bandwidth Estimation')
ax.set_xlabel('Packet Size (bytes)')
ax.set_ylabel('Bandwidth (kbps)')

plt.tight_layout()
plt.show()