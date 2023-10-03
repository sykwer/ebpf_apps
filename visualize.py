import pandas as pd
import matplotlib.pyplot as plt

log_path = "lo_traffic.log"
df = pd.read_csv(log_path, names=["timestamp", "pid", "comm", "bytes"])

# Convert timestamp column to datetime type for better handling
df['timestamp'] = pd.to_datetime(df['timestamp'], unit='s')

# Group by pid, comm, and timestamp and sum bytes for each group
grouped = df.groupby(["pid", "comm", "timestamp"])["bytes"].sum().reset_index()

# Find top 25 processes based on total bytes
top25_pids = grouped.groupby(["pid", "comm"])["bytes"].sum().nlargest(15).reset_index()["pid"].tolist()

# Plot each of the top 25 processes
plt.figure(figsize=(15, 7))

for pid in top25_pids:
    subset = grouped[grouped["pid"] == pid]
    plt.plot(subset["timestamp"].to_numpy(), subset["bytes"].to_numpy(), label="pid={}, {}".format(pid, subset["comm"].iloc[0]))


plt.xlabel("Timestamp")
plt.ylabel("Bytes per second")
plt.title("Top 25 Processes Traffic over Time")
plt.legend()
plt.tight_layout()
plt.show()
