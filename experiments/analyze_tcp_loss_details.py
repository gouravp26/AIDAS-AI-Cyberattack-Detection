import pandas as pd

df = pd.read_csv("data/processed/train_part.csv")

tcp = df[df["proto"] == "tcp"].copy()

print("TCP RECORDS:", len(tcp))

print("\n1. LOSS GREATER THAN PACKET COUNT")

for loss_col, packet_col in [
    ("sloss", "spkts"),
    ("dloss", "dpkts"),
]:
    count = (tcp[loss_col] > tcp[packet_col]).sum()

    print(
        f"{loss_col} > {packet_col}: "
        f"{count} records"
    )

print("\n2. LOSS-TO-PACKET RATIOS")

tcp["sloss_ratio"] = (
    tcp["sloss"] / tcp["spkts"]
)

tcp["dloss_ratio"] = (
    tcp["dloss"] / tcp["dpkts"].replace(0, pd.NA)
)

print(
    tcp[["sloss_ratio", "dloss_ratio"]]
    .describe()
)

print("\n3. CORRELATION")

print(
    tcp[["spkts", "dpkts", "sloss", "dloss"]]
    .corr()
)

print("\n4. EXAMPLES WHERE LOSS EXCEEDS PACKET COUNT")

print(
    tcp.loc[
        (tcp["sloss"] > tcp["spkts"])
        | (tcp["dloss"] > tcp["dpkts"]),
        ["spkts", "dpkts", "sloss", "dloss"]
    ].head(15).to_string(index=False)
)

print("\n5. TCP LOSS SUMMARY")

print(
    tcp[["spkts", "dpkts", "sloss", "dloss"]]
    .describe()
)