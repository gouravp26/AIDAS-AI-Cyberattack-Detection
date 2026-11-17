import pandas as pd

df = pd.read_csv("data/processed/train_part.csv")

print("LOSS FEATURE SUMMARY")
print(df[["sloss", "dloss"]].describe())

print("\nUNIQUE VALUES (first 30)")
print("sloss:", sorted(df["sloss"].dropna().unique())[:30])
print("dloss:", sorted(df["dloss"].dropna().unique())[:30])

print("\nZERO COUNTS")
print("sloss zero:", (df["sloss"] == 0).sum())
print("dloss zero:", (df["dloss"] == 0).sum())

print("\nNON-ZERO COUNTS")
print("sloss non-zero:", (df["sloss"] > 0).sum())
print("dloss non-zero:", (df["dloss"] > 0).sum())

print("\nLOSS BY PROTOCOL")
print(
    df.groupby("proto")[["sloss", "dloss"]]
    .agg(["count", "mean", "median", "max"])
    .to_string()
)

print("\nLOSS BY PACKET COUNTS")
print(
    df[["spkts", "dpkts", "sloss", "dloss"]]
    .describe()
)