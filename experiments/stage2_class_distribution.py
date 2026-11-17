import pandas as pd
import matplotlib

matplotlib.use("Agg")  # draw to a file only, no pop-up window
import matplotlib.pyplot as plt
import seaborn as sns

# AIDAS Stage 2 - attack category distribution (training set)

TRAIN_PATH = "data/raw/UNSW_NB15_training-set.csv"
OUTPUT_PATH = "reports/stage2_class_distribution.png"

df = pd.read_csv(TRAIN_PATH)
counts = df["attack_cat"].value_counts()

plt.figure(figsize=(10, 6))
ax = sns.barplot(x=counts.values, y=counts.index.tolist(), color="steelblue")
ax.set_xscale("log")
ax.bar_label(ax.containers[0], padding=4)
ax.set_xlabel("Number of rows (log scale)")
ax.set_ylabel("Category")
ax.set_title("UNSW-NB15 training set: rows per category")
plt.tight_layout()
plt.savefig(OUTPUT_PATH, dpi=150)

print("Chart saved to:", OUTPUT_PATH)