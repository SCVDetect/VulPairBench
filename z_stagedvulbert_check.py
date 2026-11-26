
from pathlib import Path
import pandas as pd

run = Path("Results/StagedVulBERT/pairvul_top10_staged_01")
df = pd.read_csv(run / "raw_preds.csv")

before = df[df["version"] == "before"].set_index("pair_id")
after = df[df["version"] == "after"].set_index("pair_id")

cols = [
    "score_vulnerable",
    "pred_label",
    "original_tokens",
    "visible_tokens",
    "truncated"
]

pairs = before[cols].join(
    after[cols],
    lsuffix="_before",
    rsuffix="_after",
    validate="one_to_one"
)

pairs["score_delta"] = (
    pairs["score_vulnerable_before"]
    - pairs["score_vulnerable_after"]
)

pairs["score_changed"] = pairs["score_delta"].abs() > 1e-6

pairs["truncated_before"] = (
    pairs["truncated_before"].astype(str).str.lower() == "true"
)
pairs["truncated_after"] = (
    pairs["truncated_after"].astype(str).str.lower() == "true"
)

pairs["any_truncation"] = (
    pairs["truncated_before"] | pairs["truncated_after"]
)

print("Evaluated pairs:", len(pairs))
print("Pairs with at least one truncated version:",
      pairs["any_truncation"].sum())

print("Pairs with score changes > 1e-6:",
      pairs["score_changed"].sum())

print("Before score higher:",
      (pairs["score_delta"] > 1e-6).sum())

print("After score higher:",
      (pairs["score_delta"] < -1e-6).sum())

print("\nScore delta statistics:")
print(pairs["score_delta"].describe(
    percentiles=[.05, .25, .5, .75, .95, .99]
))

print("\nScore distribution by version:")
print(df.groupby("version")["score_vulnerable"].describe(
    percentiles=[.5, .9, .95, .99]
))

print("\nScore changes by truncation:")
print(pairs.groupby("any_truncation")["score_delta"].agg(
    ["count", "mean", "median", "std"]
))

pairs.to_csv(run / "pair_diagnostics.csv")
