
import pandas as pd
from transformers import AutoTokenizer

path = "datasets/processed/pairvul_top10/linevul_test.csv"
df = pd.read_csv(path)

tokenizer = AutoTokenizer.from_pretrained(
    "microsoft/codebert-base"
)

records = []

for pair_id, group in df.groupby("pair_id"):
    if set(group["version"]) != {"before", "after"}:
        continue

    before = group.loc[
        group["version"] == "before", "processed_func"
    ].iloc[0]

    after = group.loc[
        group["version"] == "after", "processed_func"
    ].iloc[0]

    before_ids = tokenizer.encode(
        before, add_special_tokens=False
    )
    after_ids = tokenizer.encode(
        after, add_special_tokens=False
    )

    records.append({
        "pair_id": pair_id,
        "before_tokens": len(before_ids),
        "after_tokens": len(after_ids),
        "before_truncated": len(before_ids) > 510,
        "after_truncated": len(after_ids) > 510,
        "identical_model_input":
            before_ids[:510] == after_ids[:510]
    })

audit = pd.DataFrame(records)

print("Total pairs:", len(audit))
print("Before truncated:", audit.before_truncated.sum())
print("After truncated:", audit.after_truncated.sum())
print(
    "Identical inputs after truncation:",
    audit.identical_model_input.sum()
)

print("\nPercentages:")
print(
    audit[
        ["before_truncated",
         "after_truncated",
         "identical_model_input"]
    ].mean().mul(100).round(2)
)

audit.to_csv(
    "datasets/processed/pairvul_top10/"
    "linevul_token_audit.csv",
    index=False
)
