
import pandas as pd
from transformers import AutoTokenizer

data_path = "datasets/processed/pairvul_top10/linevul_test.csv"
df = pd.read_csv(data_path)

tokenizer = AutoTokenizer.from_pretrained("microsoft/codebert-base")

records = []

for pair_id, group in df.groupby("pair_id"):
    b = group.loc[group.version == "before", "processed_func"].iloc[0]
    a = group.loc[group.version == "after", "processed_func"].iloc[0]

    bt = tokenizer.tokenize(str(b))
    at = tokenizer.tokenize(str(a))

    same_full = bt == at
    same_visible = bt[:510] == at[:510]

    if same_full:
        reason = "identical_full_tokens"
    elif same_visible:
        reason = "difference_lost_by_truncation"
    else:
        reason = "different_visible_tokens"

    records.append({
        "pair_id": pair_id,
        "before_tokens": len(bt),
        "after_tokens": len(at),
        "before_truncated": len(bt) > 510,
        "after_truncated": len(at) > 510,
        "same_full_tokens": same_full,
        "same_visible_tokens": same_visible,
        "reason": reason
    })

audit = pd.DataFrame(records)

print(audit["reason"].value_counts())
print("\nPercentages:")
print((audit["reason"].value_counts(normalize=True) * 100).round(2))

audit.to_csv(
    "datasets/processed/pairvul_top10/"
    "linevul_input_visibility.csv",
    index=False
)
