
import pandas as pd

pred = pd.read_csv(
    "Results/LineVul/pairvul_top10_test01/predictions.csv"
)

audit = pd.read_csv(
    "datasets/processed/pairvul_top10/"
    "linevul_input_visibility.csv"
)

wide = pred.pivot(
    index="pair_id",
    columns="version",
    values=["pred_label", "score_vulnerable"]
)

wide.columns = [
    f"{field}_{version}"
    for field, version in wide.columns
]

results = audit.merge(
    wide.reset_index(),
    on="pair_id",
    validate="one_to_one"
)

results["score_delta"] = (
    results["score_vulnerable_before"] -
    results["score_vulnerable_after"]
)

def classify(row):
    b, a = int(row.pred_label_before), int(row.pred_label_after)
    return {
        (1, 0): "correct_pair",
        (1, 1): "both_vulnerable",
        (0, 0): "both_benign",
        (0, 1): "inverted"
    }[(b, a)]

results["outcome"] = results.apply(classify, axis=1)

print("Prediction outcomes by input visibility:")
print(pd.crosstab(
    results["reason"],
    results["outcome"],
    margins=True
))

print("\nScore differences by input visibility:")
print(
    results.groupby("reason")["score_delta"]
    .agg(["count", "mean", "median", "std"])
)

print("\nScore distribution by code version:")
print(
    pred.groupby("version")["score_vulnerable"]
    .describe()
)

# Confirm the predicted labels match a 0.5 threshold.
expected = (pred["score_vulnerable"] >= 0.5).astype(int)
print("\nLabel/score mismatches:",
      (expected != pred["pred_label"]).sum())

results.to_csv(
    "Results/LineVul/pairvul_top10_test01/"
    "prediction_visibility_analysis.csv",
    index=False
)
