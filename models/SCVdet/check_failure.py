from pathlib import Path
import pandas as pd

run = Path("Results/SCVdet/pairvul_top10_scvdet_01")

for filename in [
    "joern_status.csv",
    "graph_status.csv",
    "prediction_failures.csv",
]:
    path = run / filename

    print(f"\n{'=' * 60}")
    print(filename)
    print("=" * 60)

    if not path.exists():
        print("File not found")
        continue

    df = pd.read_csv(path)
    print("Total records:", len(df))

    if "status" in df.columns:
        print("\nStatuses:")
        print(df["status"].value_counts(dropna=False))

        successful = df["status"].isin(["ok", "cached"])
        print("Successful samples:", successful.sum())

        pair_status = (
            df.assign(success=successful)
            .pivot_table(
                index="pair_id",
                columns="version",
                values="success",
                aggfunc="max",
                fill_value=False
            )
            .reindex(
                columns=["before", "after"],
                fill_value=False
            )
        )

        print(
            "Pairs with BOTH versions successful:",
            pair_status.all(axis=1).sum()
        )

        errors = df.loc[~successful, "error"].dropna()
        if not errors.empty:
            print("\nTop errors:")
            print(errors.value_counts().head(10).to_string())
            print("\nFirst error:")
            print(errors.iloc[0][:1500])

    if "reason" in df.columns:
        reasons = df["reason"].fillna("Unknown")
        print("\nMost common inference failures:")
        print(reasons.value_counts().head(10).to_string())
        print("\nFirst failure:")
        print(reasons.iloc[0][:1500])