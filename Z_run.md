
prepare the dataset

python scripts/prepare_pairvul.py \
  --input datasets/raw/Linux_kernel_clean_data_top10_CWEs.json \
  --out datasets/processed/pairvul_top10



Run LineVul
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
You can start testing LineVul now. I checked the `VulPairBench` repository we prepared and verified the pair-preparation script using three actual pairs from your Vul-RAG JSON.

**The JSON belongs under&#x20;**`datasets/raw/`**, the prepared test data goes under&#x20;**`datasets/processed/`**, and LineVul's predictions go under&#x20;**`Results/LineVul/`**.**

## **1. Where to place the JSON**

Use this structure:

**VulPairBench/**

📁 datasets/

📁 raw/

Linux_kernel_clean_data_top10_CWEs.json

📁 processed/

📁 manifests/

📁 models/LineVul/

📁 Results/LineVul/

📁 scripts/

Your `.gitignore` already excludes the raw and processed datasets, so they will stay local.

## **2. Prepare the paired dataset**

Open your terminal from the **VulPairBench repository root**.

You can use your existing LineVul virtual environment. The preparation script itself uses only Python standard-library modules.

Run:

```
python scripts/prepare_pairvul.py \
  --input datasets/raw/Linux_kernel_clean_data_top10_CWEs.json \
  --out datasets/processed/pairvul_top10
```

This creates the following files:

| File                  | Purpose                                          |
| --------------------- | ------------------------------------------------ |
| `pairs.csv`           | Maps vulnerable and patched versions to one pair |
| `samples.csv`         | Complete function-level sample manifest          |
| `linevul_test.csv`    | **Direct input for LineVul**                     |
| `dataset_report.json` | Counts and preprocessing quality flags           |

For your Top-10 dataset with 2,740 pairs, the script should produce 5,480 function-level samples. It preserves all pairs and flags questionable ones rather than silently removing them.

You do not need `--export-c` for LineVul, because this model accepts source-code sequences directly. That option will be useful later for Joern and the GNNs.

## **3. Where to place your LineVul checkpoint**

The repository expects the checkpoint at:

```
VulPairBench/
└── models/
    └── LineVul/
        └── checkpoints/
            └── checkpoint-best-f1/
                └── 12heads_linevul_model.bin
```

This example uses the original LineVul checkpoint name. If yours has a different filename, specify it using `--model_name`.

## **4. Run your first LineVul evaluation**

From the repository root, with the LineVul environment activated:

```
python3 scripts/run_model.py \
  --model LineVul \
  --run-id pairvul_top10_test01 \
  -- \
  --do_test \
  --write_raw_preds \
  --model_type roberta \
  --model_name 12heads_linevul_model.bin \
  --model_name_or_path microsoft/codebert-base \
  --tokenizer_name microsoft/codebert-base \
  --test_data_file ../../../datasets/processed/pairvul_top10/linevul_test.csv \
  --block_size 512 \
  --eval_batch_size 16
```

The `../../../datasets/...` path is intentional: the launcher executes LineVul from `models/LineVul/linevul/`.

This command performs inference using the saved checkpoint. It does not request model training.

Before running the complete dataset, I recommend testing just 5–10 pairs to confirm that the tokenizer, checkpoint, and inference pipeline are compatible.

## **5. Where will LineVul save its predictions?**

The results will be stored automatically under:

```
VulPairBench/
└── Results/
    └── LineVul/
        └── pairvul_top10_test01/
            ├── run_metadata.json
            ├── raw_preds.csv
            └── test_precision_recall_12heads_linevul_model.bin.pdf
```

`raw_preds.csv` will contain the original code metadata, predicted labels, and vulnerability probabilities. The file names above reflect the updated LineVul implementation; the PDF and prediction file are generated after successful inference.

### **Convert predictions into the common benchmark format**

After successful inference, run:

```
python3 scripts/standardize_predictions.py \
  --model LineVul \
  --run-id pairvul_top10_test01 \
  --manifest datasets/processed/pairvul_top10/samples.csv \
  --raw Results/LineVul/pairvul_top10_test01/raw_preds.csv \
  --id-col sample_id \
  --pred-col pred_label \
  --score-col score_vulnerable
```

This generates:

`Results/LineVul/pairvul_top10_test01/predictions.csv`

Then evaluate vulnerable/patched discrimination:

```
python3 scripts/summarize_pairs.py \
  --predictions Results/LineVul/pairvul_top10_test01/predictions.csv \
  --out-dir Results/comparisons/pairvul_top10_test01/LineVul
```

It generates `summary.json` and `pair_outcomes.csv`, reporting pair accuracy, prediction changes, and the four categories: correctly distinguished, both vulnerable, both benign, and inverted.

## **6. One important check before the full evaluation**

Remember that `prepare_pairvul.py` prepares **all pairs in the input JSON**. It does not automatically select the authors' official 586-pair PairVul test partition.

Since you have verified the original dataset, make sure you use the intended held-out subset when conducting the final publication evaluation. Also check for overlap with the training data used by your LineVul checkpoint.

I would start with a small smoke test, then validate the checkpoint and data split before running the full evaluation.

**One thing I would like you to confirm next:** Do you already have the pretrained LineVul checkpoint `12heads_linevul_model.bin` inside your repository, or do you need to retrieve it from the original implementation?


@Linevul first analysis
Your first LineVul results are interesting, but I would be careful about interpreting them as evidence that the model cannot understand security patches until we verify the preprocessing and inference pipeline.

## **1. What the results tell us**

Pair accuracy

# **0.22%**

Prediction-change rate

# **0.22%**

Pair coverage

# **100%**

LineVul prediction outcomes

2,740 vulnerable–patched pairs

07501.5K2.2K3KBoth benignBoth vulnerableCorrect pairInverted

The striking result is not simply the low pair accuracy. It is that **LineVul classifies 99.1% of the pairs as benign in both versions**.

This could be a genuine generalization problem, but it could also result from an incorrect checkpoint, preprocessing mismatch, score interpretation, threshold, or data-format issue.

Also, 100% pair coverage means predictions were produced for all pairs. It does not guarantee that every input was fully represented or that the predictions are valid.

## **2. Should we remove comments before testing?**

**Not automatically. My recommendation is to preserve the original code for the primary evaluation and investigate comment removal as a separate preprocessing experiment.**

There are three reasons:

1. LineVul is a pretrained code model. Changing the input preprocessing without checking how it was trained can create a train–test mismatch.
2. Comments sometimes contain security-relevant information, while removing them might change token positions or which code fits within the 512-token limit.
3. For GNNs, Joern generally handles comments through parsing. The important comparison is between the actual graph inputs, not necessarily identical source-text transformations across every architecture.

We should distinguish **comments**, **formatting differences**, and **non-functional modifications**. These are not the same thing.

In particular, I would not remove `#ifdef`, `#define`, or other C preprocessor directives as cosmetic text. They can change program behavior.

## **3. What I found in your repository code**

I inspected the `prepare_pairvul.py` and LineVul inference implementation from the repository ZIP we prepared.

The preparation script currently does this:

```
'processed_func': code,'target': label
```

It preserves the original source code, including comments and formatting.

LineVul then performs:

```
code_tokens = tokenizer.tokenize(str(func))[:args.block_size-2]
```

With your `block_size=512`, LineVul sees at most **510 source-code tokens**, plus special tokens.

The original LineVul documentation also identifies `processed_func` as its source-code input field; it does not establish that every incoming function must have comments removed first.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://github.com\&sz=32)

GitHub



This raises an important question: **Are some of the security patches located beyond the 510-token boundary, making them invisible to LineVul?**

If both code versions produce identical truncated token sequences, LineVul receives identical inputs and cannot distinguish them.

### **Run this diagnostic first**

You can run the following script from the VulPairBench repository root, using the LineVul virtual environment:

```
import pandas as pdfrom transformers import AutoTokenizerpath = "datasets/processed/pairvul_top10/linevul_test.csv"df = pd.read_csv(path)tokenizer = AutoTokenizer.from_pretrained(    "microsoft/codebert-base")records = []for pair_id, group in df.groupby("pair_id"):    if set(group["version"]) != {"before", "after"}:        continue    before = group.loc[        group["version"] == "before", "processed_func"    ].iloc[0]    after = group.loc[        group["version"] == "after", "processed_func"    ].iloc[0]    before_ids = tokenizer.encode(        before, add_special_tokens=False    )    after_ids = tokenizer.encode(        after, add_special_tokens=False    )    records.append({        "pair_id": pair_id,        "before_tokens": len(before_ids),        "after_tokens": len(after_ids),        "before_truncated": len(before_ids) > 510,        "after_truncated": len(after_ids) > 510,        "identical_model_input":            before_ids[:510] == after_ids[:510]    })audit = pd.DataFrame(records)print("Total pairs:", len(audit))print("Before truncated:", audit.before_truncated.sum())print("After truncated:", audit.after_truncated.sum())print(    "Identical inputs after truncation:",    audit.identical_model_input.sum())print("\nPercentages:")print(    audit[        ["before_truncated",         "after_truncated",         "identical_model_input"]    ].mean().mul(100).round(2))
```

This will establish how much of your first result could be affected by input truncation.

## **4. Before modifying preprocessing, verify the checkpoint**

I also noticed that the version of LineVul we packaged loads model weights with:

```
model.load_state_dict(    torch.load(output_dir, map_location=args.device),    strict=False)
```

Using `strict=False` can silently tolerate missing or unexpected checkpoint parameters. It does not necessarily mean anything went wrong, but with such extreme results, you should verify that the full intended model was loaded.

I would perform three checks, in this order:

1. **Original benchmark smoke test:** Run the same checkpoint on a small portion of LineVul's original test dataset. Confirm that it produces both vulnerable and benign predictions and reproduces plausible published behavior.
2. **Checkpoint integrity:** Print missing and unexpected parameter keys during loading. Ideally, confirm that the expected classifier weights have been restored.
3. **Score distribution:** Examine `score_vulnerable` separately for before and after versions, rather than relying only on predicted labels.

For the last check:

```
import pandas as pdp = pd.read_csv(    "Results/LineVul/pairvul_top10_test01/predictions.csv")print(    p.groupby("version")["score_vulnerable"]    .describe(percentiles=[0.1, 0.25, 0.5, 0.75, 0.9]))
```

If the original benchmark behaves as expected but PairVul produces almost exclusively benign predictions, you would have much stronger evidence of a real out-of-distribution or patch-discrimination problem.

## **5. Should we update&#x20;**`prepare_pairvul.py`**?**

Yes, but **I would update it to support preprocessing variants, not to remove comments by default.**

I suggest the following design:

| Variant                             | Description                                                                 | Purpose                                                             |
| ----------------------------------- | --------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| `raw`                               | Original code, unchanged                                                    | Primary baseline                                                    |
| `comments_removed`                  | Remove comments using a C/C++-aware parser while preserving executable code | Sensitivity experiment                                              |
| `comments_removed_truncation_audit` | Same cleaning, with token-visibility measurements                           | Investigate whether comments conceal patches beyond the token limit |

Keep all original source files and metadata. Avoid simple regular-expression removal because comment delimiters can also occur inside string literals. Preserve preprocessor directives and keep line mappings for subsequent security analysis.

I would not remove non-cosmetic modifications: those are precisely the potentially security-relevant changes you want to study. For cosmetic-only changes, flag affected pairs for review rather than modifying the code to force a difference.

For the final paper, we can report raw-input results and comment-removal sensitivity results separately. We should not select whichever variant performs best on the final test set, because that would turn the benchmark into a tuning set.

## **6. What this could contribute to the TOSEM paper**

You now have several distinct hypotheses worth investigating:

- **H1:** The sequence-based model frequently predicts both versions as benign.
- **H2:** Some failures are caused by security-relevant modifications being truncated from the model input.
- **H3:** Comments and other non-executable information influence prediction stability.
- **H4:** Even when relevant patches are visible, the model may not distinguish the underlying vulnerability mechanism.

These are experimentally testable. We should not assume all four are true.

The most valuable comparison will eventually be to determine whether GNNs, using their actual Joern-derived input graphs, retain security-relevant changes that LineVul loses through truncation—and whether retaining those changes actually improves predictions.

**My recommendation for your next action:** Run the token-visibility audit above, then verify the checkpoint on LineVul's original test data. I would not rerun all 2,740 pairs with comments removed until those checks are complete. The current result is worth preserving as `raw` experiment 01, not replacing.

That way, we build a defensible empirical study rather than merely collecting poor model scores.



Observation on the Linevul
These results are important for your empirical study. They show that **LineVul cannot distinguish a substantial proportion of your vulnerable/patched pairs because its input representation is identical for both versions**.

However, they also show something more concerning: **truncation alone cannot explain the extremely low pair accuracy**.

## **1. Interpretation of your tokenization audit**

Before versions truncated

# **47.70%**

1,307 of 2,740

After versions truncated

# **48.69%**

1,334 of 2,740

Identical model inputs

# **17.01%**

466 pairs

Distinguishable token sequences

# **2,274**

82.99% of pairs

The key finding is that LineVul receives identical token sequences for 466 vulnerable/patched pairs after applying the 510-token limit.

For a deterministic model evaluated independently under identical settings, these pairs must receive the same prediction. Therefore, their pair accuracy is necessarily zero.

This also means that, under the current input configuration, the theoretical maximum pair accuracy is **82.99%**.

But your measured pair accuracy is only **0.22% (6 out of 2,740)**. Even among the 2,274 pairs with different token sequences, only 6 were classified correctly in both versions—approximately **0.26%**.

That suggests we need to investigate both:

1. **Input representation limitations:** Important changes may be discarded through truncation.
2. **Prediction behavior:** LineVul overwhelmingly predicts benign even when the two inputs differ.

The second problem may involve domain shift, the checkpoint, classification threshold, or another inference issue. We cannot attribute it entirely to model weakness yet.

## **2. What the warning messages mean**

The two warnings do not explain the poor predictions by themselves.

- `resume_download`**&#x20;FutureWarning:** A Hugging Face dependency warning. It does not affect your experiment.
- `790 > 512`**&#x20;warning:** Your diagnostic tokenizer encountered a function longer than the configured limit. The LineVul code we packaged truncates the tokens to 510 before passing them to the model, so this warning does not necessarily indicate an inference error.

I checked the LineVul implementation in our repository: the normal CodeBERT preprocessing uses `tokenizer.tokenize()` followed by truncation to `block_size - 2`. Your diagnostic using `tokenizer.encode(..., add_special_tokens=False)` is close to that behavior, but I would use the exact original tokenization method for the final audit.

## **3. Next experiment: explain the 466 identical pairs**

Before changing the code, we need to distinguish two situations:

- **Original token sequences are identical:** The difference may involve whitespace, formatting or other text that the tokenizer does not distinguish.
- **Original token sequences differ, but the first 510 tokens are identical:** The difference is invisible because of truncation.

Run the following code from your repository root. It uses the original LineVul tokenization procedure.

```
import pandas as pdfrom transformers import AutoTokenizerdata_path = "datasets/processed/pairvul_top10/linevul_test.csv"df = pd.read_csv(data_path)tokenizer = AutoTokenizer.from_pretrained("microsoft/codebert-base")records = []for pair_id, group in df.groupby("pair_id"):    b = group.loc[group.version == "before", "processed_func"].iloc[0]    a = group.loc[group.version == "after", "processed_func"].iloc[0]    bt = tokenizer.tokenize(str(b))    at = tokenizer.tokenize(str(a))    same_full = bt == at    same_visible = bt[:510] == at[:510]    if same_full:        reason = "identical_full_tokens"    elif same_visible:        reason = "difference_lost_by_truncation"    else:        reason = "different_visible_tokens"    records.append({        "pair_id": pair_id,        "before_tokens": len(bt),        "after_tokens": len(at),        "before_truncated": len(bt) > 510,        "after_truncated": len(at) > 510,        "same_full_tokens": same_full,        "same_visible_tokens": same_visible,
```

This establishes how many pairs have differences that are entirely beyond the token limit.

One limitation remains: even if the visible token sequences differ, the difference might be a comment or unrelated modification rather than the actual security fix. We will eventually need patch-line visibility analysis to establish that connection.

## **4. Connect token visibility to LineVul's predictions**

Now analyze whether the successful and failed predictions are associated with token visibility.

This reads your standardized predictions directly.

```
wide.columns = [    f"{field}_{version}"    for field, version in wide.columns]results = audit.merge(    wide.reset_index(),    on="pair_id",    validate="one_to_one")results["score_delta"] = (    results["score_vulnerable_before"] -    results["score_vulnerable_after"])def classify(row):    b, a = int(row.pred_label_before), int(row.pred_label_after)    return {        (1, 0): "correct_pair",        (1, 1): "both_vulnerable",        (0, 0): "both_benign",        (0, 1): "inverted"    }[(b, a)]results["outcome"] = results.apply(classify, axis=1)print("Prediction outcomes by input visibility:")print(pd.crosstab(    results["reason"],    results["outcome"],    margins=True))print("\nScore differences by input visibility:")print(    results.groupby("reason")["score_delta"]    .agg(["count", "mean", "median", "std"]))print("\nScore distribution by code version:")print(    pred.groupby("version")["score_vulnerable"]    .describe())# Confirm the predicted labels match a 0.5 threshold.expected = (pred["score_vulnerable"] >= 0.5).astype(int)print("\nLabel/score mismatches:",      (expected != pred["pred_label"]).sum())results.to_csv(    "Results/LineVul/pairvul_top10_test01/"    "prediction_visibility_analysis.csv",    index=False)
```

This will tell us whether LineVul is insensitive even when the input changes and whether the probability scores contain information that binary predictions hide.

## **5. What should happen before another full evaluation?**

I would follow this order:

1. **Complete the input-visibility analysis above.** We need to understand the 466 identical inputs before changing the dataset.
2. **Verify the checkpoint on LineVul's original test dataset.** Check that its expected classifier weights loaded correctly and that it produces plausible positive and negative predictions.
3. **Investigate the score distributions.** Check whether the model is genuinely assigning very low vulnerability probabilities or whether labels and probabilities are incorrectly mapped.
4. **Preserve the current experiment as the raw baseline.** Do not overwrite `pairvul_top10_test01`.
5. **Only then test comment removal as a separate sensitivity experiment**, ideally alongside a patch-visibility analysis.

For the eventual paper, I would report both overall pair accuracy and accuracy among pairs with distinguishable model inputs. The latter is useful diagnostically, but the former must not silently exclude difficult cases.

There is also an important distinction: your current file contains 2,740 pairs from the Top-10 CWE collection, not necessarily the paper's official held-out 586-pair evaluation split. Before claiming generalization results, we still need to verify training overlap and the intended evaluation partition.

## **6. Why these results may become important for the GNN comparison**

When we evaluate VVulDet and SCVdet, we can investigate whether their Joern-derived graphs preserve the changes that LineVul's 510-token input window loses.

For example, if LineVul receives identical inputs for a pair but Joern captures a changed security-sensitive condition and the GNN correctly distinguishes the versions, that would make a compelling case study.

Conversely, a GNN might preserve the condition in its graph and still fail to classify the patch correctly. That would motivate investigating learned representations, security evidence and vulnerability-domain knowledge.

**The next result I particularly want to see is the distribution across&#x20;**`identical_full_tokens`**,&#x20;**`difference_lost_by_truncation`**, and&#x20;**`different_visible_tokens`**, together with the score-distribution and label/score consistency checks.** Those will help us decide whether to investigate preprocessing, the checkpoint, or the model's actual sensitivity to security-relevant changes first.