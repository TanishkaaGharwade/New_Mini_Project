# CyberSentinel — Training Log

This is the chronological record of every training, retraining and test run for the detection model. It exists so that results can be verified later. Entries are never edited after the fact; new work is added as a new entry at the end.

**How to read it**

- Each entry has a date, what was run, the exact numbers, and the decision taken.
- **Precision (P):** of the flows the model labelled as a class, the share that really were that class.
- **Recall (R):** of the flows that really were a class, the share the model caught.
- **Macro F1:** the average F1 score across all classes, so a rare class counts as much as a common one.
- All scores are on a held-out test set the model never saw during training, unless an entry says otherwise.

**How to verify any number here:** follow `DATASET.md` to get the data, then run `train_cicids2017.ipynb` top to bottom. The random seed is fixed at 42, so the same split and the same model are produced.

---

## Summary of results

| Entry | Date | What | Headline result |
|---|---|---|---|
| 1 | 2026-10-08 | Diagnosis of the old (downloaded) model | Flags benign traffic as attacks; misses a clean port scan |
| 2 | 2026-10-12 | Dataset audit | 2,830,743 flows, 15 labels, 8 files |
| 3 | 2026-10-12 | Data-quality findings | Flag-count columns unusable; lengths are payload bytes |
| 4 | 2026-10-12 | Exploratory run: feature groups | Core features chosen; macro F1 0.9475 |
| 5 | 2026-10-12 | Exploratory run: class imbalance | No weighting chosen |
| 6 | 2026-10-12 | Final training of `model_v1` | Accuracy 0.9956, macro F1 0.9472 on 184,679 test flows |
| 7 | 2026-10-12 | Reproducibility rerun | Identical scores and byte-identical model file |
| 8 | 2026-10-12 | Verification on 1,553,034 unseen benign flows | 0.247% false alarms; 0.102% at blocking threshold 0.90 |
| 9 | 2026-10-12 | Test on excluded attack types | Not detected, as expected (0% to 4.8%) |
| 10 | 2026-10-12 | Load check in a second environment | Loads correctly |
| 11 | 2026-10-13 | Synthetic test of the new engine (Part A) | Benign traffic stays benign; attacks are caught by rules only, and the model misses port scans because of a dataset artifact |
| 12 | 2026-10-13 | Length-convention fix in the engine, plus a blocking safeguard | Model detects 300 of 300 scan probes (was 0); no retraining needed |

---

## Entry 1 — Diagnosis of the previous model (baseline)

**Date:** 2026-10-08
**What:** the model shipped with the original project (`model.pkl` + `preprocessor.pkl`, taken from another repository) was tested offline by replaying synthetic traffic through the project's own feature-extraction code.
**Important:** this was synthetic traffic built to imitate normal HTTPS downloads, not a labelled test set. It shows a failure, not an accuracy figure.

Model facts read from the files:

| Property | Value |
|---|---|
| Algorithm | Random Forest, 100 trees |
| Preprocessing | One-hot encoding + scaling, then PCA down to 10 components |
| Classes | 20 labels ending in dots (`satan.`, `neptune.`, `normal.`, ...) |
| Likely training data | KDD Cup 99, not NSL-KDD (dot-suffixed labels; `count` feature mean 333) |
| Training code or metrics available | None |

Replay of 20 benign HTTPS flows (30 packets each), using the engine as written:

| Flow | `dst_host_diff_srv_rate` | Per-packet predictions |
|---|---|---|
| 1 | 0.0 | 30 normal |
| 2 | 2.0 | 16 satan, 2 portsweep, 12 normal |
| 4 | 6.0 | 30 satan |
| 6 | 4.0 | 30 satan |
| 7 | 12.0 | 30 satan |
| 10 | 3.0 | 30 portsweep |

| Test | Result |
|---|---|
| 600 benign packets, engine as written | 78 normal, 376 satan, 146 portsweep |
| 20 benign flows, engine's verdict per flow | 2 normal, 13 satan, 5 portsweep |
| Same 600 packets, state reset per flow | 600 normal |
| Simulated SYN port scan (40 packets), clean state | 40 normal (attack missed) |
| Same scan, single-vector confidence | normal 0.36, ipsweep 0.20, satan 0.17 |

**Finding:** features that should be rates between 0 and 1 grew without limit because the extractor's counters were global and never reset. The training mean for `dst_host_diff_srv_rate` was 0.03 (standard deviation 0.11), so values of 2 to 12 looked like an extreme scanner.

**Decision:** replace both the feature extractor and the model. Train our own model on CICIDS2017.

---

## Entry 2 — Dataset audit

**Date:** 2026-10-12
**What:** every row of the downloaded CICIDS2017 CSV files was counted by file and by label.

| File | Rows | Labels |
|---|---|---|
| Monday-WorkingHours | 529,918 | BENIGN 529,918 |
| Tuesday-WorkingHours | 445,909 | BENIGN 432,074; FTP-Patator 7,938; SSH-Patator 5,897 |
| Wednesday-workingHours | 692,703 | BENIGN 440,031; DoS Hulk 231,073; DoS GoldenEye 10,293; DoS slowloris 5,796; DoS Slowhttptest 5,499; Heartbleed 11 |
| Thursday-Morning-WebAttacks | 170,366 | BENIGN 168,186; Web Attack Brute Force 1,507; Web Attack XSS 652; Web Attack Sql Injection 21 |
| Thursday-Afternoon-Infilteration | 288,602 | BENIGN 288,566; Infiltration 36 |
| Friday-Morning | 191,033 | BENIGN 189,067; Bot 1,966 |
| Friday-Afternoon-PortScan | 286,467 | BENIGN 127,537; PortScan 158,930 |
| Friday-Afternoon-DDos | 225,745 | BENIGN 97,718; DDoS 128,027 |
| **Total** | **2,830,743** | |

Totals by original label:

| Label | Rows | Share |
|---|---|---|
| BENIGN | 2,273,097 | 80.30% |
| DoS Hulk | 231,073 | 8.16% |
| PortScan | 158,930 | 5.61% |
| DDoS | 128,027 | 4.52% |
| DoS GoldenEye | 10,293 | 0.36% |
| FTP-Patator | 7,938 | 0.28% |
| SSH-Patator | 5,897 | 0.21% |
| DoS slowloris | 5,796 | 0.20% |
| DoS Slowhttptest | 5,499 | 0.19% |
| Bot | 1,966 | 0.07% |
| Web Attack Brute Force | 1,507 | 0.05% |
| Web Attack XSS | 652 | 0.02% |
| Infiltration | 36 | 0.001% |
| Web Attack Sql Injection | 21 | 0.001% |
| Heartbleed | 11 | 0.0004% |

- All 8 files have the same 79 columns (78 features + `Label`).
- Column names have leading spaces; `Fwd Header Length` appears twice (second copy named `Fwd Header Length.1`).

---

## Entry 3 — Data-quality findings

**Date:** 2026-10-12
**What:** the PortScan file (286,467 rows) was inspected to learn how the dataset encodes its features, because the live engine must compute them the same way.

| Check | Result |
|---|---|
| Rows with `Infinity` in `Flow Bytes/s` or `Flow Packets/s` | 371 |
| Rows with `NaN` in those columns | 15 |
| Rows with `Flow Duration` of zero or less | 407 (36 negative) |
| Maximum `Flow Duration` | 119,999,949, so the unit is microseconds and flows are cut at 120 s |
| Exact duplicate rows among PortScan flows | 68,111 of 158,930 (42.9%) |
| `Init_Win_bytes_forward` equal to -1 (no value) | 21.0% of rows |
| `Init_Win_bytes_backward` equal to -1 | 26.9% of rows |
| PortScan flows with forward payload of 6 bytes or less | 99.6% |

TCP flag-count columns, all 286,467 rows:

| Column | Maximum value | Rows equal to 1 |
|---|---|---|
| FIN Flag Count | 1 | 2,490 |
| SYN Flag Count | 1 | 6,014 |
| RST Flag Count | 1 | 21 |
| PSH Flag Count | 1 | 189,267 |
| ACK Flag Count | 1 | 35,555 |

**Findings**

- **Flag counts are unusable.** They are never above 1, and `SYN Flag Count` is 0 for port-scan flows that are made of SYN packets. A live engine counting real flags would produce values the model never saw.
- **Length features are payload bytes**, not full packet sizes. A SYN-only flow has length 0.
- **Duplicates are heavy** in the attack classes, so they must be removed before splitting, or identical rows land in both train and test and inflate the scores.

**Decision:** treat flag counts as a separate candidate group and test whether they are needed (entry 4). Remove exact duplicates before the split.

---

## Entry 4 — Exploratory run: feature groups

**Date:** 2026-10-12
**What:** a first pass to choose the feature set, run as a standalone script before the notebook was written. The notebook repeats this experiment in its section 4.1, and those repeated numbers are recorded in entry 6.

Setup:

| Setting | Value |
|---|---|
| Cleaning | Excluded labels dropped; `Infinity`/`NaN`/negative-duration rows dropped; exact duplicates dropped |
| Rows | 2,830,743 raw → 2,828,516 in kept classes → 2,825,534 finite → 2,476,428 after duplicates removed |
| Classes after cleaning | Benign 2,053,034; DoS 193,593; DDoS 128,011; PortScan 90,694; BruteForce 9,148; Botnet 1,948 |
| Sampling | Benign downsampled to 500,000; all attack rows kept |
| Split | 80/20 stratified, seed 42: 738,715 train, 184,679 test |
| Model | Random Forest, 60 trees, max depth 20, min samples per leaf 2, no class weighting |

Candidate feature groups:

| Group | Features |
|---|---|
| Core (19) | Flow Duration, Total Fwd Packets, Total Backward Packets, Total Length of Fwd Packets, Total Length of Bwd Packets, Fwd Packet Length Max, Fwd Packet Length Mean, Bwd Packet Length Max, Bwd Packet Length Mean, Packet Length Mean, Packet Length Std, Flow Bytes/s, Flow Packets/s, Flow IAT Mean, Flow IAT Std, Flow IAT Max, Fwd IAT Mean, Bwd IAT Mean, Down/Up Ratio |
| Flags (5) | SYN, FIN, RST, PSH, ACK Flag Count |
| Window (2) | Init_Win_bytes_forward, Init_Win_bytes_backward |
| Port (1) | Destination Port |

Results on the test set (P = precision, R = recall):

| Feature set | Macro F1 | Benign P / R | Botnet P / R | BruteForce P / R | DDoS P / R | DoS P / R | PortScan P / R |
|---|---|---|---|---|---|---|---|
| Core | 0.9475 | 0.995 / 0.998 | 0.879 / 0.599 | 0.999 / 0.972 | 0.999 / 0.999 | 0.996 / 0.992 | 0.997 / 0.999 |
| Core + flags | 0.9476 | 0.995 / 0.998 | 0.882 / 0.596 | 0.999 / 0.972 | 0.999 / 0.999 | 0.997 / 0.992 | 0.997 / 0.999 |
| Core + window | 0.9827 | 0.998 / 0.999 | 0.903 / 0.910 | 0.999 / 0.993 | 1.000 / 0.999 | 0.999 / 0.997 | 0.997 / 0.999 |
| Core + port | 0.9583 | 0.997 / 0.998 | 0.852 / 0.694 | 0.993 / 0.996 | 1.000 / 0.999 | 0.997 / 0.995 | 0.997 / 0.999 |
| Core + window + port | 0.9856 | 0.999 / 0.999 | 0.916 / 0.920 | 1.000 / 0.999 | 1.000 / 0.999 | 0.999 / 0.999 | 0.997 / 0.999 |
| All candidates | 0.9848 | 0.999 / 0.999 | 0.917 / 0.910 | 1.000 / 0.999 | 1.000 / 1.000 | 0.999 / 0.999 | 0.997 / 0.999 |

Most common `Init_Win_bytes_forward` values per class (share of that class's flows):

| Class | Top three values |
|---|---|
| Benign | -1 (42.3%), 8192 (12.8%), 29200 (9.7%) |
| Botnet | 8192 (62.9%), 237 (32.6%), 1255 (0.8%) |
| BruteForce | 29200 (76.0%), 229 (21.5%), 259 (2.3%) |
| DDoS | 256 (54.5%), 8192 (45.3%), 29200 (0.1%) |
| DoS | 0 (30.4%), 251 (29.1%), 274 (21.8%) |
| PortScan | 29200 (50.3%), 1024 (49.6%), 251 (0.1%) |

Feature importance, core set:

| Feature | Importance |
|---|---|
| Packet Length Std | 0.115 |
| Bwd Packet Length Mean | 0.103 |
| Total Length of Fwd Packets | 0.097 |
| Bwd Packet Length Max | 0.094 |
| Fwd Packet Length Max | 0.088 |
| Total Length of Bwd Packets | 0.073 |
| Packet Length Mean | 0.073 |
| Fwd Packet Length Mean | 0.062 |
| Flow Packets/s | 0.046 |
| Total Fwd Packets | 0.043 |
| Flow IAT Std | 0.042 |
| Flow Duration | 0.034 |
| Flow IAT Max | 0.032 |
| Flow IAT Mean | 0.028 |
| Fwd IAT Mean | 0.025 |
| Flow Bytes/s | 0.020 |
| Total Backward Packets | 0.018 |
| Bwd IAT Mean | 0.004 |
| Down/Up Ratio | 0.002 |

When all candidates were available, importance share was: window 0.059, port 0.043, flags 0.042.

**Findings**

- **Flags add nothing:** macro F1 0.9475 without them, 0.9476 with them.
- **Window sizes add the most:** macro F1 +0.035, almost all from Botnet recall (0.599 → 0.910). But each attack class has two or three signature values, which belong to the lab's attacker machines and tools. On another network those values would differ.
- **Port adds a little:** macro F1 +0.011, mainly BruteForce recall (0.972 → 0.996), by learning the service ports.

**Decision:** use the 19 core features only. The scores are lower than they could be, but they rest on behaviour the live engine can measure, not on properties of the lab. The cost is a weak Botnet class (recall about 0.60), which is reported as a limitation.

---

## Entry 5 — Exploratory run: class imbalance

**Date:** 2026-10-12
**What:** same data, split and model settings as entry 4, core features, comparing ways of handling the rare classes.

| Method | Macro F1 | Benign P / R | Botnet P / R | BruteForce P / R | DDoS P / R | DoS P / R | PortScan P / R |
|---|---|---|---|---|---|---|---|
| No weighting | 0.9475 | 0.995 / 0.998 | 0.879 / 0.599 | 0.999 / 0.972 | 0.999 / 0.999 | 0.996 / 0.992 | 0.997 / 0.999 |
| `class_weight="balanced"` | 0.8565 | 0.997 / 0.969 | 0.125 / 0.967 | 0.918 / 0.974 | 0.999 / 0.999 | 0.993 / 0.994 | 0.997 / 0.999 |
| `class_weight="balanced_subsample"` | 0.8565 | 0.997 / 0.969 | 0.126 / 0.972 | 0.912 / 0.974 | 0.999 / 0.999 | 0.994 / 0.993 | 0.996 / 0.999 |
| Oversample rare classes to 30,000 | 0.8861 | 0.996 / 0.986 | 0.219 / 0.871 | 0.997 / 0.974 | 0.999 / 0.999 | 0.996 / 0.992 | 0.997 / 0.999 |

**Findings**

- Weighting raises Botnet recall from 0.599 to about 0.97, but Botnet precision falls from 0.879 to 0.125. Seven of every eight "Botnet" alerts would be benign traffic.
- Benign recall drops from 0.998 to 0.969, which means about 3% of normal flows flagged as attacks instead of 0.2%.

**Decision:** no weighting. For a system that can block IPs automatically, false alarms are the more expensive mistake.

---

## Entry 6 — Final training of `model_v1`

**Date:** 2026-10-12
**What:** `train_cicids2017.ipynb` run top to bottom. It repeats the experiments of entries 4 and 5, then trains and saves the final model.

Settings:

| Setting | Value |
|---|---|
| Algorithm | Random Forest inside one scikit-learn pipeline (median imputer, then forest) |
| Trees | 100 |
| Maximum depth | 20 |
| Minimum samples per leaf | 2 |
| Class weighting | None |
| Features | 19 (the core set, listed in `features.json`) |
| Seed | 42 |
| Environment | Python 3.10.18, scikit-learn 1.7.2, pandas 2.3.3, numpy 2.2.6, joblib 1.3.2 |
| Machine | Intel Core Ultra 5 125H (14 cores, 18 threads), 16 GB RAM, CPU only |

Data at each step:

| Step | Rows |
|---|---|
| Raw | 2,830,743 |
| After dropping excluded labels | 2,828,516 |
| After removing Infinity/NaN/negative duration | 2,825,534 |
| After removing exact duplicates | 2,476,428 |
| After downsampling Benign to 500,000 | 923,394 |

Train and test split:

| Class | Train | Test |
|---|---|---|
| Benign | 400,000 | 100,000 |
| Botnet | 1,559 | 389 |
| BruteForce | 7,318 | 1,830 |
| DDoS | 102,409 | 25,602 |
| DoS | 154,874 | 38,719 |
| PortScan | 72,555 | 18,139 |
| **Total** | **738,715** | **184,679** |

Experiments repeated inside the notebook (60 trees). These match entries 4 and 5:

| Experiment | Features | Macro F1 | Botnet P | Botnet R | BruteForce R | Benign R |
|---|---|---|---|---|---|---|
| Core | 19 | 0.9475 | 0.8792 | 0.5990 | 0.9721 | 0.9976 |
| Core + flags | 24 | 0.9476 | 0.8821 | 0.5964 | 0.9721 | 0.9979 |
| Core + window | 21 | 0.9827 | 0.9031 | 0.9100 | 0.9929 | 0.9987 |
| Core + port | 20 | 0.9583 | 0.8517 | 0.6941 | 0.9962 | 0.9977 |
| Core + window + port | 22 | 0.9856 | 0.9156 | 0.9203 | 0.9995 | 0.9989 |
| All candidates | 27 | 0.9848 | 0.9171 | 0.9100 | 0.9995 | 0.9989 |
| Core, no weighting | 19 | 0.9475 | 0.8792 | 0.5990 | 0.9721 | 0.9976 |
| Core, `balanced` | 19 | 0.8565 | 0.1247 | 0.9666 | 0.9738 | 0.9689 |
| Core, `balanced_subsample` | 19 | 0.8565 | 0.1265 | 0.9717 | 0.9743 | 0.9692 |
| Core, oversample to 30,000 | 19 | 0.8861 | 0.2187 | 0.8715 | 0.9743 | 0.9858 |

### Final model results (100 trees) on the 184,679 test flows

| Metric | Value |
|---|---|
| Accuracy | 0.9956 |
| Macro F1 | 0.9472 |
| Training time | 33 seconds |
| Model file size | 7.8 MB |

| Class | Precision | Recall | F1 | Test flows |
|---|---|---|---|---|
| Benign | 0.9945 | 0.9976 | 0.9961 | 100,000 |
| Botnet | 0.8788 | 0.5964 | 0.7106 | 389 |
| BruteForce | 0.9989 | 0.9721 | 0.9853 | 1,830 |
| DDoS | 0.9994 | 0.9988 | 0.9991 | 25,602 |
| DoS | 0.9962 | 0.9920 | 0.9941 | 38,719 |
| PortScan | 0.9966 | 0.9989 | 0.9978 | 18,139 |

Confusion matrix (rows are the true class, columns the predicted class):

| | Benign | Botnet | BruteForce | DDoS | DoS | PortScan |
|---|---|---|---|---|---|---|
| **Benign** | 99,762 | 32 | 2 | 14 | 131 | 59 |
| **Botnet** | 157 | 232 | 0 | 0 | 0 | 0 |
| **BruteForce** | 51 | 0 | 1,779 | 0 | 0 | 0 |
| **DDoS** | 29 | 0 | 0 | 25,572 | 1 | 0 |
| **DoS** | 304 | 0 | 0 | 2 | 38,411 | 2 |
| **PortScan** | 7 | 0 | 0 | 0 | 13 | 18,119 |

- Correct predictions: 183,875 of 184,679.
- Errors: 804. Of these, 548 are attacks called Benign (missed), 238 are Benign called an attack (false alarms), and 18 are one attack type called another.

Effect of the confidence threshold on automatic blocking (test set):

| Threshold | Attack flows blocked | Benign flows blocked by mistake | Benign mistakes per 100,000 flows |
|---|---|---|---|
| 0.50 | 99.35% | 0.236% | 236 |
| 0.70 | 99.14% | 0.150% | 150 |
| 0.80 | 98.95% | 0.111% | 111 |
| 0.90 | 98.66% | 0.083% | 83 |
| 0.95 | 98.29% | 0.068% | 68 |
| 0.99 | 94.82% | 0.046% | 46 |

Feature importance of the final model:

| Feature | Importance |
|---|---|
| Packet Length Std | 0.1074 |
| Bwd Packet Length Mean | 0.0992 |
| Total Length of Fwd Packets | 0.0987 |
| Packet Length Mean | 0.0916 |
| Bwd Packet Length Max | 0.0852 |
| Fwd Packet Length Max | 0.0848 |
| Total Length of Bwd Packets | 0.0738 |
| Fwd Packet Length Mean | 0.0676 |
| Total Fwd Packets | 0.0449 |
| Flow Packets/s | 0.0396 |
| Flow IAT Std | 0.0395 |
| Flow IAT Max | 0.0363 |
| Flow Duration | 0.0283 |
| Flow IAT Mean | 0.0270 |
| Fwd IAT Mean | 0.0268 |
| Flow Bytes/s | 0.0222 |
| Total Backward Packets | 0.0190 |
| Bwd IAT Mean | 0.0050 |
| Down/Up Ratio | 0.0031 |

**Findings**

- Four attack classes (DDoS, DoS, PortScan, BruteForce) have recall of 0.97 or higher with precision above 0.99.
- **Botnet is weak:** 232 of 389 caught (recall 0.596). The 157 missed were all called Benign.
- Raising the blocking threshold from 0.50 to 0.90 cuts benign mistakes from 236 to 83 per 100,000 flows while still blocking 98.66% of attack flows. This supports the planned threshold of 0.90.
- Going from 60 to 100 trees did not change the scores meaningfully (macro F1 0.9475 → 0.9472).

**Output files:** `python-engine/models/model_v1.pkl`, `model_v1.meta.json`, `training/features.json`, `reports/model_v1.md`, `reports/model_v1_confusion_matrix.png`.

---

## Entry 7 — Reproducibility rerun

**Date:** 2026-10-12
**What:** the saved model was deleted and the whole notebook was run a second time from the raw CSV files. Only the report's number formatting was changed between the two runs.

| Check | Run 1 | Run 2 |
|---|---|---|
| Accuracy | 0.9956 | 0.9956 |
| Macro F1 | 0.9472 | 0.9472 |
| Per-class precision and recall | as entry 6 | identical |
| Notebook run time, start to finish | 4 min 46 s | about 5 min |

Model file SHA-256, both runs:

```
009ba6d0bea749a9cc1a896fd0538dbad47e48ec974ee32eae79b5d7ab2809c7
```

**Finding:** the two model files are byte-for-byte identical. Anyone with the same data, package versions and seed should get this same checksum, which is a simple way to prove a model file is the one described here.

---

## Entry 8 — Verification on unseen benign traffic

**Date:** 2026-10-12
**What:** `verify_model.py` ran the saved model on every cleaned benign flow that was **not** used for training or testing. This is a much larger sample than the test set and measures the false-alarm rate.

| Measure | Value |
|---|---|
| Unseen benign flows | 1,553,034 |
| Flagged as any attack | 3,833 (0.247%) |
| Called DoS | 2,076 |
| Called PortScan | 941 |
| Called Botnet | 525 |
| Called DDoS | 265 |
| Called BruteForce | 26 |

False alarms that would also be blocked automatically, by threshold:

| Threshold | Benign flows blocked | Share |
|---|---|---|
| 0.70 | 2,498 | 0.161% |
| 0.90 | 1,587 | 0.102% |
| 0.95 | 1,381 | 0.089% |
| 0.99 | 724 | 0.047% |

**Findings**

- The false-alarm rate on 1.55 million unseen flows (0.247%) agrees with the test set (0.236%), so the test-set figure was not a lucky sample.
- 0.102% at the 0.90 threshold is about 1 benign flow in 1,000. A busy machine opens thousands of flows an hour, so the model alone would still block some legitimate traffic. This is why the engine design also uses rules and a whitelist, and defaults to detect-only mode.

---

## Entry 9 — Test on excluded attack types

**Date:** 2026-10-12
**What:** `verify_model.py` ran the model on the attack labels left out of training, to confirm and quantify the stated limitation. The model has no class for these, so "detected" here means flagged as any attack.

| Label | Flows | Flagged as some attack | Predictions |
|---|---|---|---|
| Web Attack Brute Force | 1,507 | 1.3% | 1,488 Benign, 18 DoS, 1 PortScan |
| Web Attack XSS | 652 | 0.5% | 649 Benign, 2 DoS, 1 PortScan |
| Web Attack Sql Injection | 21 | 4.8% | 20 Benign, 1 DoS |
| Infiltration | 36 | 0.0% | 36 Benign |
| Heartbleed | 11 | 0.0% | 11 Benign |

**Finding:** these attacks pass as benign. This is expected and is documented as a limitation: `model_v1` detects DoS, DDoS, port scans, FTP/SSH brute force and (partly) botnet traffic only.

---

## Entry 10 — Load check in a second environment

**Date:** 2026-10-12
**What:** the model file was loaded in a different Python environment on the same machine, to check that teammates with slightly different package versions can use it.

| | Training environment | Second environment |
|---|---|---|
| Python | 3.10.18 | 3.11.13 |
| scikit-learn | 1.7.2 | 1.7.2 |
| numpy | 2.2.6 | 2.3.1 |
| joblib | 1.3.2 | 1.5.2 |
| Result | Trained and saved | Loaded correctly: 6 classes, 19 features |

**Finding:** the file loads across Python, numpy and joblib versions when scikit-learn is the same. scikit-learn is the version that must match, and it is pinned in `python-engine/requirements.txt`. A load on a different laptop has not been tested yet.

---

## Entry 11 — Synthetic test of the new engine (Part A)

**Date:** 2026-10-13
**What:** after Part A was pushed (new flow tracker, rules, classifier wiring), hand-built packet sequences were fed through the engine's own `FlowTracker`, `RuleEngine` and `ThreatClassifier`. No real capture and no firewall were involved.
**Important:** this is synthetic traffic written to imitate each pattern. It is a functional check, not an accuracy measurement.

Engine unit tests: 104 passed (pytest 9.1.1).

| Scenario | Packets | Flows | Model verdicts | Rule hits |
|---|---|---|---|---|
| Benign HTTPS, 400 sessions to 8 servers | 20,069 | 400 | 400 Benign | none |
| Benign DNS, 200 lookups | 400 | 200 | 200 Benign | none |
| SYN port scan, 40 ports, no replies (the `simulate_attack.py` pattern) | 40 | 40 | 40 Benign | PortScan |
| nmap-style scan, 300 ports, RST replies | 600 | 300 | 300 Benign | PortScan, SynFlood |
| SYN flood, 2,000 packets in 1 second | 2,000 | 2,000 | 2,000 Benign | SynFlood |
| ICMP flood, 1,500 packets | 1,500 | 1 | 1 Benign | IcmpFlood |

Benign share of the first 100 HTTPS flows: 1.00. Of the last 100: 1.00.

**Finding 1: the original bug is fixed.** In entry 1 the old engine drifted from "normal" to "satan" as traffic accumulated. The new engine classified all 600 benign flows as Benign, with no drift between the first and last flows.

**Finding 2: every attack was caught, but only by the rules.** The model called every scan and flood flow Benign.

**Finding 3: the model's PortScan detection depends on a dataset artifact.** The cause was traced in the dataset's 158,930 PortScan rows:

| Flow shape in the dataset (forward packets, backward packets, forward bytes, backward bytes) | Rows |
|---|---|
| 1, 1, 0, 6 | 79,488 |
| 1, 1, 2, 6 | 77,955 |
| all other shapes | 1,487 |

99% of PortScan rows are one probe and one reply whose reply has a "payload" of 6 bytes. A reset reply carries no payload. The 6 bytes are the padding that fills a short frame up to the minimum Ethernet size, which the dataset's tool counted as payload (suspected in entry 3). Our engine computes true payload, which is 0.

Model output for a one-probe, one-reply flow, varying only the byte counts and duration:

| Forward bytes | Backward bytes | 60 µs | 200 µs | 2,000 µs |
|---|---|---|---|---|
| 0 | 0 (true payload, what the engine produces) | Benign 1.00 | Benign 1.00 | Benign 0.99 |
| 0 | 6 (as in the dataset) | PortScan 1.00 | PortScan 1.00 | Benign 0.56 |
| 2 | 6 (as in the dataset) | PortScan 0.99 | PortScan 1.00 | Benign 0.52 |
| 6 | 6 | Benign 0.99 | Benign 1.00 | Benign 1.00 |

**Conclusion**

- The PortScan recall of 0.9989 in entry 6 is real for the dataset but does not carry over: the model learned "reply of exactly 6 bytes", not scanning behaviour. On live traffic `model_v1` should be expected to miss port scans.
- Port scans are still detected, by the rate rule (more than 20 distinct ports in 5 seconds), which fired in both scan scenarios.
- SYN and ICMP floods are not in the model's training classes in this form (the dataset's DoS class is HTTP-level floods), so rule-only detection there is expected.

**Open decision:** either accept rule-only detection for scans, or train a `model_v2` with the padding artifact removed from the length features (for example treating lengths of 6 or less as 0) and measure whether PortScan is still learnable from the remaining features.

---

## Entry 12 — Length-convention fix in the engine, plus a blocking safeguard

**Date:** 2026-10-13
**What:** resolved the open decision of entry 11. The model was **not** retrained. Instead the engine was changed to measure TCP lengths the way the dataset does. `model_v1.pkl` is unchanged (same SHA-256 as entry 7).

### Why not retrain

Entry 11 proposed training a `model_v2` with the artifact removed. That turned out not to be possible: the dataset only gives per-flow totals, and padding is added per packet, so it cannot be subtracted afterwards. The alternative is to make the engine produce the same numbers the model was trained on.

### What the artifact is

An Ethernet frame carries at least 46 bytes. A shorter IP packet is padded up to that, and the dataset's tool counted the padding as TCP payload.

| Packet | IP packet size | Padding counted as "payload" |
|---|---|---|
| TCP with no options and no data (bare ACK, RST) | 40 bytes | 6 |
| SYN with only an MSS option | 44 bytes | 2 |
| TCP with 8 or more bytes of options, or 6 or more bytes of data | 46 bytes or more | 0 |

Evidence from all 2,830,743 dataset rows, counting flows by their smallest packet length (TCP-port flows only):

| Smallest forward length | Flows | | Smallest backward length | Flows |
|---|---|---|---|---|
| 0 | 1,316,972 | | 0 | 1,428,449 |
| 1 | 214 | | 1 | 95 |
| 2 | 141,138 | | 2 | 21,924 |
| 3 | 0 | | 3 | 5 |
| 4 | 0 | | 4 | 786 |
| 5 | 1 | | 5 | 2 |
| 6 | 358,110 | | 6 | 351,123 |

Lengths of exactly 2 and 6 are very common, while 1, 3, 4 and 5 almost never occur. Real payloads would not skip those values; padding to a fixed minimum explains it exactly. This also explains the two PortScan shapes in entry 11: a probe with full options (0) or MSS only (2), answered by a reset (6).

### The change

In `python-engine/feature_extractor.py`, TCP length is now `payload + max(0, 46 − IP packet size)`. It is computed from the IP header, so it gives the same answer whether or not the capture saw the padded frame. UDP and ICMP are unchanged: the effect could not be confirmed for them, because the dataset's UDP payloads are all larger than the minimum.

### Results: same packets, before and after

Real Scapy packets were passed through `parse_packet`, the flow tracker, the rules and the model. Synthetic traffic; no capture, no firewall.

| Scenario | Flows | Model before | Model after | Rules (both) |
|---|---|---|---|---|
| Benign HTTPS, 400 sessions | 400 | 400 Benign | 400 Benign | none |
| Benign DNS, 200 lookups | 200 | 200 Benign | 200 Benign | none |
| 50 outbound connections refused by a remote server | 50 | 50 Benign | 50 Benign | none |
| Scan, SYN with MSS only (`nmap -sS` style), 300 ports | 300 | 300 Benign | **300 PortScan**, all at confidence ≥ 0.90 | PortScan, SynFlood |
| Scan, SYN with full options (`nmap -sT` style), 300 ports | 300 | 300 Benign | **300 PortScan**, all at confidence ≥ 0.90 | PortScan, SynFlood |
| `simulate_attack.py` pattern (SYN with no options), 40 ports | 40 | 40 Benign | 40 Benign | PortScan |
| SYN flood, 2,000 packets, no replies | 2,000 | 2,000 Benign | 2,000 Benign | SynFlood |
| ICMP flood, 1,500 packets | 1 | Benign | Benign | IcmpFlood |
| One inbound connection attempt to a closed port | 1 | Benign | **PortScan ≥ 0.90** | none |

- The model now recognises both common scan styles: 600 of 600 probes, against 0 of 600 before.
- Benign results did not change: 650 of 650 benign flows stayed Benign.
- `simulate_attack.py` sends SYNs with no options at all, a shape that is not in the dataset. The model still calls it Benign; the rule catches it.

### The side effect, and the safeguard

The last row is a new risk created by the fix. To the model, one refused connection looks identical to one scan probe, so a single stray connection to a closed port would have been blocked.

A safeguard was added to `python-engine/detector.py`: **the model alone may block a source only after 3 of its flows are judged attacks within 10 seconds** (`MODEL_BLOCK_MIN_FLOWS` in `config.py`). Earlier ones are recorded as `alert_only`. Rule matches still block immediately.

Full decision engine, blocking enabled, fake firewall:

| Scenario | Records | Blocked? |
|---|---|---|
| 1 stray inbound connection to a closed port | 1 PortScan, `alert_only` | No |
| 2 attempts from the same host, 1 second apart | 2 PortScan, `alert_only` | No |
| 300-port scan, model only (rules switched off) | 2 `alert_only`, then 298 `blocked` | Yes, from the 3rd probe |
| 300-port scan, model and rules | 2 `alert_only`, then 300 `blocked` (282 as `both`) | Yes, from the 3rd probe |
| Slow scan: 12 ports at 2 per second, below the rule's 20-port threshold | 2 `alert_only`, then 10 `blocked` | Yes, from the 3rd probe |

The slow scan is the case where the model adds something the rules cannot: it never reaches the rule threshold, and only the model catches it.

The safeguard also lowers the general false-block risk measured in entry 8 (about 1 benign flow in 1,000 at confidence ≥ 0.90), since a single misjudged flow no longer blocks anyone. That reduction has not been measured.

Engine unit tests after both changes: 113 passed (104 before; 9 added).

### What this does and does not show

- The model's port-scan detection was restored without retraining, by matching the dataset's measurement convention.
- It still depends on that convention. This is a property of the dataset, and a clear example of a benchmark score (PortScan recall 0.9989) that only holds if the live system copies the benchmark's quirks.
- All of this is synthetic. Real scans from a second machine are still untested.

---

## Not yet tested

These are open and will be added as new entries when done:

- **Live traffic.** Entries 11 and 12 used synthetic packets. The engine has still not been run on real captured traffic with real attacks (Part A's step A15); those results are not in this log yet.
- **A different laptop.** A teammate pulling the repo and loading the model.
- **Training on some days and testing on others,** which would be a stricter test of generalisation than a random split.
