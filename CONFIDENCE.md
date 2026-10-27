# Confidence and continuous learning

Cairn's confidence value answers one question:

> Given the evidence and the detector that produced it, what is the probability
> that this observation is valid?

It is **not** a severity score, a CVSS replacement, or a claim that a target is
exploitable. A high-confidence "exposed Git metadata" finding means the Git
metadata is probably there. It does not mean an attacker can use it.

## The baseline

Each candidate finding is represented by nine inspectable features:

| Feature | Meaning |
| --- | --- |
| `prior_logit` | Log-odds of the detector's historical reliability prior |
| `direct` | Whether the observation came from a direct response |
| `corroboration` | Evidence count, capped at three |
| `independent` | Independent sources, capped at two |
| `specificity` | How unambiguous the signature is |
| `soft404_clear` | Whether the response is distinguishable from a catch-all page |
| `coverage` | Fraction of the planned probes that completed |
| `freshness` | Exponential decay of evidence age (45-day half-life) |
| `scope_certainty` | Confidence that the target is inside the authorized scope |

The baseline is a logistic model with fixed weights:

```text
z = -1.8
  + 0.85 · prior_logit
  + 1.00 · direct
  + 0.45 · corroboration
  + 0.55 · independent
  + 0.95 · specificity
  + 0.60 · soft404_clear
  + 0.35 · coverage
  + 0.15 · freshness
  + 0.50 · scope_certainty

p = sigmoid(z)
```

The weights and priors live in `cairn/intel/features.py`. They are deliberately
small enough to inspect and challenge. The model card in the GUI lists the top
contributors for every finding, including whether each feature supported or
weakened the score.

## Learning from analysts

An analyst can record one of five verdicts on a finding:

- `confirmed` — the observation is real.
- `false_positive` — the observation is not real or is not what the detector
  claimed.
- `accepted_risk` — the observation is real but accepted by the owner; it is
  treated as a positive with a slightly lower weight.
- `uncertain` — not used for training; useful for the review queue.
- `duplicate` — not used for training.

`confirmed`, `false_positive`, and `accepted_risk` become labels. The feature
vector is read from the finding at training time. Human labels always enter the
evaluation set; weak labels never do.

### Weak labels

When there are at least ten human labels, Cairn may add a small number of
high-confidence, uncorroborated-by-humans findings as weak positives, capped at
weight 0.2 and only when:

- the finding is still open,
- confidence is at least 0.92,
- corroboration is at least 0.66,
- specificity is at least 0.80,
- no human feedback exists for that finding.

The number of weak labels is capped at one third of the human label count. They
help the model see more structure without letting the model grade its own
homework: evaluation is always human-only.

## Training and evaluation

The trainer (`cairn/intel/learning.py`) uses weighted L2 logistic regression
with balanced class weights. The evaluation protocol is:

1. Shuffle the labeled rows deterministically.
2. Split into five folds.
3. For each fold, train on the other four and predict the held-out fold. These
   are out-of-fold (OOF) predictions.
4. Compute metrics on the OOF predictions, restricted to human labels.
5. If there are at least 30 human labels, fit an isotonic calibrator on the OOF
   probabilities and evaluate it **leave-one-out**: for each human label, fit a
   calibrator on the other OOF points and score the held-out point. This avoids
   evaluating the calibrator on its own fit.
6. If there are fewer than 30 human labels, use identity calibration. Isotonic
   regression has too much variance at small sample sizes and can turn a
   reasonable model into a badly calibrated one.

The deployed score is the calibrated probability, clamped to `[0.02, 0.995]`.

### Metrics

- **Brier score** — mean squared error of probabilities. Lower is better.
  Cairn reports calibrated Brier as the headline, raw Brier for transparency,
  and a base-rate baseline Brier.
- **ECE** — expected calibration error over eight probability bins. Lower is
  better. A model can be accurate and still poorly calibrated.
- **Log loss** — probability quality with a harsher penalty for confident
  mistakes.
- **Accuracy / precision / recall** — reported for context, but not used as
  promotion gates. Threshold-dependent accuracy can look good on a tiny sample
  while the probabilities remain unusable.

### Promotion gates

A challenger becomes champion only if **all** of these hold:

| Gate | Threshold |
| --- | --- |
| Held-out human labels | at least 30 |
| Calibrated Brier vs. base rate | better by more than 0.002 |
| Calibration error | ECE at most 0.15 |
| Margin over existing champion | at least 0.005 Brier |

If no champion exists, the champion-margin gate is skipped. If any gate fails,
the model is stored as a `challenger` with its metrics and a
`promotion_blockers` list. The dashboard shows the failing checks rather than
hiding the miss. This is why a challenger can have a better training fit and
still not be deployed.

When a champion is promoted, Cairn demotes the previous champion, rescored open
findings with the new model, and stores the model version in each explanation.
A finding's historical explanation is not rewritten after the fact.

## Reading the reliability diagram

The dashboard plots predicted probability against observed frequency for each
non-empty bin. The diagonal is perfect calibration. Points above the diagonal
mean the model is under-confident in that bin; points below mean it is
over-confident.

With a small number of labels, a single bin can dominate. That is a signal to
collect more labels, not a reason to lower the gates. The UI reports the number
of evaluation labels next to the chart and labels identity calibration
explicitly.

## Active learning and adaptive probing

Two separate feedback loops improve coverage:

- **Active learning queue.** Findings with confidence between 0.30 and 0.70 are
  ranked for review. Analyst verdicts on uncertain findings are more informative
  than verdicts on obvious ones.
- **Thompson sampling.** `path_stats` and `probe_stats` track trials and
  successes for content paths and detector probes. The scanner samples from a
  Beta posterior to balance exploiting known-good paths and exploring untried
  ones. This is ordering, not confidence; the evidence still determines the
  finding.

## What can go wrong

- **Label leakage.** Never train on labels that were derived from the model's own
  predictions. Cairn's weak labels are capped and excluded from evaluation.
- **Calibration overfit.** Isotonic regression can memorize small samples.
  Cairn waits for 30 human labels and evaluates the calibrator leave-one-out.
- **Class imbalance.** Balanced class weights keep the model from collapsing to
  "everything is a false positive" when one class is rare.
- **Distribution shift.** A model trained on one customer's web stack may not
  transfer to another. Detector reliability and calibration are displayed per
  database; use engagement-specific assessment and fresh labels.
- **False precision.** A probability with two labels is not a scientific fact.
  The UI reports `n_eval` and refuses to promote on small samples.

## Reproducing a training run

```bash
cairn learn stats
cairn learn retrain
cairn learn retrain --no-weak
```

Training is deterministic for a fixed database and seed. The database stores the
model weights, calibration points, metrics, parent model, and notes. To inspect
a run programmatically:

```python
from cairn.db import Database
from cairn.intel.learning import train_confidence_model

db = Database(".cairn/cairn.db")
result = train_confidence_model(db)
print(result["status"], result["metrics"])
```

The `notes` field on each model records the calibration method and promotion
gates used at training time, so a future maintainer can reconstruct why a model
was deployed.
