# Human checkpoint study protocol

**Goal:** measure whether a principal can supply the declassification decision at the
accuracy the mechanism needs. H18 is a simulated approval; this protocol replaces it
with human data.

## Why this is the right question

`results/checkpoint_sensitivity.json` (analysis of existing transcripts) gives the
target. With the plain condition:

| corpus | raw ASR | false-approval rate q for absolute ASR ≤ 5 % |
|---|---|---|
| H8b local | 80.0 % | **q ≤ 6.2 %** |
| H12 hosted | 71.1 % | **q ≤ 7.0 %** |
| H14 external | 44.0 % | **q ≤ 11.4 %** |

Utility scales linearly with the approval rate p: p = 0.8 recovers 80 % of the raw
utility. So the study must measure **both** false approvals (security) and false denials
(utility); a principal who approves everything is useless, and one who denies
everything is safe but unhelpful.

## Design

* **Within-subjects**, four conditions, counterbalanced with a Latin square.
* **N = 24** participants (power simulation below), 20 trials per condition = 480
  decisions per condition, 1,920 total.
* **Trial**: a synthetic brief shows the agent's proposed tool call, the provenance path
  (origin ticket + line), the resolved effect (recipient, count), and the counter-text.
  The participant approves or denies.
* **Conditions**:
  1. no checkpoint (the agent executes; participant observes) — baseline;
  2. per-tool allowlist (the tool is trusted, not the segment);
  3. per-segment approval (the content digest is what is approved);
  4. blanket trust (positive control for automation bias).
* **Stimuli**: 50 % attack / 50 % benign, drawn from the committed H8b/H13/InjecAgent
  transcripts, with synthetic addresses only. Randomize order within condition;
  attention checks; no deception.

## Outcomes

* **Primary security**: false-approval rate on attack trials.
* **Primary utility**: false-denial rate on benign trials.
* **Secondary**: decision time; NASA-TLX workload; confidence; explanation helpfulness;
  agreement with the provenance path.
* **Exclusions**: pre-registered (failure on attention checks, incomplete sessions).

## Analysis

* Mixed-effects logistic regression: decision ~ condition + (1 | participant) +
  (1 | scenario), with trial-level covariates (attack/benign, path length).
* Paired condition contrasts with Holm correction; report odds ratios and 95 % CIs.
* Workload/time: paired t-tests or Wilcoxon, with effect sizes.
* Pre-register the primary contrasts and the non-inferiority margin for utility.
* Power: with 24 participants × 20 trials, the design detects a 10–15 percentage-point
  difference in false approval at α = .05, power ≥ .8, allowing for a 20 % exclusion
  rate.

## Ethics and data

* IRB/ethics approval before recruitment; informed consent; right to withdraw.
* No real personal data: synthetic tickets, addresses (`example` domains), and names;
  no model outputs containing PII.
* Store only anonymized participant IDs, choices, times and questionnaire responses;
  no audio/video; no keystroke logging.
* Compensation at the local standard; debrief explains the attack/defence framing.
* No deception: participants are told the task is to catch unsafe agent actions.
* Data and materials: publish the stimuli, the analysis script and the anonymized
  decisions; do not publish anything that could identify a participant.

## Procedure

1. Pilot with 5 expert participants (not counted) to fix wording and timing.
2. Pre-register on OSF/AsPredicted: hypotheses, conditions, primary outcomes, exclusions,
   analysis.
3. Run 24 participants in one 50–60 minute session each (4 conditions × 20 trials,
   plus consent, instructions, NASA-TLX and debrief).
4. Analyze; report both false approvals and false denials, never one without the other.

## What this would and would not establish

* **Would**: whether humans can hit the specificity the mechanism needs (q ≤ 7 %), and
  the utility cost of their false denials; whether provenance explanations help;
  whether per-segment approval is better than per-tool.
* **Would not**: that the checkpoint is safe in deployment (a lab task is not an
  approval workflow), or that the simulated H18 numbers transfer to real operators.
* **Effort**: 4–6 weeks including IRB and recruitment; ~$3–5k in participant
  compensation at typical rates, plus analysis time.

## Why you cannot “pull human data from the internet”

There is no public dataset of decisions for **these** briefs, and unrelated public
decisions cannot be used as if they were participants:

* **No probability sample.** Public logs/labels are not a sample of the population that
  would operate this checkpoint; the false-approval rate would not estimate anything.
* **No consent, no IRB.** Treating scraped or public human decisions as study data
  bypasses consent and ethics review; it can also breach platform terms and privacy law.
* **No control of framing.** The checkpoint's effect depends on how the action and
  provenance are presented; a public dataset does not have that manipulation.
* **No linkage to the outcome.** You need per-trial approve/deny against known
  attack/benign labels; public data does not carry those labels for this task.

What is allowed:

1. **Crowdsourced study with IRB/consent** (Prolific/MTurk): 24 participants × 50–60
   minutes at $10–12/hour ≈ **$300–400** including fees; expedited IRB, 1–2 weeks.
2. **Expert pilot with consent** (5 colleagues): fixes wording/timing, not a
   generalizable estimate, not counted in the main result.
3. **Published priors for power analysis**: phishing detection, SOC alert triage and
   automation-bias studies can set plausible effect sizes, but they do not replace the
   study and should be cited as priors, not data.

The protocol above is written so that (1) can be run without redesign; the stimuli and
analysis script are the only remaining build items.
