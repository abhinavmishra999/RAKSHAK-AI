# Accuracy benchmark (sandbox corpus, offline)

Run: 2026-11-26 13:20 UTC · machine: sandbox · build: phase-2 (remediation + adaptation) · engine: same pipeline as the console.

**Read this first.** This is a *labeled synthetic corpus in a sandbox*, built by this project, replayed through the real offline engine. It measures this build against the families present here - it is NOT a production accuracy claim and NOT an industry benchmark (for that, run the same script against CIC-IDS2017 or your own logs; that step is on the plan and has not been done). Corpus: 93 benign lines (8 addresses), 34 labelled attack lines (12 addresses), 260 flood lines (1), 14 failed-SSH lines (1). Total 402 lines.

## Baseline (bundled rules only)

| Family | Detected / addresses | Rate |
|---|---|---|
| sql injection | 2 / 2 | 100% |
| xss | 2 / 2 | 100% |
| path traversal | 2 / 2 | 100% |
| command injection | 2 / 2 | 100% |
| sensitive probe | 1 / 1 | 100% |
| scanner tool | 1 / 1 | 100% |
| novel encoded | 0 / 2 | 0% |
| flood (behavioural) | 1 / 1 | caught |
| brute force (behavioural) | 1 / 1 | caught |

**Detection (attack sources): 12/14 = 86%.**
**False alarms: 0/8 benign addresses alerted (0%); 0 benign log lines flagged.**

Misses: novel_encoded 45.60.7.72 -> silent; novel_encoded 45.60.7.71 -> silent.

## Adaptation loop (the 7/10 fix, measured)

The novel AI-style family (`b64:`/`0x` encoded payloads) was missed 2 time(s) by bundled rules - by design, no vendor feed existed for it offline. An analyst drafts a two-rule pack, which must pass the schema gate and its own positive/negative self-test before import. After import and replay *of the same corpus*:

| Family | Baseline | After 1 imported pack |
|---|---|---|
| novel encoded | 0% | 100% |
| everything else | unchanged | unchanged |

Overall detection: 86% -> **100%**. Benign false alarms: 0 -> 0 addresses; benign lines flagged 0 -> 0 (new pack added no false positives on this corpus).

## AI-origin scoring on the same runs

| Attacker address | ai_score | 'machine-generated' reason present? |
|---|---|---|
| 45.60.1.11 (readable payloads) | 0.1 | no |
| 45.60.1.12 (readable payloads) | 0.2 | yes |
| 45.60.2.21 (readable payloads) | 0.2 | yes |
| 45.60.7.71 (encoded blobs) | 0.2 | yes |
| 45.60.7.72 (encoded blobs) | 0.0 | no / silent before adaptation |

*Reading note:* the hex-blob address stayed at 0.0 because hex characters cap near 4 bits and the signal needs at least three unique FLAGGED payloads in the window - an honest edge of the feature, kept visible instead of tuning the corpus until it reads perfect. The deterministic imported rule caught that family regardless: layers, not silver bullets.

The payload-entropy feature (Shannon bits over unique flagged payloads) is what separates machine-encoded blobs from hand-typed injections without any signature; the imported pack adds the deterministic half of the same story.

## What this does NOT prove

- Encrypted traffic, memory attacks, malware, insider threat, DNS/exfil channels: not in scope of this corpus.
- The novel family is *defined by the author*, so 'missed then caught' demonstrates the LOOP, not real-world prevalence.
- Thresholds (entropy 4.2 bits, behaviour limits) are not tuned against your traffic; measure before trusting them.
- Accuracy numbers here cannot be quoted as production SLAs. Re-run this script against your own labelled logs.
