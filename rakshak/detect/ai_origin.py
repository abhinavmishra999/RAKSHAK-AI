"""AI-origin score: how likely is it that an attack is driven by an automated / AI agent?

This is an estimate from behaviour signals, NOT proof. Each signal is measured from
the real events in the source's 60-second window and explained in plain language.
"""
from difflib import SequenceMatcher


def _mutation_similarity(payloads):
    """Average similarity between distinct malicious payloads.

    LLM-mutated attacks produce many payloads that are different but related
    (similarity roughly 0.3-0.9). A human retyping tends to repeat a few payloads.
    """
    uniq = list(dict.fromkeys(payloads))[-15:]
    if len(uniq) < 4:
        return None
    sims = []
    for i in range(len(uniq)):
        for j in range(i + 1, min(i + 4, len(uniq))):
            sims.append(SequenceMatcher(None, uniq[i], uniq[j]).ratio())
    return sum(sims) / len(sims) if sims else None


def score(f):
    if not f:
        return 0.0, []
    signals = []

    # 1. Speed: humans rarely sustain more than ~2 requests per second.
    if f["rate"] >= 5:
        signals.append((0.30, f"Machine speed: {f['rate']:.1f} requests per second (a person manages about 1)."))
    elif f["rate"] >= 2:
        signals.append((0.15, f"Fast: {f['rate']:.1f} requests per second."))

    # 2. Timing regularity: scripts fire at very even intervals.
    if f["count"] >= 10 and f["timing_cv"] < 0.5:
        signals.append((0.15, "Very regular timing between requests, typical of a script."))

    # 3. Payload mutation: many different-but-related attack strings.
    sim = _mutation_similarity(f["payloads"])
    if f["unique_payloads"] >= 8 and sim is not None and 0.25 <= sim <= 0.92:
        signals.append((0.30, f"{f['unique_payloads']} different attack variants that look auto-generated "
                              f"(rewritten versions of the same idea)."))
    elif f["unique_payloads"] >= 4:
        signals.append((0.10, f"{f['unique_payloads']} different attack strings tried."))

    # 4. Keeps going after being blocked, with no human pause.
    if f["requests_after_block"] >= 10:
        signals.append((0.15, f"Kept retrying {f['requests_after_block']} times after being blocked."))

    # 5. User-agent rotation from one source.
    if f["unique_uas"] >= 4:
        signals.append((0.10, f"Switched between {f['unique_uas']} browser identities to hide."))

    # 6. Payload character entropy: hand-written injections read like text; encoded /
    # randomly generated blobs (obfuscators, LLM-generated encodings) measure high.
    ent = f.get("payload_entropy")
    if ent is not None and f["unique_payloads"] >= 3:
        if ent >= 4.2:
            signals.append((0.20, f"Attack strings look machine-generated: character randomness "
                                  f"{ent:.1f} bits (people write readable payloads)."))
        elif ent >= 3.7:
            signals.append((0.10, f"High payload character randomness ({ent:.1f} bits), typical of "
                                  f"encoded or generated strings."))

    # Capped at 0.95: behaviour signals give strong evidence, never certainty.
    total = min(0.95, sum(w for w, _ in signals))
    return round(total, 2), [r for _, r in signals]


def label(s):
    if s >= 0.7:
        return "Likely AI / automated bot"
    if s >= 0.4:
        return "Possibly automated"
    return "Likely a person"
