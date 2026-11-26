"""Offline PDF reports built with ReportLab.

These documents are drafts for review. They do not provide legal, compliance, exploit,
attacker-intent, or security-absence guarantees.
"""
import time
from datetime import datetime
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from .knowledge import explain

NAVY = colors.HexColor("#0F2344")
TEAL = colors.HexColor("#007B83")


def _t(ts):
    return datetime.fromtimestamp(ts).strftime("%d %b %Y, %H:%M:%S") if ts else "-"


def _esc(value):
    text = "" if value is None else str(value)
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _paragraph(value, style):
    return Paragraph(_esc(value), style)


def _validation_label(incident):
    status = incident.get("validation") or "pending"
    labels = {
        "evidence_checked": "evidence_checked (deterministic rule/behaviour reproduction)",
        "suspected": "suspected (ML-only or not deterministic)",
        "invalid_evidence": "invalid_evidence",
    }
    return labels.get(status, status)


def build_report(incident, actions, out_dir: Path, org: str = "Enterprise Deployment") -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"incident_{incident['id']}.pdf"
    knowledge = explain(incident["category"])
    ss = getSampleStyleSheet()
    h = ParagraphStyle("h", parent=ss["Heading1"], textColor=NAVY, fontSize=18)
    h2 = ParagraphStyle("h2", parent=ss["Heading2"], textColor=TEAL, fontSize=12, spaceBefore=10)
    body = ParagraphStyle("b", parent=ss["BodyText"], fontSize=9.5, leading=13)
    small = ParagraphStyle("s", parent=body, fontSize=8, textColor=colors.grey)
    mono = ParagraphStyle("mono", parent=body, fontName="Courier", fontSize=7, leading=9)

    due = (incident["detected_at"] or time.time()) + 6 * 3600
    validation_detail = incident.get("validation_detail") or {}
    rows = [
        [_paragraph("Report generated", body), _paragraph(_t(time.time()), body)],
        [_paragraph("Organisation", body), _paragraph(org, body)],
        [_paragraph("Incident ID", body), _paragraph(f"RAK-{incident['id']:05d}", body)],
        [_paragraph("CERT-In category (Annexure I)", body), _paragraph(knowledge["certin_category"], body)],
        [_paragraph("MITRE ATT&CK", body), _paragraph(f"{knowledge['mitre_id']} - {knowledge['mitre_name']}", body)],
        [_paragraph("Severity", body), _paragraph(str(incident["severity"]).upper(), body)],
        [_paragraph("Attack source", body), _paragraph(incident["source_ip"], body)],
        [_paragraph("Evidence validation", body), _paragraph(_validation_label(incident), body)],
        [_paragraph("First seen", body), _paragraph(_t(incident["first_seen"]), body)],
        [_paragraph("Detected", body), _paragraph(_t(incident["detected_at"]), body)],
        [_paragraph("Contained", body), _paragraph(_t(incident["contained_at"]), body)],
        [_paragraph("Evidence rows in validation period", body), _paragraph(len(validation_detail.get("event_ids", [])), body)],
        [_paragraph("Observed flagged events", body), _paragraph(validation_detail.get("observed_flagged_count", "-"), body)],
        [_paragraph("AI-origin estimate", body), _paragraph(f"{int(incident['ai_score'] * 100)}% (heuristic estimate, not proof)", body)],
        [_paragraph("Report to CERT-In by", body), _paragraph(_t(due) + " (draft timing only)", body)],
    ]
    tbl = Table(rows, colWidths=[55 * mm, 115 * mm])
    tbl.setStyle(TableStyle([
        ("FONT", (0, 0), (0, -1), "Helvetica-Bold", 9), ("FONT", (1, 0), (1, -1), "Helvetica", 9),
        ("TEXTCOLOR", (0, 0), (0, -1), NAVY), ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#D0DCE8")),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F1F7FC")), ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))

    story = [Paragraph("RAKSHAK-AI Incident Report", h),
             Paragraph("DRAFT for human review. This offline document is not an official legal, regulatory, or compliance submission and makes no guarantee that an exploit occurred, that a person or AI was responsible, or that absence of a finding means a system is secure.", small),
             Spacer(1, 6), tbl,
             Paragraph("What happened", h2), Paragraph(_esc(knowledge["title"] + ". " + knowledge["what"]), body),
             Paragraph("Why it matters", h2), Paragraph(_esc(knowledge["why"]), body),
             Paragraph("Evidence validation", h2),
             Paragraph(_esc("The evidence_checked label means deterministic rules and the behaviour heuristic were reproduced from stored event rows, including the 60-second pre-window. This is rule reproduction only, not exploit confirmation or attacker-intent attribution."), body)]
    if incident.get("validation_detail"):
        detail = incident["validation_detail"]
        story.append(Paragraph(_esc("Matching stored event IDs: " + ", ".join(map(str, detail.get("matching_event_ids", []))) +
                               f"; observed flagged count: {detail.get('observed_flagged_count', 0)}."), body))
    story.append(Paragraph("Detections", h2))
    for detection in incident.get("detections", [])[:12]:
        text = f"- {detection.get('rule_id', '')}: {detection.get('name', '')}"
        if detection.get("matched"):
            text += f" (matched: {detection['matched']})"
        story.append(Paragraph(_esc(text), body))
    if incident.get("ai_reasons"):
        story.append(Paragraph("Why Rakshak thinks this may be automated / AI-driven", h2))
        for reason in incident["ai_reasons"]:
            story.append(Paragraph(_esc("- " + str(reason)), body))
        story.append(Paragraph(_esc("AI behaviour signals are non-probabilistic heuristics in this report and are not proof of AI use, identity, exploit, or intent."), small))
    story.append(Paragraph("Actions taken", h2))
    for action in actions:
        text = (f"- {_t(action.get('ts'))}: {action.get('action', '')} on {action.get('target', '')} - "
                f"{action.get('status', '')} ({action.get('detail', '')}). Signature {str(action.get('signature', ''))[:16]}...")
        story.append(Paragraph(_esc(text), body))
    if not actions:
        story.append(Paragraph("- None yet.", body))
    story.append(Paragraph("Recommended next steps", h2))
    for todo in knowledge["todo"]:
        story.append(Paragraph(_esc("- " + str(todo)), body))
    story.append(Paragraph("Evidence (sample log lines)", h2))
    for evidence in incident.get("evidence", [])[:8]:
        story.append(Paragraph(_esc(str(evidence)[:300]), mono))
    story.append(Spacer(1, 10))
    story.append(Paragraph("Stored logs are hash-chained and tamper-evident within this database. Audit HMACs support authenticity checks but are not immutable storage and do not guarantee truncation detection. This is not an immutable archive or a guarantee of retention, completeness, or security.", small))

    SimpleDocTemplate(str(path), pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm,
                      topMargin=16 * mm, bottomMargin=16 * mm,
                      title=f"Incident RAK-{incident['id']:05d}").build(story)
    return path


def build_plugin_report(run, out_dir: Path, org: str = "Enterprise Deployment") -> Path:
    """Build an offline security-test report from a signed, verified run record.

    Only findings with status "confirmed" (seen by the tool AND reproduced by Rakshak's
    own independent re-check) go in the main section. Everything else is listed with
    its status so nothing is hidden, but it is never presented as a problem.
    """
    if run.get("verified") is not True:
        raise ValueError("Run record signature not verified; no report is produced.")
    out_dir.mkdir(parents=True, exist_ok=True)
    run_id = run.get("id")
    path = out_dir / f"plugin_run_{run_id}.pdf"
    findings = list(run.get("findings") or [])
    by = lambda s: [f for f in findings if f.get("status") == s]  # noqa: E731
    main, not_rep, inconc, passes = by("confirmed"), by("not_reproduced"), by("inconclusive"), by("observed_pass")
    other = [f for f in findings if f.get("status") not in ("confirmed", "not_reproduced", "inconclusive", "observed_pass")]
    ss = getSampleStyleSheet()
    h = ParagraphStyle("ph", parent=ss["Heading1"], textColor=NAVY, fontSize=18)
    h2 = ParagraphStyle("ph2", parent=ss["Heading2"], textColor=TEAL, fontSize=12, spaceBefore=10)
    body = ParagraphStyle("pb", parent=ss["BodyText"], fontSize=9.5, leading=13)
    cell = ParagraphStyle("pc", parent=body, fontSize=8.5, leading=11)
    small = ParagraphStyle("ps", parent=body, fontSize=8, textColor=colors.grey)
    hashes = run.get("file_hashes") or {}
    summ = run.get("summary") or {}

    story = [Paragraph("RAKSHAK-AI Security Test Report", h),
             Paragraph(_esc("DRAFT for human review. The signed run record was verified before this report was generated. "
                            "Only results that Rakshak reproduced with its own independent re-check are listed as findings."), small)]
    summary = [
        [_paragraph("Report generated", body), _paragraph(_t(time.time()), body)],
        [_paragraph("Organisation", body), _paragraph(org, body)],
        [_paragraph("Run ID", body), _paragraph(run_id, body)],
        [_paragraph("Tool", body), _paragraph(f"{run.get('plugin_id', '')} v{run.get('plugin_version', '')}", body)],
        [_paragraph("Target", body), _paragraph(run.get("target", ""), body)],
        [_paragraph("Requested by / reason", body), _paragraph(f"{run.get('requested_by', '')}: {run.get('authorised_statement') or '-'}", body)],
        [_paragraph("Approved by", body), _paragraph(f"{run.get('approved_by') or '-'} at {_t(run.get('approved_at'))}", body)],
        [_paragraph("Ran", body), _paragraph(f"{_t(run.get('started_at'))} to {_t(run.get('finished_at'))}", body)],
        [_paragraph("Run status", body), _paragraph(f"{run.get('status', '')}" + (f" - {summ.get('reason')}" if summ.get("reason") else ""), body)],
        [_paragraph("Tool file sha256 (pinned)", body), _paragraph(hashes.get("executable", "-"), small)],
        [_paragraph("Tool output sha256", body), _paragraph(run.get("stdout_sha256") or "-", small)],
        [_paragraph("Confirmed findings", body), _paragraph(len(main), body)],
        [_paragraph("Not reproduced (not counted)", body), _paragraph(len(not_rep), body)],
        [_paragraph("Inconclusive (could not observe)", body), _paragraph(len(inconc), body)],
        [_paragraph("Observed passes", body), _paragraph(len(passes), body)],
    ]
    table = Table(summary, colWidths=[65 * mm, 105 * mm])
    table.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#D0DCE8")),
                               ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F1F7FC")),
                               ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story.extend([Spacer(1, 6), table, Paragraph("How to read this report", h2),
                  Paragraph(_esc("Confirmed: the tool observed it AND a new, independent re-check by Rakshak saw it again. "
                                 "Not reproduced: the tool reported it but the re-check did not see it, so it is not reported as a problem. "
                                 "Inconclusive: Rakshak could not make a reliable observation (for example the page did not answer). "
                                 "Observed pass: the check looked fine this time; this is not proof that the system is secure."), body),
                  Paragraph(f"Confirmed findings ({len(main)})", h2)])
    if main:
        for finding in main:
            rows = [[_paragraph("Finding", cell), _paragraph(f"{finding.get('title', '')}  [{str(finding.get('severity', '')).upper()}]  Confirmed", cell)],
                    [_paragraph("What it means", cell), _paragraph(finding.get("what", ""), cell)],
                    [_paragraph("Tool observation", cell), _paragraph(finding.get("evidence", ""), cell)],
                    [_paragraph("Independent re-check", cell), _paragraph(finding.get("validation_evidence", ""), cell)],
                    [_paragraph("How to fix", cell), _paragraph(finding.get("fix", ""), cell)]]
            t = Table(rows, colWidths=[38 * mm, 132 * mm])
            t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#D0DCE8")),
                                   ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F1F7FC")),
                                   ("BACKGROUND", (1, 0), (1, 0), colors.HexColor("#FDECEC")),
                                   ("VALIGN", (0, 0), (-1, -1), "TOP")]))
            story.extend([t, Spacer(1, 5)])
    else:
        story.append(Paragraph(_esc("No finding was confirmed by an independent re-check. This does not mean that no vulnerability exists or that the target is secure."), body))
    for title, items in (("Not reproduced (listed for transparency, not counted as problems)", not_rep),
                         ("Inconclusive (could not observe)", inconc), ("Observed passes", passes), ("Other records", other)):
        if not items:
            continue
        story.append(Paragraph(f"{title} ({len(items)})", h2))
        for finding in items:
            extra = f" Re-check: {finding['validation_evidence']}" if finding.get("validation_evidence") and finding.get("status") == "not_reproduced" else ""
            story.append(Paragraph(_esc(f"- {finding.get('title', '')}: {finding.get('evidence', '')}.{extra}"), cell))
    story.append(Spacer(1, 10))
    story.append(Paragraph(_esc("Tool output was size-limited, parsed by a strict parser and re-checked independently where a re-check exists. "
                                "Observed passes are not proof of security. This draft offers no legal, regulatory, compliance, exploit, "
                                "attacker-intent, or absence-of-vulnerability guarantee."), small))
    SimpleDocTemplate(str(path), pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm,
                      topMargin=16 * mm, bottomMargin=16 * mm,
                      title=f"Security test run {run_id}").build(story)
    return path
