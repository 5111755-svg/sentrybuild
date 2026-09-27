"""Baseline-vs-candidate drift detection.

Takes two snapshots produced by `elf_scanner.scan_file` (a trusted baseline
and a candidate — e.g. the same package after a rebuild, a re-download, or
a suspected compromise) and reports what changed, with a severity assigned
to each kind of change. This is where "supply chain tampering" actually
gets detected: individual scans describe structure, but tampering shows up
as *drift* — a new IFUNC that wasn't there before, a relocation now
pointing at a different symbol, a new NEEDED library, hardening flags that
got weaker.
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

SEVERITY_ORDER = {"INFO": 0, "WARNING": 1, "CRITICAL": 2}


def _index_symbols(symbols: List[Dict[str, Any]]) -> Dict[Tuple[str, str], Dict[str, Any]]:
    """Index symbols by (name, type) since a name can appear with several types."""
    return {(s["name"], s["type"]): s for s in symbols}


def _index_relocations(relocs: List[Dict[str, Any]]) -> Dict[Tuple[str, str], Dict[str, Any]]:
    """Index relocations by (section, offset) — the slot being patched."""
    return {(r["section"], r["offset"]): r for r in relocs}


def diff_scans(baseline: Dict[str, Any], candidate: Dict[str, Any]) -> Dict[str, Any]:
    """Compare a baseline scan dict against a candidate scan dict.

    Returns a report dict with `findings` (list of {severity, code, message})
    and `summary` counts, plus `max_severity` for easy CI gating.
    """
    findings: List[Dict[str, str]] = []

    if baseline.get("sha256") == candidate.get("sha256"):
        findings.append(
            {
                "severity": "INFO",
                "code": "IDENTICAL_FILE",
                "message": "Baseline and candidate have identical SHA-256 digests.",
            }
        )
        return _finalize(findings, baseline, candidate)

    findings.append(
        {
            "severity": "INFO",
            "code": "HASH_CHANGED",
            "message": (
                f"SHA-256 changed: {baseline.get('sha256')} -> {candidate.get('sha256')}"
            ),
        }
    )

    findings.extend(_diff_ifuncs(baseline, candidate))
    findings.extend(_diff_relocations(baseline, candidate))
    findings.extend(_diff_needed(baseline, candidate))
    findings.extend(_diff_search_paths(baseline, candidate))
    findings.extend(_diff_hardening(baseline, candidate))
    findings.extend(_diff_entry_point(baseline, candidate))
    findings.extend(_diff_symbol_table_shape(baseline, candidate))

    return _finalize(findings, baseline, candidate)


def _diff_ifuncs(base: Dict[str, Any], cand: Dict[str, Any]) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    base_names = {s["name"] for s in base.get("ifunc_symbols", [])}
    cand_names = {s["name"] for s in cand.get("ifunc_symbols", [])}

    added = sorted(cand_names - base_names)
    removed = sorted(base_names - cand_names)

    if added:
        out.append(
            {
                "severity": "CRITICAL",
                "code": "IFUNC_ADDED",
                "message": (
                    "New STT_GNU_IFUNC resolver symbol(s) not present in baseline: "
                    + ", ".join(added)
                    + ". IFUNC resolvers run arbitrary code at load time before "
                    "normal control-flow protections apply — verify this is an "
                    "intentional upstream change, not an injected hook."
                ),
            }
        )
    if removed:
        out.append(
            {
                "severity": "WARNING",
                "code": "IFUNC_REMOVED",
                "message": (
                    "IFUNC resolver(s) present in baseline are missing from candidate: "
                    + ", ".join(removed)
                    + ". Confirm this matches an expected upstream change."
                ),
            }
        )
    return out


def _diff_relocations(base: Dict[str, Any], cand: Dict[str, Any]) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    base_idx = _index_relocations(base.get("relocations", []))
    cand_idx = _index_relocations(cand.get("relocations", []))

    added_slots = [k for k in cand_idx if k not in base_idx]
    removed_slots = [k for k in base_idx if k not in cand_idx]
    changed_slots = [
        k
        for k in cand_idx
        if k in base_idx
        and (
            cand_idx[k]["symbol"] != base_idx[k]["symbol"]
            or cand_idx[k]["type"] != base_idx[k]["type"]
        )
    ]

    hijacked_plt = [
        k
        for k in changed_slots
        if base_idx[k]["is_plt_slot"] and cand_idx[k]["is_plt_slot"]
    ]
    if hijacked_plt:
        details = [
            f"{sec}@{off:#x}: {base_idx[(sec, off)]['symbol']} -> {cand_idx[(sec, off)]['symbol']}"
            for sec, off in hijacked_plt[:10]
        ]
        out.append(
            {
                "severity": "CRITICAL",
                "code": "PLT_SLOT_RETARGETED",
                "message": (
                    "PLT/GOT slot(s) now resolve to a different symbol than in the "
                    "baseline — this is the exact pattern of a dynamic symbol hook: "
                    + "; ".join(details)
                    + (" ..." if len(hijacked_plt) > 10 else "")
                ),
            }
        )

    other_changed = [k for k in changed_slots if k not in hijacked_plt]
    if other_changed:
        out.append(
            {
                "severity": "WARNING",
                "code": "RELOCATION_TARGET_CHANGED",
                "message": (
                    f"{len(other_changed)} non-PLT relocation slot(s) changed target "
                    "symbol/type between baseline and candidate."
                ),
            }
        )

    added_indirect = [k for k in added_slots if cand_idx[k]["is_indirect"]]
    if added_indirect:
        out.append(
            {
                "severity": "CRITICAL",
                "code": "NEW_IRELATIVE_RELOCATION",
                "message": (
                    f"{len(added_indirect)} new IRELATIVE (indirect/IFUNC-resolved) "
                    "relocation(s) appear in the candidate that were not in the "
                    "baseline."
                ),
            }
        )

    plain_added = [k for k in added_slots if k not in added_indirect]
    if plain_added:
        out.append(
            {
                "severity": "INFO",
                "code": "RELOCATION_ADDED",
                "message": f"{len(plain_added)} new relocation slot(s) present in candidate only.",
            }
        )
    if removed_slots:
        out.append(
            {
                "severity": "INFO",
                "code": "RELOCATION_REMOVED",
                "message": f"{len(removed_slots)} relocation slot(s) present in baseline are gone in candidate.",
            }
        )
    return out


def _diff_needed(base: Dict[str, Any], cand: Dict[str, Any]) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    base_needed = set(base.get("needed", []))
    cand_needed = set(cand.get("needed", []))
    added = sorted(cand_needed - base_needed)
    removed = sorted(base_needed - cand_needed)
    if added:
        out.append(
            {
                "severity": "WARNING",
                "code": "NEEDED_LIBRARY_ADDED",
                "message": (
                    "New DT_NEEDED shared library dependency/dependencies: "
                    + ", ".join(added)
                    + ". Confirm each is an intended, pinned dependency and not a "
                    "typosquat or dependency-confusion insertion."
                ),
            }
        )
    if removed:
        out.append(
            {
                "severity": "INFO",
                "code": "NEEDED_LIBRARY_REMOVED",
                "message": "Shared library dependency/dependencies removed: " + ", ".join(removed),
            }
        )
    return out


def _diff_search_paths(base: Dict[str, Any], cand: Dict[str, Any]) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    if not base.get("rpath") and cand.get("rpath"):
        out.append(
            {
                "severity": "CRITICAL",
                "code": "RPATH_INTRODUCED",
                "message": (
                    "Candidate introduces DT_RPATH not present in baseline: "
                    + ", ".join(cand["rpath"])
                    + ". This can redirect library resolution to an attacker-controlled path."
                ),
            }
        )
    added_runpath = set(cand.get("runpath", [])) - set(base.get("runpath", []))
    if added_runpath:
        out.append(
            {
                "severity": "WARNING",
                "code": "RUNPATH_CHANGED",
                "message": "New DT_RUNPATH entries in candidate: " + ", ".join(sorted(added_runpath)),
            }
        )
    if base.get("soname") != cand.get("soname"):
        out.append(
            {
                "severity": "WARNING",
                "code": "SONAME_CHANGED",
                "message": f"DT_SONAME changed: {base.get('soname')} -> {cand.get('soname')}",
            }
        )
    return out


def _diff_hardening(base: Dict[str, Any], cand: Dict[str, Any]) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    relro_rank = {"none": 0, "partial": 1, "full": 2}
    if relro_rank.get(cand.get("relro", "none"), 0) < relro_rank.get(base.get("relro", "none"), 0):
        out.append(
            {
                "severity": "WARNING",
                "code": "RELRO_WEAKENED",
                "message": f"RELRO weakened: {base.get('relro')} -> {cand.get('relro')}",
            }
        )
    if base.get("bind_now") and not cand.get("bind_now"):
        out.append(
            {
                "severity": "INFO",
                "code": "BIND_NOW_LOST",
                "message": "BIND_NOW was set in baseline but not in candidate.",
            }
        )
    if base.get("nx") and not cand.get("nx"):
        out.append(
            {
                "severity": "CRITICAL",
                "code": "NX_LOST",
                "message": "Baseline had a non-executable stack; candidate's stack is executable.",
            }
        )
    if base.get("is_pie") and not cand.get("is_pie"):
        out.append(
            {
                "severity": "WARNING",
                "code": "PIE_LOST",
                "message": "Baseline was position-independent (PIE); candidate is not.",
            }
        )
    return out


def _diff_entry_point(base: Dict[str, Any], cand: Dict[str, Any]) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    if base.get("is_pie") and cand.get("is_pie"):
        # Entry point is an offset for PIE binaries, so a change is meaningful
        # even without knowing the runtime load address.
        if base.get("entry_point") != cand.get("entry_point"):
            out.append(
                {
                    "severity": "INFO",
                    "code": "ENTRY_POINT_CHANGED",
                    "message": (
                        f"Entry point offset changed: {base.get('entry_point'):#x} -> "
                        f"{cand.get('entry_point'):#x} (expected with recompilation; "
                        "flagged for awareness)."
                    ),
                }
            )
    return out


def _diff_symbol_table_shape(base: Dict[str, Any], cand: Dict[str, Any]) -> List[Dict[str, str]]:
    """Flag exported symbols that changed binding/visibility/type in a way
    that would change how they're resolved by other modules — a common
    trick for silently swapping in a hook without renaming anything."""
    out: List[Dict[str, str]] = []
    base_idx = {s["name"]: s for s in base.get("symbols", []) if s["bind"] != "STB_LOCAL"}
    cand_idx = {s["name"]: s for s in cand.get("symbols", []) if s["bind"] != "STB_LOCAL"}

    suspicious = []
    for name, cs in cand_idx.items():
        bs = base_idx.get(name)
        if bs is None:
            continue
        if bs["type"] != cs["type"] or bs["bind"] != cs["bind"]:
            suspicious.append((name, bs["type"], bs["bind"], cs["type"], cs["bind"]))

    if suspicious:
        details = [f"{n} ({bt}/{bb} -> {ct}/{cb})" for n, bt, bb, ct, cb in suspicious[:10]]
        out.append(
            {
                "severity": "WARNING",
                "code": "SYMBOL_TYPE_OR_BINDING_CHANGED",
                "message": (
                    "Global/weak symbol(s) changed type or binding between baseline "
                    "and candidate, which can alter dynamic symbol resolution order: "
                    + "; ".join(details)
                    + (" ..." if len(suspicious) > 10 else "")
                ),
            }
        )
    return out


def _finalize(
    findings: List[Dict[str, str]], baseline: Dict[str, Any], candidate: Dict[str, Any]
) -> Dict[str, Any]:
    summary = {"INFO": 0, "WARNING": 0, "CRITICAL": 0}
    for f in findings:
        summary[f["severity"]] = summary.get(f["severity"], 0) + 1

    max_severity = "INFO"
    for f in findings:
        if SEVERITY_ORDER[f["severity"]] > SEVERITY_ORDER[max_severity]:
            max_severity = f["severity"]

    return {
        "baseline_path": baseline.get("path"),
        "candidate_path": candidate.get("path"),
        "baseline_sha256": baseline.get("sha256"),
        "candidate_sha256": candidate.get("sha256"),
        "findings": findings,
        "summary": summary,
        "max_severity": max_severity,
    }


def diff_scan_lists(
    baselines: List[Dict[str, Any]], candidates: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """Diff two directory scans, matched by file path relative structure is
    not assumed — matching is done by basename when exact path doesn't match,
    falling back to reporting unmatched files on either side."""
    base_by_path = {b["path"]: b for b in baselines if "path" in b}
    cand_by_path = {c["path"]: c for c in candidates if "path" in c}

    reports = []
    matched_cand_paths = set()

    for path, base_scan in base_by_path.items():
        cand_scan = cand_by_path.get(path)
        if cand_scan is None:
            reports.append(
                {
                    "baseline_path": path,
                    "candidate_path": None,
                    "findings": [
                        {
                            "severity": "WARNING",
                            "code": "FILE_MISSING_IN_CANDIDATE",
                            "message": f"File present in baseline but missing from candidate: {path}",
                        }
                    ],
                    "summary": {"INFO": 0, "WARNING": 1, "CRITICAL": 0},
                    "max_severity": "WARNING",
                }
            )
            continue
        matched_cand_paths.add(path)
        reports.append(diff_scans(base_scan, cand_scan))

    for path in cand_by_path:
        if path in matched_cand_paths:
            continue
        reports.append(
            {
                "baseline_path": None,
                "candidate_path": path,
                "findings": [
                    {
                        "severity": "WARNING",
                        "code": "NEW_FILE_IN_CANDIDATE",
                        "message": f"File present in candidate but not in baseline: {path}",
                    }
                ],
                "summary": {"INFO": 0, "WARNING": 1, "CRITICAL": 0},
                "max_severity": "WARNING",
            }
        )

    overall_max = "INFO"
    total_summary = {"INFO": 0, "WARNING": 0, "CRITICAL": 0}
    for r in reports:
        for sev, count in r["summary"].items():
            total_summary[sev] += count
        if SEVERITY_ORDER[r["max_severity"]] > SEVERITY_ORDER[overall_max]:
            overall_max = r["max_severity"]

    return {"reports": reports, "summary": total_summary, "max_severity": overall_max}
