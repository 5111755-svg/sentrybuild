"""ELF structural scanner.

Extracts a normalized, JSON-serializable snapshot of an ELF binary's
security-relevant properties: dynamic symbols (including STT_GNU_IFUNC
resolvers), relocation entries (GOT/PLT), declared shared library
dependencies, search paths, and standard hardening flags (RELRO, BIND_NOW,
PIE, NX).

This module only *extracts and describes* structure. It does not make a
malicious/benign judgment call on its own — that comparison is the job of
`diff_engine`, which looks for drift against a trusted baseline snapshot
produced by this scanner.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.dynamic import DynamicSection
    from elftools.elf.relocation import RelocationSection
    from elftools.elf.sections import SymbolTableSection
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "SentryBuild requires 'pyelftools'. Install it with "
        "`pip install pyelftools` or `pip install -r requirements.txt`."
    ) from exc


SCHEMA_VERSION = 1

# Relocation types (x86-64 and generic) whose target is resolved indirectly
# at load/run time rather than pointing at a fixed symbol address. These are
# the mechanism IFUNC resolvers and lazily-bound PLT stubs rely on, and the
# ones worth extra scrutiny when they appear somewhere unexpected.
_INDIRECT_RELOC_TYPE_NAMES = {
    "R_X86_64_IRELATIVE",
    "R_386_IRELATIVE",
    "R_AARCH64_IRELATIVE",
}
_PLT_RELOC_TYPE_NAMES = {
    "R_X86_64_JUMP_SLOT",
    "R_386_JMP_SLOT",
    "R_AARCH64_JUMP_SLOT",
}
_GLOBAL_DATA_RELOC_TYPE_NAMES = {
    "R_X86_64_GLOB_DAT",
    "R_386_GLOB_DAT",
    "R_AARCH64_GLOB_DAT",
}


def sha256_file(path: str) -> str:
    """Return the hex SHA-256 digest of a file's contents."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass
class ScanResult:
    path: str
    sha256: str
    size_bytes: int
    arch: str
    elf_class: str
    is_pie: bool
    entry_point: int
    needed: List[str] = field(default_factory=list)
    rpath: List[str] = field(default_factory=list)
    runpath: List[str] = field(default_factory=list)
    soname: Optional[str] = None
    relro: str = "none"  # "none" | "partial" | "full"
    bind_now: bool = False
    nx: bool = True
    symbols: List[Dict[str, Any]] = field(default_factory=list)
    ifunc_symbols: List[Dict[str, Any]] = field(default_factory=list)
    relocations: List[Dict[str, Any]] = field(default_factory=list)
    exec_segments: List[Dict[str, int]] = field(default_factory=list)
    findings: List[Dict[str, str]] = field(default_factory=list)
    schema_version: int = SCHEMA_VERSION

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "path": self.path,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "arch": self.arch,
            "elf_class": self.elf_class,
            "is_pie": self.is_pie,
            "entry_point": self.entry_point,
            "needed": self.needed,
            "rpath": self.rpath,
            "runpath": self.runpath,
            "soname": self.soname,
            "relro": self.relro,
            "bind_now": self.bind_now,
            "nx": self.nx,
            "symbols": self.symbols,
            "ifunc_symbols": self.ifunc_symbols,
            "relocations": self.relocations,
            "exec_segments": self.exec_segments,
            "findings": self.findings,
        }


# pyelftools resolves the string-table-backed value for a handful of DT_*
# tags and stashes it as a named attribute on `tag.entry` (not on the tag
# object itself). This maps DT_* tag name -> that attribute name.
_TAG_ENTRY_FIELD = {
    "DT_NEEDED": "needed",
    "DT_RPATH": "rpath",
    "DT_RUNPATH": "runpath",
    "DT_SONAME": "soname",
}


def _dynamic_tag_strings(elffile: "ELFFile", tag_name: str) -> List[str]:
    """Return string values (e.g. NEEDED, RPATH) for a given DT_* tag."""
    field = _TAG_ENTRY_FIELD.get(tag_name)
    if field is None:
        return []
    out: List[str] = []
    for section in elffile.iter_sections():
        if not isinstance(section, DynamicSection):
            continue
        for tag in section.iter_tags():
            if tag.entry.d_tag == tag_name:
                val = getattr(tag.entry, field, None)
                if val:
                    out.append(val)
    return out


def _get_dynamic_section(elffile: "ELFFile") -> Optional[DynamicSection]:
    for section in elffile.iter_sections():
        if isinstance(section, DynamicSection):
            return section
    return None


def _check_relro(elffile: "ELFFile") -> str:
    has_gnu_relro = any(
        seg["p_type"] == "PT_GNU_RELRO" for seg in elffile.iter_segments()
    )
    if not has_gnu_relro:
        return "none"
    dyn = _get_dynamic_section(elffile)
    if dyn is None:
        return "partial"
    for tag in dyn.iter_tags():
        if tag.entry.d_tag == "DT_BIND_NOW":
            return "full"
        if tag.entry.d_tag == "DT_FLAGS_1" and (tag.entry.d_val & 0x1):  # DF_1_NOW
            return "full"
        if tag.entry.d_tag == "DT_FLAGS" and (tag.entry.d_val & 0x8):  # DF_BIND_NOW
            return "full"
    return "partial"


def _check_bind_now(elffile: "ELFFile") -> bool:
    dyn = _get_dynamic_section(elffile)
    if dyn is None:
        return False
    for tag in dyn.iter_tags():
        if tag.entry.d_tag == "DT_BIND_NOW":
            return True
        if tag.entry.d_tag == "DT_FLAGS_1" and (tag.entry.d_val & 0x1):
            return True
        if tag.entry.d_tag == "DT_FLAGS" and (tag.entry.d_val & 0x8):
            return True
    return False


def _check_nx(elffile: "ELFFile") -> bool:
    for seg in elffile.iter_segments():
        if seg["p_type"] == "PT_GNU_STACK":
            return not bool(seg["p_flags"] & 0x1)  # PF_X
    # No PT_GNU_STACK header at all is itself an anomaly (older/odd toolchains
    # aside); treat as "not confirmed NX" rather than silently assuming safe.
    return False


def _exec_segments(elffile: "ELFFile") -> List[Dict[str, int]]:
    segs = []
    for seg in elffile.iter_segments():
        if seg["p_type"] == "PT_LOAD" and (seg["p_flags"] & 0x1):  # PF_X
            segs.append(
                {
                    "vaddr": seg["p_vaddr"],
                    "memsz": seg["p_memsz"],
                    "offset": seg["p_offset"],
                }
            )
    return segs


def _addr_in_exec_segment(addr: int, exec_segments: Iterable[Dict[str, int]]) -> bool:
    for seg in exec_segments:
        if seg["vaddr"] <= addr < seg["vaddr"] + seg["memsz"]:
            return True
    return False


def _extract_symbols(elffile: "ELFFile") -> List[Dict[str, Any]]:
    symbols: List[Dict[str, Any]] = []
    for section in elffile.iter_sections():
        if not isinstance(section, SymbolTableSection):
            continue
        section_name = section.name
        for sym in section.iter_symbols():
            if not sym.name:
                continue
            info = sym["st_info"]
            symbols.append(
                {
                    "name": sym.name,
                    "value": sym["st_value"],
                    "size": sym["st_size"],
                    "type": info.type,
                    "bind": info.bind,
                    "visibility": sym["st_other"]["visibility"],
                    "section_table": section_name,
                    "shndx": sym["st_shndx"],
                }
            )
    return symbols


def _extract_relocations(elffile: "ELFFile") -> List[Dict[str, Any]]:
    relocs: List[Dict[str, Any]] = []
    symtab = elffile.get_section_by_name(".dynsym") or elffile.get_section_by_name(
        ".symtab"
    )
    for section in elffile.iter_sections():
        if not isinstance(section, RelocationSection):
            continue
        for reloc in section.iter_relocations():
            sym_name = None
            if symtab is not None:
                sym_idx = reloc["r_info_sym"]
                if 0 <= sym_idx < symtab.num_symbols():
                    sym = symtab.get_symbol(sym_idx)
                    sym_name = sym.name or None
            relocs.append(
                {
                    "section": section.name,
                    "offset": reloc["r_offset"],
                    "type_id": reloc["r_info_type"],
                    "symbol": sym_name,
                    "addend": reloc["r_addend"] if section.is_RELA() else None,
                }
            )
    return relocs


def _reloc_type_name(elffile: "ELFFile", type_id: int) -> str:
    from elftools.elf.enums import ENUM_RELOC_TYPE_x64, ENUM_RELOC_TYPE_i386, ENUM_RELOC_TYPE_AARCH64

    arch = elffile.get_machine_arch()
    table = {
        "x64": ENUM_RELOC_TYPE_x64,
        "x86": ENUM_RELOC_TYPE_i386,
        "AArch64": ENUM_RELOC_TYPE_AARCH64,
    }.get(arch)
    if not table:
        return str(type_id)
    for name, val in table.items():
        if val == type_id:
            return name
    return str(type_id)


def scan_file(path: str) -> Dict[str, Any]:
    """Scan a single ELF file and return a JSON-serializable snapshot dict."""
    if not os.path.isfile(path):
        raise FileNotFoundError(path)

    digest = sha256_file(path)
    size_bytes = os.path.getsize(path)

    with open(path, "rb") as f:
        elffile = ELFFile(f)

        arch = elffile.get_machine_arch()
        elf_class = f"ELF{elffile.elfclass}"
        elf_type = elffile.header["e_type"]
        is_pie = elf_type == "ET_DYN"
        entry_point = elffile.header["e_entry"]

        needed = _dynamic_tag_strings(elffile, "DT_NEEDED")
        rpath = _dynamic_tag_strings(elffile, "DT_RPATH")
        runpath = _dynamic_tag_strings(elffile, "DT_RUNPATH")
        soname_list = _dynamic_tag_strings(elffile, "DT_SONAME")
        soname = soname_list[0] if soname_list else None

        relro = _check_relro(elffile)
        bind_now = _check_bind_now(elffile)
        nx = _check_nx(elffile)
        exec_segments = _exec_segments(elffile)

        all_symbols = _extract_symbols(elffile)
        ifunc_symbols = [s for s in all_symbols if s["type"] == "STT_GNU_IFUNC"]

        raw_relocs = _extract_relocations(elffile)
        relocations = []
        for r in raw_relocs:
            type_name = _reloc_type_name(elffile, r["type_id"])
            relocations.append(
                {
                    "section": r["section"],
                    "offset": r["offset"],
                    "type": type_name,
                    "symbol": r["symbol"],
                    "addend": r["addend"],
                    "is_indirect": type_name in _INDIRECT_RELOC_TYPE_NAMES,
                    "is_plt_slot": type_name in _PLT_RELOC_TYPE_NAMES,
                    "is_glob_dat": type_name in _GLOBAL_DATA_RELOC_TYPE_NAMES,
                }
            )

    findings = _analyze_structural_findings(
        ifunc_symbols=ifunc_symbols,
        relocations=relocations,
        exec_segments=exec_segments,
        relro=relro,
        bind_now=bind_now,
        nx=nx,
        rpath=rpath,
        runpath=runpath,
    )

    result = ScanResult(
        path=os.path.abspath(path),
        sha256=digest,
        size_bytes=size_bytes,
        arch=arch,
        elf_class=elf_class,
        is_pie=is_pie,
        entry_point=entry_point,
        needed=needed,
        rpath=rpath,
        runpath=runpath,
        soname=soname,
        relro=relro,
        bind_now=bind_now,
        nx=nx,
        symbols=all_symbols,
        ifunc_symbols=ifunc_symbols,
        relocations=relocations,
        exec_segments=exec_segments,
        findings=findings,
    )
    return result.to_dict()


def _analyze_structural_findings(
    *,
    ifunc_symbols: List[Dict[str, Any]],
    relocations: List[Dict[str, Any]],
    exec_segments: List[Dict[str, int]],
    relro: str,
    bind_now: bool,
    nx: bool,
    rpath: List[str],
    runpath: List[str],
) -> List[Dict[str, str]]:
    """Single-file structural observations (not baseline-relative drift).

    These are informational/hardening findings visible from one binary in
    isolation. Cross-build tamper detection (new/changed IFUNCs, hijacked
    relocations, weakened hardening relative to a known-good build) belongs
    in diff_engine, which compares two scans.
    """
    findings: List[Dict[str, str]] = []

    if ifunc_symbols:
        findings.append(
            {
                "severity": "INFO",
                "code": "IFUNC_PRESENT",
                "message": (
                    f"{len(ifunc_symbols)} STT_GNU_IFUNC resolver symbol(s) present: "
                    + ", ".join(s["name"] for s in ifunc_symbols[:10])
                    + (" ..." if len(ifunc_symbols) > 10 else "")
                ),
            }
        )

    indirect_outside_exec = [
        r
        for r in relocations
        if r["is_indirect"]
        and r["addend"] is not None
        and not _addr_in_exec_segment(r["addend"], exec_segments)
    ]
    if indirect_outside_exec:
        findings.append(
            {
                "severity": "WARNING",
                "code": "IRELATIVE_TARGET_OUTSIDE_EXEC",
                "message": (
                    f"{len(indirect_outside_exec)} IRELATIVE relocation(s) resolve to an "
                    "address outside any executable segment, which is unusual for a "
                    "legitimate IFUNC resolver."
                ),
            }
        )

    if relro == "none":
        findings.append(
            {
                "severity": "WARNING",
                "code": "NO_RELRO",
                "message": (
                    "Binary has no GNU_RELRO segment; GOT is fully writable after "
                    "relocation, which weakens resistance to GOT-overwrite hooking."
                ),
            }
        )
    elif relro == "partial" and not bind_now:
        findings.append(
            {
                "severity": "INFO",
                "code": "PARTIAL_RELRO",
                "message": (
                    "Binary has partial RELRO only (no BIND_NOW); the PLT GOT region "
                    "remains writable until first call."
                ),
            }
        )

    if not nx:
        findings.append(
            {
                "severity": "WARNING",
                "code": "STACK_EXECUTABLE",
                "message": "PT_GNU_STACK marks the stack executable (or is missing/ambiguous).",
            }
        )

    if rpath:
        findings.append(
            {
                "severity": "WARNING",
                "code": "DT_RPATH_PRESENT",
                "message": (
                    f"DT_RPATH set ({', '.join(rpath)}); RPATH takes precedence over "
                    "LD_LIBRARY_PATH and can be used to smuggle in attacker-controlled "
                    "libraries. Prefer DT_RUNPATH or no runtime search path at all."
                ),
            }
        )

    for rp in runpath:
        if rp.startswith(".") or "$ORIGIN" in rp:
            findings.append(
                {
                    "severity": "INFO",
                    "code": "RELATIVE_RUNPATH",
                    "message": (
                        f"DT_RUNPATH contains a relative or $ORIGIN-relative entry ({rp}); "
                        "verify this cannot be repointed by an attacker who controls the "
                        "install layout."
                    ),
                }
            )

    return findings


def scan_directory(root: str, recursive: bool = True) -> List[Dict[str, Any]]:
    """Scan every ELF file under `root`, skipping files that aren't ELF."""
    results = []
    walker = os.walk(root) if recursive else [(root, [], os.listdir(root))]
    for dirpath, _dirs, files in walker:
        for name in files:
            full = os.path.join(dirpath, name)
            if not os.path.isfile(full):
                continue
            try:
                with open(full, "rb") as f:
                    if f.read(4) != b"\x7fELF":
                        continue
            except OSError:
                continue
            try:
                results.append(scan_file(full))
            except Exception as exc:  # noqa: BLE001 - report and continue
                results.append(
                    {
                        "path": os.path.abspath(full),
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                )
    return results
