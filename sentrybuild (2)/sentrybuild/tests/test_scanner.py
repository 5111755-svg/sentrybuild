"""Tests for sentrybuild.elf_scanner and sentrybuild.diff_engine.

These tests compile small real ELF fixtures with the system C compiler
(gcc/clang) at test time rather than relying on pre-built binary blobs,
so the suite exercises the actual pyelftools-based parsing path against
real IFUNC resolvers, relocations, and hardening flags. Tests are skipped
if no C compiler is available on the runner.
"""

from __future__ import annotations

import copy
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sentrybuild import diff_engine, elf_scanner  # noqa: E402

CC = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")

SIMPLE_SRC = r"""
#include <stdio.h>
int add(int a, int b) { return a + b; }
int main(void) {
    printf("%d\n", add(2, 3));
    return 0;
}
"""

# A minimal but real IFUNC resolver. `hello` gets resolved at load time to
# one of two implementations depending on resolver logic, which produces a
# genuine STT_GNU_IFUNC symbol and an R_*_IRELATIVE relocation - exactly
# what elf_scanner is meant to detect.
IFUNC_SRC = r"""
#include <stdio.h>

static void hello_v1(void) { puts("v1"); }
static void hello_v2(void) { puts("v2"); }

static void *resolve_hello(void) {
    return (void *)hello_v1;
}

__attribute__((ifunc("resolve_hello")))
void hello(void);

int main(void) {
    hello();
    return 0;
}
"""


def _compile(src: str, out_path: str, extra_args=None) -> None:
    extra_args = extra_args or []
    with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as f:
        f.write(src)
        src_path = f.name
    try:
        subprocess.run(
            [CC, src_path, "-o", out_path, "-no-pie", "-fno-stack-protector"] + extra_args,
            check=True,
            capture_output=True,
            text=True,
        )
    finally:
        os.unlink(src_path)


@unittest.skipUnless(CC, "no C compiler available to build test fixtures")
class TestElfScanner(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp(prefix="sentrybuild-test-")
        cls.simple_bin = os.path.join(cls.tmpdir, "simple")
        cls.ifunc_bin = os.path.join(cls.tmpdir, "ifunc_prog")
        cls.ifunc_bin_full_relro = os.path.join(cls.tmpdir, "ifunc_prog_relro")

        _compile(SIMPLE_SRC, cls.simple_bin)
        _compile(IFUNC_SRC, cls.ifunc_bin, extra_args=["-Wl,-z,norelro"])
        _compile(
            IFUNC_SRC,
            cls.ifunc_bin_full_relro,
            extra_args=["-Wl,-z,relro", "-Wl,-z,now"],
        )

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_scan_file_basic_fields(self):
        result = elf_scanner.scan_file(self.simple_bin)
        self.assertEqual(result["schema_version"], elf_scanner.SCHEMA_VERSION)
        self.assertTrue(result["sha256"])
        self.assertEqual(len(result["sha256"]), 64)
        self.assertGreater(result["size_bytes"], 0)
        self.assertIn(result["arch"], ("x64", "x86", "AArch64"))
        self.assertIsInstance(result["symbols"], list)
        self.assertTrue(len(result["symbols"]) > 0)

    def test_scan_file_missing_raises(self):
        with self.assertRaises(FileNotFoundError):
            elf_scanner.scan_file(os.path.join(self.tmpdir, "does-not-exist"))

    def test_ifunc_symbol_detected(self):
        result = elf_scanner.scan_file(self.ifunc_bin)
        names = [s["name"] for s in result["ifunc_symbols"]]
        self.assertIn("hello", names)

    def test_ifunc_generates_irelative_relocation(self):
        result = elf_scanner.scan_file(self.ifunc_bin)
        indirect = [r for r in result["relocations"] if r["is_indirect"]]
        self.assertGreater(
            len(indirect), 0, "expected at least one IRELATIVE relocation for the ifunc"
        )

    def test_no_relro_flagged(self):
        result = elf_scanner.scan_file(self.ifunc_bin)
        self.assertEqual(result["relro"], "none")
        codes = [f["code"] for f in result["findings"]]
        self.assertIn("NO_RELRO", codes)

    def test_full_relro_bind_now_detected(self):
        result = elf_scanner.scan_file(self.ifunc_bin_full_relro)
        self.assertEqual(result["relro"], "full")
        self.assertTrue(result["bind_now"])
        codes = [f["code"] for f in result["findings"]]
        self.assertNotIn("NO_RELRO", codes)

    def test_scan_directory_finds_elf_and_skips_non_elf(self):
        non_elf = os.path.join(self.tmpdir, "notes.txt")
        with open(non_elf, "w") as f:
            f.write("not an ELF file")

        results = elf_scanner.scan_directory(self.tmpdir, recursive=False)
        paths = {r["path"] for r in results if "path" in r}
        self.assertIn(os.path.abspath(self.simple_bin), paths)
        self.assertNotIn(os.path.abspath(non_elf), paths)


@unittest.skipUnless(CC, "no C compiler available to build test fixtures")
class TestDiffEngine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp(prefix="sentrybuild-diff-test-")
        cls.baseline_bin = os.path.join(cls.tmpdir, "baseline_bin")
        cls.identical_bin = os.path.join(cls.tmpdir, "identical_bin")
        _compile(IFUNC_SRC, cls.baseline_bin, extra_args=["-Wl,-z,norelro"])
        shutil.copyfile(cls.baseline_bin, cls.identical_bin)

        cls.baseline_scan = elf_scanner.scan_file(cls.baseline_bin)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_identical_file_short_circuits(self):
        candidate_scan = elf_scanner.scan_file(self.identical_bin)
        report = diff_engine.diff_scans(self.baseline_scan, candidate_scan)
        self.assertEqual(report["max_severity"], "INFO")
        self.assertEqual([f["code"] for f in report["findings"]], ["IDENTICAL_FILE"])

    def test_new_ifunc_flagged_critical(self):
        base = copy.deepcopy(self.baseline_scan)
        candidate = copy.deepcopy(self.baseline_scan)
        candidate["sha256"] = "0" * 64  # force past the identical-file short circuit
        candidate["ifunc_symbols"] = candidate["ifunc_symbols"] + [
            {
                "name": "evil_resolver",
                "value": 0,
                "size": 0,
                "type": "STT_GNU_IFUNC",
                "bind": "STB_GLOBAL",
                "visibility": "STV_DEFAULT",
                "section_table": ".dynsym",
                "shndx": 1,
            }
        ]
        report = diff_engine.diff_scans(base, candidate)
        codes = [f["code"] for f in report["findings"]]
        self.assertIn("IFUNC_ADDED", codes)
        self.assertEqual(report["max_severity"], "CRITICAL")

    def test_plt_slot_retargeted_flagged_critical(self):
        base = copy.deepcopy(self.baseline_scan)
        candidate = copy.deepcopy(self.baseline_scan)
        candidate["sha256"] = "1" * 64

        # Inject a matching PLT slot pair, then retarget it in the candidate.
        base["relocations"] = base["relocations"] + [
            {
                "section": ".rela.plt",
                "offset": 0x4000,
                "type": "R_X86_64_JUMP_SLOT",
                "symbol": "printf",
                "addend": None,
                "is_indirect": False,
                "is_plt_slot": True,
                "is_glob_dat": False,
            }
        ]
        candidate["relocations"] = candidate["relocations"] + [
            {
                "section": ".rela.plt",
                "offset": 0x4000,
                "type": "R_X86_64_JUMP_SLOT",
                "symbol": "evil_printf_hook",
                "addend": None,
                "is_indirect": False,
                "is_plt_slot": True,
                "is_glob_dat": False,
            }
        ]

        report = diff_engine.diff_scans(base, candidate)
        codes = [f["code"] for f in report["findings"]]
        self.assertIn("PLT_SLOT_RETARGETED", codes)
        self.assertEqual(report["max_severity"], "CRITICAL")

    def test_new_needed_library_flagged_warning(self):
        base = copy.deepcopy(self.baseline_scan)
        candidate = copy.deepcopy(self.baseline_scan)
        candidate["sha256"] = "2" * 64
        candidate["needed"] = candidate["needed"] + ["libtotally-legit.so.1"]

        report = diff_engine.diff_scans(base, candidate)
        codes = [f["code"] for f in report["findings"]]
        self.assertIn("NEEDED_LIBRARY_ADDED", codes)

    def test_rpath_introduced_is_critical(self):
        base = copy.deepcopy(self.baseline_scan)
        candidate = copy.deepcopy(self.baseline_scan)
        candidate["sha256"] = "3" * 64
        base["rpath"] = []
        candidate["rpath"] = ["/tmp/attacker-controlled"]

        report = diff_engine.diff_scans(base, candidate)
        codes = [f["code"] for f in report["findings"]]
        self.assertIn("RPATH_INTRODUCED", codes)
        self.assertEqual(report["max_severity"], "CRITICAL")

    def test_relro_weakened_flagged(self):
        base = copy.deepcopy(self.baseline_scan)
        candidate = copy.deepcopy(self.baseline_scan)
        candidate["sha256"] = "4" * 64
        base["relro"] = "full"
        candidate["relro"] = "none"

        report = diff_engine.diff_scans(base, candidate)
        codes = [f["code"] for f in report["findings"]]
        self.assertIn("RELRO_WEAKENED", codes)

    def test_diff_scan_lists_matches_by_path(self):
        base_list = [self.baseline_scan]
        cand_scan = copy.deepcopy(self.baseline_scan)
        cand_scan["sha256"] = "5" * 64
        report = diff_engine.diff_scan_lists(base_list, [cand_scan])
        self.assertEqual(len(report["reports"]), 1)
        self.assertIn("HASH_CHANGED", [f["code"] for f in report["reports"][0]["findings"]])


class TestCliSmoke(unittest.TestCase):
    """Lightweight CLI tests that don't require compiling fixtures."""

    def test_version_flag(self):
        from sentrybuild.cli import build_parser

        parser = build_parser()
        with self.assertRaises(SystemExit) as ctx:
            parser.parse_args(["--version"])
        self.assertEqual(ctx.exception.code, 0)

    def test_scan_missing_file_returns_error_code(self):
        from sentrybuild.cli import main

        code = main(["scan", "/nonexistent/path/to/binary"])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
