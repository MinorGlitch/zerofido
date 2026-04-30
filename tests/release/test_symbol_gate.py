"""Unit tests for FAP symbol-budget parsing and release artifact stripping."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tests.harness import ROOT, load_module

symbol_gate = load_module("check_symbol_gate", ROOT / "host_tools" / "check_symbol_gate.py")


RAW_FAP_SECTIONS = """
Section Headers:
  [ 1] .text             PROGBITS        00000000 000038 014b2c 00  AX  0   0  8
  [ 2] .rel.text         REL             00000000 02827c 005bc0 08   I 12   1  4
  [ 9] .fast.rel.text    PROGBITS        00000000 016e44 00445f 00      0   0  1
  [12] .symtab           SYMTAB          00000000 01b614 007f30 10     13 1481  4
  [13] .strtab           STRTAB          00000000 023544 004d35 00      0   0  1
"""

RAW_FAP_SYMBOLS = """
Symbol table '.symtab' contains 1843 entries:
   Num:    Value  Size Type    Bind   Vis      Ndx Name
  1777: 00000495   120 FUNC    GLOBAL DEFAULT    1 zf_ctap_parse_get_assertion
  1839: 00000001    28 FUNC    GLOBAL DEFAULT    1 zerofido_main
"""

OPTIMIZED_FAP_SECTIONS = """
Section Headers:
  [ 1] .text             PROGBITS        00000000 000038 014b2c 00  AX  0   0  8
  [ 6] .fast.rel.text    PROGBITS        00000000 016e44 00445f 00      0   0  1
  [ 9] .symtab           SYMTAB          00000000 01b614 000020 10     10   1  4
  [10] .strtab           STRTAB          00000000 01b634 00000f 00      0   0  1
"""

OPTIMIZED_FAP_SYMBOLS = """
Symbol table '.symtab' contains 2 entries:
   Num:    Value  Size Type    Bind   Vis      Ndx Name
     1: 0000f01d    92 FUNC    GLOBAL DEFAULT    1 zerofido_main
"""


class SymbolGateTests(unittest.TestCase):
    def test_raw_fap_violates_export_and_table_budgets(self) -> None:
        sections = symbol_gate.parse_readelf_sections(RAW_FAP_SECTIONS)
        symbols = symbol_gate.parse_readelf_symbols(RAW_FAP_SYMBOLS)

        violations = symbol_gate.fap_budget_violations(sections, symbols)

        self.assertTrue(any("unexpected globally defined" in item for item in violations))
        self.assertTrue(any("standard relocation sections remain" in item for item in violations))
        self.assertTrue(any(".symtab budget exceeded" in item for item in violations))
        self.assertTrue(any(".strtab budget exceeded" in item for item in violations))

    def test_optimized_fap_fits_export_and_table_budgets(self) -> None:
        sections = symbol_gate.parse_readelf_sections(OPTIMIZED_FAP_SECTIONS)
        symbols = symbol_gate.parse_readelf_symbols(OPTIMIZED_FAP_SYMBOLS)

        self.assertEqual(symbol_gate.fap_budget_violations(sections, symbols), [])

    def test_package_optimized_fap_copies_source_before_stripping(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "zerofido.fap"
            output = Path(temp_dir) / "release" / "zerofido.fap"
            source.write_bytes(b"raw fap bytes")

            with mock.patch.object(symbol_gate, "optimize_fap_exports") as optimize:
                symbol_gate.package_optimized_fap("objcopy", "readelf", source, output)

            self.assertEqual(output.read_bytes(), b"raw fap bytes")
            optimize.assert_called_once_with("objcopy", "readelf", output)

    def test_output_fap_argument_is_parsed(self) -> None:
        args = symbol_gate.parse_args(
            ["--fap", "dist/zerofido.fap", "--output-fap", "dist/zerofido-release.fap"]
        )

        self.assertEqual(args.fap, Path("dist/zerofido.fap"))
        self.assertEqual(args.output_fap, Path("dist/zerofido-release.fap"))


if __name__ == "__main__":
    unittest.main()
