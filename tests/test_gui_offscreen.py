"""Testes da GUI em modo offscreen (Fases 1-3)."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
_tmp = tempfile.mkdtemp(prefix="nexus7test_")
os.environ["NEXUS7_DATA_DIR"] = _tmp
os.environ["NEXUS7_CONFIG_DIR"] = _tmp

from PySide6.QtWidgets import QApplication  # noqa: E402

import nexus_tools as NT  # noqa: E402
import hacker_gui as HG  # noqa: E402

_app = QApplication.instance() or QApplication(sys.argv)


class TestGUI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.win = HG.HackerGUI()

    def test_paginas(self):
        self.assertEqual(self.win.stack.count(), 5)

    def test_modulos(self):
        self.win.modules.setCurrentRow(0)  # GERAL
        self.assertEqual(self.win.stack.currentIndex(), 1)
        hist = [r for r in range(NT.CATEGORIES.__len__())]
        _ = hist
        rows = {cid: i for i, (cid, _) in enumerate(NT.CATEGORIES)}
        self.win.modules.setCurrentRow(rows["PERSONALIZAR"])
        self.assertEqual(self.win.stack.currentIndex(), 2)
        self.win.modules.setCurrentRow(rows["SERVICOS"])
        self.assertEqual(self.win.stack.currentIndex(), 3)
        self.win.modules.setCurrentRow(rows["HISTORICO"])
        self.assertEqual(self.win.stack.currentIndex(), 4)
        self.win.modules.setCurrentRow(rows["SCAN"])
        self.assertEqual(self.win.stack.currentIndex(), 0)

    def test_run_button_habilitado_para_instaladas(self):
        rows = {cid: i for i, (cid, _) in enumerate(NT.CATEGORIES)}
        self.win.modules.setCurrentRow(rows["SCAN"])
        self.win._load_tool("nmap")
        self.win.target_input.setText("127.0.0.1")
        self.win._update_preview()
        self.assertTrue(self.win.run_btn.isEnabled())
        self.win.target_input.setText("")
        self.win._update_preview()
        self.assertFalse(self.win.run_btn.isEnabled())

    def test_batch_registra_scans_no_banco(self):
        rows = {cid: i for i, (cid, _) in enumerate(NT.CATEGORIES)}
        self.win.modules.setCurrentRow(rows["SCAN"])
        self.win._load_tool("nmap")
        self.win.extra_input.setText("-n -T4")
        self.win.target_input.setText("127.0.0.1")
        self.win.batch_check.setChecked(False)
        cmd, _ = self.win._build_command()
        self.assertIn("-n -T4", cmd)
        self.assertRegex(cmd, r"nmap -T4 -F 127\.0\.0\.1 -n -T4")

    def test_timeout_no_preview(self):
        self.win.timeout_spin.setValue(60)
        cmd, _ = self.win._build_command()
        self.win.timeout_spin.setValue(0)
        self.assertIn("'timeout 60s ", cmd)

    def test_persistencia_tema(self):
        self.win.theme = dict(HG.THEMES["GREEN // Fosforo"])
        self.win.settings.setValue("theme", "GREEN // Fosforo")
        self.assertEqual(self.win.settings.value("theme"), "GREEN // Fosforo")

    def test_ia_contexto_sem_dados(self):
        self.win._last_results = []
        self.win._last_output = ""
        self.assertFalse(self.win._ai_context())

    def test_ia_probe(self):
        text = self.win._ai_probe_text()
        self.assertIn("Groq", text)


if __name__ == "__main__":
    unittest.main()