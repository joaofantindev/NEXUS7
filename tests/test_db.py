"""Testes do motor de dados (Fase 2: SQLite)."""

from __future__ import annotations

import os
import tempfile
import unittest

_tmp = tempfile.mkdtemp(prefix="nexus7test_")
os.environ["NEXUS7_DATA_DIR"] = _tmp
os.environ["NEXUS7_CONFIG_DIR"] = _tmp

import nexus_db as NDB  # noqa: E402


class TestDB(unittest.TestCase):
    def setUp(self):
        NDB.init_db()

    def test_scan_ciclo(self):
        sid = NDB.add_scan("nmap", "Nmap", "light", "10.0.0.1", "", "direto")
        self.assertIsInstance(sid, int)
        NDB.finish_scan(sid, 0)
        scan = NDB.get_scan(sid)
        self.assertEqual(scan["tool_id"], "nmap")
        self.assertEqual(scan["status"], "done")
        self.assertIsNotNone(scan["finished_at"])

    def test_resultados(self):
        sid = NDB.add_scan("nmap", "Nmap", "advanced", "10.0.0.1", "", "tor")
        items = [("host", "10.0.0.1", ""), ("porta", "22/tcp", "ssh")]
        NDB.add_results(sid, items)
        rows = NDB.list_results(sid)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["kind"], "host")

    def test_save_log(self):
        sid = NDB.add_scan("nuclei", "Nuclei", "light", "x", "", "")
        NDB.save_log(sid, "linha 1\nlinha 2")
        self.assertIn("linha 2", NDB.get_scan(sid)["log"])

    def test_targets_recorrentes(self):
        NDB.touch_target("exemplo.com")
        NDB.touch_target("exemplo.com")
        NDB.touch_target("10.0.0.1")
        rec = NDB.recent_targets()
        # ordena por ultimo uso e, em empate, por numero de usos
        self.assertEqual(rec[0], "exemplo.com")
        self.assertEqual(set(rec[:3]), {"exemplo.com", "10.0.0.1"})

    def test_settings(self):
        NDB.set_setting("theme", "GREEN")
        self.assertEqual(NDB.get_setting("theme"), "GREEN")
        self.assertEqual(NDB.get_setting("nao_existe", "padrao"), "padrao")


if __name__ == "__main__":
    unittest.main()