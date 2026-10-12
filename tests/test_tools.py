"""Testes unitarios de nexus_tools (Fase 1: sanitizacao, parser, proxy)."""

from __future__ import annotations

import unittest

import nexus_tools as NT


class TestCommandSanitization(unittest.TestCase):
    def test_target_shlex_quoted(self):
        evil = "127.0.0.1$(reboot)"
        cmd = NT.TOOL_BY_ID["nmap"].command(evil, "", "light")
        self.assertEqual(cmd, f"nmap -T4 -F '{evil}'")

    def test_target_comillas_neutralizadas(self):
        cmd = NT.TOOL_BY_ID["nuclei"].command('https://x";id;', "", "light")
        self.assertIn("'https://x\";id;'", cmd)
        self.assertNotIn("\";id;\";", cmd)

    def test_extra_permanece_fragmento_shell(self):
        cmd = NT.TOOL_BY_ID["nmap"].command("10.0.0.1 22", "-Pn -p 22", "light")
        self.assertIn("-Pn -p 22", cmd)
        self.assertIn("'10.0.0.1 22'", cmd)

    def test_alvo_vazio(self):
        cmd = NT.TOOL_BY_ID["openssl"].command("", "", "light")
        self.assertNotIn("''", cmd)

    def test_sqlmap_sem_aspas_duplas_no_artefato(self):
        cmd = NT.TOOL_BY_ID["sqlmap"].command(
            "http://alvo?id=1&a=2", "", "light")
        self.assertIn("'http://alvo?id=1&a=2'", cmd)

    def test_consent_categorias(self):
        self.assertTrue(NT.TOOL_BY_ID["sqlmap"].requires_consent())
        self.assertTrue(NT.TOOL_BY_ID["wifite2"].requires_consent())
        self.assertFalse(NT.TOOL_BY_ID["nmap"].requires_consent())


class TestParseReport(unittest.TestCase):
    def test_nmap_hosts_e_portas(self):
        out = """Starting Nmap ...
Nmap scan report for 10.0.0.1
PORT     STATE SERVICE
22/tcp   open  ssh
443/tcp  open  https
Nmap scan report for 10.0.0.2
Nmap done."""
        items = NT.parse_report("nmap", out)
        kinds = {k for k, _, _ in items}
        self.assertIn("host", kinds)
        self.assertIn("porta", kinds)
        ports = [(t, d) for k, t, d in items if k == "porta"]
        self.assertIn(("22/tcp", "ssh"), ports)
        self.assertIn(("443/tcp", "https"), ports)

    def test_nuclei_achados(self):
        out = """[https://exemplo.com] [critical] CVE-2020-XYZ RCE
[https://exemplo.com] [medium] Sensitive Cookie"""
        items = NT.parse_report("nuclei", out)
        self.assertEqual(len(items), 2)
        self.assertEqual(items[0][1], "CVE-2020-XYZ RCE")
        self.assertIn("critical", items[0][2])

    def test_nikto(self):
        items = NT.parse_report("nikto", "+ /etc/passwd?")
        self.assertEqual(items[0][1], "/etc/passwd?")


class TestProxy(unittest.TestCase):
    def test_burp_env(self):
        cmd, env = NT.wrap_proxy("nuclei -u X", "burp")
        self.assertIn("http://127.0.0.1:8080", env["HTTP_PROXY"])

    def test_tor_eh_torsocks_ou_env(self):
        cmd, env = NT.wrap_proxy("nmap X", "tor")
        ok = cmd.startswith("torsocks") or ("ALL_PROXY" in env)
        self.assertTrue(ok)


class TestMisc(unittest.TestCase):
    def test_looks_like_url(self):
        self.assertTrue(NT.looks_like_url("https://exemplo.com/a"))
        self.assertFalse(NT.looks_like_url("10.0.0.1"))

    def test_categorias_tem_historico(self):
        ids = [c for c, _ in NT.CATEGORIES]
        self.assertIn("HISTORICO", ids)


if __name__ == "__main__":
    unittest.main()