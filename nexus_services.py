"""NEXUS-7 - controlador de servicos de infraestrutura.

Permite ligar/desligar todos os servicos (ou um a um) com um clique:

  * Tor     - proxy SOCKS5 (anonimato)      -> porta 9050
  * Burp    - proxy de interceptacao        -> porta 8080
  * gvmd    - OpenVAS/GVM manager           (socket)
  * gsad    - OpenVAS web UI                -> porta 9392
  * ospd    - OpenVAS scanner               (socket)

Servicos systemd usam `pkexec` (prompt grafico nativo). Processos como o Burp
sao iniciados/encerrados como o proprio usuario.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass


def which(name: str) -> str | None:
    return shutil.which(name)


@dataclass
class Service:
    id: str
    name: str
    desc: str
    kind: str            # "systemd" | "proc"
    unit: str = ""       # usado quando kind == systemd
    pattern: str = ""    # usado quando kind == proc (pgrep)
    check: str = ""      # binario que indica presenca
    port: int = 0
    url: str = ""

    def installed(self) -> bool:
        if not self.check:
            return True
        return which(self.check) is not None

    def status(self) -> str:
        """'running' | 'stopped' | 'missing' | 'unknown'."""
        if not self.installed():
            return "missing"
        try:
            if self.kind == "systemd":
                r = subprocess.run(["systemctl", "is-active", self.unit],
                                   capture_output=True, text=True, timeout=5)
                return "running" if r.stdout.strip() == "active" else "stopped"
            else:
                r = subprocess.run(["pgrep", "-f", self.pattern],
                                   stdout=subprocess.DEVNULL, timeout=5)
                return "running" if r.returncode == 0 else "stopped"
        except Exception:
            return "unknown"


SERVICES: list[Service] = [
    Service(
        id="tor", name="Tor", kind="systemd", unit="tor",
        desc="Proxy SOCKS5 para anonimato (torsocks/proxychains).",
        check="tor", port=9050,
    ),
    Service(
        id="burp", name="Burp Suite", kind="proc", pattern="burpsuite",
        desc="Proxy de interceptacao e scanner web.",
        check="burpsuite", port=8080,
        url="http://127.0.0.1:8080",
    ),
    Service(
        id="gvmd", name="OpenVAS/GVM manager", kind="systemd", unit="gvmd",
        desc="Gerencia alvos, tarefas e resultados de scan.",
        check="gvmd",
    ),
    Service(
        id="gsad", name="OpenVAS web UI", kind="systemd", unit="gsad",
        desc="Painel web da suite Greenbone.",
        check="gsad", port=9392,
        url="https://127.0.0.1:9392",
    ),
    Service(
        id="ospd-openvas", name="OpenVAS scanner", kind="systemd", unit="ospd-openvas",
        desc="Motor de varredura OpenVAS.",
        check="ospd-openvas",
    ),
]


def launch(svc: Service, action: str) -> tuple[list[str], str]:
    """Retorna (programa, args) para iniciar/parar um servico."""
    if svc.kind == "systemd":
        return ["pkexec", "systemctl", action, svc.unit], ""
    if action == "start":
        return ["bash", "-lc", f"nohup {svc.check} >/dev/null 2>&1 &"], ""
    pat = f"[{svc.pattern[0]}]{svc.pattern[1:]}" if svc.pattern else svc.pattern
    return ["bash", "-lc", f"pkill -f {pat}"], ""