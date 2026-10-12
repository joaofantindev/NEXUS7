"""NEXUS-7 - Registro de ferramentas (o "canivete suico").

Cada Tool descreve:
  - como detectar se esta instalada (binario no PATH) ou disponivel no codigo-fonte (pasta repos/);
  - templates de comando em modo LEVE e AVANCADO;
  - se aceita proxy (Tor / Burp), sudo e execucao interativa.

Os templates usam os placeholders {target} e {extra}.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path

BASE = Path(__file__).resolve().parent
REPOS = BASE / "repos"


def which(name: str) -> str | None:
    return shutil.which(name)


def is_root() -> bool:
    import os
    return os.geteuid() == 0


# --------------------------------------------------------------------------- #
# Categorias
# --------------------------------------------------------------------------- #
# (id, rotulo)
CATEGORIES = [
    ("GERAL", "Modo geral / assistente"),
    ("OSINT", "Vigilancia e OSINT"),
    ("SCAN", "Scan e analise de infra"),
    ("EXPLOIT", "Exploracao"),
    ("MALWARE", "Analise de malware"),
    ("WIRELESS", "Wi-Fi / Radio"),
    ("SENSING", "RF sensing (RuView)"),
    ("CRYPTO", "Criptografia"),
    ("SERVICOS", "Servicos (infra)"),
    ("PERSONALIZAR", "Temas e fontes"),
]


# --------------------------------------------------------------------------- #
# Modelo de ferramenta
# --------------------------------------------------------------------------- #
@dataclass
class Tool:
    id: str
    name: str
    category: str
    description: str
    target_label: str = "Alvo"
    target_placeholder: str = ""
    needs_target: bool = True
    light: str = ""
    advanced: str = ""
    repo_light: str = ""
    repo_advanced: str = ""
    supports_proxy: bool = False
    needs_root: bool = False
    interactive: bool = False
    bin: str = ""
    repo: str = ""
    install: str = ""
    extra_hint: str = ""

    # -- deteccao ---------------------------------------------------------- #
    def status(self) -> str:
        """'installed' | 'source' | 'missing'."""
        if self.bin and which(self.bin):
            return "installed"
        if self.repo and (REPOS / self.repo).exists():
            return "source"
        return "missing"

    def template(self, mode: str) -> str:
        st = self.status()
        if st == "installed":
            tpl = self.light if mode == "light" else self.advanced
        elif st == "source":
            tpl = self.repo_light if mode == "light" else self.repo_advanced
            if not tpl:
                tpl = self.light if mode == "light" else self.advanced
        else:
            tpl = self.light if mode == "light" else self.advanced
        return tpl or ""

    def command(self, target: str = "", extra: str = "", mode: str = "light") -> str:
        tpl = self.template(mode)
        if not tpl:
            return ""
        cmd = tpl.replace("{target}", target or "").replace("{extra}", extra or "")
        while "  " in cmd:
            cmd = cmd.replace("  ", " ")
        return cmd.strip()


# --------------------------------------------------------------------------- #
# Ferramentas
# --------------------------------------------------------------------------- #
TOOLS: list[Tool] = [
    # ---------------------------- OSINT ---------------------------------- #
    Tool(
        id="amass", name="Amass", category="OSINT",
        description="Enumeracao de DNS e mapeamento de superficie de ataque (Go).",
        target_label="Dominio", target_placeholder="exemplo.com",
        light="amass enum -passive -d {target} {extra}",
        advanced="amass enum -active -d {target} -brute {extra}",
        repo_light="cd repos/amass && go run ./cmd/amass enum -passive -d {target} {extra}",
        repo_advanced="cd repos/amass && go run ./cmd/amass enum -active -d {target} -brute {extra}",
        supports_proxy=True, bin="amass", repo="amass",
        install="go install -v github.com/owasp-amass/amass/v4/...@master && ln -sf ~/go/bin/amass ~/.local/bin/amass",
    ),
    Tool(
        id="theharvester", name="theHarvester", category="OSINT",
        description="Coleta de e-mails, subdominios e nomes de pessoas.",
        target_label="Dominio", target_placeholder="exemplo.com",
        light="theHarvester -d {target} -b duckduckgo {extra}",
        advanced="theHarvester -d {target} -b all -l 300 {extra}",
        supports_proxy=True, bin="theHarvester", repo="theHarvester",
        install="python3 -m pip install --user -e repos/theHarvester",
    ),
    Tool(
        id="spiderfoot", name="SpiderFoot", category="OSINT",
        description="Automacao de OSINT integrando centenas de fontes.",
        target_label="Dominio / IP / E-mail", target_placeholder="exemplo.com",
        light="spiderfoot -s {target} {extra}",
        advanced="spiderfoot -s {target} -m all -q {extra}",
        repo_light="cd repos/spiderfoot && python3 sf.py -s {target} {extra}",
        repo_advanced="cd repos/spiderfoot && python3 sf.py -s {target} -m all {extra}",
        supports_proxy=True, bin="spiderfoot", repo="spiderfoot",
        install="python3 -m pip install --user -r repos/spiderfoot/requirements.txt",
    ),
    Tool(
        id="user-scanner", name="user-scanner", category="OSINT",
        description="Suite OSINT de e-mail/username (2720+ vetores).",
        target_label="Usuario / E-mail", target_placeholder="johndoe ou john@mail.com",
        light="user-scanner -u {target} {extra}",
        advanced="user-scanner -u {target} --cross-scan {extra}",
        repo_light="cd repos/user-scanner && python3 -m user_scanner -u {target} {extra}",
        repo_advanced="cd repos/user-scanner && python3 -m user_scanner -u {target} --cross-scan {extra}",
        supports_proxy=True, bin="user-scanner", repo="user-scanner",
        install="pipx install user-scanner",
    ),
    # ---------------------------- SCAN ----------------------------------- #
    Tool(
        id="nmap", name="Nmap", category="SCAN",
        description="Descoberta de hosts e varredura de portas/servicos.",
        target_label="IP / Host / Rede", target_placeholder="10.0.0.1 ou 10.0.0.0/24",
        light="nmap -T4 -F {target} {extra}",
        advanced="nmap -sS -sV -sC -O -T4 -p- {target} {extra}",
        needs_root=True, bin="nmap", repo="nmap",
        install="sudo pacman -S nmap",
    ),
    Tool(
        id="nuclei", name="Nuclei", category="SCAN",
        description="Scanner de vulnerabilidades baseado em templates YAML (Go).",
        target_label="URL / Host", target_placeholder="https://exemplo.com",
        light="nuclei -u {target} -silent {extra}",
        advanced="nuclei -u {target} -severity low,medium,high,critical -stats {extra}",
        repo_light="cd repos/nuclei && go run ./cmd/nuclei -u {target} -silent {extra}",
        supports_proxy=True, bin="nuclei", repo="nuclei",
        install="go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    ),
    Tool(
        id="nikto", name="Nikto", category="SCAN",
        description="Arquivos perigosos e software desatualizado em servidores web.",
        target_label="URL / Host", target_placeholder="https://exemplo.com",
        light="nikto -h {target} {extra}",
        advanced="nikto -h {target} -Tuning 123bde -Display V {extra}",
        repo_light="cd repos/nikto/program && perl nikto.pl -h {target} {extra}",
        supports_proxy=True, bin="nikto", repo="nikto",
        install="sudo pacman -S nikto",
    ),
    Tool(
        id="openvas", name="OpenVAS / GVM", category="SCAN",
        description="Framework completo de gestao e scanning de vulnerabilidades.",
        target_label="Host (opcional)", target_placeholder="10.0.0.1",
        needs_target=False,
        light="gvm-check-setup",
        advanced="sudo systemctl start gvmd gsad ospd-openvas",
        bin="gvm-cli", repo="openvas-scanner",
        install="AUR (compilacao longa): yay -S gvm-libs gvmd gsa gsad openvas-scanner python-gvm",
    ),
    # --------------------------- EXPLOIT --------------------------------- #
    Tool(
        id="sqlmap", name="SQLMap", category="EXPLOIT",
        description="Automacao de injecao de SQL e takeover de banco de dados.",
        target_label="URL com parametro", target_placeholder="http://alvo/item.php?id=1",
        light="sqlmap -u \"{target}\" --batch --random-agent {extra}",
        advanced="sqlmap -u \"{target}\" --batch --level 5 --risk 3 --dbs {extra}",
        repo_light="cd repos/sqlmap && python3 sqlmap.py -u \"{target}\" --batch {extra}",
        supports_proxy=True, bin="sqlmap", repo="sqlmap",
        install="sudo pacman -S sqlmap",
    ),
    Tool(
        id="metasploit", name="Metasploit Framework", category="EXPLOIT",
        description="Plataforma para desenvolvimento e execucao de exploits.",
        target_label="Termo de busca", target_placeholder="ex: vsftpd",
        light="msfconsole -q -x 'version; exit'",
        advanced="msfconsole -q -x 'db_status; search {target}; exit'",
        interactive=True, bin="msfconsole", repo="metasploit-framework",
        install="sudo pacman -S metasploit",
    ),
    Tool(
        id="beef", name="BeEF", category="EXPLOIT",
        description="Browser Exploitation Framework (lado cliente/navegador).",
        target_label="Alvo (opcional)", target_placeholder="",
        needs_target=False, interactive=True,
        light="cd repos/beef && ./beef",
        advanced="cd repos/beef && ./beef -c config.yaml",
        bin="beef", repo="beef",
        install="yay -S beef",
    ),
    # --------------------------- MALWARE --------------------------------- #
    Tool(
        id="cuckoo", name="Cuckoo Sandbox", category="MALWARE",
        description="Analise de malware em ambiente isolado.",
        target_label="Arquivo da amostra", target_placeholder="/caminho/amostra.exe",
        light="cuckoo submit {target}",
        advanced="cuckoo submit --timeout 120 {target}",
        repo_light="cd repos/cuckoo && python3 -m cuckoo submit {target}",
        bin="cuckoo", repo="cuckoo",
        install="pipx install cuckoo",
    ),
    # --------------------------- WIRELESS -------------------------------- #
    Tool(
        id="aircrack-ng", name="Aircrack-ng", category="WIRELESS",
        description="Auditoria Wi-Fi, cracking WEP/WPA (handshake).",
        target_label="Arquivo .cap / .pcap", target_placeholder="/caminho/handshake.cap",
        light="aircrack-ng {target}",
        advanced="aircrack-ng -w /usr/share/wordlists/rockyou.txt {target}",
        bin="aircrack-ng", repo="aircrack-ng",
        install="sudo pacman -S aircrack-ng",
    ),
    Tool(
        id="wifite2", name="Wifite2", category="WIRELESS",
        description="Automacao de ataques a redes sem fio.",
        target_label="Alvo (opcional)", target_placeholder="",
        needs_target=False, needs_root=True, interactive=True,
        light="wifite --kill",
        advanced="wifite --wpa --dict /usr/share/wordlists/rockyou.txt --kill",
        repo_light="cd repos/wifite2 && python3 Wifite.py --kill",
        repo_advanced="cd repos/wifite2 && python3 Wifite.py --wpa --kill",
        bin="wifite", repo="wifite2",
        install="sudo pacman -S wifite",
    ),
    Tool(
        id="kismet", name="Kismet", category="WIRELESS",
        description="Detector e sniffer de redes wireless (alimenta o mapa).",
        target_label="Interface (opcional)", target_placeholder="wlan0",
        needs_target=False, needs_root=True, interactive=True,
        light="kismet",
        advanced="kismet -c {target}",
        bin="kismet", repo="kismet",
        install="sudo pacman -S kismet",
    ),
    # --------------------------- SENSING --------------------------------- #
    Tool(
        id="ruview", name="RuView (WiFi DensePose)", category="SENSING",
        description="Sensing por Wi-Fi: presenca, respiracao, batimentos e pose (CSI).",
        target_label="Dispositivo / CSI (opcional)", target_placeholder="",
        needs_target=False,
        light="wdp --help",
        advanced="wdp sense --live {extra}",
        repo_light="cd repos/RuView && python3 -m src.cli --help",
        bin="wdp", repo="RuView",
        install="pip install 'wifi-densepose'",
    ),
    # --------------------------- CRYPTO ---------------------------------- #
    Tool(
        id="openssl", name="OpenSSL", category="CRYPTO",
        description="Criptografia / hash de arquivos (AES-256).",
        target_label="Arquivo", target_placeholder="/caminho/arquivo",
        light="openssl enc -aes-256-cbc -pbkdf2 -salt -in {target} -out {target}.enc {extra}",
        advanced="openssl enc -aes-256-gcm -pbkdf2 -salt -in {target} -out {target}.enc {extra}",
        bin="openssl",
        install="sudo pacman -S openssl",
    ),
    Tool(
        id="hashcat", name="Hashcat", category="CRYPTO",
        description="Recuperacao de senhas / cracking de hashes (GPU/CPU).",
        target_label="Hash ou arquivo", target_placeholder="5f4dcc3b5aa765d61d8327deb882cf99",
        light="hashcat -m 0 {target} /usr/share/wordlists/rockyou.txt {extra}",
        advanced="hashcat -m 1000 -a 3 {target} ?a?a?a?a?a?a {extra}",
        bin="hashcat",
        install="sudo pacman -S hashcat",
    ),
]


TOOL_BY_ID = {t.id: t for t in TOOLS}


def tools_in(category: str) -> list[Tool]:
    return [t for t in TOOLS if t.category == category]


# --------------------------------------------------------------------------- #
# Modo geral (assistente por intencao)
# --------------------------------------------------------------------------- #
# (rotulo, tool_id, mode, descricao curta)
INTENTS: list[tuple[str, str, str, str]] = [
    ("Descobrir superficie de dominio", "amass", "light",
     "Enumera subdominios e DNS de um dominio."),
    ("Coletar e-mails e hosts", "theharvester", "light",
     "OSINT de e-mails/subdominios por fontes publicas."),
    ("Mapear pegada de usuario/e-mail", "user-scanner", "light",
     "Descobre perfis a partir de um username ou e-mail."),
    ("Varredura de portas rapida", "nmap", "light",
     "Scan rapido de portas mais comuns."),
    ("Fingerprint de servicos (avancado)", "nmap", "advanced",
     "Versoes, scripts e SO em todas as portas."),
    ("Detectar vulnerabilidades web", "nuclei", "light",
     "Templates YAML contra um alvo web."),
    ("Auditar servidor web", "nikto", "light",
     "Arquivos perigosos e software antigo."),
    ("Testar injecao de SQL", "sqlmap", "light",
     "Deteccao/exploracao de SQLi em uma URL."),
    ("Iniciar Metasploit", "metasploit", "light",
     "Console do Metasploit Framework."),
    ("Auditar Wi-Fi automaticamente", "wifite2", "light",
     "Auditoria wireless assistida (requer root)."),
    ("Captura wireless passiva", "kismet", "light",
     "Sniffer de redes e dispositivos."),
    ("Cracking de handshake WPA", "aircrack-ng", "advanced",
     "Dicionario rockyou contra um .cap."),
    ("Cracking de hash", "hashcat", "light",
     "Recupera senha a partir de um hash."),
    ("Sensing por Wi-Fi (RuView)", "ruview", "light",
     "Presenca/vitais por CSI (WiFi DensePose)."),
]


# --------------------------------------------------------------------------- #
# Proxy / anonimato
# --------------------------------------------------------------------------- #
def wrap_proxy(cmd: str, mode: str) -> tuple[str, dict]:
    """Retorna (comando, variaveis de ambiente) para o modo de anonimato."""
    if mode == "tor":
        if which("torsocks"):
            return "torsocks " + cmd, {}
        env = {
            "ALL_PROXY": "socks5h://127.0.0.1:9050",
            "HTTP_PROXY": "socks5h://127.0.0.1:9050",
            "HTTPS_PROXY": "socks5h://127.0.0.1:9050",
            "http_proxy": "socks5h://127.0.0.1:9050",
            "https_proxy": "socks5h://127.0.0.1:9050",
        }
        return cmd, env
    if mode == "burp":
        bev = {
            "HTTP_PROXY": "http://127.0.0.1:8080",
            "HTTPS_PROXY": "http://127.0.0.1:8080",
            "http_proxy": "http://127.0.0.1:8080",
            "https_proxy": "http://127.0.0.1:8080",
        }
        return cmd, bev
    return cmd, {}


def find_terminal() -> list[str] | None:
    """Retorna o prefixo de comando para abrir um terminal externo."""
    for cand in ("xdg-terminal-exec", "ghostty", "alacritty", "kitty", "foot",
                 "wezterm", "gnome-terminal", "konsole", "xterm"):
        if which(cand):
            if cand == "gnome-terminal":
                return [cand, "--"]
            if cand == "wezterm":
                return [cand, "start", "--"]
            return [cand, "-e"]
    return None
