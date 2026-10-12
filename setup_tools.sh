#!/usr/bin/env bash
# ============================================================
# NEXUS-7 - setup das ferramentas do toolkit
# Uso:
#   bash setup_tools.sh            instala TUDO
#   bash setup_tools.sh --anon     so Tor + proxychains + Burp
#   bash setup_tools.sh --main     so as ferramentas principais
# Requer: sudo (pedira a senha) e yay (AUR).
# ============================================================
set -euo pipefail

MODE="${1:-all}"

say()  { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }

if [[ $EUID -eq 0 ]]; then
    warn "nao rode como root direto; o script usa sudo isoladamente."
    SU=""
else
    SU="sudo"
fi

need_yay() {
    if ! command -v yay >/dev/null 2>&1; then
        warn "yay nao encontrado (AUR). Instale: sudo pacman -S --needed base-devel git && git clone https://aur.archlinux.org/yay-bin /tmp/yay && cd /tmp/yay && makepkg -si"
        exit 1
    fi
}

# ------------------------------------------------------------------ #
# 1) Anonimato: Tor + torsocks + proxychains + Burp Suite
# ------------------------------------------------------------------ #
install_anon() {
    need_yay
    say "instalando Tor, torsocks e proxychains-ng..."
    $SU pacman -S --needed --noconfirm tor torsocks proxychains-ng

    say "instalando Burp Suite Community (AUR)..."
    yay -S --needed --noconfirm burpsuite || warn "falha ao instalar burpsuite (tente novamente depois)."

    say "habilitando serviço do Tor..."
    $SU systemctl enable --now tor || $SU rc-update add tor default 2>/dev/null || true

    cat <<'EOF'

  Tor rodando na porta 9050 (SOCKS).
  Teste: curl --socks5 127.0.0.1:9050 https://check.torproject.org/api/ip
  No toolkit, escolha "Tor" na opção Anonimato.
  Burp Suite: lance `burpsuite` e ative o listener na porta 8080,
  depois escolha "Burp" no toolkit.
EOF
}

# ------------------------------------------------------------------ #
# 2) Ferramentas principais (pacman + pipx + go)
# ------------------------------------------------------------------ #
install_main() {
    need_yay
    say "instalando ferramentas por pacman..."
    $SU pacman -S --needed --noconfirm \
        nmap sqlmap nikto metasploit aircrack-ng kismet hashcat openssl \
        python-pipx go go-wan jq git wifite

    say "nuclei (via go install)..."
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest || \
        warn "nuclei: go install falhou"

    say "amass (via go install)..."
    go install -v github.com/owasp-amass/amass/v4/...@master || \
        warn "amass: go install falhou"

    say "ferramentas python (da pasta repos/)..."
    (cd repos/theHarvester && python3 -m pip install --user -e .) || warn "theHarvester falhou"
    (cd repos/spiderfoot && python3 -m pip install --user -r requirements.txt) || warn "spiderfoot: deps nao instaladas (rode de repos/spiderfoot)"
    (cd repos/user-scanner && python3 -m pip install --user -e .) || warn "user-scanner falhou"

    if command -v ln >/dev/null; then
        for b in amass nuclei; do
            [[ -f "$HOME/go/bin/$b" ]] && ln -sf "$HOME/go/bin/$b" "$HOME/.local/bin/$b"
        done || true
    fi

    say "dependencias das ferramentas de repos/ (python)..."
    for d in repos/RuView; do
        if [[ -d "$d" ]]; then
            # shellcheck disable=SC2164
            (cd "$d" && python3 -m pip install --user -e . 2>/dev/null) || \
                warn "$d - instalacao python pulada (dependencias podem faltar)"
        fi
    done

    warn "OpenVAS/GVM: compile do AUR (demorado):"
    echo "   yay -S gvm-libs gvmd gsa gsad openvas-scanner python-gvm"

    cat <<'EOF'

  Ferramentas prontas. Rode o toolkit e Detective... 
  se algo aparecer como FALTA, confira a saída acima.
EOF
}

# ------------------------------------------------------------------ #
# 3) RuView (WiFi DensePose) e Cuckoo - opcionais / pesados
# ------------------------------------------------------------------ #
install_optional() {
    say "RuView (wifi-densepose) - requer hardware ESP32/CSI e PyTorch; pulando por padrao."
    warn "instale manualmente: pip install wifi-densepose  (ou siga repos/RuView/README.md)"
    warn "Cuckoo exige VM Windows para analise; configure conforme repos/cuckoo/README.rst"
}

case "$MODE" in
    --anon) install_anon ;;
    --main) install_main ;;
    --optional) install_optional ;;
    all|*)
        install_anon
        install_main
        install_optional
        say "setup concluido."
        ;;
esac