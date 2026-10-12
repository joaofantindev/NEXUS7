# NEXUS-7 — Swiss-Army Security Toolkit

Interface gráfica (PySide6) que orquestra ferramentas de **OSINT, scan,
exploração, wireless e criptografia** como um canivete suíço: você escolhe o que
fazer, informa o alvo e a ferramenta certa é montada e executada — em modo
**leve** ou **avançado**, com anonimato via **Tor** ou **Burp**.

> Status: em desenvolvimento. Existe um recurso de módulos por categoria, modo
> geral (assistente por intenção) e central de serviços. A **IA** (Groq/LLM para
> geração de scripts) ainda será implementada — ver "Roteiro".

---

## 1. Instalação

Pré-requisitos: Linux (Arch/Omarchy), Python 3.12+, PySide6 e `yay` (AUR).

```bash
# dependências da GUI
python3 -m pip install --user pyside6

# clonar os repositórios das ferramentas (16 projetos open-source)
./setup_tools.sh --anon   # Tor + proxychains + Burp Suite
./setup_tools.sh --main   # nmap, nuclei, amass, metasploit, sqlmap, ...
```

O `setup_tools.sh` instala os binários via pacman/pipx/go e habilita o Tor
(porta `9050`). O Burp Suite abre na porta `8080` (você ativa o listener no
próprio programa).

## 2. Executar

```bash
python3 hacker_gui.py
```

Na primeira tela, o **Modo Geral** já aparece: escolha uma intenção ("varrer
portas", "detectar vulnerabilidades web", ...) que a ferramenta e o modo são
pré-selecionados. Alternativamente, use o menu lateral para navegar por
categoria.

### Fluxo básico (qualquer ferramenta)

1. Selecione a **categoria** no menu lateral (OSINT, SCAN, EXPLOIT, ...).
2. Escolha a **ferramenta** na lista (o status indica `[OK]` instalada,
   `[SRC]` disponível em `repos/`, `[FALTA]` não instalada).
3. Informe apenas o **alvo** (e, opcionalmente, opções extras).
4. Escolha o **modo**: LEVE (rápido, menos ruído) ou AVANÇADO (agressivo,
   fingerprint completo).
5. Configure o **anonimato**: Direto, Tor ou Burp.
6. Clique em **EXECUTAR**. O comando é mostrado no painel e a saída sai no
   console. Use **PARAR** para interromper, **COPIAR** para levar o comando
   para o terminal e **STATUS/INSTALAR** para conferir/receber a receita.

---

## 3. Casos de uso (exemplos)

### 3.1 Reconhecimento de domínio (OSINT)

**Objetivo:** mapear subdomínios, e-mails e infraestrutura de `exemplo.com`.

- Modo Geral → **"Descobrir superfície de domínio"** → alvo: `exemplo.com`
  → EXECUTAR. (Amass em modo leve; use AVANÇADO para `-brute`.)
- Depois **"Coletar e-mails e hosts"** → theHarvester, modo avançado
  (`-b all -l 300`) para cruzar todas as fontes.
- **"Mapear pegada de usuário"** → user-scanner com um username/e-mail.

Anonimato: marque **Tor** para sair pelos nós, ou **Burp** para inspecionar
requisições no proxy.

### 3.2 Auditoria de infraestrutura (SCAN)

**Objetivo:** saber o que existe em `10.0.0.1` e se há vuln conhecida.

1. Modo Geral → **"Varredura de portas rápida"** → alvo `10.0.0.1`.
2. Troque para AVANÇADO (`-sS -sV -sC -O -p-`) para fingerprint completo.
3. Em seguida **"Detectar vulnerabilidades web"** (nuclei) contra `https://...`
   ou **"Auditar servidor web"** (nikto).

Para rotear o scan via rede de anonimato: **Tor** (torsocks) ou **Burp**.

> Portas/serviços encontrados podem ser copiados do console e usados como alvo
> das ferramentas de EXPLOIT.

### 3.3 Teste de injeção SQL (EXPLOIT)

**Objetivo:** validar se `http://alvo/item.php?id=1` é injetável.

- Modo Geral → **"Testar injeção de SQL"** → alvo `http://alvo/item.php?id=1`
  → leva ao SQLMap em modo leve (`--batch`). Em AVANÇADO vira
  `--level 5 --risk 3 --dbs` para enumerar bancos.
- Marque **Tor** para anonimizar as requisições contra o alvo.

### 3.4 Auditoria Wi-Fi (WIRELESS)

**Objetivo:** auditar a própria rede WPA.

- Modo Geral → **"Auditar Wi-Fi automaticamente"** (Wifite2) — requer **sudo**
  e executa em **terminal externo** (marque a opção; ele também re-spawna
  terminal para a senha).
- Capture o handshake e use **"Cracking de handshake WPA"** (aircrack-ng +
  rockyou) apontando para o `.cap`.
- **"Captura wireless passiva"** (Kismet) alimenta o mapa de redes próximas.

### 3.5 Criptografia / recuperação de senha (CRYPTO)

- **OpenSSL:** cifrar/decifrar um arquivo com AES-256 (modo leve/avançado).
- **Hashcat:** a partir de um hash, e.g. `5f4dcc3b5aa765d61d8327deb882cf99`
  → `hashcat -m 0 <hash> rockyou.txt`. Use AVANÇADO para ataques por máscara
  (`-a 3 ?a?a?a?a?a?a`).

### 3.6 Anonimato em ação

**Tor:** garanta o serviço ativo (Central de Serviços) e escolha "Tor" no campo
Anonimato — o toolkit prefixa `torsocks` (ou injeta `ALL_PROXY=socks5://…:9050`).

**Burp:** inicie o Burp (Central de Serviços → LIGAR + ABRIR), ative o listener
em `127.0.0.1:8080` e escolha "Burp" no campo Anonimato — as ferramentas passam
pelo proxy (http/https), permitindo interceptar e alterar os fluxos.

Check rápido:

```bash
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip
```

---

## 4. Central de Serviços (infra)

Menu lateral → **Serviços (infra)**, ou os botões **LIGAR SERVIÇOS /
DESLIGAR SERVIÇOS**:

| Serviço | Função | Porta | Como é ligado |
|--------|--------|-------|---------------|
| Tor | Proxy SOCKS5 p/ anonimato | 9050 | `pkexec systemctl start tor` |
| Burp Suite | Proxy de interceptação | 8080 | `nohup burpsuite &` / `pkill` |
| OpenVAS/GVM (se instalado) | Scan completo de vulns | 9392 (web) | `pkexec systemctl …` |

O status é atualizado a cada 3s (● ativo / ○ parado / · não instalado) e há
botões por serviço **LIGAR / PARAR** e **ABRIR** (painel web).

---

## 5. Estrutura do projeto

```
main_idea.md           ideia original do sistema
hacker_gui.py          interface (PySide6) — ponto de entrada
nexus_tools.py         registro: categorias, ferramentas e templates de comando
nexus_services.py      controlador de serviços (Tor/Burp/GVM)
setup_tools.sh         script de instalação (--anon / --main / --optional)
repos/                 16 ferramentas clonadas (amass, nmap, sqlmap, RuView, ...)
```

---

## 6. Roteiro — IA (próxima fase)

- **Gerador de scripts via LLM (Groq/LLM):** capturar a saída de um scan e
  enviar à IA para gerar um script de teste específico (prompt engineering de
  contexto técnico — persona "especialista em red teaming em ambiente de
  laboratório").
- **Assistente do modo Geral:** sugerir próxima etapa com base no resultado
  ("porta 80 aberta → sugira nikto/nuclei").
- **Conexão com MCP (user-scanner/ruview)** para agentes autônomos.

---

## 7. Avisos

- Use **apenas em sistemas com autorização** (seus servidores, laboratórios,
  CTFs, testes de contrato). Cracking/deauth/injeção sem permissão é crime nas
  principais jurisdições.
- Ferramentas de EXPLOIT (sqlmap, metasploit, beef) pressupõem alvo autorizado.
- Troque a senha do sudo periodicamente se ela foi exposta no ambiente de setup.