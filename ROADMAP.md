# NEXUS-7 — Roteiro em 10 etapas: de GUI a Sistema Operacional

Objetivo final: transformar o projeto num **sistema operacional completo**, com
boot por pendrive (ISO). As etapas 8 a 10 são a infraestrutura de SO; a 9 é a
personalização; a 10 gera a imagem.

---

## Etapa 1 — Blindagem do núcleo (estabilizar o app)
Corrige as dívidas técnicas do que já existe e prepara o terreno.

- Sanitização de alvo/extra (`shlex.quote`) nos placeholders para evitar injeção no `bash -lc`.
- Confirmação de consentimento (EXPLOIT/WIRELESS) antes de executar.
- EXECUTAR desabilitado quando a ferramenta está `FALTA`; botão vira INSTALAR.
- Persistência de tema/fonte e últimos alvos (QSettings).
- Exportar console para `.log`; parser básico de saída (nmap/nuclei) → relatório.
- Suíte de testes (pytest + `QT_QPA_PLATFORM=offscreen`).
- Varredura de status por ferramenta (detectar binário compilado por repo).

**Feito quando:** app estável com testes, sem injeção possível pelo alvo, e
produz relatório exportável a partir de um scan.

## Etapa 2 — Motor de dados (o app vira plataforma)
Dá memória, filas e execução confiável para o sistema inteiro.

- Banco local **SQLite**: alvos, scans, resultados, configurações (abandona de vez os JSON soltos).
- Modo **batch** (lista de alvos) e fila de execução com retry/timeout.
- Daemon de trabalhos em background; estado persistente entre sessões; sessão/histórico por scan.
- Multiplicidade: mesma ferramenta rodando cerca de execuções simultâneas controladas.
- Logs estruturados (módulo central) com níveis; ping de saúde dos serviços.

**Feito quando:** um scan custa "trabalho" e fica salvo com metadados; é possível
reabrir, comparar e reexportar resultados.

## Etapa 3 — Inteligência (IA prometida entra aqui)
É o que dá "cole de automação" ao sistema.

- **Gerador de scripts via LLM (Groq)** a partir da saída de um scan (persona
  "red team em laboratório autorizado", prompt de contexto técnico).
- Assistente **próxima etapa** no Modo Geral (“porta 80 aberta → sugerir nikto/nuclei”).
- Integração **MCP** (user-scanner/ruview) para agentes autônomos.
- Fallback de modelo local (llama.cpp/Ollama) para ambientes sem internet.

**Feito quando:** você roda um scan, a IA propõe o próximo passo e gera um
script de teste executável, com revisão humana.

## Etapa 4 — Ecossistema de ferramentas (arquitetura de plugins)
Permite crescer sem estourar o `nexus_tools.py`.

- Formato de **manifesto** por ferramenta (YAML: categorias, templates, proxy, root, detector) — vira plugin.
- Loja/gestor de instalação versionada (o que instalar, qual versão, como).
- Integração completa do **OpenVAS/GVM**; novas categorias (forense, reversa, recon passivo).
- Isolamento das ferramentas em **sandbox** (firejail/bwrap) quando aplicável.

**Feito quando:** ferramenta nova = drop de um YAML + `nexus-ctl install`, sem
tocar no código da GUI.

## Etapa 5 — Núcleo de sistema (o app vira "brane")
Separa a interface do motor para a futura camada de SO.

- **Core como serviço daemon** (`nexusd`): API local (socket/REST), executa e
  agenda trabalhos, sem precisar da GUI aberta.
- CLI **`nexus`** (mesmo que a GUI, por linha de comando).
- Camada de **segredos** (secret service) para chaves/credenciais das ferramentas.
- Modo **headless**: o motor roda a partir do boot sem display.
- Política de recursos por ferramenta (cpu/mem/timeout) e perfil de rede.

**Feito quando:** `nexusd` roda sozinho, atende a CLI e à GUI nativamente, e
agenda scans mesmo sem sessão gráfica.

## Etapa 6 — Ambiente gráfico (o SO ganha cara)
O toolkit vira o **desktop inteiro**, não só uma janela.

- **Shell** baseado em Qt: sessão própria, dock/launcher, bandeja, notificações, painel com monitoramento (CPU/rede/tor).
- Espaços de trabalho e multi-monitor; atalhos globais.
- Reaproveita a estética NEXUS-7 (temas/fontes) para todo o desktop (compositor/wallpaper/prompt).
- App de boas-vindas (onboarding) com configuração inicial.

**Feito quando:** loga direto na “área de trabalho NEXUS-7”, com as ferramentas
a um clique e o console integrado ao sistema.

## Etapa 7 — Administração do sistema (SO de verdade)
Gerenciamento que todo SO precisa, integrado ao app.

- **Instalador/gestor de pacotes** na GUI (pacman wrapper) e atualizações do sistema.
- Usuários/permissões, firewall (nftables com perfis), rede (gio/networkmanager).
- **Criptografia de disco (LUKS)** e snapshots/rollback (btrfs).
- Gestão de energia/sessão e gerenciador de boot na GUI.
- Perfil de “principiante” vs “power user” (não expor EXPLOIT de cara).

**Feito quando:** dá para instalar, atualizar, configurar rede/disco/firewall e
restaurar sistema sem sair da interface.

## Etapa 8 — Escolha da base Linux
Decisão técnica da distribuição-mãe.

- Avaliar **base Arch (pacman/yay)** — já é o ambiente de dev — vs Debian/outras.
  Candidata natural: **Arch** (reaproveita tooling, AUR, mkinitcpio, archiso).
- Montar o **profile de distro**: kernel, mkinitcpio, pacotes-base, units do
  `nexusd`, session do passo 6 como “default session”.
- Definir camadas: base OS rendereada nas etapas 6/7 + ferramentas.
- Documentar decisão (ADR) e pinar versões dos pacotes-base.

**Feito quando:** existe um upfront de pacotes que, instalado numa máquina
mínima, vira o sistema NEXUS-7 bootável localmente.

## Etapa 9 — Personalização e acabamento
A identidade e o “produto” do sistema.

- Tema único (cores/fonte do NEXUS-7) em todo o desktop; wallpapers, splash de boot.
- Dotfiles/presets: prompt, aliases, terminal padrão, atalhos.
- Branding: nome, logo (`images/`), sobre, documentação do SO.
- Segurança por padrão: lockdown do firewall, hardening do boot, senha obrigatória.
- Dica permanente: toda auditoria **somente em alvos autorizados**.

**Feito quando:** qualquer pessoa faz `dd` da ISO e se sente em casa, com a
identidade visual e a política de segurança aplicadas de fábrica.

## Etapa 10 — ISO e boot por pendrive
O sistema deixa de depender de seu computador de dia a dia.

- **Build de ISO** (archiso/live-build) com script `build_iso.sh`: profile,
  pacotes, fábrica de ferramentas, boot splash, autologin na sessão NEXUS.
- Primeiro-boot: wizard de idioma/usuário/rede/encriptação.
- Testes em QEMU (boot completo) e em pendrive real (Ventoy ou `dd`).
- Scripts de gravação e docs: `dd if=nexus.iso of=/dev/sdX` + opção de persistência.

**Feito quando:** `build_iso.sh` produz uma ISO que bota em QEMU e em pendrive,
com o sistema completo, ferramentas e IA funcionando.

---

## Observações de governança

- Cada etapa tem critério de **“feito quando”**; não avance sem validar.
- A base Arch escolhida na etapa 8 não invalida etapas 1–7 (o app vira camada
  do SO, empacotado como um “meta-pacote”).
- Manter os limites: sem DDoS/deface automático, sem automação maliciosa;
  “somente alvos autorizados” é regra, não sugestão.