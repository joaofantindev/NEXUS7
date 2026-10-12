"""NEXUS-7 - canivete suico de seguranca ofensiva/OSINT.

Interface grafica (PySide6) que detecta, constroi e executa as ferramentas
clonadas em repos/ (ou instaladas no sistema). Recursos:

  * modulos por categoria (OSINT, SCAN, EXPLOIT, MALWARE, WIRELESS, SENSING, CRYPTO);
  * selecao de ferramenta com modos LEVE e AVANCADO;
  * entrada apenas de alvo + opcoes extras;
  * anonimato via Tor (torsocks/socks5) ou Burp Suite (proxy HTTP);
  * modo GERAL: escolha o que fazer e o alvo, a ferramenta e sugerida;
  * execucao real (QProcess) com console, parar, copiar comando e instalar.
"""

import os
import sys
import random
import datetime
import shlex

from PySide6.QtCore import Qt, QTimer, QProcess, QProcessEnvironment, QUrl
from PySide6.QtGui import QFont, QFontDatabase, QColor, QDesktopServices
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QLabel, QLineEdit, QPushButton,
    QListWidget, QListWidgetItem, QVBoxLayout, QHBoxLayout,
    QGridLayout, QFrame, QStackedWidget, QPlainTextEdit,
    QComboBox, QCheckBox, QScrollArea,
)

import nexus_tools as NT
import nexus_services as NS

THEMES = {
    "RED // Classico": {
        "bg": "#000000", "panel": "#0a0000", "panel2": "#120000",
        "main": "#ff0033", "dim": "#8a0018", "faint": "#3a000c",
        "text": "#ff4d4d", "text_dim": "#a11a2a", "good": "#00ff88",
    },
    "GREEN // Fosforo": {
        "bg": "#000000", "panel": "#00120a", "panel2": "#001a10",
        "main": "#00ff88", "dim": "#00a356", "faint": "#003322",
        "text": "#33ffaa", "text_dim": "#0f8f5f", "good": "#a8ff3c",
    },
    "AMBER // Ambar": {
        "bg": "#000000", "panel": "#120d00", "panel2": "#1a1500",
        "main": "#ffb000", "dim": "#b07a00", "faint": "#3a2a00",
        "text": "#ffc94d", "text_dim": "#a87f1a", "good": "#8cff66",
    },
    "CYAN // Gelo": {
        "bg": "#000000", "panel": "#000a12", "panel2": "#00121a",
        "main": "#00e5ff", "dim": "#009bb3", "faint": "#002b3a",
        "text": "#66f0ff", "text_dim": "#0f8ea3", "good": "#7dff9b",
    },
    "VIOLET // Estelar": {
        "bg": "#000000", "panel": "#0d0012", "panel2": "#15001a",
        "main": "#b026ff", "dim": "#7a12b0", "faint": "#2b0a3a",
        "text": "#d07cff", "text_dim": "#8b3db8", "good": "#66ffd9",
    },
}

FONT_CANDIDATES = [
    "JetBrains Mono", "Ubuntu Mono", "Source Code Pro", "Fira Code",
    "DejaVu Sans Mono", "Menlo", "Consolas", "Monospace", "Monofur",
    "Cascadia Mono", "Hack", "Courier New",
]


def available_mono_fonts():
    installed = set(QFontDatabase.families())
    ordered = [f for f in FONT_CANDIDATES if f in installed]
    ordered += [f for f in FONT_CANDIDATES if f not in installed]
    return ordered


class HackerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("root@nexus:~# // TOOLKIT")
        self.resize(1240, 800)
        self.theme = dict(THEMES[list(THEMES)[0]])
        self.font_name = "DejaVu Sans Mono"
        self._proc = None
        self._active_module = "GERAL"
        self.current_tool = None
        self._build_ui()
        self._apply_theme()
        self._boot_sequence()

    # ---------- theming ----------

    def _apply_theme(self):
        self.setStyleSheet(self._stylesheet())
        self.console.setFont(QFont(self.font_name, 11))
        self.cmd_preview.setFont(QFont(self.font_name, 11))
        self.preview.setFont(QFont(self.font_name, 16))
        self.preview.setStyleSheet(
            f"background-color: {self.theme['panel']}; color: {self.theme['main']};"
            f"border: 1px solid {self.theme['dim']}; padding: 14px;"
        )
        self.preview_mini.setText(f"current: {self.font_name}")
        self._refresh_tool_list()

    def _stylesheet(self):
        T = self.theme
        F = self.font_name
        return f"""
        QMainWindow, QWidget {{
            background-color: {T['bg']};
            color: {T['text']};
            font-family: "{F}";
            font-size: 13px;
        }}
        QLabel#brand {{
            color: {T['main']}; font-size: 22px; font-weight: bold; letter-spacing: 4px;
        }}
        QLabel#sub {{ color: {T['text_dim']}; font-size: 11px; letter-spacing: 2px; }}
        QLabel#status {{ color: {T['main']}; font-size: 11px; letter-spacing: 1px; }}
        QLabel#stat-val {{ color: {T['main']}; font-size: 20px; font-weight: bold; }}
        QLabel#stat-lbl {{ color: {T['text_dim']}; font-size: 10px; letter-spacing: 2px; }}
        QLabel#panel-title, QLabel#mod-title {{
            color: {T['main']}; letter-spacing: 2px; font-weight: bold;
        }}
        QLabel#prompt {{ color: {T['main']}; font-weight: bold; }}
        QLabel#field {{ color: {T['text_dim']}; font-size: 11px; letter-spacing: 1px; }}
        QLabel#desc {{ color: {T['text_dim']}; font-size: 11px; }}
        QLabel#barbase, QLabel#barright {{ color: {T['text_dim']}; font-size: 10px; letter-spacing: 1px; }}
        QFrame#panel {{ background-color: {T['panel']}; border: 1px solid {T['faint']}; }}
        QFrame#header {{ background-color: {T['panel']}; border-bottom: 2px solid {T['main']}; }}
        QListWidget {{
            background-color: {T['panel']}; border: 1px solid {T['faint']}; outline: none; padding: 4px;
        }}
        QListWidget::item {{ padding: 8px 6px; border-left: 3px solid transparent; }}
        QListWidget::item:selected {{
            background-color: {T['faint']}; color: {T['main']}; border-left: 3px solid {T['main']};
        }}
        QListWidget::item:hover {{ background-color: {T['panel2']}; }}
        QPlainTextEdit, QTextEdit {{
            background-color: {T['panel']}; border: 1px solid {T['faint']}; color: {T['text']};
            selection-background-color: {T['main']}; selection-color: #000000; padding: 6px;
        }}
        QLineEdit {{
            background-color: {T['panel2']}; border: 1px solid {T['dim']}; padding: 8px;
            color: {T['text']}; selection-background-color: {T['main']}; selection-color: #000000;
        }}
        QLineEdit:focus {{ border: 1px solid {T['main']}; }}
        QComboBox {{
            background-color: {T['panel2']}; border: 1px solid {T['dim']}; padding: 7px;
            color: {T['text']};
        }}
        QComboBox:focus {{ border: 1px solid {T['main']}; }}
        QComboBox QAbstractItemView {{
            background-color: {T['panel2']}; color: {T['text']};
            selection-background-color: {T['main']}; selection-color: #000000;
        }}
        QCheckBox {{ color: {T['text_dim']}; spacing: 6px; }}
        QPushButton {{
            background-color: {T['panel2']}; border: 1px solid {T['main']}; color: {T['main']};
            padding: 9px 16px; letter-spacing: 1px; font-weight: bold;
        }}
        QPushButton:hover {{ background-color: {T['main']}; color: #000000; }}
        QPushButton:pressed {{ background-color: {T['dim']}; color: #000000; }}
        QPushButton:disabled {{ border: 1px solid {T['faint']}; color: {T['faint']}; }}
        QScrollBar:vertical {{ background: {T['bg']}; width: 10px; margin: 0; }}
        QScrollBar::handle:vertical {{ background: {T['dim']}; min-height: 20px; }}
        QScrollBar::handle:vertical:hover {{ background: {T['main']}; }}
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
        QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{ background: {T['bg']}; }}
        QScrollBar:horizontal {{ background: {T['bg']}; height: 10px; margin: 0; }}
        QScrollBar::handle:horizontal {{ background: {T['dim']}; min-width: 20px; }}
        QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}
        QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {{ background: {T['bg']}; }}
        """

    def _panel(self):
        f = QFrame()
        f.setObjectName("panel")
        return f

    def _stat(self, parent_layout, label):
        box = QWidget()
        v = QVBoxLayout(box)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(2)
        val = QLabel("0")
        val.setObjectName("stat-val")
        lbl = QLabel(label)
        lbl.setObjectName("stat-lbl")
        v.addWidget(val)
        v.addWidget(lbl)
        parent_layout.addWidget(box)
        return val

    # ---------- layout ----------

    def _build_ui(self):
        root = QWidget()
        self.setCentralWidget(root)
        outer = QVBoxLayout(root)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        outer.addWidget(self._header())

        body = QHBoxLayout()
        body.setContentsMargins(12, 12, 12, 8)
        body.setSpacing(12)
        outer.addLayout(body, 1)

        body.addWidget(self._sidebar(), 0)

        self.stack = QStackedWidget()
        self.stack.addWidget(self._workspace_page())   # 0
        self.stack.addWidget(self._general_page())     # 1
        self.stack.addWidget(self._custom_page())      # 2
        self.stack.addWidget(self._services_page())    # 3
        body.addWidget(self.stack, 1)

        self.stack.setCurrentIndex(1)
        self._svc_timer = QTimer(self)
        self._svc_timer.timeout.connect(self._svc_refresh)
        self._svc_timer.start(3000)
        self._svc_procs = []
        outer.addWidget(self._statusbar())

    def _header(self):
        f = QFrame()
        f.setObjectName("header")
        f.setFixedHeight(70)
        h = QHBoxLayout(f)
        h.setContentsMargins(20, 8, 20, 8)

        left = QVBoxLayout()
        left.setSpacing(0)
        brand = QLabel("// NEXUS-7")
        brand.setObjectName("brand")
        sub = QLabel("SWISS-ARMY SECURITY TOOLKIT v3.0")
        sub.setObjectName("sub")
        left.addWidget(brand)
        left.addWidget(sub)
        h.addLayout(left)
        h.addStretch()

        stats = QHBoxLayout()
        stats.setSpacing(34)
        self.stat_cpu = self._stat(stats, "CPU LOAD")
        self.stat_net = self._stat(stats, "PACKETS")
        self.stat_tools = self._stat(stats, "TOOLS")
        h.addLayout(stats)

        clock_box = QVBoxLayout()
        clock_box.setSpacing(0)
        self.clock = QLabel("00:00:00")
        self.clock.setObjectName("stat-val")
        self.clock.setAlignment(Qt.AlignRight)
        cl = QLabel("SYSTEM TIME")
        cl.setObjectName("stat-lbl")
        cl.setAlignment(Qt.AlignRight)
        clock_box.addWidget(self.clock)
        clock_box.addWidget(cl)
        h.addLayout(clock_box)
        return f

    def _sidebar(self):
        f = self._panel()
        f.setFixedWidth(240)
        v = QVBoxLayout(f)
        v.setContentsMargins(10, 12, 10, 12)
        v.setSpacing(10)

        title = QLabel("> CATEGORIAS")
        title.setObjectName("mod-title")
        v.addWidget(title)

        self.modules = QListWidget()
        for cid, label in NT.CATEGORIES:
            it = QListWidgetItem(f"  {label}")
            it.setData(Qt.UserRole, cid)
            self.modules.addItem(it)
        self.modules.currentRowChanged.connect(self._on_module)
        self.modules.setCurrentRow(0)
        v.addWidget(self.modules, 1)

        lbl = QLabel("> SERVICOS")
        lbl.setObjectName("mod-title")
        v.addWidget(lbl)
        on_btn = QPushButton("LIGAR SERVICOS")
        on_btn.clicked.connect(self._svc_start_all)
        off_btn = QPushButton("DESLIGAR SERVICOS")
        off_btn.clicked.connect(self._svc_stop_all)
        v.addWidget(on_btn)
        v.addWidget(off_btn)

        btn = QPushButton("DETECTAR FERRAMENTAS")
        btn.clicked.connect(self._detect_all)
        v.addWidget(btn)
        return f

    # ---------- workspace ----------

    def _workspace_page(self):
        page = QWidget()
        v = QVBoxLayout(page)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(12)
        v.addWidget(self._workspace_top(), 0)
        v.addWidget(self._console_panel(), 1)
        return page

    def _workspace_top(self):
        holder = QWidget()
        row = QHBoxLayout(holder)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(12)

        # -- lista de ferramentas -- #
        left = self._panel()
        left.setFixedWidth(250)
        lv = QVBoxLayout(left)
        lv.setContentsMargins(10, 10, 10, 10)
        lv.setSpacing(8)
        self.tools_title = QLabel("> FERRAMENTAS")
        self.tools_title.setObjectName("panel-title")
        lv.addWidget(self.tools_title)
        self.tools_list = QListWidget()
        self.tools_list.currentItemChanged.connect(self._on_tool)
        lv.addWidget(self.tools_list, 1)
        row.addWidget(left)

        # -- parametros -- #
        right = self._panel()
        rv = QVBoxLayout(right)
        rv.setContentsMargins(12, 10, 12, 10)
        rv.setSpacing(8)

        self.tool_name = QLabel("> SELECIONE UMA FERRAMENTA")
        self.tool_name.setObjectName("panel-title")
        rv.addWidget(self.tool_name)
        self.tool_desc = QLabel("")
        self.tool_desc.setObjectName("desc")
        self.tool_desc.setWordWrap(True)
        rv.addWidget(self.tool_desc)

        grid = QGridLayout()
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(6)
        grid.setColumnStretch(1, 1)

        self.target_label = QLabel("Alvo")
        self.target_label.setObjectName("field")
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("informe o alvo")
        self.target_input.textChanged.connect(self._update_preview)
        grid.addWidget(self.target_label, 0, 0)
        grid.addWidget(self.target_input, 0, 1)

        extra_label = QLabel("Opcoes extras")
        extra_label.setObjectName("field")
        self.extra_input = QLineEdit()
        self.extra_input.setPlaceholderText("argumentos adicionais (opcional)")
        self.extra_input.textChanged.connect(self._update_preview)
        grid.addWidget(extra_label, 1, 0)
        grid.addWidget(self.extra_input, 1, 1)

        rv.addLayout(grid)

        opts = QHBoxLayout()
        opts.setSpacing(14)
        mode_label = QLabel("Modo")
        mode_label.setObjectName("field")
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["LEVE", "AVANCADO"])
        self.mode_combo.currentIndexChanged.connect(self._update_preview)
        opts.addWidget(mode_label)
        opts.addWidget(self.mode_combo)

        proxy_label = QLabel("Anonimato")
        proxy_label.setObjectName("field")
        self.proxy_combo = QComboBox()
        self.proxy_combo.addItems(["Direto", "Tor", "Burp"])
        self.proxy_combo.currentIndexChanged.connect(self._update_preview)
        opts.addWidget(proxy_label)
        opts.addWidget(self.proxy_combo)

        self.sudo_check = QCheckBox("usar sudo")
        opts.addWidget(self.sudo_check)
        self.term_check = QCheckBox("terminal externo")
        opts.addWidget(self.term_check)
        opts.addStretch()
        rv.addLayout(opts)

        prev_label = QLabel("> COMANDO")
        prev_label.setObjectName("panel-title")
        rv.addWidget(prev_label)
        self.cmd_preview = QPlainTextEdit()
        self.cmd_preview.setReadOnly(True)
        self.cmd_preview.setFixedHeight(58)
        rv.addWidget(self.cmd_preview)

        btns = QHBoxLayout()
        btns.setSpacing(8)
        self.run_btn = QPushButton("EXECUTAR")
        self.run_btn.clicked.connect(self._run_tool)
        self.stop_btn = QPushButton("PARAR")
        self.stop_btn.clicked.connect(self._stop_tool)
        copy_btn = QPushButton("COPIAR")
        copy_btn.clicked.connect(self._copy_command)
        install_btn = QPushButton("INSTALAR")
        install_btn.clicked.connect(self._install_tool)
        check_btn = QPushButton("STATUS")
        check_btn.clicked.connect(self._check_tool)
        for b in (self.run_btn, self.stop_btn, copy_btn, install_btn, check_btn):
            btns.addWidget(b)
        rv.addLayout(btns)

        row.addWidget(right, 1)
        return holder

    def _console_panel(self):
        f = self._panel()
        v = QVBoxLayout(f)
        v.setContentsMargins(10, 10, 10, 10)
        v.setSpacing(8)

        bar = QHBoxLayout()
        t = QLabel("> OUTPUT STREAM")
        t.setObjectName("panel-title")
        bar.addWidget(t)
        bar.addStretch()
        clear = QPushButton("LIMPAR")
        clear.clicked.connect(lambda: self.console.clear())
        bar.addWidget(clear)
        self.status = QLabel("● ONLINE")
        self.status.setObjectName("status")
        bar.addWidget(self.status)
        v.addLayout(bar)

        self.console = QPlainTextEdit()
        self.console.setReadOnly(True)
        self.console.setFont(QFont(self.font_name, 11))
        v.addWidget(self.console, 1)
        return f

    # ---------- general (assistente) ----------

    def _general_page(self):
        page = QWidget()
        v = QVBoxLayout(page)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(10)

        f = self._panel()
        fv = QVBoxLayout(f)
        fv.setContentsMargins(14, 12, 14, 12)
        title = QLabel("> O QUE VOCE QUER FAZER?")
        title.setObjectName("panel-title")
        fv.addWidget(title)
        hint = QLabel("escolha uma intencao; a ferramenta e o modo sao sugeridos automaticamente")
        hint.setObjectName("desc")
        fv.addWidget(hint)

        grid = QGridLayout()
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(10)
        for i, (label, tool_id, mode, desc) in enumerate(NT.INTENTS):
            b = QPushButton(label)
            b.setToolTip(desc)
            b.setMinimumHeight(52)
            b.clicked.connect(lambda _=False, t=tool_id, m=mode: self._launch_intent(t, m))
            grid.addWidget(b, i // 3, i % 3)
        fv.addLayout(grid)
        v.addWidget(f)
        v.addStretch()
        return page

    def _launch_intent(self, tool_id: str, mode: str):
        tool = NT.TOOL_BY_ID[tool_id]
        self.modules.setCurrentRow(self._row_for_category(tool.category))
        self._load_tool(tool_id)
        self.mode_combo.setCurrentIndex(0 if mode == "light" else 1)
        self._update_preview()

    def _row_for_category(self, cat: str) -> int:
        for i, (cid, _) in enumerate(NT.CATEGORIES):
            if cid == cat:
                return i
        return 0

    # ---------- services page ----------

    def _services_page(self):
        page = QWidget()
        v = QVBoxLayout(page)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(12)

        f = self._panel()
        fv = QVBoxLayout(f)
        fv.setContentsMargins(12, 10, 12, 10)
        fv.setSpacing(8)
        bar = QHBoxLayout()
        bar.setSpacing(8)
        t = QLabel("> CENTRAL DE SERVICOS")
        t.setObjectName("panel-title")
        bar.addWidget(t)
        bar.addStretch()
        for text, slot in (("LIGAR TODOS", self._svc_start_all),
                           ("DESLIGAR TODOS", self._svc_stop_all),
                           ("ATUALIZAR", self._svc_refresh)):
            b = QPushButton(text)
            b.clicked.connect(slot)
            bar.addWidget(b)
        fv.addLayout(bar)
        hint = QLabel("servicos de infraestrutura: Tor (anonimato) e Burp (proxy) "
                      "sempre disponiveis; OpenVAS/GVM entram apenas se instalados.")
        hint.setObjectName("desc")
        fv.addWidget(hint)
        v.addWidget(f)

        body = QScrollArea()
        body.setWidgetResizable(True)
        body.setFrameShape(QFrame.NoFrame)
        body.setStyleSheet("QScrollArea { background: transparent; }")
        self.svc_rows = QWidget()
        self.svc_rows.setLayout(QVBoxLayout())
        self.svc_rows.layout().setSpacing(8)
        self.svc_refs = {}
        for svc in NS.SERVICES:
            self._svc_add_card(svc)
        body.setWidget(self.svc_rows)
        v.addWidget(body, 1)
        return page

    def _svc_add_card(self, svc):
        card = QFrame()
        card.setObjectName("panel")
        h = QHBoxLayout(card)
        h.setContentsMargins(10, 8, 10, 8)
        h.setSpacing(12)

        info = QVBoxLayout()
        info.setSpacing(2)
        name = QLabel(svc.name)
        name.setObjectName("panel-title")
        info.addWidget(name)
        desc = QLabel(svc.desc)
        desc.setObjectName("desc")
        info.addWidget(desc)
        h.addLayout(info, 1)

        status = QLabel("...")
        status.setObjectName("status")
        status.setAlignment(Qt.AlignCenter)
        status.setMinimumWidth(110)
        h.addWidget(status)

        on = QPushButton("LIGAR")
        on.clicked.connect(lambda _=False, s=svc: self._svc_action(s, "start"))
        off = QPushButton("PARAR")
        off.clicked.connect(lambda _=False, s=svc: self._svc_action(s, "stop"))
        h.addWidget(on)
        h.addWidget(off)

        if svc.url:
            ab = QPushButton("ABRIR")
            ab.clicked.connect(lambda _=False, s=svc: QDesktopServices.openUrl(QUrl(s.url)))
            h.addWidget(ab)

        self.svc_rows.layout().addWidget(card)
        self.svc_refs[svc.id] = {"card": card, "status": status, "svc": svc}

    def _svc_refresh(self):
        if not hasattr(self, "svc_refs"):
            return
        colmap = {"running": self.theme["good"], "stopped": self.theme["dim"],
                  "missing": self.theme["faint"], "unknown": self.theme["main"]}
        for ref in self.svc_refs.values():
            svc = ref["svc"]
            st = svc.status()
            txt = {"running": "● ATIVO", "stopped": "○ PARADO",
                   "missing": "· NAO INSTALADO", "unknown": "? DESCONHECIDO"}[st]
            port = f"  :{svc.port}" if svc.port else ""
            ref["status"].setText(txt + port)
            ref["status"].setStyleSheet(f"color:{colmap[st]}; font-weight:bold;")

    def _svc_action(self, svc, action):
        st = svc.status()
        if st == "missing":
            self.log(f"{svc.name}: nao instalado, nada a fazer.", self.theme["dim"])
            return
        if action == "start":
            if st == "running":
                self.log(f"{svc.name}: ja esta ativo.", self.theme["good"])
                return
            prog, args = NS.launch(svc, "start")
            self.log(f"ligando {svc.name}...", self.theme["main"])
        else:
            if st == "stopped":
                self.log(f"{svc.name}: ja esta parado.", self.theme["good"])
                return
            prog, args = NS.launch(svc, "stop")
            self.log(f"desligando {svc.name}...", self.theme["main"])
        self._run_async(prog, [args] if args else None, cmd_note=f"[{svc.name}]")
        self._svc_refresh()

    def _svc_start_all(self):
        q = [s for s in NS.SERVICES if s.installed() and s.status() != "running"]
        self.log(f"ligando todos ({len(q)})...", self.theme["main"])
        self._svc_chain = list(q)
        self._svc_next("start")

    def _svc_stop_all(self):
        q = [s for s in NS.SERVICES if s.installed() and s.status() == "running"]
        self.log(f"desligando todos ({len(q)})...", self.theme["main"])
        self._svc_chain = list(q)
        self._svc_next("stop")

    def _svc_next(self, action):
        if not self._svc_chain:
            self.log("fila de servicos concluida.", self.theme["good"])
            self._svc_refresh()
            return
        svc = self._svc_chain.pop(0)
        self.log(f"  {action}: {svc.name}", self.theme["text"])
        prog, args = NS.launch(svc, action)
        self._run_async(prog, [args] if args else None,
                        cmd_note=f"[{svc.name}]",
                        on_finish=lambda: self._svc_next(action))

    # ---------- custom page ----------

    def _custom_page(self):
        page = QWidget()
        outer = QVBoxLayout(page)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(12)
        outer.addWidget(self._custom_preview(), 0)
        outer.addWidget(self._custom_lists(), 1)
        outer.addWidget(self._custom_footer(), 0)
        return page

    def _custom_preview(self):
        f = self._panel()
        v = QVBoxLayout(f)
        v.setContentsMargins(10, 10, 10, 10)
        v.setSpacing(8)
        t = QLabel("> PREVIEW")
        t.setObjectName("panel-title")
        v.addWidget(t)
        self.preview = QLabel("AaGgHh 0123 // NEXUS-7 -> root@nexus:~#")
        self.preview.setFont(QFont(self.font_name, 16))
        self.preview_mini = QLabel(f"current: {self.font_name}")
        self.preview_mini.setStyleSheet("color:#888; font-size:10px;")
        v.addWidget(self.preview)
        v.addWidget(self.preview_mini)
        return f

    def _custom_lists(self):
        row = QHBoxLayout()
        row.setSpacing(12)

        f1 = self._panel()
        v1 = QVBoxLayout(f1)
        v1.setContentsMargins(10, 10, 10, 10)
        v1.setSpacing(8)
        l1 = QLabel("> THEMES")
        l1.setObjectName("panel-title")
        v1.addWidget(l1)
        self.theme_list = QListWidget()
        for name in THEMES:
            item = QListWidgetItem(name)
            item.setData(Qt.UserRole, name)
            self.theme_list.addItem(item)
        self.theme_list.currentItemChanged.connect(self._on_theme)
        v1.addWidget(self.theme_list, 1)
        row.addWidget(f1, 1)

        f2 = self._panel()
        v2 = QVBoxLayout(f2)
        v2.setContentsMargins(10, 10, 10, 10)
        v2.setSpacing(8)
        l2 = QLabel("> FONTS")
        l2.setObjectName("panel-title")
        v2.addWidget(l2)
        self.font_list = QListWidget()
        for name in available_mono_fonts():
            item = QListWidgetItem(name)
            item.setData(Qt.UserRole, name)
            item.setFont(QFont(name, 12))
            self.font_list.addItem(item)
        self.font_list.currentItemChanged.connect(self._on_font)
        v2.addWidget(self.font_list, 1)
        row.addWidget(f2, 1)

        holder = QWidget()
        holder.setLayout(row)
        return holder

    def _custom_footer(self):
        f = self._panel()
        h = QHBoxLayout(f)
        h.setContentsMargins(10, 8, 10, 8)
        hint = QLabel("selecao aplicada na hora")
        hint.setObjectName("barbase")
        h.addWidget(hint)
        h.addStretch()
        restore = QPushButton("RESTAURAR PADRAO")
        restore.clicked.connect(self._restore_defaults)
        h.addWidget(restore)
        return f

    def _statusbar(self):
        f = QFrame()
        f.setObjectName("panel")
        f.setFixedHeight(26)
        h = QHBoxLayout(f)
        h.setContentsMargins(14, 0, 14, 0)
        self.barbase = QLabel("SESSION: 0x%08X" % random.getrandbits(32))
        self.barbase.setObjectName("barbase")
        self.barright = QLabel("")
        self.barright.setObjectName("barright")
        h.addWidget(self.barbase)
        h.addStretch()
        h.addWidget(self.barright)
        return f

    # ---------- customization ----------

    def _on_theme(self, current, previous):
        if current is None:
            return
        self.theme = dict(THEMES[current.data(Qt.UserRole)])
        self._apply_theme()

    def _on_font(self, current, previous):
        if current is None:
            return
        self.font_name = current.data(Qt.UserRole)
        self._apply_theme()

    def _restore_defaults(self):
        self.theme = dict(THEMES["RED // Classico"])
        self.font_name = "DejaVu Sans Mono"
        for i in range(self.theme_list.count()):
            if self.theme_list.item(i).data(Qt.UserRole) == "RED // Classico":
                self.theme_list.setCurrentRow(i)
        for i in range(self.font_list.count()):
            if self.font_list.item(i).data(Qt.UserRole) == "DejaVu Sans Mono":
                self.font_list.setCurrentRow(i)
        self._apply_theme()
        self.log("tema e fonte restaurados aos padroes.", self.theme["good"])

    # ---------- navigation ----------

    def _on_module(self, row):
        item = self.modules.item(row)
        if item is None or not getattr(self, "stack", None):
            return
        cid = item.data(Qt.UserRole)
        self._active_module = cid
        if cid == "GERAL":
            self.stack.setCurrentIndex(1)
        elif cid == "PERSONALIZAR":
            self.stack.setCurrentIndex(2)
        elif cid == "SERVICOS":
            self.stack.setCurrentIndex(3)
        else:
            self.stack.setCurrentIndex(0)
            self.tools_title.setText(f"> FERRAMENTAS // {cid}")
            self._refresh_tool_list()

    # ---------- tool list ----------

    def _refresh_tool_list(self):
        if not hasattr(self, "tools_list"):
            return
        self.tools_list.blockSignals(True)
        self.tools_list.clear()
        cat = self._active_module
        if cat in ("GERAL", "PERSONALIZAR", "SERVICOS"):
            cat = "OSINT"
        tools = NT.tools_in(cat)
        tagmap = {"installed": "OK", "source": "SRC", "missing": "FALTA"}
        colmap = {"installed": self.theme["good"],
                  "source": self.theme["main"], "missing": self.theme["dim"]}
        for t in tools:
            st = t.status()
            item = QListWidgetItem(f"  {t.name}   [{tagmap[st]}]")
            item.setData(Qt.UserRole, t.id)
            item.setForeground(QColor(colmap[st]))
            item.setToolTip(t.description)
            self.tools_list.addItem(item)
        self.tools_list.blockSignals(False)
        self.current_tool = None
        if tools:
            self.tools_list.setCurrentRow(0)
            self._on_tool(self.tools_list.item(0), None)

    def _on_tool(self, current, previous):
        if current is None:
            self.current_tool = None
            return
        self.current_tool = NT.TOOL_BY_ID[current.data(Qt.UserRole)]
        self._apply_tool_to_form()

    def _load_tool(self, tool_id: str):
        for i in range(self.tools_list.count()):
            if self.tools_list.item(i).data(Qt.UserRole) == tool_id:
                self.tools_list.setCurrentRow(i)
                if self.current_tool is None or self.current_tool.id != tool_id:
                    self._on_tool(self.tools_list.item(i), None)
                return

    def _apply_tool_to_form(self):
        t = self.current_tool
        if t is None:
            return
        self.tool_name.setText(f"> {t.name.upper()}")
        st = t.status()
        label = {"installed": "instalada no sistema",
                 "source": "disponivel no codigo-fonte (repos/)",
                 "missing": "nao instalada"}[st]
        self.tool_desc.setText(f"{t.description}   [{label}]")
        self.target_label.setText(t.target_label)
        self.target_input.setPlaceholderText(t.target_placeholder or "informe o alvo")
        self.target_input.setEnabled(t.needs_target)
        if not t.needs_target:
            self.target_input.clear()
        self.extra_input.clear()
        self.sudo_check.setEnabled(t.needs_root)
        self.sudo_check.setChecked(t.needs_root and not NT.is_root())
        self.term_check.setChecked(t.interactive)
        self._update_preview()

    # ---------- command building ----------

    def _mode(self) -> str:
        return "light" if self.mode_combo.currentIndex() == 0 else "advanced"

    def _proxy_mode(self) -> str:
        return {0: "direct", 1: "tor", 2: "burp"}[self.proxy_combo.currentIndex()]

    def _build_command(self):
        t = self.current_tool
        if t is None:
            return "", {}
        target = self.target_input.text().strip()
        extra = self.extra_input.text().strip()
        cmd = t.command(target, extra, self._mode())
        if not cmd:
            return "", {}
        env = {}
        pm = self._proxy_mode()
        if t.supports_proxy and pm != "direct":
            cmd, env = NT.wrap_proxy(cmd, pm)
        elif pm != "direct":
            env = NT.wrap_proxy(cmd, pm)[1]
        if t.needs_root and self.sudo_check.isChecked() and not NT.is_root():
            cmd = "sudo -E bash -c " + shlex.quote(cmd)
        return cmd, env

    def _update_preview(self):
        cmd, env = self._build_command()
        t = self.current_tool
        note = ""
        if t is not None:
            parts = []
            if t.needs_root and self.sudo_check.isChecked():
                parts.append("root")
            pm = self._proxy_mode()
            if t.supports_proxy and pm != "direct":
                parts.append(pm)
            if t.interactive or self.term_check.isChecked():
                parts.append("interativo")
            if parts:
                note = "   // " + " + ".join(parts)
        self.cmd_preview.setPlainText((cmd or "<sem comando>") + note)
        if self.run_btn is not None:
            ready = bool(cmd) and (t is None or not t.needs_target or bool(self.target_input.text().strip()))
            self.run_btn.setEnabled(ready)

    # ---------- behavior ----------

    def log(self, text, color=None):
        color = color or self.theme["text"]
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        safe = (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
        self.console.appendHtml(
            f'<span style="color:{self.theme["dim"]}">[{ts}]</span> '
            f'<span style="color:{color}">{safe}</span>'
        )
        self.console.verticalScrollBar().setValue(self.console.verticalScrollBar().maximum())

    def _boot_sequence(self):
        n_inst = sum(1 for t in NT.TOOLS if t.status() == "installed")
        n_src = sum(1 for t in NT.TOOLS if t.status() == "source")
        lines = [
            ("inicializando NEXUS-7 toolkit...", self.theme["text"]),
            (f"ferramentas detectadas: {n_inst} instaladas, {n_src} em repos/", self.theme["good"]),
            ("proxy: Tor :9050 / Burp :8080 (quando ativos)", self.theme["text_dim"]),
            ("SISTEMA PRONTO. escolha uma categoria ou o modo GERAL.", self.theme["main"]),
        ]
        self._pending = list(lines)
        self._push_boot()
        self._tick()

    def _push_boot(self):
        if self._pending:
            text, color = self._pending.pop(0)
            self.log(text, color)
            QTimer.singleShot(240, self._push_boot)

    def _tick(self):
        self._packets = getattr(self, "_packets", 12903)
        self._packets += random.randint(5, 240)
        self.stat_cpu.setText(f"{random.randint(8, 97)}%")
        self.stat_net.setText(f"{self._packets:,}")
        n = sum(1 for t in NT.TOOLS if t.status() in ("installed", "source"))
        self.stat_tools.setText(f"{n}/{len(NT.TOOLS)}")
        self.clock.setText(datetime.datetime.now().strftime("%H:%M:%S"))
        self.barright.setText(
            f"MEM {random.randint(320,780)}MB   |   PID {random.randint(1000,9999)}   |   TLS 1.3"
        )
        QTimer.singleShot(1000, self._tick)

    def _detect_all(self):
        n_inst = sum(1 for t in NT.TOOLS if t.status() == "installed")
        n_src = sum(1 for t in NT.TOOLS if t.status() == "source")
        n_missing = len(NT.TOOLS) - n_inst - n_src
        self.log("varredura de ferramentas:", self.theme["main"])
        for t in NT.TOOLS:
            st = t.status()
            color = {"installed": self.theme["good"], "source": self.theme["main"],
                     "missing": self.theme["dim"]}[st]
            self.log(f"  {t.name:<28} {st:<10} {t.bin or t.repo}", color)
        self.log(f"total: {n_inst} instaladas | {n_src} no fonte | {n_missing} ausentes",
                 self.theme["good"])
        self._refresh_tool_list()

    def _check_tool(self):
        t = self.current_tool
        if t is None:
            return
        st = t.status()
        self.log(f"{t.name}: {st} ({t.bin or t.repo or '-'})", self.theme["good"])
        if st == "missing" and t.install:
            self.log(f"  instalar: {t.install}", self.theme["text"])

    def _install_tool(self):
        t = self.current_tool
        if t is None or not t.install:
            self.log("esta ferramenta nao possui receita de instalacao.", self.theme["dim"])
            return
        self.log(f"instalacao de {t.name}: {t.install}", self.theme["main"])
        self._launch_terminal(t.install)

    def _copy_command(self):
        cmd, _ = self._build_command()
        QApplication.clipboard().setText(cmd)
        self.log("comando copiado para a area de transferencia.", self.theme["good"])

    # ---------- execution ----------

    def _launch_terminal(self, cmd):
        term = NT.find_terminal()
        if term is None:
            self.log("nenhum terminal externo encontrado; executando aqui.", self.theme["dim"])
            self._spawn("bash", ["-lc", cmd], {})
            return
        full = cmd + '; echo; echo "[pressione ENTER]"; read'
        program = term[0]
        args = term[1:] + ["bash", "-lc", full]
        ok = QProcess.startDetached(program, args)
        if ok:
            self.log(f"aberto em terminal externo: {term[0]}", self.theme["good"])
        else:
            self.log("falha ao abrir terminal externo.", self.theme["dim"])

    def _run_tool(self):
        t = self.current_tool
        if t is None:
            self.log("selecione uma ferramenta primeiro.", self.theme["dim"])
            return
        if t.needs_target and not self.target_input.text().strip():
            self.log("informe o alvo antes de executar.", self.theme["dim"])
            return
        cmd, env = self._build_command()
        if not cmd:
            self.log("nao ha comando para executar.", self.theme["dim"])
            return
        if t.interactive or self.term_check.isChecked():
            self._launch_terminal(cmd)
            return
        self._spawn("bash", ["-lc", cmd], env)

    def _run_async(self, program, args=None, env=None, cmd_note="", on_finish=None):
        if isinstance(program, list):
            prog, args_all = program[0], list(program[1:]) + list(args or [])
        else:
            prog, args_all = program, list(args or [])
        p = QProcess(self)
        p.setProcessChannelMode(QProcess.MergedChannels)
        qenv = QProcessEnvironment.systemEnvironment()
        for k, v in (env or {}).items():
            qenv.insert(k, v)
        p.setProcessEnvironment(qenv)
        note = f" {cmd_note}" if cmd_note else ""
        self.log(f"$ {prog} {' '.join(args_all)}{note}", self.theme["main"])
        p.readyReadStandardOutput.connect(lambda: self._async_read(p))
        p.finished.connect(lambda c, s: self._async_done(p, c, on_finish))
        p.start(prog, args_all)
        self._svc_procs.append(p)

    def _async_read(self, p):
        data = bytes(p.readAllStandardOutput()).decode(errors="replace")
        for line in data.splitlines():
            self.log(line, self.theme["text"])

    def _async_done(self, p, code, on_finish):
        self.log(f"  processo finalizado (exit {code}).",
                 self.theme["good"] if code == 0 else self.theme["dim"])
        if on_finish:
            QTimer.singleShot(0, on_finish)

    def _spawn(self, program, args, env):
        if self._proc is not None and self._proc.state() != QProcess.NotRunning:
            self.log("ja existe um processo em execucao. aguarde ou clique PARAR.", self.theme["dim"])
            return
        self.log("$ " + " ".join(shlex.quote(p) for p in [program, *args]), self.theme["main"])
        self._proc = QProcess(self)
        self._proc.setProcessChannelMode(QProcess.MergedChannels)
        qenv = QProcessEnvironment.systemEnvironment()
        for k, v in env.items():
            qenv.insert(k, v)
        self._proc.setProcessEnvironment(qenv)
        self._proc.readyReadStandardOutput.connect(self._read_proc)
        self._proc.finished.connect(self._proc_finished)
        self._proc.start(program, args)
        self.status.setText("● RUNNING")

    def _read_proc(self):
        if self._proc is None:
            return
        data = bytes(self._proc.readAllStandardOutput()).decode(errors="replace")
        for line in data.splitlines():
            self.log(line, self.theme["text"])

    def _proc_finished(self, code, status):
        self.status.setText("● ONLINE")
        self.log(f"processo finalizado (exit {code}).",
                 self.theme["good"] if code == 0 else self.theme["dim"])

    def _stop_tool(self):
        if self._proc is not None and self._proc.state() != QProcess.NotRunning:
            self._proc.kill()
            self.log("processo interrompido.", self.theme["dim"])


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("NEXUS-7")
    f = HackerGUI()
    f.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
