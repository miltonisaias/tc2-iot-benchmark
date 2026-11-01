#!/usr/bin/env python3
"""Figuras conceituais: arquitetura do benchmark e fluxos de mensagens do handshake DTLS 1.2 (PSK e ECDHE-ECDSA)."""
import os
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch
D = os.path.dirname(os.path.abspath(__file__))
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 8})

def box(ax, x, y, w, h, t, fc="#e8eef5"):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02", fc=fc, ec="#44556a", lw=1))
    ax.text(x + w / 2, y + h / 2, t, ha="center", va="center", wrap=True)
def arrow(ax, x1, y1, x2, y2):
    ax.annotate("", xy=(x2, y2), xytext=(x1, y1), arrowprops=dict(arrowstyle="->", color="#44556a", lw=1.2))

# ---- arquitetura
fig, ax = plt.subplots(figsize=(6.8, 4.2)); ax.set_xlim(0, 10); ax.set_ylim(0, 6); ax.axis("off")
box(ax, 0.2, 4.6, 2.6, 1.0, "Testes de correção\n(10 testes; consistência\ndo ECDH)", "#f3e6d3")
box(ax, 0.2, 2.9, 2.6, 1.2, "Geração de cargas\n(chaves, nonces, políticas\nRBAC/ABAC sintéticas,\nrequisições)", "#e8eef5")
box(ax, 3.7, 4.9, 2.6, 0.9, "Módulo 1: operações de\nhandshake (PSK, ECDHE)")
box(ax, 3.7, 3.6, 2.6, 0.9, "Módulo 2: proteção de\nmensagens (AES-CCM)")
box(ax, 3.7, 2.3, 2.6, 0.9, "Módulo 3: autorização\n(RBAC, ABAC, indexado)")
box(ax, 3.7, 1.0, 2.6, 0.9, "Módulo extra: AEAD,\nP-256 vs. Curve25519", "#e3efe0")
box(ax, 7.0, 3.5, 2.8, 1.2, "Resultados por sessão\n(JSON; 5 sessões)", "#f3e6d3")
box(ax, 7.0, 1.6, 2.8, 1.2, "Agregação e estatística\n(mediana, p5–p95)\n+ gráficos", "#e8eef5")
box(ax, 7.0, 0.1, 2.8, 0.9, "Tabelas e figuras\ndo TC", "#e3efe0")
for y in (5.35, 4.05, 2.75, 1.45): arrow(ax, 2.9, 3.5, 3.6, y)
for y in (5.35, 4.05, 2.75, 1.45): arrow(ax, 6.4, y, 6.95, 4.1 if y > 2 else 3.8)
arrow(ax, 8.4, 3.45, 8.4, 2.85); arrow(ax, 8.4, 1.55, 8.4, 1.05); arrow(ax, 1.5, 4.55, 1.5, 4.15)
plt.tight_layout(); plt.savefig(os.path.join(D, "fig_arquitetura.png"), dpi=170); plt.close()

# ---- fluxos DTLS 1.2
def seq(ax, x0, titulo, msgs):
    ax.text(x0 + 1.5, 9.6, titulo, ha="center", weight="bold")
    ax.text(x0, 9.0, "Dispositivo\n(cliente)", ha="center"); ax.text(x0 + 3, 9.0, "Servidor", ha="center")
    ax.plot([x0, x0], [1.6, 8.5], color="#888", lw=1); ax.plot([x0 + 3, x0 + 3], [1.6, 8.5], color="#888", lw=1)
    y = 8.1
    for d, t in msgs:
        if d == ">": ax.annotate("", xy=(x0 + 3, y), xytext=(x0, y), arrowprops=dict(arrowstyle="->", lw=1))
        else: ax.annotate("", xy=(x0, y), xytext=(x0 + 3, y), arrowprops=dict(arrowstyle="->", lw=1))
        ax.text(x0 + 1.5, y + 0.12, t, ha="center", fontsize=7); y -= 0.75
fig, ax = plt.subplots(figsize=(7.0, 4.6)); ax.set_xlim(-0.8, 11.3); ax.set_ylim(1.4, 10); ax.axis("off")
seq(ax, 0.3, "Modo PSK", [(">", "ClientHello"), ("<", "HelloVerifyRequest (cookie)"), (">", "ClientHello (cookie)"),
    ("<", "ServerHello [+ dica de identidade]"), ("<", "ServerHelloDone"), (">", "ClientKeyExchange (identidade PSK)"),
    (">", "ChangeCipherSpec + Finished"), ("<", "ChangeCipherSpec + Finished")])
seq(ax, 6.5, "Modo ECDHE-ECDSA", [(">", "ClientHello"), ("<", "HelloVerifyRequest (cookie)"), (">", "ClientHello (cookie)"),
    ("<", "ServerHello, Certificate"), ("<", "ServerKeyExchange (ECDHE assinado)"), ("<", "[CertificateRequest], ServerHelloDone"),
    (">", "[Certificate], ClientKeyExchange (ECDHE)"), (">", "[CertificateVerify], CCS + Finished"), ("<", "ChangeCipherSpec + Finished")])
plt.tight_layout(); plt.savefig(os.path.join(D, "fig_handshake_fluxos.png"), dpi=170); plt.close()

# ---- fluxograma da decisão ABAC (negação prevalece)
from matplotlib.patches import Polygon
def diamond(ax, cx, cy, w, h, t):
    ax.add_patch(Polygon([(cx, cy + h), (cx + w, cy), (cx, cy - h), (cx - w, cy)], closed=True, fc="#f3e6d3", ec="#44556a", lw=1))
    ax.text(cx, cy, t, ha="center", va="center", fontsize=7.5)
fig, ax = plt.subplots(figsize=(6.8, 5.0)); ax.set_xlim(0, 10); ax.set_ylim(0, 10); ax.axis("off")
box(ax, 3.1, 9.0, 3.8, 0.8, "Requisição (sujeito, ação, recurso, ambiente)", "#e8eef5")
diamond(ax, 5, 7.6, 1.7, 0.75, "Há próxima regra?")
diamond(ax, 5, 5.9, 1.7, 0.75, "Ação da regra = ação\nda requisição?")
diamond(ax, 5, 4.2, 1.7, 0.75, "Todas as condições\nsão satisfeitas?")
diamond(ax, 5, 2.5, 1.7, 0.75, "Efeito da regra é\nnegação?")
box(ax, 7.6, 1.0, 2.2, 0.9, "Retorna NEGADO\n(encerra)", "#f3d3d3")
box(ax, 3.9, 0.6, 2.2, 0.9, "Marca permissão\naplicável", "#e3efe0")
box(ax, 0.2, 7.2, 2.4, 0.8, "Fim das regras:\nPERMITIDO se houve\npermissão; senão NEGADO", "#e3efe0")
arrow(ax, 5, 9.0, 5, 8.35); arrow(ax, 5, 6.85, 5, 6.65); arrow(ax, 5, 5.15, 5, 4.95); arrow(ax, 5, 3.45, 5, 3.25)
arrow(ax, 3.3, 7.6, 2.6, 7.6); ax.text(3.0, 7.75, "não", fontsize=7)
arrow(ax, 6.7, 2.5, 7.6, 1.6); ax.text(7.2, 2.3, "sim", fontsize=7)
arrow(ax, 5, 1.75, 5, 1.5); ax.text(5.1, 1.6, "não", fontsize=7)
for y, lab in ((5.9, "não"), (4.2, "não")):
    ax.plot([6.7, 8.6], [y, y], color="#44556a", lw=1.2); ax.plot([8.6, 8.6], [y, 8.2], color="#44556a", lw=1.2) if y == 5.9 else ax.plot([8.6, 8.6], [y, 5.9], color="#44556a", lw=1.2)
    ax.text(7.0, y + 0.12, lab, fontsize=7)
ax.plot([8.6, 8.6], [5.9, 8.2], color="#44556a", lw=1.2); arrow(ax, 8.6, 8.2, 5.0, 8.2)
ax.plot([5, 5], [1.5, 1.5]); ax.plot([4.0, 3.2], [1.05, 1.05], color="#44556a", lw=1.2); ax.plot([3.2, 3.2], [1.05, 8.2], color="#44556a", lw=1.2); arrow(ax, 3.2, 8.2, 4.9, 8.2)
ax.text(5, 7.9, "sim", fontsize=7); ax.text(5.1, 6.75, "sim", fontsize=7); ax.text(5.1, 5.05, "sim", fontsize=7)
plt.tight_layout(); plt.savefig(os.path.join(D, "fig_fluxo_abac.png"), dpi=170); plt.close()
print("ok")
