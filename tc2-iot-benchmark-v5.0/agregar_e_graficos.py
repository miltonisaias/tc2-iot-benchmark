#!/usr/bin/env python3
"""Agrega as sessões independentes (resultados_sessao_*.json) em resultados.json e gera os gráficos."""
import json, glob, os
import numpy as np
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
D = os.path.dirname(os.path.abspath(__file__))
S = [json.load(open(f)) for f in sorted(glob.glob(os.path.join(D, "resultados_sessao_*.json")))]
assert len(S) >= 2, "rode ao menos 2 sessões"

def st(x):
    x = np.asarray(x, float); n = len(x); sd = x.std(ddof=1)
    p = np.percentile(x, [5, 25, 50, 75, 95])
    return {"n": n, "media": x.mean(), "dp": sd, "ic95": 1.96 * sd / n ** .5, "p5": p[0], "p25": p[1], "mediana": p[2],
            "p75": p[3], "p95": p[4], "min": x.min(), "max": x.max()}
def pool(get):
    out = {}
    for clk in ("cpu", "wall"):
        per = [np.median(get(s)[clk]) for s in S]
        allv = np.concatenate([np.asarray(get(s)[clk]) for s in S])
        out[clk] = {**st(allv), "mediana_por_sessao": per, "min_sessao": min(per), "max_sessao": max(per)}
    return out

R = {"meta": {**S[0]["meta"], "sessoes": len(S), "duracao_total_s": round(sum(s["meta"]["duracao_s"] for s in S), 1)},
     "testes": S[0]["testes"], "handshake": {}, "operacoes": {}, "registros": {}, "politicas_E": {}, "politicas_C": {}}
R["meta"].pop("sessao", None); R["meta"].pop("duracao_s", None)
for k in S[0]["handshake"]: R["handshake"][k] = pool(lambda s, k=k: s["handshake"][k])
for k in S[0]["operacoes"]: R["operacoes"][k] = pool(lambda s, k=k: s["operacoes"][k])
for sz in S[0]["registros"]:
    R["registros"][sz] = {}
    for op in ("cifrar", "decifrar", "adulterada"):
        R["registros"][sz][op] = pool(lambda s, sz=sz, op=op: s["registros"][sz][op])
    R["registros"][sz]["adulterada_rejeitadas"] = sum(s["registros"][sz]["adulterada"]["rejeitadas"] for s in S)
    R["registros"][sz]["adulterada_total"] = sum(len(s["registros"][sz]["adulterada"]["cpu"]) for s in S)
for n in S[0]["politicas_E"]:
    R["politicas_E"][n] = {}
    for caso, row in S[0]["politicas_E"][n].items():
        R["politicas_E"][n][caso] = {"proporcao_permitidos": row["proporcao_permitidos"]}
        for impl in ("RBAC", "ABAC linear", "ABAC indexado"):
            R["politicas_E"][n][caso][impl] = pool(lambda s, n=n, caso=caso, impl=impl: s["politicas_E"][n][caso][impl])
for key, v in S[0]["politicas_C"].items():
    R["politicas_C"][key] = {"regras": v["regras"], "condicoes": v["condicoes"], "casos": {}}
    for caso, row in v["casos"].items():
        R["politicas_C"][key]["casos"][caso] = {k: row[k] for k in ("proporcao_permitidos", "regras_percorridas_media", "condicoes_avaliadas_media")}
        for impl in ("ABAC linear", "ABAC indexado"):
            R["politicas_C"][key]["casos"][caso][impl] = pool(lambda s, key=key, caso=caso, impl=impl: s["politicas_C"][key]["casos"][caso][impl])
R["amostras_handshake_cpu"] = {k: [x for s in S for x in s["handshake"][k]["cpu"]] for k in S[0]["handshake"]}
json.dump(R, open(os.path.join(D, "resultados.json"), "w"), ensure_ascii=False, indent=1)

# ---------------- gráficos
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 9})
def clean(ax): ax.spines[["top", "right"]].set_visible(False)
names = list(R["amostras_handshake_cpu"]); lbl = ["PSK", "ECDHE-ECDSA\n(autent. servidor)", "ECDHE-ECDSA\n(autent. mútua)"]
fig, ax = plt.subplots(figsize=(6.4, 3.5))
ax.boxplot([R["amostras_handshake_cpu"][n] for n in names], tick_labels=lbl, whis=(5, 95), showfliers=True, flierprops={"markersize": 2, "alpha": .4})
ax.set_yscale("log"); ax.set_ylabel("Tempo de CPU (µs, escala log)"); clean(ax); ax.grid(alpha=.25, which="both", axis="y")
plt.tight_layout(); plt.savefig(os.path.join(D, "fig1_operacoes_cenarios.png"), dpi=170); plt.close()

sizes = list(R["registros"]); x = [int(s) for s in sizes]
fig, ax = plt.subplots(figsize=(6.4, 3.2))
for op, c in (("cifrar", "#5b8db8"), ("decifrar", "#b5533c")):
    m = [R["registros"][s][op]["cpu"]["mediana"] for s in sizes]
    lo = [R["registros"][s][op]["cpu"]["p5"] for s in sizes]; hi = [R["registros"][s][op]["cpu"]["p95"] for s in sizes]
    ax.plot(x, m, marker="o", color=c, label=op); ax.fill_between(x, lo, hi, color=c, alpha=.15)
ax.set_xscale("log", base=2); ax.set_xlabel("Tamanho da carga (bytes)"); ax.set_ylabel("Tempo de CPU (µs)\nmediana e faixa p5–p95")
ax.legend(frameon=False); clean(ax); ax.grid(alpha=.25)
plt.tight_layout(); plt.savefig(os.path.join(D, "fig2_registros.png"), dpi=170); plt.close()

ns = list(R["politicas_E"]); xs = [int(n) for n in ns]
fig, axs = plt.subplots(1, 2, figsize=(6.8, 3.3), sharey=True)
for ax, caso in zip(axs, ("típico", "pior caso")):
    for impl, c, mk in (("RBAC", "#5b8db8", "o"), ("ABAC linear", "#b5533c", "s"), ("ABAC indexado", "#d98c3f", "^")):
        ax.plot(xs, [R["politicas_E"][n][caso][impl]["cpu"]["mediana"] for n in ns], marker=mk, color=c, label=impl)
    ax.set_xscale("log"); ax.set_yscale("log"); ax.set_title(caso); ax.set_xlabel("Nº de permissões/regras"); clean(ax); ax.grid(alpha=.25, which="both")
axs[0].set_ylabel("Tempo de CPU por decisão (µs)"); axs[0].legend(frameon=False, fontsize=8)
plt.tight_layout(); plt.savefig(os.path.join(D, "fig3_cenario_equivalente.png"), dpi=170); plt.close()

fig, ax = plt.subplots(figsize=(6.4, 3.4)); caso = "típico (requisições aleatórias)"
for k, ls in ((3, "-"), (6, "--")):
    for impl, c in (("ABAC linear", "#b5533c"), ("ABAC indexado", "#d98c3f")):
        ax.plot(xs, [R["politicas_C"][f"{n}_{k}"]["casos"][caso][impl]["cpu"]["mediana"] for n in ns], ls, color=c, marker="o", label=f"{impl}, {k} condições")
ax.set_xscale("log"); ax.set_yscale("log"); ax.set_xlabel("Nº de regras"); ax.set_ylabel("Tempo de CPU por decisão (µs)")
ax.legend(frameon=False, fontsize=8); clean(ax); ax.grid(alpha=.25, which="both")
plt.tight_layout(); plt.savefig(os.path.join(D, "fig4_cenario_contextual.png"), dpi=170); plt.close()
print("agregado:", len(S), "sessões")
