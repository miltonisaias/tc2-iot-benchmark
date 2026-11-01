#!/usr/bin/env python3
"""Agrega resultados_extra_sessao_*.json em resultados_extra.json e gera figuras 5 a 8."""
import json, glob, os
import numpy as np
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
D = os.path.dirname(os.path.abspath(__file__))
S = [json.load(open(f)) for f in sorted(glob.glob(os.path.join(D, "resultados_extra_sessao_*.json")))]
def st(x):
    x = np.asarray(x, float); n = len(x); p = np.percentile(x, [5, 25, 50, 75, 95]); sd = x.std(ddof=1)
    return {"n": n, "media": x.mean(), "dp": sd, "p5": p[0], "p25": p[1], "mediana": p[2], "p75": p[3], "p95": p[4], "min": x.min(), "max": x.max()}
def pool(get):
    out = {}
    for clk in ("cpu", "wall"):
        per = [float(np.median(get(s)[clk])) for s in S]
        out[clk] = {**st(np.concatenate([np.asarray(get(s)[clk]) for s in S])), "mediana_por_sessao": per, "min_sessao": min(per), "max_sessao": max(per)}
    return out
R = {"sessoes": len(S), "cryptography": S[0]["cryptography"], "aead": {}, "operacoes": {}, "cenarios": {}}
for alg in S[0]["aead"]:
    R["aead"][alg] = {sz: {op: pool(lambda s, alg=alg, sz=sz, op=op: s["aead"][alg][sz][op]) for op in ("cifrar", "decifrar")} for sz in S[0]["aead"][alg]}
for k in S[0]["operacoes"]: R["operacoes"][k] = pool(lambda s, k=k: s["operacoes"][k])
for k in S[0]["cenarios"]: R["cenarios"][k] = pool(lambda s, k=k: s["cenarios"][k])
R["amostras_cenarios_cpu"] = {k: [x for s in S for x in s["cenarios"][k]["cpu"]] for k in S[0]["cenarios"]}
json.dump(R, open(os.path.join(D, "resultados_extra.json"), "w"), ensure_ascii=False, indent=1)
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 9})
def clean(ax): ax.spines[["top", "right"]].set_visible(False)

fig, ax = plt.subplots(figsize=(6.4, 3.3)); sizes = list(next(iter(R["aead"].values())))
for (alg, v), c in zip(R["aead"].items(), ("#5b8db8", "#b5533c", "#6a9a4f")):
    x = [int(s) for s in sizes]; m = [v[s]["cifrar"]["cpu"]["mediana"] for s in sizes]
    lo = [v[s]["cifrar"]["cpu"]["p5"] for s in sizes]; hi = [v[s]["cifrar"]["cpu"]["p95"] for s in sizes]
    ax.plot(x, m, marker="o", color=c, label=alg); ax.fill_between(x, lo, hi, color=c, alpha=.12)
ax.set_xscale("log", base=2); ax.set_xlabel("Tamanho da carga (bytes)"); ax.set_ylabel("Tempo de CPU para cifrar (µs)\nmediana e faixa p5–p95"); ax.legend(frameon=False, fontsize=8); clean(ax); ax.grid(alpha=.25)
plt.tight_layout(); plt.savefig(os.path.join(D, "fig5_aead.png"), dpi=170); plt.close()

ks = list(R["operacoes"]); fig, ax = plt.subplots(figsize=(6.6, 3.6))
cores = ["#5b8db8"] * 4 + ["#d98c3f"] * 2 + ["#6a9a4f"] * 3
ax.barh(range(len(ks)), [R["operacoes"][k]["cpu"]["mediana"] for k in ks], color=cores)
ax.set_yticks(range(len(ks))); ax.set_yticklabels(ks); ax.invert_yaxis(); ax.set_xscale("log"); ax.set_xlabel("Mediana do tempo de CPU (µs, escala log)"); clean(ax); ax.grid(alpha=.25, axis="x", which="both")
plt.tight_layout(); plt.savefig(os.path.join(D, "fig6_assimetricas.png"), dpi=170); plt.close()

ks = list(R["cenarios"]); fig, ax = plt.subplots(figsize=(6.6, 3.6))
ax.boxplot([R["amostras_cenarios_cpu"][k] for k in ks], tick_labels=["PSK", "P-256\nservidor", "P-256\nmútua", "X25519+Ed25519\nservidor", "X25519+Ed25519\nmútua"], whis=(5, 95), flierprops={"markersize": 2, "alpha": .4})
ax.set_yscale("log"); ax.set_ylabel("Tempo de CPU (µs, escala log)"); clean(ax); ax.grid(alpha=.25, which="both", axis="y")
plt.tight_layout(); plt.savefig(os.path.join(D, "fig7_cenarios_extra.png"), dpi=170); plt.close()

# amortização: (T_hs + N*T_msg)/N com T_msg = mediana de cifrar 128 B (AES-128-CCM, mesma sessão de medição extra)
tmsg = R["aead"]["AES-128-CCM (etiqueta de 8 bytes)"]["128"]["cifrar"]["cpu"]["mediana"]
Ns = np.array([1, 2, 5, 10, 20, 50, 100, 200, 500, 1000]); fig, ax = plt.subplots(figsize=(6.4, 3.4))
for k, c in zip(ks, ("#5b8db8", "#d98c3f", "#b5533c", "#6a9a4f", "#3d6b2a")):
    th = R["cenarios"][k]["cpu"]["mediana"]; ax.plot(Ns, (th + Ns * tmsg) / Ns, marker="o", ms=3, color=c, label=k)
ax.set_xscale("log"); ax.set_yscale("log"); ax.set_xlabel("Mensagens protegidas por sessão (N)"); ax.set_ylabel("Tempo de CPU médio por mensagem (µs)"); ax.legend(frameon=False, fontsize=7); clean(ax); ax.grid(alpha=.25, which="both")
plt.tight_layout(); plt.savefig(os.path.join(D, "fig8_amortizacao.png"), dpi=170); plt.close()
print("extra agregado:", len(S), "sessões; T_msg(128B, CCM)=", round(tmsg, 3))
