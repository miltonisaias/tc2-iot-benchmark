#!/usr/bin/env python3
"""ANÁLISE EXPLORATÓRIA sobre amostras agrupadas (Mann-Whitney U unilateral, delta de Cliff) e consistência por sessão.
As repetições de uma mesma sessão não são independentes: estes valores-p NÃO são usados para rejeitar hipóteses.
A inferência do trabalho está em analise_sessoes.py (sessão como unidade). Grava testes_hipoteses.json."""
import json, glob, os
import numpy as np
from scipy.stats import mannwhitneyu
D = os.path.dirname(os.path.abspath(__file__))
S = [json.load(open(f)) for f in sorted(glob.glob(os.path.join(D, "resultados_sessao_*.json")))]
def cliff(a, b):  # delta de Cliff (a > b): P(a>b) - P(a<b), por amostragem para evitar O(n*m) grande
    rng = np.random.default_rng(1); a = np.asarray(a); b = np.asarray(b)
    i = rng.integers(0, len(a), 200000); j = rng.integers(0, len(b), 200000)
    return float(np.mean(a[i] > b[j]) - np.mean(a[i] < b[j]))
def pooled(get): return np.concatenate([np.asarray(get(s)) for s in S])
out = {"H1": {}, "H2": {}}
psk = lambda s: s["handshake"]["PSK"]["cpu"]
for nome in ("ECDHE-ECDSA (autenticação do servidor)", "ECDHE-ECDSA (autenticação mútua)"):
    a = pooled(lambda s, n=nome: s["handshake"][n]["cpu"]); b = pooled(psk)
    u = mannwhitneyu(a, b, alternative="greater")
    out["H1"][nome] = {"p": float(u.pvalue), "cliff": cliff(a, b), "sessoes_maior": int(sum(np.median(s["handshake"][nome]["cpu"]) > np.median(psk(s)) for s in S)), "sessoes": len(S)}
for n in S[0]["politicas_E"]:
    for caso in ("típico", "pior caso"):
        a = pooled(lambda s: s["politicas_E"][n][caso]["ABAC linear"]["cpu"]); b = pooled(lambda s: s["politicas_E"][n][caso]["RBAC"]["cpu"])
        c = pooled(lambda s: s["politicas_E"][n][caso]["ABAC indexado"]["cpu"])
        out["H2"][f"{n}|{caso}"] = {"p_linear_gt_rbac": float(mannwhitneyu(a, b, alternative="greater").pvalue),
                                    "p_linear_gt_indexado": float(mannwhitneyu(a, c, alternative="greater").pvalue),
                                    "sessoes_linear_gt_rbac": int(sum(np.median(s["politicas_E"][n][caso]["ABAC linear"]["cpu"]) > np.median(s["politicas_E"][n][caso]["RBAC"]["cpu"]) for s in S)), "sessoes": len(S)}
json.dump(out, open(os.path.join(D, "testes_hipoteses.json"), "w"), ensure_ascii=False, indent=1)
print(json.dumps(out["H1"], indent=1)); print({k: (round(v['p_linear_gt_rbac'], 6), v['sessoes_linear_gt_rbac']) for k, v in out["H2"].items()})
