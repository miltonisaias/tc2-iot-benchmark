#!/usr/bin/env python3
"""
Análise inferencial com a SESSÃO como unidade de análise (TC II – Milton I. J. de Oliveira, UNIP).

Motivo: as repetições dentro de uma sessão não são observações independentes; as sessões (processos distintos, com
chaves novas) são a unidade com independência aproximada.  Por isso:
  * a inferência é feita sobre as medianas por sessão, com o PAREAMENTO das configurações executadas em cada sessão
    (teste de postos sinalizados de Wilcoxon, exato, unilateral, n = 5 sessões; menor valor-p possível = 1/32 = 0,03125);
  * os testes de Mann-Whitney sobre amostras agrupadas (testes_hipoteses.py) são tratados como EXPLORATÓRIOS;
  * os intervalos mín–máx entre sessões e as razões por sessão descrevem a variação; NÃO são intervalos de confiança.
Entradas : resultados_sessao_*.json (benchmark principal, ordem fixa) e resultados_controle_sessao_*.json (controle).
Saídas   : analise_sessoes.json e fig12_razao_por_sessao.png
"""
import json, glob, os
import numpy as np
from scipy.stats import wilcoxon
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt

D = os.path.dirname(os.path.abspath(__file__))
P = [json.load(open(f)) for f in sorted(glob.glob(os.path.join(D, "resultados_sessao_*.json")))]
C = [json.load(open(f)) for f in sorted(glob.glob(os.path.join(D, "resultados_controle_sessao_*.json")))]
med = lambda x: float(np.median(np.asarray(x, float)))
pct = lambda x, q: float(np.percentile(np.asarray(x, float), q))

def exato_unilateral(maior, menor):
    """Wilcoxon de postos sinalizados exato, H1: maior > menor (pares = sessões)."""
    d = np.asarray(maior) - np.asarray(menor)
    if np.all(d > 0): return 1 / 2 ** len(d)          # todas as diferenças positivas: p = (1/2)^n
    return float(wilcoxon(maior, menor, alternative="greater", method="exact").pvalue)

def resumo_razoes(num, den):
    r = np.asarray(num) / np.asarray(den)
    return {"razoes_por_sessao": [float(x) for x in r], "min": float(r.min()), "max": float(r.max()), "mediana": float(np.median(r)),
            "sessoes_num_maior": int(np.sum(np.asarray(num) > np.asarray(den))), "sessoes": len(r),
            "p_exato_unilateral": exato_unilateral(num, den)}

out = {"n_sessoes_principal": len(P), "n_sessoes_controle": len(C)}

# ---------------------------------------------------------------- 1) benchmark principal (ordem fixa): sessão como unidade
ps = lambda s, k: med(s["handshake"][k]["cpu"])
psk = [ps(s, "PSK") for s in P]
H1 = {}
for k in ("ECDHE-ECDSA (autenticação do servidor)", "ECDHE-ECDSA (autenticação mútua)"):
    H1[k] = {"medianas_sessao": [ps(s, k) for s in P], **resumo_razoes([ps(s, k) for s in P], psk)}
out["principal_H1"] = {"PSK_medianas_sessao": psk, **H1}
H2 = {}
for n in P[0]["politicas_E"]:
    for caso in ("típico", "pior caso"):
        g = lambda impl: [med(s["politicas_E"][n][caso][impl]["cpu"]) for s in P]
        rb, li, ix = g("RBAC"), g("ABAC linear"), g("ABAC indexado")
        H2[f"{n}|{caso}"] = {"RBAC": rb, "linear": li, "indexado": ix, "linear_sobre_RBAC": resumo_razoes(li, rb),
                              "linear_sobre_indexado": resumo_razoes(li, ix), "indexado_sobre_RBAC_razoes": [float(a / b) for a, b in zip(ix, rb)]}
out["principal_H2"] = H2

# ---------------------------------------------------------------- 2) controle: sobrecarga da medição
S = lambda s: s["sobrecarga"]
def pool(chave, fn):
    return np.concatenate([np.asarray(fn(s)[chave], float) for s in C])
ov = {"operacao_vazia": {}, "granularidade": {}, "individual_vs_lotes": {}, "estrutura_lote": {}}
for clk in ("cpu", "wall"):
    v = pool(clk, lambda s: S(s)["operacao_vazia"])
    ov["operacao_vazia"][clk] = {"mediana": med(v), "p5": pct(v, 5), "p95": pct(v, 95),
                                  "mediana_por_sessao": [med(S(s)["operacao_vazia"][clk]) for s in C]}
for rel in ("thread_time_ns", "perf_counter_ns"):
    g = [S(s)["granularidade_relogios"][rel] for s in C]
    ov["granularidade"][rel] = {"menor_delta_positivo_ns": min(x["menores_deltas_positivos_ns"][0] for x in g),
                                 "mediana_do_custo_de_chamada_ns": med([x["mediana_ns"] for x in g]),
                                 "fracao_zero": max(x["fracao_zero"] for x in g)}
for op in S(C[0])["individual"]:
    row = {}
    for clk in ("cpu", "wall"):
        i = [med(S(s)["individual"][op][clk]) for s in C]; l = [med(S(s)["em_lotes"][op][clk]) for s in C]
        row[clk] = {"individual_mediana_sessoes": med(i), "lotes_mediana_sessoes": med(l), "diferenca": med(i) - med(l),
                    "diferenca_por_sessao": [a - b for a, b in zip(i, l)], "razao_individual_sobre_lotes": med(i) / med(l)}
    ov["individual_vs_lotes"][op] = row
for k in S(C[0])["estrutura_lote"]:
    ov["estrutura_lote"][k] = {"cpu_por_decisao_mediana": med([med(S(s)["estrutura_lote"][k]["cpu"]) for s in C]),
                                "por_sessao": [med(S(s)["estrutura_lote"][k]["cpu"]) for s in C]}
out["sobrecarga"] = ov

# ---------------------------------------------------------------- 3) controle: efeito da ordem
ordem = {"handshake": {}, "politicas": {}}
def hs_arm(s, braco, cen):
    h = s["handshake"]
    return med(h["sequencial_cpu"][cen]) if braco == "seq" else med(np.concatenate(h["intercalado_cpu_por_rodada"][cen]))
for cen in ("ECDHE-ECDSA (servidor)", "ECDHE-ECDSA (mútua)"):
    r = {}
    for braco in ("seq", "int"):
        num = [hs_arm(s, braco, cen) for s in C]; den = [hs_arm(s, braco, "PSK") for s in C]
        r[braco] = {"PSK_medianas": den, "cenario_medianas": num, **resumo_razoes(num, den)}
    r["diferenca_razao_int_menos_seq_por_sessao"] = [a - b for a, b in zip(r["int"]["razoes_por_sessao"], r["seq"]["razoes_por_sessao"])]
    # pareamento por rodada dentro de cada sessão (exploratório): razão cenário/PSK em cada rodada do braço intercalado
    pr = []
    for s in C:
        h = s["handshake"]["intercalado_cpu_por_rodada"]
        pr.append(med([med(a) / med(b) for a, b in zip(h[cen], h["PSK"])]))
    r["razao_mediana_das_rodadas_por_sessao"] = pr
    ordem["handshake"][cen] = r
ordem["handshake"]["PSK_mediana_por_braco"] = {"seq": [hs_arm(s, "seq", "PSK") for s in C], "int": [hs_arm(s, "int", "PSK") for s in C]}
for n in C[0]["politicas"]:
    for caso in ("típico", "pior caso"):
        cel = {}
        for braco, chave in (("seq", "sequencial_cpu"), ("int", "intercalado_cpu")):
            g = lambda impl: [med(s["politicas"][n][caso][chave][impl]) for s in C]
            rb, li, ix = g("RBAC"), g("ABAC linear"), g("ABAC indexado")
            cel[braco] = {"RBAC": rb, "linear": li, "indexado": ix, "linear_sobre_RBAC": resumo_razoes(li, rb),
                          "linear_sobre_indexado": resumo_razoes(li, ix),
                          "indexado_sobre_RBAC": {"razoes_por_sessao": [float(a / b) for a, b in zip(ix, rb)],
                                                   "min": float(min(a / b for a, b in zip(ix, rb))), "max": float(max(a / b for a, b in zip(ix, rb))),
                                                   "mediana": med([a / b for a, b in zip(ix, rb)])}}
        ordem["politicas"][f"{n}|{caso}"] = cel
out["ordem"] = ordem

# ---------------------------------------------------------------- 4) controle: custo dos índices e ponto de equilíbrio
idx = {}
for n in C[0]["indices"]:
    g = lambda k: [med(s["indices"][n][k]["cpu"]) for s in C]
    constr, ins, insr = g("construir_indice"), g("inserir_200_regras_indice"), g("inserir_200_permissoes_rbac")
    dec = lambda impl: med([med(s["politicas"][n]["típico"]["sequencial_cpu"][impl]) for s in C]) if n in C[0]["politicas"] else None
    row = {"construir_indice_us": med(constr), "construir_por_sessao": constr, "inserir_regra_indice_us": med(ins), "inserir_permissao_rbac_us": med(insr)}
    if dec("ABAC linear") is not None:
        gain = dec("ABAC linear") - dec("ABAC indexado")
        row.update({"decisao_linear_us": dec("ABAC linear"), "decisao_indexado_us": dec("ABAC indexado"), "ganho_por_decisao_us": gain,
                    "decisoes_para_compensar_construcao": med(constr) / gain})
    idx[n] = row
out["indices"] = idx
json.dump(out, open(os.path.join(D, "analise_sessoes.json"), "w"), ensure_ascii=False, indent=1)

# ---------------------------------------------------------------- figura: razão ECDHE-ECDSA (servidor) / PSK por sessão
k1 = "ECDHE-ECDSA (autenticação do servidor)"; k2 = "ECDHE-ECDSA (servidor)"
series = [("Principal\n(ordem fixa)", out["principal_H1"][k1]["razoes_por_sessao"]),
          ("Controle\nsequencial", ordem["handshake"][k2]["seq"]["razoes_por_sessao"]),
          ("Controle\nintercalado", ordem["handshake"][k2]["int"]["razoes_por_sessao"])]
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 9})
fig, ax = plt.subplots(figsize=(6.0, 3.2))
for i, (nome, v) in enumerate(series):
    ax.scatter(np.full(len(v), i) + np.linspace(-.12, .12, len(v)), v, s=28, color="#5b8db8", zorder=3)
    ax.hlines(np.median(v), i - .25, i + .25, color="#b5533c", lw=2, zorder=2)
ax.axhline(1, color="gray", lw=.8, ls=":")
ax.set_xticks(range(3)); ax.set_xticklabels([s[0] for s in series]); ax.set_ylabel("Razão entre medianas\n(ECDHE-ECDSA servidor / PSK)")
ax.set_ylim(0, max(max(v) for _, v in series) * 1.15); ax.spines[["top", "right"]].set_visible(False); ax.grid(alpha=.25, axis="y")
plt.tight_layout(); plt.savefig(os.path.join(D, "fig12_razao_por_sessao.png"), dpi=170); plt.close()
print("OK analise_sessoes.json")
