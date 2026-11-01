#!/usr/bin/env python3
"""
Verificação focalizada de controle metodológico (TC II – Milton I. J. de Oliveira, UNIP)

Responde a três dúvidas metodológicas sobre o benchmark principal (benchmark_iot.py), SEM repetir todo o estudo:
  A) Sobrecarga do próprio procedimento de medição (operação vazia, granularidade efetiva dos relógios,
     medição individual x em lotes, estrutura de execução das decisões de autorização).
  B) Efeito da ordem de execução: cada sessão executa dois braços – SEQUENCIAL (um mecanismo após o outro, como no
     benchmark principal) e INTERCALADO ALEATORIZADO (blocos curtos, ordem dos mecanismos sorteada a cada rodada).
     A ordem dos braços (e dos blocos) alterna entre as sessões.
  C) Custo de construção e de atualização das estruturas de índice do ABAC indexado (fora da medição de decisão
     no benchmark principal) e de atualização do RBAC.

Reutiliza as funções do benchmark principal (importa benchmark_iot).  Uso: python3 benchmark_controle.py --sessao N
Grava resultados_controle_sessao_N.json  (valores em microssegundos, salvo indicação).
"""
import time, json, os, sys, random, platform, argparse, hashlib
import cryptography
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
import benchmark_iot as B

OUT = os.path.dirname(os.path.abspath(__file__))
RODADAS, REP_BLOCO = 30, 10            # handshake: 30 rodadas x 10 repetições = 300 por cenário
N_POL = [100, 1000]                    # tamanhos de política da verificação de ordem
CASOS = ["típico", "pior caso"]
IMPLS = ["RBAC", "ABAC linear", "ABAC indexado"]

def t_pair(fn):
    """Uma medição individual (CPU da thread e tempo decorrido), no mesmo formato do benchmark principal."""
    w0 = time.perf_counter_ns(); c0 = time.thread_time_ns(); fn()
    c1 = time.thread_time_ns(); w1 = time.perf_counter_ns()
    return (c1 - c0) / 1000.0, (w1 - w0) / 1000.0

# ------------------------------------------------------------------ A) SOBRECARGA DA MEDIÇÃO
def sobrecarga():
    out = {}
    out["operacao_vazia"] = B.measure(lambda i: None, 5000)                       # mesma função de medição, fn vazia
    # granularidade efetiva: menores variações não nulas entre chamadas consecutivas do relógio
    g = {}
    for nome, f in (("thread_time_ns", time.thread_time_ns), ("perf_counter_ns", time.perf_counter_ns)):
        d = []
        for _ in range(20000):
            a = f(); b = f(); d.append(b - a)
        pos = sorted(x for x in d if x > 0)
        g[nome] = {"amostras": len(d), "fracao_zero": sum(1 for x in d if x == 0) / len(d),
                   "menores_deltas_positivos_ns": sorted(set(pos))[:5], "mediana_ns": sorted(d)[len(d) // 2],
                   "p95_ns": sorted(d)[int(0.95 * len(d))]}
    out["granularidade_relogios"] = g
    # medição individual x em lotes (K chamadas por medição, valor dividido por K)
    K = 200; aead = AESCCM(AESCCM.generate_key(128), tag_length=8); pt, aad = os.urandom(128), os.urandom(13)
    blob = os.urandom(64)
    ops = {
        "PSK (operações do cenário)": (lambda: B.hs_psk(), None),
        "ECDH P-256": (lambda: B._dev_eph.exchange(B.ec.ECDH(), B.SRV_EPH_PUB), None),
        "SHA-256 de 64 bytes": (lambda: hashlib.sha256(blob).digest(), None),
        "AES-CCM cifrar 128 B": (None, aead),
    }
    ind, lote = {}, {}
    for nome, (f, a) in ops.items():
        if a is None:
            ind[nome] = B.measure(lambda i, f=f: f(), 1000)
            def corpo(i, f=f):
                for _ in range(K): f()
            r = B.measure(corpo, 200, warm=5)
        else:
            ind[nome] = B.measure(lambda n: a.encrypt(n, pt, aad), 1000, prep=lambda i: os.urandom(12))
            def corpo(ns, a=a):
                for n in ns: a.encrypt(n, pt, aad)
            r = B.measure(corpo, 200, prep=lambda i: [os.urandom(12) for _ in range(K)], warm=5)
        lote[nome] = {k: [x / K for x in v] for k, v in r.items()}
    out["individual"], out["em_lotes"], out["K_lote"] = ind, lote, K
    # estrutura de execução das decisões: tempo por decisão de funções triviais no formato "lote de 500 / 500"
    rng = random.Random(B.SEED + 1000); perms, rbac, rules = B.make_E(1000, rng)
    reqs = B.requests_E(perms, rng)["típico"]
    rb = lambda q: (q["act"], q["res"]["id"]) in rbac[q["subj"]["role"]]
    def laco_vazio():
        for q in reqs: pass
    estr = {"laço vazio sobre 500 requisições": laco_vazio,
            "chamada de função trivial (lambda q: True)": lambda: [(lambda q: True)(q) for q in reqs],
            "decisão RBAC (como no benchmark principal)": lambda: [rb(q) for q in reqs]}
    out["estrutura_lote"] = {k: {kk: [x / len(reqs) for x in vv] for kk, vv in B.measure(lambda i, f=f: f(), 300, warm=5).items()}
                             for k, f in estr.items()}
    return out

# ------------------------------------------------------------------ B) ORDEM DOS MECANISMOS
def handshake_scenarios():
    return {"PSK": lambda i: B.hs_psk(), "ECDHE-ECDSA (servidor)": lambda i: B.hs_ecdhe(False),
            "ECDHE-ECDSA (mútua)": lambda i: B.hs_ecdhe(True)}

def ordem_handshake(rng, seq_primeiro):
    sc = handshake_scenarios(); nomes = list(sc)
    for f in sc.values():                                     # aquecimento global (todos os cenários), fora dos braços
        for i in range(B.WARM): f(i)
    def braco_seq():                                          # sequencial: 300 de cada, um cenário após o outro
        return {n: [t_pair(lambda: sc[n](0))[0] for _ in range(RODADAS * REP_BLOCO)] for n in nomes}
    def braco_int():                                          # intercalado: ordem sorteada a cada rodada
        inter = {n: [] for n in nomes}; ordens = []
        for r in range(RODADAS):
            o = nomes[:]; rng.shuffle(o); ordens.append(o)
            for n in o:
                inter[n].append([t_pair(lambda: sc[n](0))[0] for _ in range(REP_BLOCO)])
        return inter, ordens
    if seq_primeiro: seq = braco_seq(); inter, ordens = braco_int()
    else: inter, ordens = braco_int(); seq = braco_seq()
    return {"sequencial_cpu": seq, "intercalado_cpu_por_rodada": inter, "ordens": ordens, "sequencial_primeiro": seq_primeiro}

def ordem_politicas(rng, n, seq_primeiro):
    r0 = random.Random(B.SEED + n)                            # mesma construção do benchmark principal
    perms, rbac, rules = B.make_E(n, r0); idx = B.build_index(rules, lambda r: (r["act"], r["conds"][1][2]))
    kreq = lambda q: (q["act"], q["res"]["id"]); rb = lambda q: (q["act"], q["res"]["id"]) in rbac[q["subj"]["role"]]
    res = {}
    for caso, reqs in B.requests_E(perms, r0).items():
        if caso not in CASOS: continue
        impls = {"RBAC": lambda: [rb(q) for q in reqs], "ABAC linear": lambda: [B.abac_linear(rules, q, True) for q in reqs],
                 "ABAC indexado": lambda: [B.abac_indexed(idx, kreq, q) for q in reqs]}
        for f in impls.values():
            for _ in range(3): f()                            # aquecimento
        def braco_seq(): return {k: [t_pair(f)[0] / len(reqs) for _ in range(B.R_POL)] for k, f in impls.items()}
        def braco_int():
            inter = {k: [] for k in impls}; ordens = []
            for r in range(B.R_POL):
                o = list(impls); rng.shuffle(o); ordens.append(o)
                for k in o: inter[k].append(t_pair(impls[k])[0] / len(reqs))
            return inter, ordens
        if seq_primeiro: seq = braco_seq(); inter, ordens = braco_int()
        else: inter, ordens = braco_int(); seq = braco_seq()
        res[caso] = {"sequencial_cpu": seq, "intercalado_cpu": inter, "ordens": ordens}
    return res

# ------------------------------------------------------------------ C) CUSTO DOS ÍNDICES
def custo_indices():
    out = {}
    for n in [10, 50, 100, 500, 1000]:
        rng = random.Random(B.SEED + n); perms, rbac, rules = B.make_E(n, rng)
        key = lambda r: (r["act"], r["conds"][1][2])
        novas = [{"act": rng.choice(B.ACTS), "effect": "permit", "conds": [("subj.role", "eq", rng.choice(B.ROLES)), ("res.id", "eq", B.RID + j)]}
                 for j in range(200)]                           # 200 novas regras/permissões (ids fora do intervalo existente)
        idx0 = B.build_index(rules, key)
        constr = B.measure(lambda i: B.build_index(rules, key), 200, warm=5)                      # construção do zero
        def copia_idx(i): return {k: list(v) for k, v in idx0.items()}
        def ins_idx(d):
            for r in novas: d.setdefault(key(r), []).append(r)
        ins = B.measure(ins_idx, 200, prep=copia_idx, warm=5)
        def copia_rb(i): return {k: set(v) for k, v in rbac.items()}
        def ins_rb(d):
            for r in novas: d[r["conds"][0][2]].add((r["act"], r["conds"][1][2]))
        insr = B.measure(ins_rb, 200, prep=copia_rb, warm=5)
        out[n] = {"construir_indice": constr, "inserir_200_regras_indice": {k: [x / 200 for x in v] for k, v in ins.items()},
                  "inserir_200_permissoes_rbac": {k: [x / 200 for x in v] for k, v in insr.items()}}
    return out

if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("--sessao", type=int, default=1); a = ap.parse_args()
    t0 = time.time(); B.run_tests()
    rng = random.Random(7000 + a.sessao)                       # semente da ordem aleatória, registrada nos metadados
    res = {}
    res["sobrecarga"] = sobrecarga()
    # entre sessões alternam-se a ordem dos braços e qual bloco (handshake ou políticas) é executado primeiro,
    # para não fixar um braço ou um bloco no início ou no fim da sessão
    sp = a.sessao % 2 == 1                                     # sessões ímpares: braço sequencial primeiro
    blocos = [("handshake", lambda: ordem_handshake(rng, sp)),
              ("politicas", lambda: {str(n): ordem_politicas(rng, n, sp) for n in N_POL})]
    if a.sessao % 2 == 0: blocos.reverse()
    ordem_blocos = []
    for nome, f in blocos: res[nome] = f(); ordem_blocos.append(nome)
    res["indices"] = custo_indices()
    try:
        from cryptography.hazmat.backends.openssl.backend import backend; ossl = backend.openssl_version_text()
    except Exception: ossl = "indisponível"
    res["meta"] = {"sessao": a.sessao, "python": sys.version.split()[0], "cryptography": cryptography.__version__, "openssl": ossl,
                   "so": platform.platform(), "cpu": [l.split(":")[1].strip() for l in open("/proc/cpuinfo") if l.startswith("model name")][:1],
                   "nucleos": os.cpu_count(), "semente_ordem": 7000 + a.sessao, "ordem_dos_blocos": ordem_blocos, "sequencial_primeiro": sp,
                   "rodadas_handshake": RODADAS, "repeticoes_por_bloco": REP_BLOCO, "tamanhos_politica": N_POL,
                   "duracao_s": round(time.time() - t0, 1)}
    json.dump(res, open(os.path.join(OUT, f"resultados_controle_sessao_{a.sessao}.json"), "w"), ensure_ascii=False)
    print("OK controle sessão", a.sessao, res["meta"]["duracao_s"], "s")
