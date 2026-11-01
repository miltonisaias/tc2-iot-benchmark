#!/usr/bin/env python3
"""
Benchmark de mecanismos de autenticação e autorização para IoT de recursos restritos
Autor: Milton Isaías Júlio de Oliveira (TC II - UNIP)

NATUREZA DO EXPERIMENTO
  Benchmark, em ambiente não embarcado, de (i) operações criptográficas selecionadas de cenários de handshake
  inspirados em suítes DTLS 1.2 para CoAP, (ii) proteção/verificação de mensagens com AES-CCM e
  (iii) decisões de autorização RBAC e ABAC implementadas em Python.
NÃO MODELA: rede, CoAP, pilha DTLS completa, retransmissão, validação de cadeias de certificados,
  ataques, proteção contra repetição, dispositivo embarcado nem energia.

MÉTRICAS
  cpu  = time.thread_time_ns()   (tempo de CPU da thread)
  wall = time.perf_counter_ns()  (tempo decorrido; inclui escalonamento do SO)
Uso: python3 benchmark_iot.py --sessao N   (grava resultados_sessao_N.json)
"""
import time, json, hmac, hashlib, random, platform, os, sys, argparse
import cryptography
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

SEED = 42
R_HS, R_REC, R_POL, BATCH, WARM = 300, 300, 30, 500, 20
OUT = os.path.dirname(os.path.abspath(__file__))

def measure(fn, reps, prep=None, warm=WARM):
    """Executa fn(arg) reps vezes (após aquecimento); arg = prep(i) preparado FORA da medição."""
    cpu, wall = [], []
    for i in range(warm + reps):
        arg = prep(i) if prep else i
        w0 = time.perf_counter_ns(); c0 = time.thread_time_ns()
        fn(arg)
        c1 = time.thread_time_ns(); w1 = time.perf_counter_ns()
        if i >= warm:
            cpu.append((c1 - c0) / 1000.0); wall.append((w1 - w0) / 1000.0)
    return {"cpu": cpu, "wall": wall}

def measure_batch(fn, reps, per):
    r = measure(fn, reps, warm=3)
    return {k: [x / per for x in v] for k, v in r.items()}

# ------------------------------------------------------------------ 1) HANDSHAKE (operações selecionadas, encadeadas)
CURVE = ec.SECP256R1()
SRV_KEY, DEV_KEY, CA_KEY = (ec.generate_private_key(CURVE) for _ in range(3))
CA_PUB, SRV_PUB = CA_KEY.public_key(), SRV_KEY.public_key()
CR, SR = os.urandom(32), os.urandom(32)
SRV_EPH = ec.generate_private_key(CURVE); SRV_EPH_PUB = SRV_EPH.public_key()
CERT_SIG = CA_KEY.sign(b"cert-servidor", ec.ECDSA(hashes.SHA256()))
SKE_DATA = CR + SR + b"params-ecdhe-p256"
SKE_SIG = SRV_KEY.sign(SKE_DATA, ec.ECDSA(hashes.SHA256()))
PSK = os.urandom(16)

def prf(secret, label, seed, n):
    """PRF do TLS 1.2 (P_SHA256, RFC 5246)."""
    seed = label + seed; a = seed; out = b""
    while len(out) < n:
        a = hmac.new(secret, a, hashlib.sha256).digest()
        out += hmac.new(secret, a + seed, hashlib.sha256).digest()
    return out[:n]

def derive(premaster):
    ms = prf(premaster, b"master secret", CR + SR, 48)
    return prf(ms, b"key expansion", SR + CR, 40)

def hs_psk():
    pm = len(PSK).to_bytes(2, "big") + bytes(len(PSK)) + len(PSK).to_bytes(2, "big") + PSK   # RFC 4279
    return derive(pm)

def hs_ecdhe(mutual):
    CA_PUB.verify(CERT_SIG, b"cert-servidor", ec.ECDSA(hashes.SHA256()))      # certificado (simplificado)
    SRV_PUB.verify(SKE_SIG, SKE_DATA, ec.ECDSA(hashes.SHA256()))              # ServerKeyExchange
    eph = ec.generate_private_key(CURVE)                                      # chave efêmera do dispositivo (USADA no ECDH)
    pm = eph.exchange(ec.ECDH(), SRV_EPH_PUB)                                 # segredo ECDH alimenta a derivação
    kb = derive(pm)
    if mutual: DEV_KEY.sign(b"certificate-verify", ec.ECDSA(hashes.SHA256()))
    return kb

def check_handshake_consistency():
    eph = ec.generate_private_key(CURVE)
    assert eph.exchange(ec.ECDH(), SRV_EPH_PUB) == SRV_EPH.exchange(ec.ECDH(), eph.public_key())   # ambos os lados chegam ao mesmo segredo
    assert len(hs_psk()) == 40 and len(hs_ecdhe(True)) == 40
    return True

_dev_eph = ec.generate_private_key(CURVE)
OPS = {
  "geração de chave P-256": lambda i: ec.generate_private_key(CURVE),
  "ECDH P-256": lambda i: _dev_eph.exchange(ec.ECDH(), SRV_EPH_PUB),
  "verificação ECDSA": lambda i: SRV_PUB.verify(SKE_SIG, SKE_DATA, ec.ECDSA(hashes.SHA256())),
  "assinatura ECDSA": lambda i: DEV_KEY.sign(b"certificate-verify", ec.ECDSA(hashes.SHA256())),
  "derivação PRF (HMAC-SHA256)": lambda i: derive(PSK),
}
def bench_handshake():
    sc = {"PSK": lambda i: hs_psk(), "ECDHE-ECDSA (autenticação do servidor)": lambda i: hs_ecdhe(False),
          "ECDHE-ECDSA (autenticação mútua)": lambda i: hs_ecdhe(True)}
    return ({k: measure(f, R_HS) for k, f in sc.items()}, {k: measure(f, R_HS) for k, f in OPS.items()})

# ------------------------------------------------------------------ 2) REGISTROS (cifrar, decifrar, rejeitar adulterada)
def bench_records():
    aead = AESCCM(AESCCM.generate_key(128), tag_length=8); out = {}
    for size in [16, 64, 128, 256, 512, 1024]:
        pt, aad = os.urandom(size), os.urandom(13); N = WARM + R_REC
        nonces = [os.urandom(12) for _ in range(N)]                # nonce distinto por execução, gerado FORA da medição
        cts = [aead.encrypt(nonces[i], pt, aad) for i in range(N)]
        bad = [c[:-1] + bytes([c[-1] ^ 1]) for c in cts]           # etiqueta adulterada
        enc = measure(lambda i: aead.encrypt(nonces[i], pt, aad), R_REC)
        dec = measure(lambda i: aead.decrypt(nonces[i], cts[i], aad), R_REC)
        rej = {"n": 0}
        def tamper(i):
            try: aead.decrypt(nonces[i], bad[i], aad)
            except InvalidTag: rej["n"] += 1
        tam = measure(tamper, R_REC); tam["rejeitadas"] = rej["n"] - WARM   # todas devem ser rejeitadas
        out[size] = {"cifrar": enc, "decifrar": dec, "adulterada": tam}
    return out

# ------------------------------------------------------------------ 3) AUTORIZAÇÃO
ROLES = ["sensor", "atuador", "gateway", "admin", "manutencao"]
RES_T = ["temperatura", "umidade", "porta", "luz", "camera", "firmware"]
ACTS = ["read", "write", "update", "delete"]
ZONES = ["sala", "cozinha", "garagem", "externo", "servidor"]
RID = 10000

def get_attr(req, path):
    a, b = path.split("."); return req[a][b]
def cond_ok(req, c):
    path, op, val = c; v = get_attr(req, path)
    if op == "eq": return v == val
    if op == "ge": return v >= val
    if op == "range": return val[0] <= v <= val[1]
    return False

def abac_linear(rules, req, first_applicable=False):
    """Percorre as regras em ordem. Encerra ao achar NEGAÇÃO aplicável (deny-overrides) e, se
    first_applicable, também ao achar a primeira PERMISSÃO aplicável."""
    permit = False
    for r in rules:
        if r["act"] != req["act"]: continue
        if all(cond_ok(req, c) for c in r["conds"]):
            if r["effect"] == "deny": return False
            permit = True
            if first_applicable: return True
    return permit

def abac_linear_count(rules, req, first_applicable=False):
    permit, nr, nc = False, 0, 0
    for r in rules:
        nr += 1
        if r["act"] != req["act"]: continue
        ok = True
        for c in r["conds"]:
            nc += 1
            if not cond_ok(req, c): ok = False; break
        if ok:
            if r["effect"] == "deny": return False, nr, nc
            permit = True
            if first_applicable: return True, nr, nc
    return permit, nr, nc

def build_index(rules, keyfn):
    idx = {}
    for r in rules: idx.setdefault(keyfn(r), []).append(r)
    return idx
def abac_indexed(idx, keyfn_req, req):
    permit = False
    for r in idx.get(keyfn_req(req), ()):
        if all(cond_ok(req, c) for c in r["conds"]):
            if r["effect"] == "deny": return False
            permit = True
    return permit

# ---- Cenário E (semanticamente equivalente): permissões (papel, ação, recurso)
def make_E(n, rng):
    perms = set()
    while len(perms) < n: perms.add((rng.choice(ROLES), rng.choice(ACTS), rng.randrange(RID)))
    perms = sorted(perms); rng.shuffle(perms)
    rbac = {r: set() for r in ROLES}
    for r, a, i in perms: rbac[r].add((a, i))
    rules = [{"act": a, "effect": "permit", "conds": [("subj.role", "eq", r), ("res.id", "eq", i)]} for r, a, i in perms]
    return perms, rbac, rules
def reqE(r, a, i): return {"act": a, "subj": {"role": r}, "res": {"id": i}, "env": {}}
def requests_E(perms, rng):
    pset = set(perms)
    def denied():
        while True:
            t = (rng.choice(ROLES), rng.choice(ACTS), rng.randrange(RID))
            if t not in pset: return reqE(*t)
    best = [reqE(*perms[0])] * BATCH                                       # regra aplicável é a 1ª
    worst = [denied() for _ in range(BATCH)]                               # nenhuma regra aplicável: varredura completa
    typ = [reqE(*rng.choice(perms)) if rng.random() < 0.5 else denied() for _ in range(BATCH)]
    return {"melhor caso": best, "pior caso": worst, "típico": typ}

# ---- Cenário C (contextual): regras com atributos de sujeito, recurso e ambiente
def make_C(n, k, rng):
    rules = []
    for _ in range(n):
        conds = [("subj.role", "eq", rng.choice(ROLES)), ("res.type", "eq", rng.choice(RES_T)),
                 ("env.zone", "eq", rng.choice(ZONES)), ("env.hour", "range", (rng.randint(0, 11), rng.randint(12, 23))),
                 ("subj.fw", "ge", rng.randint(1, 5)), ("env.battery", "ge", rng.randint(5, 40))][:k]
        rules.append({"act": rng.choice(ACTS), "effect": rng.choice(["permit", "deny"]), "conds": conds, "rtype": conds[1][2]})
    return rules
def rand_req(rng):
    return {"act": rng.choice(ACTS), "subj": {"role": rng.choice(ROLES), "fw": rng.randint(1, 5)},
            "res": {"type": rng.choice(RES_T)},
            "env": {"zone": rng.choice(ZONES), "hour": rng.randint(0, 23), "battery": rng.randint(1, 100)}}
def req_satisfying(rule):
    q = {"act": rule["act"], "subj": {"role": "x", "fw": 0}, "res": {"type": "x"}, "env": {"zone": "x", "hour": 0, "battery": 0}}
    for path, op, val in rule["conds"]:
        a, b = path.split(".")
        q[a][b] = val if op == "eq" else (val[0] if op == "range" else val)
    return q
def requests_C(rules, rng):
    r0 = dict(rules[0]); r0["effect"] = "deny"; rules[0] = r0              # 1ª regra é uma negação
    best = [req_satisfying(rules[0])] * BATCH
    none = [{"act": "nenhuma", "subj": {"role": "x", "fw": 0}, "res": {"type": "x"}, "env": {"zone": "x", "hour": 0, "battery": 0}}] * BATCH
    typ = [rand_req(rng) for _ in range(BATCH)]
    return {"melhor caso (negação na 1ª regra)": best, "sem regra aplicável (varredura completa)": none, "típico (requisições aleatórias)": typ}

def bench_policies():
    E, C = {}, {}
    for n in [10, 50, 100, 500, 1000]:
        rng = random.Random(SEED + n)
        perms, rbac, rules = make_E(n, rng); idx = build_index(rules, lambda r: (r["act"], r["conds"][1][2]))
        kreq = lambda q: (q["act"], q["res"]["id"])
        rb = lambda q: (q["act"], q["res"]["id"]) in rbac[q["subj"]["role"]]
        rows = {}
        for caso, reqs in requests_E(perms, rng).items():
            for q in reqs:   # equivalência semântica em TODAS as requisições
                a, b_, c_ = rb(q), abac_linear(rules, q, True), abac_indexed(idx, kreq, q)
                assert a == b_ == c_, "divergência RBAC/ABAC/ABAC-indexado"
            pr = sum(rb(q) for q in reqs) / len(reqs)
            impls = {"RBAC": lambda reqs=reqs: [rb(q) for q in reqs],
                     "ABAC linear": lambda reqs=reqs: [abac_linear(rules, q, True) for q in reqs],
                     "ABAC indexado": lambda reqs=reqs: [abac_indexed(idx, kreq, q) for q in reqs]}
            rows[caso] = {"proporcao_permitidos": pr, **{nm: measure_batch(lambda _i, f=f: f(), R_POL, BATCH) for nm, f in impls.items()}}
        E[n] = rows
    for n in [10, 50, 100, 500, 1000]:
        for k in [3, 6]:
            rng = random.Random(SEED + 1000 * k + n)
            rules = make_C(n, k, rng); reqs_by = requests_C(rules, rng)
            idx = build_index(rules, lambda r: (r["act"], r["rtype"])); kreq = lambda q: (q["act"], q["res"]["type"])
            rows = {}
            for caso, reqs in reqs_by.items():
                dec = [abac_linear(rules, q) for q in reqs]
                assert dec == [abac_indexed(idx, kreq, q) for q in reqs], "divergência ABAC linear/indexado"
                cnt = [abac_linear_count(rules, q) for q in reqs]
                rows[caso] = {"proporcao_permitidos": sum(dec) / len(dec),
                              "regras_percorridas_media": sum(c[1] for c in cnt) / len(cnt),
                              "condicoes_avaliadas_media": sum(c[2] for c in cnt) / len(cnt),
                              "ABAC linear": measure_batch(lambda _i, reqs=reqs: [abac_linear(rules, q) for q in reqs], R_POL, BATCH),
                              "ABAC indexado": measure_batch(lambda _i, reqs=reqs: [abac_indexed(idx, kreq, q) for q in reqs], R_POL, BATCH)}
            # equivalência adicional em 2000 requisições aleatórias
            extra = [rand_req(rng) for _ in range(2000)]
            assert all(abac_linear(rules, q) == abac_indexed(idx, kreq, q) for q in extra)
            C[f"{n}_{k}"] = {"regras": n, "condicoes": k, "casos": rows}
    return E, C

def run_tests():
    """Testes específicos de correção (devem passar antes da medição)."""
    T = []
    def t(nome, cond): T.append({"teste": nome, "ok": bool(cond)}); assert cond, nome
    kreq = lambda q: (q["act"], q["res"]["type"]); kr = lambda r: (r["act"], r["rtype"])
    mk = lambda eff, conds, act="read": {"act": act, "effect": eff, "conds": conds, "rtype": conds[1][2]}
    base = lambda **env: {"act": "read", "subj": {"role": "sensor", "fw": 3}, "res": {"type": "luz"},
                          "env": {"zone": "sala", "hour": 12, "battery": 20, **env}}
    c = lambda lo=8, hi=18, fw=3, bat=20: [("subj.role", "eq", "sensor"), ("res.type", "eq", "luz"), ("env.hour", "range", (lo, hi)),
                                          ("subj.fw", "ge", fw), ("env.battery", "ge", bat)]
    def both(rules, q):
        idx = build_index(rules, kr); a, b = abac_linear(rules, q), abac_indexed(idx, kreq, q); return a, b
    a, b = both([mk("permit", c(), "write")], base()); t("sem regra aplicável: negado por padrão (linear e indexado)", a is False and b is False)
    for ordem in (0, 1):
        rs = [mk("permit", c()), mk("deny", c())]; rs = rs if ordem == 0 else rs[::-1]
        a, b = both(rs, base()); t(f"conflito permitir/negar (ordem {ordem}): negação prevalece", a is False and b is False)
    a, b = both([mk("permit", c())], base(hour=8)); t("limite inferior da faixa de horário (inclusivo)", a and b)
    a, b = both([mk("permit", c())], base(hour=18)); t("limite superior da faixa de horário (inclusivo)", a and b)
    a, b = both([mk("permit", c())], base(hour=19)); t("fora da faixa de horário: negado", (not a) and (not b))
    a, b = both([mk("permit", c())], base(battery=20)); t("bateria igual ao limiar: permitido", a and b)
    a, b = both([mk("permit", c())], base(battery=19)); t("bateria abaixo do limiar: negado", (not a) and (not b))
    q = base(); q["subj"]["fw"] = 2; a, b = both([mk("permit", c())], q); t("firmware abaixo do mínimo: negado", (not a) and (not b))
    t("derivação de chaves consistente entre os dois lados do ECDH", check_handshake_consistency())
    return T

if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("--sessao", type=int, default=1); a = ap.parse_args()
    t0 = time.time(); testes = run_tests()
    hs, ops = bench_handshake(); rec = bench_records(); E, C = bench_policies()
    try:
        from cryptography.hazmat.backends.openssl.backend import backend; ossl = backend.openssl_version_text()
    except Exception: ossl = "indisponível"
    meta = {"sessao": a.sessao, "python": sys.version.split()[0], "cryptography": cryptography.__version__, "openssl": ossl,
            "so": platform.platform(), "cpu": [l.split(":")[1].strip() for l in open("/proc/cpuinfo") if l.startswith("model name")][:1],
            "nucleos": os.cpu_count(), "seed_politicas": SEED, "repeticoes": {"handshake": R_HS, "registro": R_REC, "lotes_politica": R_POL, "decisoes_por_lote": BATCH, "aquecimento": WARM},
            "resolucao_ns": {"perf_counter": time.get_clock_info("perf_counter").resolution, "thread_time": time.get_clock_info("thread_time").resolution},
            "duracao_s": round(time.time() - t0, 1)}
    json.dump({"meta": meta, "testes": testes, "handshake": hs, "operacoes": ops, "registros": rec, "politicas_E": E, "politicas_C": C},
              open(os.path.join(OUT, f"resultados_sessao_{a.sessao}.json"), "w"), ensure_ascii=False)
    print("OK sessão", a.sessao, meta["duracao_s"], "s")
