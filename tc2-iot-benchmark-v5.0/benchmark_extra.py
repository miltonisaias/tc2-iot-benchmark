#!/usr/bin/env python3
"""
Medições complementares (TC II - Milton I. J. de Oliveira): reutiliza o módulo benchmark_iot.py.
  E1) Cifras autenticadas (AEAD): AES-128-CCM (etiqueta 8 B), AES-128-GCM, ChaCha20-Poly1305
  E2) Operações assimétricas: P-256 (ECDH/ECDSA) vs. X25519/Ed25519
  E3) Cenários de handshake (operações selecionadas): PSK, ECDHE-ECDSA P-256, X25519+Ed25519
Mesmas métricas e limitações de benchmark_iot.py (tempo de CPU da thread; ambiente não embarcado).
Uso: python3 benchmark_extra.py --sessao N   (grava resultados_extra_sessao_N.json)
"""
import json, os, sys, time, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cryptography
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, x25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM, AESGCM, ChaCha20Poly1305
import benchmark_iot as B

R = B.R_HS
# ---- Ed25519 / X25519 (material de chaves preparado FORA da medição)
ED_CA, ED_SRV, ED_DEV = (ed25519.Ed25519PrivateKey.generate() for _ in range(3))
ED_CA_PUB, ED_SRV_PUB = ED_CA.public_key(), ED_SRV.public_key()
ED_CERT_SIG = ED_CA.sign(b"cert-servidor")
ED_SKE_SIG = ED_SRV.sign(B.SKE_DATA)
X_SRV = x25519.X25519PrivateKey.generate(); X_SRV_PUB = X_SRV.public_key()
_x_dev = x25519.X25519PrivateKey.generate()
ED_MSG_SIG = ED_DEV.sign(b"certificate-verify"); ED_DEV_PUB = ED_DEV.public_key()

def hs_x25519(mutual):
    ED_CA_PUB.verify(ED_CERT_SIG, b"cert-servidor")
    ED_SRV_PUB.verify(ED_SKE_SIG, B.SKE_DATA)
    eph = x25519.X25519PrivateKey.generate()
    kb = B.derive(eph.exchange(X_SRV_PUB))
    if mutual: ED_DEV.sign(b"certificate-verify")
    return kb

def check():
    e = x25519.X25519PrivateKey.generate()
    assert e.exchange(X_SRV_PUB) == X_SRV.exchange(e.public_key())
    ED_DEV_PUB.verify(ED_MSG_SIG, b"certificate-verify")
    assert len(hs_x25519(True)) == 40 and len(B.hs_ecdhe(True)) == 40 and len(B.hs_psk()) == 40
    return True

def bench_aead():
    algs = {"AES-128-CCM (etiqueta de 8 bytes)": AESCCM(AESCCM.generate_key(128), tag_length=8),
            "AES-128-GCM (etiqueta de 16 bytes)": AESGCM(AESGCM.generate_key(128)),
            "ChaCha20-Poly1305 (etiqueta de 16 bytes)": ChaCha20Poly1305(ChaCha20Poly1305.generate_key())}
    out = {}
    for nome, a in algs.items():
        out[nome] = {}
        for size in [16, 64, 128, 256, 512, 1024]:
            pt, aad = os.urandom(size), os.urandom(13); N = B.WARM + B.R_REC
            nonces = [os.urandom(12) for _ in range(N)]
            cts = [a.encrypt(nonces[i], pt, aad) for i in range(N)]
            out[nome][size] = {"cifrar": B.measure(lambda i: a.encrypt(nonces[i], pt, aad), B.R_REC),
                               "decifrar": B.measure(lambda i: a.decrypt(nonces[i], cts[i], aad), B.R_REC)}
    return out

def bench_ops():
    ops = {
      "P-256: geração de chave": lambda i: ec.generate_private_key(B.CURVE),
      "P-256: ECDH": lambda i: B._dev_eph.exchange(ec.ECDH(), B.SRV_EPH_PUB),
      "P-256: ECDSA assinar": lambda i: B.DEV_KEY.sign(b"certificate-verify", ec.ECDSA(hashes.SHA256())),
      "P-256: ECDSA verificar": lambda i: B.SRV_PUB.verify(B.SKE_SIG, B.SKE_DATA, ec.ECDSA(hashes.SHA256())),
      "X25519: geração de chave": lambda i: x25519.X25519PrivateKey.generate(),
      "X25519: troca de chaves": lambda i: _x_dev.exchange(X_SRV_PUB),
      "Ed25519: geração de chave": lambda i: ed25519.Ed25519PrivateKey.generate(),
      "Ed25519: assinar": lambda i: ED_DEV.sign(b"certificate-verify"),
      "Ed25519: verificar": lambda i: ED_DEV_PUB.verify(ED_MSG_SIG, b"certificate-verify"),
    }
    return {k: B.measure(f, R) for k, f in ops.items()}

def bench_scenarios():
    sc = {"PSK": lambda i: B.hs_psk(),
          "ECDHE-ECDSA P-256 (autenticação do servidor)": lambda i: B.hs_ecdhe(False),
          "ECDHE-ECDSA P-256 (autenticação mútua)": lambda i: B.hs_ecdhe(True),
          "X25519 + Ed25519 (autenticação do servidor)": lambda i: hs_x25519(False),
          "X25519 + Ed25519 (autenticação mútua)": lambda i: hs_x25519(True)}
    return {k: B.measure(f, R) for k, f in sc.items()}

if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("--sessao", type=int, default=1); a = ap.parse_args()
    t0 = time.time(); assert check()
    res = {"sessao": a.sessao, "cryptography": cryptography.__version__, "aead": bench_aead(), "operacoes": bench_ops(), "cenarios": bench_scenarios(),
           "duracao_s": round(time.time() - t0, 1)}
    json.dump(res, open(os.path.join(os.path.dirname(os.path.abspath(__file__)), f"resultados_extra_sessao_{a.sessao}.json"), "w"), ensure_ascii=False)
    print("OK extra sessão", a.sessao, res["duracao_s"], "s")
