# tc2-iot-benchmark – versão 5.0 (2026-11-01)

Pacote de reprodução do Trabalho de Curso II **"Segurança de dados em dispositivos de Internet das Coisas (IoT) de recursos
computacionais restritos: benchmark de mecanismos de autenticação e autorização"** (UNIP – Ciência da Computação, polo EAD Bauru).
Autor: Milton Isaías Júlio de Oliveira · Orientadora: Profa. Dra. Vanessa Santos Lessa.

## O que é (e o que não é)
Benchmark em Python, em ambiente **não embarcado**, de (i) operações criptográficas selecionadas de cenários inspirados em suítes
DTLS 1.2 para CoAP (PSK e ECDHE-ECDSA), (ii) proteção de mensagens com AEAD e (iii) decisões de autorização RBAC e ABAC.
**Não** mede rede, pilha DTLS/CoAP completa, validação de certificados, energia, segurança nem hardware embarcado.
"Certificado simplificado" e "autenticação mútua" são aproximações computacionais do lado avaliado.

## Requisitos
* Python 3.12 ou superior; Linux (o script lê `/proc/cpuinfo` para os metadados).
* `pip install -r requirements.txt` (cryptography 50.0.1, NumPy 2.5.3, SciPy 1.18.1, Matplotlib 3.11.2).
* A coleta do benchmark principal foi feita com Python 3.12.3 e cryptography 46.0.6 (OpenSSL 3.5.5): ver `requirements-principal.txt`.
  A verificação de controle usou Python 3.13.16, cryptography 50.0.1 e OpenSSL 4.0.2. Os valores absolutos mudam com o ambiente.

## Passo a passo
```
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
bash run_all.sh            # coleta + análise completas (~6 min); sobrescreve os resultados
```
Para **apenas reanalisar** os dados fornecidos (sem repetir a coleta), execute somente a seção de análise:
```
python3 agregar_e_graficos.py && python3 agregar_extra.py && python3 testes_hipoteses.py && python3 analise_sessoes.py
```
Rode a coleta sem outra carga na máquina. Cada sessão deve ser um processo distinto (chaves novas a cada execução).

## Arquivos
| Arquivo | Função | Saída |
|---|---|---|
| `benchmark_iot.py` | Benchmark principal (handshake, registros AES-CCM, RBAC/ABAC); 10 testes de correção antes da medição | `resultados_sessao_N.json` |
| `benchmark_extra.py` | AEAD (CCM/GCM/ChaCha20-Poly1305), P-256 × Curve25519, 5 cenários de handshake | `resultados_extra_sessao_N.json` |
| `benchmark_controle.py` | Verificação de controle: sobrecarga da medição, ordem sequencial × intercalada aleatorizada, custo dos índices | `resultados_controle_sessao_N.json` |
| `agregar_e_graficos.py` | Agrega as sessões principais; figuras 1–4 | `resultados.json`, `fig1…fig4` |
| `agregar_extra.py` | Agrega as sessões complementares; figuras 5–8 | `resultados_extra.json`, `fig5…fig8` |
| `testes_hipoteses.py` | Mann-Whitney/Cliff sobre amostras agrupadas (**exploratório**) | `testes_hipoteses.json` |
| `analise_sessoes.py` | **Inferência por sessão** (Wilcoxon exato pareado), sobrecarga, ordem e índices; figura 12 | `analise_sessoes.json`, `fig12_razao_por_sessao.png` |
| `figuras_conceituais.py` | Figuras conceituais do texto | `fig_*.png` |
| `resultados_*sessao_N.json` | Dados brutos por sessão (tempos em µs, metadados do ambiente) | – |
| `CHECKSUMS.sha256` | Soma SHA-256 de cada arquivo | – |

Sementes: políticas sintéticas com `SEED = 42` (fixa); ordem aleatória da verificação de controle com semente `7000 + sessão` (registrada nos metadados).

## Conferência
`sha256sum -c CHECKSUMS.sha256` confere a integridade dos arquivos. A reagregação dos JSON fornecidos reproduz `resultados.json`,
`resultados_extra.json` e `testes_hipoteses.json` com os mesmos valores.
