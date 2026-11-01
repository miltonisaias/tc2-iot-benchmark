#!/usr/bin/env bash
# Executa todo o fluxo (coleta + agregação + análise). Duração aproximada: 6 minutos em um servidor virtualizado de 1-2 núcleos.
# ATENÇÃO: sobrescreve os arquivos de resultados do diretório. Para só reanalisar os dados já fornecidos, execute apenas a seção "ANÁLISE".
set -euo pipefail
cd "$(dirname "$0")"

# --- COLETA (5 sessões independentes de cada conjunto; rode sem outra carga na máquina) ---
for i in 1 2 3 4 5; do python3 benchmark_iot.py --sessao "$i"; done          # ~40 s cada  -> resultados_sessao_N.json
for i in 1 2 3 4 5; do python3 benchmark_extra.py --sessao "$i"; done         # ~1 s cada   -> resultados_extra_sessao_N.json
for i in 1 2 3 4 5; do python3 benchmark_controle.py --sessao "$i"; done      # ~25 s cada  -> resultados_controle_sessao_N.json

# --- ANÁLISE (pode ser executada isoladamente sobre os JSON fornecidos) ---
python3 agregar_e_graficos.py      # resultados.json, fig1-fig4
python3 agregar_extra.py           # resultados_extra.json, fig5-fig8
python3 testes_hipoteses.py        # testes_hipoteses.json (exploratório, amostras agrupadas)
python3 analise_sessoes.py         # analise_sessoes.json, fig12 (inferência por sessão; sobrecarga; ordem; índices)
python3 figuras_conceituais.py     # fig_arquitetura, fig_handshake_fluxos, fig_fluxo_abac
echo "Concluído."
