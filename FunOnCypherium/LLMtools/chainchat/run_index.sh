#!/bin/bash
cd /root/go/src/github.com/cypherium/cypher/tools/chainchat
source .venv/bin/activate

export OLLAMA_NUM_PARALLEL=1
export OLLAMA_KEEP_ALIVE=5m
export TOKENIZERS_PARALLELISM=false
export PYTHONUNBUFFERED=1

python3 index_build.py
