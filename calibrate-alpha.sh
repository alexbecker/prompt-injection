uv run token-gradients.py --compute-attrs --alpha 0.005 --batch-size 8 --model meta-llama/Llama-3.2-3B-Instruct
uv run token-gradients.py --compute-attrs --alpha 0.01 --batch-size 8 --model meta-llama/Llama-3.2-3B-Instruct
uv run token-gradients.py --compute-attrs --alpha 0.025 --batch-size 8 --model meta-llama/Llama-3.2-3B-Instruct
uv run token-gradients.py --compute-attrs --alpha 0.05 --batch-size 8 --model meta-llama/Llama-3.2-3B-Instruct
uv run token-gradients.py --compute-attrs --alpha 0.1 --batch-size 8 --model meta-llama/Llama-3.2-3B-Instruct
uv run token-gradients.py --compute-attrs --alpha 0.2 --batch-size 8 --model meta-llama/Llama-3.2-3B-Instruct
