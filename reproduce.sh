uv run token-gradients.py --refusal-probs --compute-attrs --alpha 0.05 --batch-size 4 --model meta-llama/Llama-3.1-8B-Instruct
uv run token-gradients.py --refusal-probs --compute-attrs --alpha 0.05 --convergence-target 0.005 --batch-size 8 --model meta-llama/Llama-3.2-3B-Instruct
uv run token-gradients.py --refusal-probs --compute-attrs --alpha 0.05 --start-steps 384 --batch-size 4 --model Qwen/Qwen2.5-7B-Instruct
uv run token-gradients.py --refusal-probs --compute-attrs --alpha 0.05 --start-steps 192 --batch-size 4 --model Qwen/Qwen3-8B
