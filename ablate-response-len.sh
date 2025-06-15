uv run token-gradients.py --generate-responses --model meta-llama/Llama-3.1-8B-Instruct --response-len 4 5 7 10 \
  --responses-path response_len_ablation.parquet
uv run token-gradients.py --compute-attrs --alpha 0.05 --batch-size 4 --model meta-llama/Llama-3.1-8B-Instruct \
  --response-len 4 5 7 10 --responses-path response_len_ablation.parquet --output-path response_len_ablation_attrs.parquet