# DETECTING PROMPT INJECTIONS WITH INTEGRATED GRADIENTS

## Prereqs

You will need a HuggingFace access token with access to the following gated repositories:
- [Llama 3.1](https://huggingface.co/collections/meta-llama/metas-llama-31-models-and-evals-675bfd70e574a62dd0e40565)
- [Llama 3.2](https://huggingface.co/collections/meta-llama/metas-llama-32-language-models-and-evals-675bfd70e574a62dd0e40586)
- [qualifire prompt injections](https://huggingface.co/collections/qualifire/security-6889de587237de6a6a04fdf4)

It is recommended to use `uv` to automatically install dependencies before running `token-gradients.py`.

## Usage

Create a `.env` file with `HF_TOKEN`.

Run once per model you want to analyze:
```bash
uv run token-gradients.py --model-id [model] --steps [N] --batch-size [B]
```

Additional arguments can be found via `--help`.

## Data

All input data can be found in the various top-level `.csv` files.
Full output data is available in `prompt_injections.parquet` and `injection_success_rates.parquet`.

## Notes

Currently only certain Llama and Qwen models are supported.
It should be possible to run `token-gradients.py` for additional sizes and possibly generations of Llama and Qwen models
by adding them to `choices` for the `--model-id` argument, but only the 4 models listed there have been tested.
Supporting other models may require further modifications depending on their vocabulary and chat template.
