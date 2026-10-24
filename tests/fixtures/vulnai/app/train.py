"""Fine-tuning job (deliberately vulnerable: see README.md)."""
import wandb
from datasets import load_dataset
from transformers import AutoModelForCausalLM, Trainer, TrainingArguments

wandb.login(key="0f4c2d9e8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e")              # planted: hard-coded W&B key (fake)
data = load_dataset("json", data_files="data/train.jsonl")             # planted: personal data in training
model = AutoModelForCausalLM.from_pretrained("acme-ai/base-1b", revision="3f2a9c1")
Trainer(model=model, args=TrainingArguments(output_dir="out"), train_dataset=data["train"]).train()
