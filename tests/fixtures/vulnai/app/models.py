"""Model loading (deliberately vulnerable: see README.md)."""
import pickle

import joblib
import numpy as np
import torch
import yaml
from huggingface_hub import hf_hub_download
from tensorflow import keras
from transformers import AutoModelForCausalLM, AutoTokenizer

classifier = pickle.load(open("models/classifier.pkl", "rb"))           # planted: pickle runs code on load
scaler = joblib.load("models/scaler.joblib")                            # planted: same for joblib
weights = torch.load("models/model.pt")                                 # planted: no weights_only=True
vectors = np.load("models/weights.npy", allow_pickle=True)             # planted: object arrays are pickles
gate = keras.models.load_model("models/lambda.keras", safe_mode=False)  # planted: Lambda layers run code
settings = yaml.load(open("models/config.yaml"), Loader=yaml.Loader)    # planted: unsafe YAML loader

# planted: remote code from the Hub, and no pinned revision (a later push changes what runs)
tok = AutoTokenizer.from_pretrained("acme-ai/support-7b")
lm = AutoModelForCausalLM.from_pretrained("acme-ai/support-7b", trust_remote_code=True)
path = hf_hub_download(repo_id="acme-ai/support-7b", filename="adapter.safetensors")
