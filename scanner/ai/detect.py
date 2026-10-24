"""What kind of AI a repository contains: the inventory every SawOne-SI stage starts from.

"AI" covers different things that need different checks, so detection looks for each one separately:

  llm-app   an application that calls a language model (OpenAI, Anthropic, Azure OpenAI, Bedrock, Vertex, ...)
  rag       retrieval: a vector store and the documents it is filled with
  agent     an LLM that calls tools (LangChain, LangGraph, LlamaIndex, CrewAI, AutoGen, Semantic Kernel, ...)
  mcp       Model Context Protocol servers, and client configurations that start them
  ml-model  model files (pickle, PyTorch, joblib, Keras, ONNX, GGUF, safetensors, ...)
  notebook  Jupyter notebooks
  training  training and fine-tuning code and datasets
  serving   model servers (vLLM, Ollama, TGI, Triton, KServe, BentoML, TorchServe, Ray Serve, Gradio, ...)
  ai-iac    cloud AI services in infrastructure code (Azure OpenAI and ML, Bedrock, SageMaker, Vertex AI, ...)

Evidence is a file and line for every signal, so the report can show why a kind was detected.
Nothing is executed and model files are only read for their first bytes.
"""
import fnmatch
import hashlib
import json
import os
import re
from pathlib import Path

CODE_EXT = {".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".java", ".kt", ".cs", ".go", ".ipynb", ".scala"}
MAX_TEXT = 1_500_000            # bytes of a source file read for signals

# name -> (category, code regexes, dependency names). Dependency names are matched as whole package names in
# requirements/pyproject/package.json/pom/csproj/go.mod; code regexes on imports and constructor calls.
SIGNALS = {
    # ---- model providers
    "OpenAI": ("provider", [r"^\s*(from|import)\s+openai\b", r"""require\(\s*['"]openai['"]\s*\)""",
                            r"""from\s+['"]openai['"]""", r"\bcom\.openai\b", r"github\.com/sashabaranov/go-openai",
                            r"\bOpenAIClient\b"], ["openai", "go-openai", "langchain-openai", "@langchain/openai",
                                                   "@ai-sdk/openai"]),
    "Azure OpenAI": ("provider", [r"\bAzureOpenAI\b", r"\bAzureChatOpenAI\b", r"Azure\.AI\.OpenAI", r"\.openai\.azure\.com",
                                  r"AzureOpenAIClient"], ["Azure.AI.OpenAI", "@azure/openai", "azure-ai-inference",
                                                          "@ai-sdk/azure"]),
    "Anthropic": ("provider", [r"^\s*(from|import)\s+anthropic\b", r"""['"]@anthropic-ai/sdk['"]""", r"\bChatAnthropic\b",
                               r"\bcom\.anthropic\b"], ["anthropic", "@anthropic-ai/sdk", "langchain-anthropic",
                                                        "@ai-sdk/anthropic", "anthropic-java"]),
    "AWS Bedrock": ("provider", [r"""client\(\s*['"]bedrock-(agent-)?runtime['"]""", r"\bChatBedrock(Converse)?\b",
                                 r"BedrockRuntimeClient", r"\bbedrock-runtime\b"],
                    ["langchain-aws", "@aws-sdk/client-bedrock-runtime", "@ai-sdk/amazon-bedrock",
                     "@aws-sdk/client-bedrock-agent-runtime"]),
    "Google Gemini / Vertex AI": ("provider", [r"^\s*(from|import)\s+(vertexai|google\.generativeai|google\.genai)\b",
                                               r"\bChatVertexAI\b", r"\bChatGoogleGenerativeAI\b",
                                               r"""['"]@google/(generative-ai|genai)['"]"""],
                                  ["google-generativeai", "google-genai", "vertexai", "langchain-google-vertexai",
                                   "langchain-google-genai", "@google/generative-ai", "@google/genai", "@ai-sdk/google"]),
    "Mistral": ("provider", [r"^\s*(from|import)\s+mistralai\b", r"\bChatMistralAI\b"], ["mistralai", "@mistralai/mistralai"]),
    "Cohere": ("provider", [r"^\s*(from|import)\s+cohere\b", r"\bChatCohere\b"], ["cohere", "cohere-ai"]),
    "Groq": ("provider", [r"^\s*(from|import)\s+groq\b", r"\bChatGroq\b"], ["groq", "groq-sdk"]),
    "Ollama (local)": ("provider", [r"^\s*(from|import)\s+ollama\b", r"\bChatOllama\b", r"\bOllamaLLM\b", r":11434\b"],
                       ["ollama", "langchain-ollama"]),
    "Hugging Face Hub": ("provider", [r"^\s*from\s+huggingface_hub\b", r"\bInferenceClient\(", r"\bhf_hub_download\(",
                                      r"\bsnapshot_download\("], ["huggingface-hub", "huggingface_hub", "@huggingface/inference"]),
    "LiteLLM": ("provider", [r"^\s*(from|import)\s+litellm\b"], ["litellm"]),
    "Alibaba Qwen / DashScope": ("provider", [r"^\s*(from|import)\s+dashscope\b", r"dashscope\.aliyuncs\.com"], ["dashscope"]),
    # ---- application and agent frameworks
    "LangChain": ("framework", [r"^\s*(from|import)\s+langchain", r"""['"](@langchain/|langchain/)"""],
                  ["langchain", "langchain-core", "langchain-community", "langchain-experimental", "langchain4j",
                   "dev.langchain4j:langchain4j"]),
    "LangGraph": ("agent", [r"^\s*(from|import)\s+langgraph\b", r"""['"]@langchain/langgraph['"]"""],
                  ["langgraph", "@langchain/langgraph"]),
    "LlamaIndex": ("framework", [r"^\s*(from|import)\s+llama_index\b", r"""['"]llamaindex['"]"""],
                   ["llama-index", "llama-index-core", "llama_index", "llamaindex"]),
    "Haystack": ("framework", [r"^\s*(from|import)\s+haystack\b"], ["haystack-ai", "farm-haystack"]),
    "Semantic Kernel": ("agent", [r"^\s*(from|import)\s+semantic_kernel\b", r"Microsoft\.SemanticKernel"],
                        ["semantic-kernel", "Microsoft.SemanticKernel"]),
    "CrewAI": ("agent", [r"^\s*(from|import)\s+crewai\b"], ["crewai", "crewai-tools"]),
    "AutoGen": ("agent", [r"^\s*(from|import)\s+(autogen|autogen_agentchat|autogen_core)\b"],
                ["pyautogen", "autogen-agentchat", "autogen-core", "ag2"]),
    "OpenAI Agents SDK": ("agent", [r"^\s*from\s+agents\s+import\s+.*\bAgent\b", r"""['"]@openai/agents['"]"""],
                          ["openai-agents", "@openai/agents"]),
    "Pydantic AI": ("agent", [r"^\s*(from|import)\s+pydantic_ai\b"], ["pydantic-ai"]),
    "smolagents": ("agent", [r"^\s*(from|import)\s+smolagents\b"], ["smolagents"]),
    "DSPy": ("framework", [r"^\s*import\s+dspy\b"], ["dspy", "dspy-ai"]),
    "Vercel AI SDK": ("framework", [r"""from\s+['"]ai['"]""", r"""['"]@ai-sdk/"""], ["ai"]),
    "Spring AI": ("framework", [r"org\.springframework\.ai\b"], ["spring-ai-core", "spring-ai-openai-spring-boot-starter"]),
    # ---- MCP
    "MCP server": ("mcp", [r"^\s*from\s+mcp\.server\b", r"\bFastMCP\(", r"""['"]@modelcontextprotocol/sdk/server""",
                           r"\bMcpServer\("], ["mcp", "fastmcp", "@modelcontextprotocol/sdk"]),
    # ---- retrieval
    "Chroma": ("vector-store", [r"^\s*import\s+chromadb\b", r"\bChroma\(", r"\bChroma\.from_"], ["chromadb", "chromadb-client"]),
    "Pinecone": ("vector-store", [r"^\s*(from|import)\s+pinecone\b", r"\bPineconeVectorStore\b"], ["pinecone", "pinecone-client",
                                                                                                     "@pinecone-database/pinecone"]),
    "Weaviate": ("vector-store", [r"^\s*import\s+weaviate\b"], ["weaviate-client", "weaviate-ts-client"]),
    "Qdrant": ("vector-store", [r"^\s*from\s+qdrant_client\b", r"\bQdrantVectorStore\b"], ["qdrant-client",
                                                                                         "@qdrant/js-client-rest"]),
    "Milvus": ("vector-store", [r"^\s*from\s+pymilvus\b"], ["pymilvus"]),
    "FAISS": ("vector-store", [r"^\s*import\s+faiss\b", r"\bFAISS\.(from_|load_local)"], ["faiss-cpu", "faiss-gpu"]),
    "pgvector": ("vector-store", [r"\bpgvector\b", r"\bPGVector\b"], ["pgvector", "langchain-postgres"]),
    "Azure AI Search": ("vector-store", [r"\bAzureSearch\b", r"azure\.search\.documents", r"\bSearchClient\("],
                        ["azure-search-documents", "@azure/search-documents"]),
    "Elasticsearch / OpenSearch": ("vector-store", [r"\bElasticsearchStore\b", r"\bOpenSearchVectorSearch\b"],
                                   ["langchain-elasticsearch", "opensearch-py"]),
    "LanceDB": ("vector-store", [r"^\s*import\s+lancedb\b"], ["lancedb"]),
    # ---- ML and training
    "PyTorch": ("ml", [r"^\s*import\s+torch\b", r"^\s*from\s+torch\b"], ["torch", "pytorch"]),
    "TensorFlow / Keras": ("ml", [r"^\s*import\s+(tensorflow|keras)\b", r"^\s*from\s+(tensorflow|keras)\b"],
                           ["tensorflow", "keras", "tensorflow-cpu", "@tensorflow/tfjs"]),
    "Transformers": ("ml", [r"^\s*from\s+transformers\b", r"^\s*import\s+transformers\b"], ["transformers"]),
    "scikit-learn": ("ml", [r"^\s*from\s+sklearn\b", r"^\s*import\s+sklearn\b"], ["scikit-learn", "sklearn"]),
    "XGBoost / LightGBM": ("ml", [r"^\s*import\s+(xgboost|lightgbm)\b"], ["xgboost", "lightgbm", "catboost"]),
    "ONNX Runtime": ("ml", [r"^\s*import\s+onnxruntime\b", r"""['"]onnxruntime-(node|web)['"]"""],
                     ["onnxruntime", "onnxruntime-gpu", "onnx", "onnxruntime-node"]),
    "JAX": ("ml", [r"^\s*import\s+jax\b"], ["jax", "flax"]),
    "Fine-tuning (PEFT / TRL / Unsloth)": ("training", [r"^\s*from\s+(peft|trl|unsloth)\b", r"\bTrainer\(", r"\bSFTTrainer\("],
                                           ["peft", "trl", "unsloth", "accelerate", "deepspeed"]),
    "MLflow": ("training", [r"^\s*import\s+mlflow\b"], ["mlflow", "mlflow-skinny"]),
    "Weights & Biases": ("training", [r"^\s*import\s+wandb\b"], ["wandb"]),
    "Datasets": ("training", [r"^\s*from\s+datasets\s+import\b", r"\bload_dataset\("], ["datasets"]),
    # ---- serving and UIs
    "vLLM": ("serving", [r"^\s*from\s+vllm\b", r"vllm/vllm-openai", r"\bvllm serve\b"], ["vllm"]),
    "Text Generation Inference": ("serving", [r"text-generation-inference"], ["text-generation"]),
    "Triton Inference Server": ("serving", [r"tritonserver", r"tritonclient"], ["tritonclient"]),
    "BentoML": ("serving", [r"^\s*import\s+bentoml\b"], ["bentoml"]),
    "TorchServe": ("serving", [r"\btorchserve\b", r"\btorch-model-archiver\b"], ["torchserve"]),
    "Ray Serve": ("serving", [r"^\s*from\s+ray\s+import\s+serve\b", r"^\s*import\s+ray\b"], ["ray"]),
    "KServe": ("serving", [r"serving\.kserve\.io", r"^\s*import\s+kserve\b"], ["kserve"]),
    "Gradio": ("serving", [r"^\s*import\s+gradio\b"], ["gradio"]),
    "Streamlit": ("serving", [r"^\s*import\s+streamlit\b"], ["streamlit"]),
    "llama.cpp": ("serving", [r"^\s*from\s+llama_cpp\b", r"llama-server", r"llama\.cpp"], ["llama-cpp-python"]),
    # ---- guardrails and observability (used by the Operate phase)
    "Guardrails": ("guardrail", [r"^\s*(from|import)\s+(guardrails|nemoguardrails|llm_guard|rebuff|lakera)\b",
                                 r"\bContentSafetyClient\b", r"moderations\.create\(", r"\bguardrailIdentifier\b",
                                 r"\bguardrail_configuration\b", r"azure\.ai\.contentsafety"],
                   ["guardrails-ai", "nemoguardrails", "llm-guard", "rebuff", "azure-ai-contentsafety", "lakera-guard"]),
    "Presidio": ("guardrail", [r"^\s*from\s+presidio_(analyzer|anonymizer)\b"], ["presidio-analyzer", "presidio-anonymizer"]),
    "LLM observability": ("observability", [r"^\s*(from|import)\s+(langfuse|langsmith|phoenix|openinference|helicone|"
                                            r"arize|traceloop|opik)\b", r"\bLANGCHAIN_TRACING_V2\b"],
                          ["langfuse", "langsmith", "arize-phoenix", "openinference-instrumentation", "traceloop-sdk",
                           "opik", "openllmetry"]),
}

MODEL_EXT = {".pkl": "pickle", ".pickle": "pickle", ".pt": "pytorch", ".pth": "pytorch", ".ckpt": "pytorch",
             ".bin": "pytorch", ".joblib": "joblib", ".npy": "numpy", ".npz": "numpy", ".h5": "keras-h5",
             ".hdf5": "keras-h5", ".keras": "keras", ".onnx": "onnx", ".gguf": "gguf", ".ggml": "gguf",
             ".safetensors": "safetensors", ".tflite": "tflite", ".mlmodel": "coreml", ".mar": "torchserve",
             ".llamafile": "llamafile", ".pb": "tensorflow", ".dill": "pickle", ".cloudpickle": "pickle"}
DATA_EXT = {".csv", ".tsv", ".jsonl", ".json", ".parquet", ".arrow", ".txt", ".md", ".html", ".htm", ".xml", ".pdf"}
DATA_DIRS = {"data", "dataset", "datasets", "training_data", "train_data", "finetune", "fine_tune", "fine-tuning",
             "eval", "evals", "evaluation", "knowledge", "knowledge_base", "knowledgebase", "kb", "corpus", "corpora",
             "rag", "documents", "docs_rag", "embeddings", "seed_data"}
CORPUS_DIRS = {"knowledge", "knowledge_base", "knowledgebase", "kb", "corpus", "corpora", "rag", "documents", "docs_rag"}
PROMPT_DIRS = {"prompts", "prompt", "prompt_templates", "system_prompts", "instructions"}
MCP_CONFIG_NAMES = {".mcp.json", "mcp.json", "mcp_config.json", "claude_desktop_config.json", "mcp.yaml", "mcp.yml",
                    "mcp_servers.json"}
AI_TF = ("azurerm_cognitive_", "azurerm_machine_learning_", "azurerm_search_service", "azurerm_ai_",
         "aws_bedrock", "aws_sagemaker_", "aws_comprehend", "google_vertex_ai_", "google_notebooks_",
         "google_workbench_", "alicloud_pai_", "azapi_resource")
AI_ARM = ("Microsoft.CognitiveServices/", "Microsoft.MachineLearningServices/", "Microsoft.Search/",
          "AWS::Bedrock::", "AWS::SageMaker::")
AI_IMAGES = {"ollama/ollama": "Ollama", "vllm/vllm-openai": "vLLM", "text-generation-inference": "TGI",
             "tritonserver": "Triton", "rayproject/ray": "Ray", "ghcr.io/mlflow/mlflow": "MLflow", "mlflow": "MLflow",
             "jupyter/": "Jupyter", "quay.io/jupyter": "Jupyter", "qdrant/qdrant": "Qdrant",
             "semitechnologies/weaviate": "Weaviate", "milvusdb/milvus": "Milvus", "chromadb/chroma": "Chroma",
             "open-webui": "Open WebUI", "langfuse/langfuse": "Langfuse", "localai/localai": "LocalAI",
             "ghcr.io/ggml-org/llama.cpp": "llama.cpp", "ghcr.io/ggerganov/llama.cpp": "llama.cpp",
             "pytorch/torchserve": "TorchServe", "kserve": "KServe", "flowiseai/flowise": "Flowise",
             "langgenius/dify": "Dify", "n8nio/n8n": "n8n"}


def _deps_text(ws, manifests):
    out = {}
    for m in manifests:
        p = ws / m
        try:
            out[m] = p.read_text(errors="replace")[:400_000]
        except OSError:
            continue
    return out


def _dep_hit(text, name, manifest):
    n = re.escape(name)
    if manifest.endswith("package.json"):
        return re.search(rf'"{n}"\s*:', text) is not None
    if manifest.endswith((".csproj", "packages.config")):
        return re.search(rf'Include="{n}"|id="{n}"', text, re.I) is not None
    if manifest.endswith(("pom.xml",)):
        part = name.split(":")[-1]
        return re.search(rf"<artifactId>{re.escape(part)}</artifactId>", text) is not None
    if manifest.endswith(("go.mod", "go.sum")):
        return name in text
    if manifest.endswith((".gradle", ".gradle.kts")):
        return re.search(rf"['\"][^'\"]*:{n}:", text) is not None
    # Python: requirements*.txt, pyproject.toml, Pipfile, setup.py, poetry.lock, uv.lock
    return re.search(rf"(^|[\s\"',\[]){n}(\[[^\]]*\])?\s*($|[<>=!~;,\"'\s\]])", text, re.I | re.M) is not None


def _magic(path, n=8):
    try:
        with open(path, "rb") as f:
            return f.read(n)
    except OSError:
        return b""


def model_format(path):
    """The model format of a file, from its extension and first bytes (None when it is not a model)."""
    p = Path(path)
    ext = p.suffix.lower()
    fmt = MODEL_EXT.get(ext)
    head = _magic(p, 8)
    if ext == ".bin":           # .bin is a PyTorch checkpoint only when it is a zip or a pickle
        return "pytorch" if head[:2] == b"PK" or head[:1] == b"\x80" else None
    if ext == ".pb" and p.name != "saved_model.pb":
        return None
    if ext == ".json" or fmt is None:
        if head[:1] == b"\x80" and len(head) > 1 and head[1] in range(2, 6) and p.suffix.lower() not in DATA_EXT:
            return "pickle"     # a pickle without a pickle extension
        return None
    return fmt


def sha256(path, limit=None):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _walk(ws, exclude, extra_skip):
    ws = Path(ws)
    for root, dirs, files in os.walk(ws):
        rel_root = Path(root).relative_to(ws)
        dirs[:] = sorted(d for d in dirs if d not in exclude and not d.startswith(".sawone")
                         and not any(fnmatch.fnmatch(str(rel_root / d), g.rstrip("/")) for g in extra_skip))
        for f in sorted(files):
            rp = rel_root / f
            if any(fnmatch.fnmatch(str(rp), g) for g in extra_skip):
                continue
            yield Path(root) / f, rp


def _line_of(text, idx):
    return text.count("\n", 0, idx) + 1


def detect(ws, exclude=(), extra_skip=(), manifests=()):
    """The AI inventory of ws. exclude: directory names never entered; extra_skip: globs (config 'exclude')."""
    ws = Path(ws)
    compiled = {name: (cat, [re.compile(r, re.M) for r in rx], deps) for name, (cat, rx, deps) in SIGNALS.items()}
    found = {}                     # name -> {"category", "evidence": [..]}

    def hit(name, ev):
        e = found.setdefault(name, {"name": name, "category": compiled[name][0], "evidence": []})
        if ev not in e["evidence"] and len(e["evidence"]) < 8:
            e["evidence"].append(ev)

    inv = {"models": [], "notebooks": [], "datasets": [], "corpora": [], "prompts": [], "mcp_configs": [],
           "ai_iac": [], "ai_images": [], "code_files": []}
    for p, rp in _walk(ws, set(exclude), list(extra_skip)):
        ext = p.suffix.lower()
        parts = [x.lower() for x in rp.parts[:-1]]
        name = p.name
        try:
            size = p.stat().st_size
        except OSError:
            continue
        fmt = model_format(p) if ext not in (".py", ".js", ".ts", ".md", ".txt", ".csv") else None
        if fmt:
            inv["models"].append({"path": str(rp), "format": fmt, "size": size})
            continue
        if ext == ".ipynb":
            inv["notebooks"].append(str(rp))
        if name.lower() in MCP_CONFIG_NAMES or (rp.parts[:1] in ((".cursor",), (".vscode",)) and name == "mcp.json"):
            inv["mcp_configs"].append(str(rp))
        if ext in (".prompt", ".prompty") or (set(parts) & PROMPT_DIRS and ext in (".txt", ".md", ".yaml", ".yml",
                                                                                     ".json", ".j2", ".jinja", ".jinja2")) \
                or re.match(r"(system[_-]?prompt|.*[_-]prompt)s?\.(txt|md|j2|jinja2?)$", name, re.I):
            inv["prompts"].append(str(rp))
        if set(parts) & DATA_DIRS and ext in DATA_EXT and name.lower() not in ("readme.md", "license", "license.txt"):
            entry = {"path": str(rp), "format": ext.lstrip("."), "size": size}
            (inv["corpora"] if set(parts) & CORPUS_DIRS else inv["datasets"]).append(entry)
        if ext in CODE_EXT and size <= MAX_TEXT:
            try:
                text = p.read_text(errors="replace")
            except OSError:
                continue
            hit_any = False
            for sig, (cat, rxs, _) in compiled.items():
                for rx in rxs:
                    m = rx.search(text)
                    if m:
                        hit(sig, f"{rp}:{_line_of(text, m.start())}")
                        hit_any = True
                        break
            if hit_any and ext != ".ipynb":
                inv["code_files"].append(str(rp))
        if ext == ".tf" and size <= MAX_TEXT:
            text = p.read_text(errors="replace")
            for m in re.finditer(r'^\s*resource\s+"([a-z0-9_]+)"\s+"([^"]+)"', text, re.M):
                if m.group(1).startswith(AI_TF) and (m.group(1) != "azapi_resource" or re.search(
                        r"Microsoft\.(CognitiveServices|MachineLearningServices)", text[m.end():m.end() + 400])):
                    inv["ai_iac"].append({"path": str(rp), "line": _line_of(text, m.start()),
                                          "type": m.group(1), "name": m.group(2)})
        if ext in (".bicep", ".json", ".yaml", ".yml", ".template") and size <= MAX_TEXT:
            text = p.read_text(errors="replace")
            for t in AI_ARM:
                for m in re.finditer(re.escape(t) + r"[A-Za-z/:]*", text):
                    inv["ai_iac"].append({"path": str(rp), "line": _line_of(text, m.start()), "type": m.group(0),
                                          "name": ""})
        if (name.startswith(("docker-compose", "compose")) and ext in (".yml", ".yaml")) or name == "Dockerfile" \
                or (ext in (".yml", ".yaml") and size <= MAX_TEXT):
            try:
                text = p.read_text(errors="replace")
            except OSError:
                continue
            for m in re.finditer(r"(?:^\s*image:\s*['\"]?|^FROM\s+)(\S+)", text, re.M | re.I):
                img = m.group(1).strip("'\"")
                for key, label in AI_IMAGES.items():
                    if key in img:
                        inv["ai_images"].append({"path": str(rp), "line": _line_of(text, m.start()), "image": img,
                                                 "product": label})
                        break
    # dependencies declared in manifests count as evidence too
    for m, text in _deps_text(ws, manifests).items():
        for sig, (cat, _, deps) in compiled.items():
            for d in deps:
                if _dep_hit(text, d, m):
                    hit(sig, f"{m} ({d})")
                    break
    inv["components"] = sorted(found.values(), key=lambda x: (x["category"], x["name"]))
    cats = {c["category"] for c in inv["components"]}
    kinds = []
    if cats & {"provider"} or (cats & {"framework", "agent"}):
        kinds.append("llm-app")
    if "vector-store" in cats or inv["corpora"]:
        kinds.append("rag")
    if "agent" in cats or _agentic(ws, inv["code_files"]):
        kinds.append("agent")
    if "mcp" in cats or inv["mcp_configs"]:
        kinds.append("mcp")
    if inv["models"]:
        kinds.append("ml-model")
    if inv["notebooks"]:
        kinds.append("notebook")
    if "training" in cats or ("ml" in cats and inv["datasets"]):
        kinds.append("training")
    if "serving" in cats or inv["ai_images"]:
        kinds.append("serving")
    if inv["ai_iac"]:
        kinds.append("ai-iac")
    inv["kinds"] = kinds
    inv["ai"] = bool(kinds)
    return inv


AGENT_RX = re.compile(r"\b(create_react_agent|create_tool_calling_agent|AgentExecutor|initialize_agent|"
                      r"create_openai_tools_agent|bind_tools\(|@tool\b|Tool\(|StructuredTool|FunctionTool|"
                      r"tool_choice|\"type\":\s*\"function\"|tools\s*=\s*\[|ToolNode\(|kernel_function)")


def _agentic(ws, files):
    for f in files:
        try:
            if AGENT_RX.search((Path(ws) / f).read_text(errors="replace")):
                return True
        except OSError:
            continue
    return False


def summary_line(inv):
    c = inv.get("components") or []
    by = {}
    for x in c:
        by.setdefault(x["category"], []).append(x["name"])
    parts = [f"kinds: {', '.join(inv['kinds']) or 'none'}"]
    for cat, label in (("provider", "providers"), ("framework", "frameworks"), ("agent", "agent frameworks"),
                       ("vector-store", "vector stores"), ("serving", "serving")):
        if by.get(cat):
            parts.append(f"{label}: {', '.join(by[cat][:5])}")
    for k, label in (("models", "model files"), ("notebooks", "notebooks"), ("datasets", "datasets"),
                     ("corpora", "RAG documents"), ("prompts", "prompt files"), ("mcp_configs", "MCP configs"),
                     ("ai_iac", "AI cloud resources")):
        if inv.get(k):
            parts.append(f"{len(inv[k])} {label}")
    return " · ".join(parts)


if __name__ == "__main__":      # pragma: no cover — handy for a quick look at a repository
    import sys
    print(json.dumps(detect(Path(sys.argv[1])), indent=1))
