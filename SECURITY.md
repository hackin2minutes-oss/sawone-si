# Security policy

Report vulnerabilities in SawOne-SI privately through GitHub's "Report a vulnerability" (Security tab) of
hackin2minutes-oss/sawone-si. Please do not open a public issue. You will get an answer within a week.

SawOne-SI runs scanners on code you give it and starts containers on the runner's Docker daemon: use it on
ephemeral runners (GitHub-hosted or equivalent).

- **Model files are never loaded.** Pickle, PyTorch, joblib, NumPy, Keras, ONNX, GGUF and safetensors files are
  parsed as data (opcodes, headers, archive entries); nothing in them is deserialised or executed.
- **The red-team stage attacks an LLM endpoint you name.** Point it at a test or staging deployment, never at
  production: attacks ask the model to call tools, leak data and ignore its instructions, and a vulnerable
  application may act on that. The API key travels only in the environment (never on a command line or in a
  log), and responses are stored in the report with secrets redacted.
- **promptfoo attack generation is off by default.** With `ai.redteam.promptfoo.generate: true` promptfoo uses a
  generator model you configure; nothing is sent to promptfoo's cloud (`PROMPTFOO_DISABLE_REMOTE_GENERATION`
  and telemetry are always set off).
