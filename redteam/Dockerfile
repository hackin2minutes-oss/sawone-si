# SawOne-SI red-team companion image: NVIDIA garak and promptfoo in one container.
# Launched only by the ai-redteam stage, and only when the user configures an endpoint they own. It attacks
# that endpoint and writes garak's *.report.jsonl and promptfoo's JSON into /out; SawOne-SI parses them.
FROM python:3.12-slim

LABEL org.opencontainers.image.title="sawone-si-redteam" \
      org.opencontainers.image.description="garak + promptfoo LLM red-team runner for SawOne-SI"

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl gnupg jq \
    && mkdir -p /etc/apt/keyrings \
    && curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_22.x nodistro main" \
       > /etc/apt/sources.list.d/nodesource.list \
    && apt-get update && apt-get install -y --no-install-recommends nodejs \
    && apt-get purge -y gnupg && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

# garak pulls a large ML stack; it is pinned in requirements.txt. promptfoo is pinned too.
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt \
    && npm install -g promptfoo@0.117.0 \
    && npm cache clean --force

COPY run.py /opt/redteam/run.py
RUN chmod +x /opt/redteam/run.py

# never phone home
ENV PROMPTFOO_DISABLE_TELEMETRY=1 \
    PROMPTFOO_DISABLE_REMOTE_GENERATION=1 \
    PROMPTFOO_DISABLE_UPDATE=1 \
    HF_HUB_DISABLE_TELEMETRY=1 \
    GARAK_DISABLE_HITLOG=1
WORKDIR /work
HEALTHCHECK NONE
ENTRYPOINT ["python", "/opt/redteam/run.py"]
