# SawOne-SI scanner: the Sawone scanner image plus the AI analysers.
# release.yml passes SAWONE_IMAGE as an immutable digest whose Sigstore signature it has verified.
ARG SAWONE_IMAGE=ghcr.io/hackin2minutes-oss/sawone-scanner:1
FROM ${SAWONE_IMAGE}

LABEL org.opencontainers.image.title="sawone-si-scanner" \
      org.opencontainers.image.description="DevSecOps for AI / LLM applications on the Sawone engine"

# The AI analysers read model files, notebooks and configs as data: no ML runtime is installed, and no model is
# ever loaded. nbformat validates notebooks; the rest is standard library and PyYAML (already in the engine).
RUN pip install --no-cache-dir "nbformat>=5.9,<6"

COPY sawone_si.py profile.yml /opt/sawone-si/
COPY ai/ /opt/sawone-si/ai/
COPY rules/ /opt/sawone-si/rules/
COPY defaults/ /opt/sawone-si/defaults/
ENV SAWONE_ENGINE=/opt/sawone \
    SAWONE_PROFILE=/opt/sawone-si/profile.yml \
    SCAN_REPORTS=sawone-si-reports
RUN chmod +x /opt/sawone-si/sawone_si.py \
    && ln -s /opt/sawone-si/sawone_si.py /usr/local/bin/sawone-si \
    && sawone-si --version

HEALTHCHECK NONE
ENTRYPOINT ["sawone-si"]
