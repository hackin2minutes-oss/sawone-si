FROM python:3.12-slim

WORKDIR /app

# The demo target uses Python standard library only (no external pip dependencies required)
COPY app.py /app/app.py

ENV PORT=8000
ENV HOST=0.0.0.0
ENV DEMO_MODE=vulnerable

EXPOSE 8000

HEALTHCHECK --interval=5s --timeout=3s --retries=3 \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

ENTRYPOINT ["python3", "/app/app.py"]
CMD ["--host", "0.0.0.0", "--port", "8000"]
