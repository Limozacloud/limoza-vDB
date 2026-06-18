# Self-contained image for the limoza-vDB MCP server. No dependency on the ingest
# image — it only needs Python, a few libs, and network access to Hasura.
FROM python:3.14-slim

WORKDIR /app
RUN useradd -u 1000 -m mcp

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY *.py ./

USER mcp
EXPOSE 8765
CMD ["python", "server.py"]
