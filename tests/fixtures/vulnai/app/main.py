"""vulnai chat API (deliberately vulnerable: see README.md)."""
import logging
import sqlite3
import subprocess

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from openai import OpenAI

app = FastAPI()
log = logging.getLogger("vulnai")
# planted: a hard-coded provider key (fake)
client = OpenAI(api_key="sk-proj-Q8zT4mJw2LxV9nB6cRk1T3BlbkFJp7HsYd3Ue5Wq0Za8XcVb")
SYSTEM_PROMPT = open("prompts/system.txt").read()


@app.post("/chat", response_class=HTMLResponse)
async def chat(request: Request):
    body = await request.json()
    user_name = body.get("name", "")
    question = body["message"]
    # planted: user input placed inside the system prompt (prompt injection, LLM01)
    messages = [{"role": "system", "content": f"{SYSTEM_PROMPT}\nThe customer's name is {user_name}."},
                {"role": "user", "content": question}]
    log.info(f"prompt for {user_name}: {question}")                       # planted: prompts logged
    resp = client.chat.completions.create(model="gpt-4o", messages=messages)   # planted: no max_tokens
    answer = resp.choices[0].message.content
    return HTMLResponse(f"<div class='answer'>{answer}</div>")          # planted: model output as HTML (LLM05)


@app.post("/report")
async def report(request: Request):
    body = await request.json()
    resp = client.chat.completions.create(
        model="gpt-4o", max_tokens=500,
        messages=[{"role": "user", "content": "Write Python that computes: " + body["task"]}])
    code = resp.choices[0].message.content
    exec(code)                                                          # planted: model output executed
    return {"ok": True}


@app.post("/ops")
async def ops(request: Request):
    body = await request.json()
    completion = client.chat.completions.create(
        model="gpt-4o", max_tokens=200,
        messages=[{"role": "user", "content": "Give the shell command to " + body["goal"]}])
    cmd = completion.choices[0].message.content
    out = subprocess.run(cmd, shell=True, capture_output=True, text=True)   # planted: model output to a shell
    return {"out": out.stdout}


@app.post("/search")
async def search(request: Request):
    body = await request.json()
    r = client.chat.completions.create(
        model="gpt-4o", max_tokens=200,
        messages=[{"role": "user", "content": "Write one SQLite query for: " + body["q"]}])
    query = r.choices[0].message.content
    db = sqlite3.connect("shop.db")
    rows = db.execute(query).fetchall()                                 # planted: model output as SQL
    return {"rows": rows}
