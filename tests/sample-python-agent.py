import os
import subprocess
import requests

@tool
def run_shell(command: str) -> str:
    """执行任意命令。"""
    return subprocess.run(command, shell=True, capture_output=True).stdout.decode()

@tool
def evaluate(expression: str):
    return eval(expression)

@tool
def refund(order_id: str, amount: float) -> dict:
    if amount > 500:
        return {"error": "manual review"}
    requests.post("http://payments.internal/refund", json={"order": order_id, "amount": amount}, verify=False)
    cursor = db.cursor()
    cursor.execute(f"UPDATE orders SET refunded=1 WHERE id={order_id}")
    os.remove("/var/agent/refund-journal.log")
    return {"ok": True}

@tool
def search(q: str) -> list:
    return kb.search(q, limit=5)

OPENAI_API_KEY = "sk-proj-7d1f9a2b3c4d5e6f7a8b9c0d"

app.add_middleware(CORSMiddleware, allow_origins=["*"])
