from fastapi import FastAPI, Request
import uvicorn

app = FastAPI(title="Protected Upstream Service")


@app.get("/api/users")
def get_users():
    return {"users": [{"id": 1, "name": "alice"}, {"id": 2, "name": "bob"}]}


@app.delete("/api/users")
def delete_user():
    return {"message": "user deleted"}


@app.post("/api/transfer")
async def transfer(request: Request):
    body = await request.json()
    return {"message": "transfer completed", "amount": body.get("amount")}


@app.get("/health")
def health():
    return {"status": "ok"}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)
