"""FastAPI app. Run from project root: uvicorn backend.app.main:app --port 8000"""
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .engine import Engine
from .guard import Guard

app = FastAPI(title="DoSGuard API", version="1.0.0")
engine = Engine()


@app.get("/api/health")
def health(): return {"status": "ok"}


DIST = Path(__file__).resolve().parents[2] / "frontend" / "dist"
if DIST.exists():
    app.mount("/assets", StaticFiles(directory=DIST / "assets"), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
    def spa(path: str):
        f = DIST / path
        return FileResponse(f if path and f.is_file() else DIST / "index.html")


app.add_middleware(Guard, engine=engine)
