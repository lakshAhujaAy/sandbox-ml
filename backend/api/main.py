"""
Dynamic Malware Analysis Sandbox — FastAPI entrypoint
"""
import asyncio
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, Request, Response, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from api.models import AnalysisRequest, AnalysisResponse, JobStatus
from api.connection_manager import ConnectionManager
from api.security import check_basic, validate_target
from job_queue_service.job_queue import JobQueue
from sandbox.orchestrator import SandboxOrchestrator
from utils.logger import get_logger

logger = get_logger(__name__)
manager = ConnectionManager()
job_queue: JobQueue = None
orchestrator: SandboxOrchestrator = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global job_queue, orchestrator
    job_queue = JobQueue()
    await job_queue.connect()
    orchestrator = SandboxOrchestrator(job_queue=job_queue, ws_manager=manager)
    asyncio.create_task(orchestrator.run_forever())
    logger.info("Sandbox orchestrator started")
    yield
    await job_queue.disconnect()
    logger.info("Shutdown complete")


app = FastAPI(
    title="Malware Sandbox API",
    description="Dynamic malware analysis with ML classification",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def require_password(request: Request, call_next):
    """Optional shared password (set BASIC_AUTH_PASSWORD). /health stays open for host health checks."""
    if request.url.path == "/health" or check_basic(request.headers.get("authorization")):
        return await call_next(request)
    return Response(status_code=401, headers={"WWW-Authenticate": 'Basic realm="MalSandbox"'})


# ── REST endpoints ────────────────────────────────────────────────────────────

@app.post("/analyze", response_model=AnalysisResponse)
async def submit_analysis(req: AnalysisRequest):
    """Submit a URL or file hash for sandboxed analysis."""
    try:
        req.target = validate_target(req.target)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    job_id = str(uuid.uuid4())
    await job_queue.push(job_id, req.model_dump())
    logger.info(f"Job queued: {job_id} → {req.target}")
    return AnalysisResponse(
        job_id=job_id,
        status=JobStatus.QUEUED,
        target=req.target,
        submitted_at=datetime.utcnow().isoformat(),
    )


@app.get("/jobs/{job_id}")
async def get_job(job_id: str):
    """Poll job status and results."""
    result = await job_queue.get_result(job_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return result


@app.get("/jobs")
async def list_jobs(limit: int = 20):
    """List recent analysis jobs."""
    return await job_queue.list_recent(limit)


@app.get("/health")
async def health():
    worker = await job_queue.get_worker_status()
    return {
        "status": "ok",
        "time": datetime.utcnow().isoformat(),
        "sandbox_mode": os.getenv("SANDBOX_MODE", "docker"),
        "ml_worker": "up" if worker else "down",
        # Which trained models the worker actually loaded (False = silently on rule-based fallback)
        "models": worker,
    }


# ── WebSocket — live job stream ───────────────────────────────────────────────

@app.websocket("/ws/{job_id}")
async def websocket_job(websocket: WebSocket, job_id: str):
    """Stream live progress events for a specific job."""
    if not check_basic(websocket.headers.get("authorization")):
        await websocket.close(code=1008)
        return
    await manager.connect(job_id, websocket)
    try:
        while True:
            await asyncio.sleep(30)  # keep-alive ping
    except WebSocketDisconnect:
        manager.disconnect(job_id, websocket)


@app.websocket("/ws/feed/all")
async def websocket_feed(websocket: WebSocket):
    """Broadcast all job events to dashboard subscribers."""
    if not check_basic(websocket.headers.get("authorization")):
        await websocket.close(code=1008)
        return
    await manager.connect("__feed__", websocket)
    try:
        while True:
            await asyncio.sleep(30)
    except WebSocketDisconnect:
        manager.disconnect("__feed__", websocket)


# ── Built React dashboard, served from the same port (registered last so API routes win) ──
FRONTEND_DIR = Path(os.getenv("FRONTEND_DIR", Path(__file__).parent.parent / "frontend_build"))
if FRONTEND_DIR.is_dir():
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
