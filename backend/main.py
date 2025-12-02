import hashlib
import random
import mimetypes
import traceback

from fastapi import FastAPI, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from prisma import Prisma
from datetime import datetime

# ==========================================================
# FASTAPI APP
# ==========================================================

app = FastAPI(title="Vestigo Backend")

# ==========================================================
# CORS CONFIG
# ==========================================================

origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:4173",
    "https://your-production-domain.com",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==========================================================
# DATABASE (PRISMA)
# ==========================================================

db = Prisma()


@app.on_event("startup")
async def startup():
    print("🔌 Connecting to database…")
    await db.connect()
    print("✅ Database connected.")


@app.on_event("shutdown")
async def shutdown():
    print("🔌 Disconnecting database…")
    await db.disconnect()
    print("🛑 Database disconnected.")


# ==========================================================
# HELPERS
# ==========================================================

CRYPTO_TYPES = [
    ("AES", "AES-128", "High", "Symmetric block cipher detected"),
    ("AES", "AES-256", "Critical", "Strong AES block detected"),
    ("RSA", "RSA-1024", "Medium", "RSA key operations found"),
    ("ECC", "Curve25519", "High", "ECC operations detected"),
    ("SHA", "SHA-256", "Low", "Hashing function present"),
    ("XOR", "XOR Loop", "Critical", "Weak obfuscation loop found"),
]


def analyze(content: bytes):
    findings = []
    count = random.randint(0, 5)

    for _ in range(count):
        name, variant, sev, desc = random.choice(CRYPTO_TYPES)
        findings.append({
            "name": name,
            "algorithm": name,
            "variant": variant,
            "severity": sev,
            "description": desc,
        })

    return findings, count


def generate_hash(data: bytes):
    return hashlib.md5(data).hexdigest()


def detect_type(filename: str):
    mime, _ = mimetypes.guess_type(filename)
    return mime or "application/octet-stream"


def format_size(bytes_len: int):
    return f"{bytes_len / 1024 / 1024:.2f} MB"


def severity_level(count: int):
    if count == 0:
        return "safe"
    if count == 1:
        return "low"
    if 2 <= count <= 3:
        return "high"
    return "critical"


# ==========================================================
# ROUTES
# ==========================================================

@app.get("/")
def home():
    return {"message": "Vestigo Backend Running"}


# ----------------------------------------------------------
# UPLOAD + ANALYZE
# ----------------------------------------------------------
@app.post("/analyze")
async def upload_and_analyze(file: UploadFile = File(...)):
    try:
        if file is None:
            return {"error": "No file provided"}

        content = await file.read()
        if not content:
            return {"error": "Empty file uploaded"}

        file_hash = generate_hash(content)
        file_type = detect_type(file.filename)
        file_size = format_size(len(content))

        # Create job entry early so frontend can correlate even if failure later
        job = await db.job.create(
            data={
                "fileName": file.filename,
                "hash": file_hash,
                "fileSize": file_size,
                "fileType": file_type,
                "status": "analyzing",
            }
        )

        # Simulated crypto detection (replace later with real logic)
        threats, count = analyze(content)

        # Bulk insert threats (sequential for now)
        for t in threats:
            await db.threat.create(
                data={**t, "jobId": job.id}
            )

        # Finalize job
        await db.job.update(
            where={"id": job.id},
            data={
                "status": "complete",
                "analysisTime": "4s",
                "findings": count,
                "severity": severity_level(count),
            }
        )

        return {"message": "Analysis complete", "jobId": job.id, "findings": count}
    except Exception as e:
        traceback.print_exc()
        # Attempt to mark job failed if it was created
        try:
            if 'job' in locals():
                await db.job.update(
                    where={"id": job.id},
                    data={"status": "failed", "severity": "safe", "analysisTime": "0s", "findings": 0}
                )
        except Exception:
            pass
        return {"error": "Upload processing failed", "detail": str(e)}


@app.get("/jobs")
async def list_jobs():
    jobs = await db.job.find_many(include={"threats": True})
    return jobs


@app.get("/jobs/{job_id}")
async def get_job(job_id: str):
    job = await db.job.find_unique(
        where={"id": job_id},
        include={"threats": True}
    )

    if not job:
        return {"error": "Job not found"}

    return job


@app.get("/jobs/{job_id}/report")
async def download_report(job_id: str):
    job = await db.job.find_unique(
        where={"id": job_id},
        include={"threats": True}
    )

    if not job:
        return {"error": "Job not found"}

    return job
