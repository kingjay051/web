"""
Casaku Webhook Receiver - Python FastAPI Example

Secure webhook endpoint with HMAC-SHA256 signature verification.
Webhook Secret didapatkan dari https://casaku.id → Dashboard → Webhook Developer

Usage:
    export WEBHOOK_SECRET=casaku_sec_ganti_dengan_secret_anda_dari_dashboard
    uvicorn main:app --host 0.0.0.0 --port 8080
"""

import os
import hmac
import hashlib
import logging

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

app = FastAPI(title="Casaku Webhook Receiver")

WEBHOOK_SECRET = os.environ.get(
    "WEBHOOK_SECRET",
    "cashify_f6e5fecf5c97805e9bc613894bdd6b0798b169bdc0f909fa1cd1b3baba4be89d0994074123e908587ebbb263f077a1b5e59bbf3dade1f5c9bf9a2e0bfad34f29",
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("casaku-webhook")


@app.post("/webhook")
async def webhook(request: Request):
    raw_body = await request.body()
    signature = request.headers.get("X-Casaku-Signature", "")

    logger.info("================ WEBHOOK RECEIVED ================")
    logger.info("Headers: %s", dict(request.headers))
    logger.info("Raw Body: %s", raw_body.decode("utf-8", errors="replace"))

    payload = await request.json() if request.headers.get("content-type") == "application/json" else {}
    logger.info("Parsed Payload: %s", payload)

    if not WEBHOOK_SECRET:
        logger.error("WEBHOOK_SECRET is not configured")
        return JSONResponse(
            {"error": "Server misconfiguration: WEBHOOK_SECRET is missing."}, status_code=500
        )

    if not signature:
        logger.warning("Missing X-Casaku-Signature header")
        return JSONResponse({"error": "Unauthorized: Missing signature."}, status_code=401)

    computed_signature = hmac.new(
        WEBHOOK_SECRET.encode("utf-8"),
        raw_body,
        hashlib.sha256,
    ).hexdigest()

    logger.info("Signature from Header: %s", signature)
    logger.info("Computed Signature: %s", computed_signature)

    if not hmac.compare_digest(computed_signature, signature):
        logger.warning("Invalid signature - rejecting request")
        return JSONResponse({"error": "Unauthorized: Invalid signature."}, status_code=401)

    logger.info("Webhook Signature Verified Successfully!")
    logger.info("Final Payload: %s", payload)

    return {"success": True, "message": "Webhook received and processed"}


@app.get("/health")
async def health():
    return {"status": "ok"}
