from fastapi import FastAPI, HTTPException, Depends, Security
from fastapi.security.api_key import APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Dict, Any
import logging
import json
from datetime import datetime
from pathlib import Path

from .database import DatabaseManager
from .auth import verify_api_key
from .models import ScanResult, RemediationPlan

app = FastAPI(title="STIG Central Management Server")
db = DatabaseManager()
logger = logging.getLogger(__name__)

# Setup CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

API_KEY_HEADER = APIKeyHeader(name="X-API-Key")

@app.post("/api/v1/results")
async def submit_results(
    scan_results: ScanResult,
    api_key: str = Security(API_KEY_HEADER)
):
    """Submit scan results from an agent"""
    try:
        await verify_api_key(api_key)
        result_id = await db.store_scan_results(scan_results)
        return {"status": "success", "result_id": result_id}
    except Exception as e:
        logger.error(f"Error storing scan results: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/results/{host}")
async def get_host_results(
    host: str,
    api_key: str = Security(API_KEY_HEADER)
):
    """Get scan results for a specific host"""
    try:
        await verify_api_key(api_key)
        results = await db.get_host_results(host)
        return results
    except Exception as e:
        logger.error(f"Error retrieving results for host {host}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/summary")
async def get_summary(
    api_key: str = Security(API_KEY_HEADER)
):
    """Get summary of all hosts"""
    try:
        await verify_api_key(api_key)
        return await db.get_summary()
    except Exception as e:
        logger.error(f"Error retrieving summary: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e)) 