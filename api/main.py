# FastAPI-based API gateway for Omnisight V2

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import asyncio
from core.scanner import UnifiedScannerV2
from core.evolutionary_scanner import EvolutionaryScanner
from features.live_scanner import LiveScanner
from isolation.network_isolation import IsolationManager, filter_my_network
import glob

app = FastAPI(title="Omnisight V2 API")
scanner = UnifiedScannerV2()
evolver = EvolutionaryScanner()
live = LiveScanner()
isolation = IsolationManager()

class ScanRequest(BaseModel):
    target: str
    aggressive: bool = True

@app.get("/status")
def status():
    return {"ok": True, "checkpoints": len(scanner.checkpoints)}

@app.post("/scan")
async def scan(req: ScanRequest):
    if isolation.is_protected(req.target):
        raise HTTPException(status_code=403, detail="Target is protected by local network isolation")
    results = await scanner.quick_scan(req.target, aggressive=req.aggressive)
    # feed evolutionary observer with recent checkpoints
    files = glob.glob("data/scan_results/checkpoint_*.json")[-5:]
    evolver.observe_checkpoints(files)
    return {"target": req.target, "results": results, "strategy": evolver.best_strategy()}

@app.get("/live_scan")
async def live_scan(domain: str):
    if isolation.is_protected(domain):
        raise HTTPException(status_code=403, detail="Target is protected by local network isolation")
    res = await live.internet_scan(domain)
    return {"domain": domain, "data": res}

