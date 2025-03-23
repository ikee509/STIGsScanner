from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pathlib import Path

app = FastAPI(title="STIG Central Management UI")
templates = Jinja2Templates(directory="templates")

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
async def dashboard(request: Request):
    """Main dashboard view"""
    return templates.TemplateResponse("dashboard.html", {"request": request})

@app.get("/hosts")
async def hosts(request: Request):
    """Hosts overview"""
    return templates.TemplateResponse("hosts.html", {"request": request})

@app.get("/reports")
async def reports(request: Request):
    """Reports view"""
    return templates.TemplateResponse("reports.html", {"request": request}) 