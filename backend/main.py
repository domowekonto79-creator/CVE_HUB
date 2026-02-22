import logging
import asyncio
from fastapi import FastAPI
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from enricher import EnricherPipeline
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = FastAPI(title="CVE Enrichment Hub API")
scheduler = AsyncIOScheduler()
pipeline = EnricherPipeline()

@app.on_event("startup")
async def startup_event():
    logger.info("Starting up CVE Enrichment Hub Backend...")
    scheduler.add_job(pipeline.run_pipeline, 'interval', hours=6)
    scheduler.start()
    # Run once on startup in background
    asyncio.create_task(pipeline.run_pipeline())

@app.get("/health")
async def health_check():
    return {"status": "ok"}

@app.post("/trigger")
async def trigger_pipeline():
    asyncio.create_task(pipeline.run_pipeline())
    return {"message": "Pipeline triggered"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
