# CVE Enrichment Hub

Kompletna aplikacja webowa do monitorowania i wzbogacania danych o podatnościach (CVE).

## Architektura
- **Backend**: Python 3.11+, FastAPI, httpx, asyncio, APScheduler
- **Baza danych**: Supabase (PostgreSQL)
- **Frontend**: Next.js 14 (App Router), Tailwind CSS

## Uruchomienie

### 1. Baza danych (Supabase)
1. Utwórz projekt w Supabase.
2. Wykonaj skrypt SQL z pliku `schema.sql` w SQL Editorze.
3. Skopiuj URL i klucze (anon oraz service_role) do `.env`.

### 2. Backend
```bash
cd backend
python -m venv venv
source venv/bin/activate
pip install fastapi uvicorn httpx asyncio apscheduler pydantic supabase python-dotenv
uvicorn main:app --reload
```

### 3. Frontend
```bash
cd frontend
npm install
npm run dev
```

## Źródła danych
- NVD NIST (główne dane)
- CISA KEV (aktywne exploity)
- OSV.dev (podatne pakiety)
- GitHub Advisory (patche)
- AlienVault OTX (kampanie i malware)
