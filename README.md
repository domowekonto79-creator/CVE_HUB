# CVE Enrichment Hub

Kompletna aplikacja webowa do monitorowania i wzbogacania danych o podatnościach (CVE), działająca całkowicie w architekturze Serverless.

## Architektura (Zero osobnych serwerów)
- **Frontend**: Next.js 14 (App Router), Tailwind CSS (Deploy na Vercel)
- **Baza danych**: Supabase (PostgreSQL)
- **Backend / Enrichment**: Supabase Edge Functions (TypeScript/Deno)
- **Scheduler**: `pg_cron` i `pg_net` (wbudowane w Supabase)

## Uruchomienie

### 1. Baza danych (Supabase)
1. Utwórz projekt w Supabase.
2. Wykonaj skrypt SQL z pliku `schema.sql` w SQL Editorze, aby utworzyć tabelę `cve_records`.
3. Skopiuj URL i klucze (anon oraz service_role) do `.env`.

### 2. Backend (Supabase Edge Functions)
Zamiast utrzymywać osobny serwer w Pythonie, logika pobierania danych (NVD, KEV, OSV, GitHub, OTX) znajduje się w Edge Function.

1. Zainstaluj Supabase CLI: `npm install -g supabase`
2. Zaloguj się: `supabase login`
3. Połącz z projektem: `supabase link --project-ref <PROJECT_REF>`
4. Ustaw zmienne środowiskowe dla Edge Function:
   ```bash
   supabase secrets set NVD_API_KEY=your_key
   supabase secrets set GITHUB_TOKEN=your_token
   supabase secrets set OTX_API_KEY=your_key
   ```
5. Wdróż funkcję:
   ```bash
   supabase functions deploy enrich-cves
   ```

### 3. Harmonogram (pg_cron)
Aby funkcja uruchamiała się automatycznie co 6 godzin, wykonaj skrypt z pliku `supabase/migrations/20240101000000_cron.sql` w SQL Editorze w Supabase. Pamiętaj, aby podmienić `<PROJECT_REF>` i `<ANON_KEY>` na własne.

### 4. Frontend (Next.js)
```bash
cd frontend
npm install
npm run dev
```
Do wdrożenia na Vercel wystarczy podpiąć repozytorium GitHub i ustawić zmienne środowiskowe `NEXT_PUBLIC_SUPABASE_URL` oraz `NEXT_PUBLIC_SUPABASE_ANON_KEY`.

## Źródła danych
- NVD NIST (główne dane)
- CISA KEV (aktywne exploity)
- OSV.dev (podatne pakiety)
- GitHub Advisory (patche)
- AlienVault OTX (kampanie i malware)
