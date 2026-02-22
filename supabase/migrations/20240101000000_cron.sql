-- Włącz rozszerzenia niezbędne do harmonogramowania i wywołań HTTP
CREATE EXTENSION IF NOT EXISTS pg_cron;
CREATE EXTENSION IF NOT EXISTS pg_net;

-- Usuń poprzednie zadanie, jeśli istnieje
SELECT cron.unschedule('enrich-cves-job');

-- Utwórz nowe zadanie uruchamiające się co 6 godzin
-- UWAGA: Zastąp <PROJECT_REF> i <ANON_KEY> swoimi danymi z Supabase
SELECT cron.schedule(
  'enrich-cves-job',
  '0 */6 * * *',
  $$
  SELECT net.http_post(
      url:='https://<PROJECT_REF>.supabase.co/functions/v1/enrich-cves',
      headers:='{"Authorization": "Bearer <ANON_KEY>"}'::jsonb
  )
  $$
);
