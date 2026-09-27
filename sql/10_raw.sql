-- staging raw separato per ogni sorgente
-- tabelle append only

begin;

create table if not exists raw_urlhaus (
    raw_id bigserial primary key,
    ingest_batch_id uuid not null,
    ingest_ts timestamptz not null default now(),
    snapshot_date date not null,
    source_record_id text,
    payload_json jsonb not null,
    trace_meta jsonb
);

create index if not exists idx_raw_urlhaus_ingest_ts
    on raw_urlhaus (ingest_ts);

create index if not exists idx_raw_urlhaus_snapshot_date
    on raw_urlhaus (snapshot_date);

create index if not exists idx_raw_urlhaus_ingest_batch_id
    on raw_urlhaus (ingest_batch_id);

create index if not exists idx_raw_urlhaus_source_record_id
    on raw_urlhaus (source_record_id);

create table if not exists raw_threatfox (
    raw_id bigserial primary key,
    ingest_batch_id uuid not null,
    ingest_ts timestamptz not null default now(),
    snapshot_date date not null,
    source_record_id text,
    payload_json jsonb not null,
    trace_meta jsonb
);

create index if not exists idx_raw_threatfox_ingest_ts
    on raw_threatfox (ingest_ts);

create index if not exists idx_raw_threatfox_snapshot_date
    on raw_threatfox (snapshot_date);

create index if not exists idx_raw_threatfox_ingest_batch_id
    on raw_threatfox (ingest_batch_id);

create index if not exists idx_raw_threatfox_source_record_id
    on raw_threatfox (source_record_id);

commit;
