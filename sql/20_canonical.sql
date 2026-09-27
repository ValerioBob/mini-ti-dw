--layer canonico comune
--definisce solo struttura vincoli e indici
--la logica etl è gestita in pythons

begin;

--tabella canonica unica
--qui vanno i record normalizzati provenienti da urlhaus e threatfox
create table if not exists canonical_observation (
    --chiave del tabella canonica
    canonical_id bigserial primary key,

    --nome sorgente
    source_name text not null,

    --nome tabella raw
    raw_table_name text not null,

    --id record raw
    raw_id bigint not null,

    --identificativo della sorgente se disponibile
    source_record_id text,

    --tipo indicatore
    indicator_type text not null,

    --valore indicatore
    indicator_value text not null,

    --timestamp evento
    event_time timestamp not null,

    --bucket giornaliero derivato dal timestamp
    day_bucket date not null,

    --stato osservazione
    status text not null,

    -- array dei tags
    tags text[] not null default '{}'::text[],

    --contenitore json con metadati non modellati
    context_json jsonb,

    --timestamp tecnico di creazione del record
    created_at timestamptz not null default now(),


    --VINCOLI

    --vincolo sul nome
    constraint chk_canonical_source_name
        check (source_name in ('urlhaus', 'threatfox')),

    --vincolo sul nome tabella raw
    constraint chk_canonical_raw_table_name
        check (raw_table_name in ('raw_urlhaus', 'raw_threatfox')),

    --vincolo sul tipo indicatore
    constraint chk_canonical_indicator_type
        check (indicator_type in ('url', 'domain', 'ip')),

    --vincolo sullo stato
    constraint chk_canonical_status
        check (status in ('online', 'offline', 'unknown'))
);

--indice utile per filtri e aggregazioni per sorgente
create index if not exists idx_canonical_source_name
    on canonical_observation (source_name);

--indice utile per analisi temporali e caricamento del dw
create index if not exists idx_canonical_day_bucket
    on canonical_observation (day_bucket);

--indice utile per analisi per tipo indicatore
create index if not exists idx_canonical_indicator_type
    on canonical_observation (indicator_type);

--indice utile per analisi per stato
create index if not exists idx_canonical_status
    on canonical_observation (status);

--indice di tracciabilità verso il raw
create index if not exists idx_canonical_raw_id
    on canonical_observation (raw_table_name, raw_id);

--indice univoco per deduplica
--una osservazione per sorgente tipo valore giorno
create unique index if not exists ux_canonical_observation_dedup
    on canonical_observation (
        source_name,
        indicator_type,
        indicator_value,
        day_bucket
    );

commit;