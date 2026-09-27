--star schema
--layer parte dal canonico e prepara per le query olap
begin;

--dimensione sorgente contiene elenco delle sorgenti 
create table if not exists dim_source (
    source_id smallserial primary key,
    source_name text not null unique
);

--dimensione tipo indicatore
--limitato a url domain ip
create table if not exists dim_indicator_type (
    indicator_type_id smallserial primary key,
    indicator_type_name text not null unique
);

--dimensione stato
create table if not exists dim_status (
    status_id smallserial primary key,
    status_name text not null unique
);

--dimensione tempo
--time_id usa il formato yyyymmdd
create table if not exists dim_time (
    --chiave nel formato yyyymmdd
    time_id integer primary key,

    --data completa del giorno
    day_date date not null unique,

    --attributi utili per aggregazioni temporali
    day_of_month smallint not null,
    month_num smallint not null,
    month_name text not null,
    quarter_num smallint not null,
    year_num integer not null
);

--indice utile per filtri e group by per anno e mese
create index if not exists idx_dim_time_year_month
    on dim_time (year_num, month_num);

--dimensione indicatore
create table if not exists dim_indicator (
    --chiave indicatore
    indicator_id bigserial primary key,

    --tipo indicatore collegato al dizionario dedicato
    indicator_type_id smallint not null references dim_indicator_type (indicator_type_id),

    --valore indicatore
    --coincide con il valore normalizzato nel layer canonico
    indicator_value text not null,

    --registrable domain o domain estratto
    --per gli ip normalmente resta null
    domain_value text,

    --tld derivato
    tld text,

    --timestamp di creazione del record
    created_at timestamptz not null default now(),

    --constraint: indicatore univoco all interno del proprio tipo
    constraint ux_dim_indicator_type_value
        unique (indicator_type_id, indicator_value)
);

--indici utili per ricerche e join di supporto analitico
create index if not exists idx_dim_indicator_value
    on dim_indicator (indicator_value);

create index if not exists idx_dim_indicator_domain
    on dim_indicator (domain_value);

create index if not exists idx_dim_indicator_tld
    on dim_indicator (tld);

--dimensione tag
create table if not exists dim_tag (
    tag_id bigserial primary key,
    tag_name text not null unique
);

create index if not exists idx_dim_tag_name
    on dim_tag (tag_name);

--==========================================================
--fact principale
--una osservazione unica di un indicatore in un certo giorno e sorgente
--
--canonical_id mantiene il collegamento diretto record canonico
--obs_count resta sempre 1 (usato per count e sum)
--is_online è una misura derivata utile per urlhaus
--==========================================================

create table if not exists fact_observation (
    --chiave del fact
    observation_id bigserial primary key,

    --riferimento al layer canonico
    --serve per tracciabilità e caricamenti
    canonical_id bigint not null unique references canonical_observation (canonical_id),

    --dimensioni principali del fatto
    time_id integer not null references dim_time (time_id),
    source_id smallint not null references dim_source (source_id),
    indicator_type_id smallint not null references dim_indicator_type (indicator_type_id),
    indicator_id bigint not null references dim_indicator (indicator_id),
    status_id smallint not null references dim_status (status_id),

    --misura base del fatto
    --ogni riga vale una osservazione
    obs_count integer not null default 1,

    --misura derivata opzionale
    --true per online
    --false per offline
    --null per unknown
    is_online boolean,

    --timestamp tecnico di inserimento nel dw
    inserted_at timestamptz not null default now(),

    --vincolo minimo sulla misura
    constraint chk_fact_observation_obs_count
        check (obs_count > 0),

    --vincolo di grain logico del fatto
    --evita duplicati nel dw sulla stessa osservazione analitica
    constraint ux_fact_observation_grain
        unique (
            time_id,
            source_id,
            indicator_type_id,
            indicator_id
        )
);

--indici utili per query olap frequenti
create index if not exists idx_fact_observation_time
    on fact_observation (time_id);

create index if not exists idx_fact_observation_source_time
    on fact_observation (source_id, time_id);

create index if not exists idx_fact_observation_type_time
    on fact_observation (indicator_type_id, time_id);

create index if not exists idx_fact_observation_status_time
    on fact_observation (status_id, time_id);

create index if not exists idx_fact_observation_indicator
    on fact_observation (indicator_id);

--==========================================================
--tabella ponte osservazione tag
--gestisce la relazione molti a molti tra fact e tag
--i tag appartengono all osservazione e non all indicatore in astratto
--==========================================================

create table if not exists bridge_observation_tag (
    observation_id bigint not null references fact_observation (observation_id) on delete cascade,
    tag_id bigint not null references dim_tag (tag_id),
    primary key (observation_id, tag_id)
);

create index if not exists idx_bridge_observation_tag_tag
    on bridge_observation_tag (tag_id);

--==========================================================
--seed delle dimensioni statiche
--on conflict permette rerun sicuri del file
--==========================================================

insert into dim_source (source_name)
values
    ('urlhaus'),
    ('threatfox')
on conflict (source_name) do nothing;

insert into dim_indicator_type (indicator_type_name)
values
    ('url'),
    ('domain'),
    ('ip')
on conflict (indicator_type_name) do nothing;

insert into dim_status (status_name)
values
    ('online'),
    ('offline'),
    ('unknown')
on conflict (status_name) do nothing;

commit;