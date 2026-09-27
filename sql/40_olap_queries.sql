--query olap
--questo file raccoglie le analisi principali
--le query lavorano sullo star schema

begin;

--==========================================================
--1 trend mensile osservazioni per sorgente
--mostra il volume di osservazioni nel tempo per ciascuna sorgente
--==========================================================

select
    make_date(dt.year_num, dt.month_num, 1) as month_start,
    dt.year_num,
    dt.month_num,
    dt.month_name,
    ds.source_name,
    sum(f.obs_count) as total_observations
from fact_observation f
join dim_time dt
    on dt.time_id = f.time_id
join dim_source ds
    on ds.source_id = f.source_id
group by
    make_date(dt.year_num, dt.month_num, 1),
    dt.year_num,
    dt.month_num,
    dt.month_name,
    ds.source_name
order by
    month_start,
    ds.source_name;

--==========================================================
--2 distribuzione indicator type per sorgente
--mostra la composizione dei dati per ciascuna sorgente
--aggiungo anche la percentuale sul totale della sorgente
--==========================================================

with source_totals as (
    select
        f.source_id,
        sum(f.obs_count) as source_total
    from fact_observation f
    group by f.source_id
)
select
    ds.source_name,
    dit.indicator_type_name,
    sum(f.obs_count) as total_observations,
    round(
        100.0 * sum(f.obs_count) / st.source_total,
        2
    ) as pct_on_source
from fact_observation f
join dim_source ds
    on ds.source_id = f.source_id
join dim_indicator_type dit
    on dit.indicator_type_id = f.indicator_type_id
join source_totals st
    on st.source_id = f.source_id
group by
    ds.source_name,
    dit.indicator_type_name,
    st.source_total
order by
    ds.source_name,
    total_observations desc,
    dit.indicator_type_name;

--==========================================================
--3a overlap cross source
--conteggi distinti per sorgente e intersezione
--la chiave logica di confronto è tipo più valore canonico
--==========================================================

with urlhaus_indicators as (
    select distinct
        dit.indicator_type_name,
        di.indicator_value
    from fact_observation f
    join dim_source ds
        on ds.source_id = f.source_id
    join dim_indicator di
        on di.indicator_id = f.indicator_id
    join dim_indicator_type dit
        on dit.indicator_type_id = f.indicator_type_id
    where ds.source_name = 'urlhaus'
),
threatfox_indicators as (
    select distinct
        dit.indicator_type_name,
        di.indicator_value
    from fact_observation f
    join dim_source ds
        on ds.source_id = f.source_id
    join dim_indicator di
        on di.indicator_id = f.indicator_id
    join dim_indicator_type dit
        on dit.indicator_type_id = f.indicator_type_id
    where ds.source_name = 'threatfox'
),
common_indicators as (
    select
        u.indicator_type_name,
        u.indicator_value
    from urlhaus_indicators u
    join threatfox_indicators t
        on t.indicator_type_name = u.indicator_type_name
       and t.indicator_value = u.indicator_value
)
select
    (select count(*) from urlhaus_indicators) as urlhaus_distinct_indicators,
    (select count(*) from threatfox_indicators) as threatfox_distinct_indicators,
    (select count(*) from common_indicators) as common_distinct_indicators;

--==========================================================
--3b top indicatori comuni tra le due sorgenti
--mostra i valori presenti in entrambe con frequenza per sorgente
--==========================================================

with per_source_counts as (
    select
        ds.source_name,
        dit.indicator_type_name,
        di.indicator_value,
        sum(f.obs_count) as total_observations
    from fact_observation f
    join dim_source ds
        on ds.source_id = f.source_id
    join dim_indicator di
        on di.indicator_id = f.indicator_id
    join dim_indicator_type dit
        on dit.indicator_type_id = f.indicator_type_id
    group by
        ds.source_name,
        dit.indicator_type_name,
        di.indicator_value
),
common_indicators as (
    select
        u.indicator_type_name,
        u.indicator_value,
        u.total_observations as urlhaus_observations,
        t.total_observations as threatfox_observations,
        u.total_observations + t.total_observations as total_common_observations
    from per_source_counts u
    join per_source_counts t
        on t.indicator_type_name = u.indicator_type_name
       and t.indicator_value = u.indicator_value
    where u.source_name = 'urlhaus'
      and t.source_name = 'threatfox'
)
select
    indicator_type_name,
    indicator_value,
    urlhaus_observations,
    threatfox_observations,
    total_common_observations
from common_indicators
order by
    total_common_observations desc,
    indicator_type_name,
    indicator_value
limit 20;

--==========================================================
--4 top tld per sorgente
--considera solo indicatori con tld valorizzato
--limito ai primi 10 per sorgente
--==========================================================

with tld_counts as (
    select
        ds.source_name,
        di.tld,
        sum(f.obs_count) as total_observations,
        row_number() over (
            partition by ds.source_name
            order by sum(f.obs_count) desc, di.tld
        ) as rn
    from fact_observation f
    join dim_source ds
        on ds.source_id = f.source_id
    join dim_indicator di
        on di.indicator_id = f.indicator_id
    join dim_indicator_type dit
        on dit.indicator_type_id = f.indicator_type_id
    where di.tld is not null
      and dit.indicator_type_name in ('url', 'domain')
    group by
        ds.source_name,
        di.tld
)
select
    source_name,
    tld,
    total_observations
from tld_counts
where rn <= 10
order by
    source_name,
    total_observations desc,
    tld;

--==========================================================
--5 online vs offline nel tempo per urlhaus
--==========================================================

select
    make_date(dt.year_num, dt.month_num, 1) as month_start,
    dt.year_num,
    dt.month_num,
    dt.month_name,
    dst.status_name,
    sum(f.obs_count) as total_observations
from fact_observation f
join dim_time dt
    on dt.time_id = f.time_id
join dim_source ds
    on ds.source_id = f.source_id
join dim_status dst
    on dst.status_id = f.status_id
where ds.source_name = 'urlhaus'
  and dst.status_name in ('online', 'offline')
group by
    make_date(dt.year_num, dt.month_num, 1),
    dt.year_num,
    dt.month_num,
    dt.month_name,
    dst.status_name
order by
    month_start,
    dst.status_name;

rollback;