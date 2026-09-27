# mini-ti-dw

Mini Threat Intelligence Data Warehouse based on PostgreSQL, Docker Compose and a Python pipeline.

The project integrates two public threat intelligence sources:

- URLhaus, accessed via CSV feed
- ThreatFox, accessed through its API with a key

The pipeline maintains three separate layers:

1. `raw`, where original payloads are stored without business transformations
2. `canonical`, where URLhaus and ThreatFox data are normalized into a common format
3. `dw`, where canonical data are loaded into a star schema for OLAP analysis

The central fact in the data warehouse represents a unique observation of an indicator on a given day from a given source.

PostgreSQL executes the SQL files in alphabetical order when the Docker volume is first initialized:

1. `10_raw.sql` creates the raw tables
2. `20_canonical.sql` creates the canonical layer
3. `30_dw.sql` creates the star schema
4. `40_olap_queries.sql` contains the final analysis queries

## Prerequisites

You need:

- Docker and Docker Compose
- a ThreatFox API key to use the `ingest_threatfox.py` script
```bash
python -m venv .venv
source .venv/bin/activate
pip install "psycopg[binary]" requests python-dotenv pytest
```

To run the scripts without installing the package, use `PYTHONPATH=src`.

## Configuration

Copy the example file:

```bash
cp .env.example .env
```
insert THREATFOX_AUTH_KEY=insert_tf_auth_key in the .env file.

## Starting the database

Start PostgreSQL:

```bash
docker compose up -d
```

The SQL scripts in `sql/` are mounted at `/docker-entrypoint-initdb.d`.
PostgreSQL runs them automatically.

## Pipeline execution order

Run the full workflow in this order:

1. ingest URLhaus data
2. ingest ThreatFox data
3. normalize data into the canonical layer
4. load the data warehouse
5. run the final OLAP queries

### 1. Ingest URLhaus

Downloads the recent URLhaus feed and inserts the raw records into `raw_urlhaus`.

```bash
PYTHONPATH=src python scripts/ingest_urlhaus.py
```

### 2. Ingest ThreatFox

Downloads recent IOCs from ThreatFox and inserts the raw records into `raw_threatfox`.

```bash
PYTHONPATH=src python scripts/ingest_threatfox.py --days 7
```
`--days` must be between `1` and `7`.

This script requires `THREATFOX_AUTH_KEY` to be set in `.env`.

### 3. Canonical normalization

Reads `raw_urlhaus` and `raw_threatfox`, normalizes the main fields and saves the result in `canonical_observation`.

```bash
PYTHONPATH=src python scripts/normalize_to_canonical.py
```

Normalization:

- converts source data into the common format
- discards invalid or out-of-scope records
- deduplicates by source, indicator type and indicator value and day
- preserves metadata not covered by the model in `context_json`
- stores tags as a text array

The canonical layer contains only these indicator types:

- `url`
- `domain`
- `ip`

### 4. Loading the DW

Loads the canonical layer into the final star schema.

```bash
PYTHONPATH=src python scripts/load_dw.py
```

The loader populates:

- `dim_time`
- `dim_source`
- `dim_indicator_type`
- `dim_status`
- `dim_indicator`
- `dim_tag`
- `fact_observation`
- `bridge_observation_tag`

When finished, it prints a summary with the number of canonical records read and the number of new rows inserted into the main tables.

### 5. OLAP queries

The final queries are in `sql/40_olap_queries.sql`.

To run them inside the container:

```bash
docker compose exec postgres sh -lc 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -f /docker-entrypoint-initdb.d/40_olap_queries.sql'
```

The file contains:

- monthly observation trends by source
- indicator type distribution by source
- cross-source overlap between URLhaus and ThreatFox
- top indicators shared across sources
- top TLDs by source
- optional online vs offline analysis for URLhaus

## Full command example

With the database already running and `.env` configured:

```bash
PYTHONPATH=src python scripts/ingest_urlhaus.py
PYTHONPATH=src python scripts/ingest_threatfox.py --days 7
PYTHONPATH=src python scripts/normalize_to_canonical.py
PYTHONPATH=src python scripts/load_dw.py
docker compose exec postgres sh -lc 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -f /docker-entrypoint-initdb.d/40_olap_queries.sql'
```
## Resetting the local database

To delete the volume and local data:

```bash
docker compose down -v
```

## Tests

Run the Python tests:

```bash
PYTHONPATH=src python -m unittest discover -s tests
```

The tests mainly cover normalization and deduplication in the canonical layer.
