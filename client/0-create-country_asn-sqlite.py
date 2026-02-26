#!/usr/bin/env python3

import csv
import ipaddress
import os
import sqlite3
import sys
import zipfile
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
BASE_DIR = SCRIPT_DIR.parent
CSV_PATH = Path(os.getenv("COUNTRY_ASN_CSV_PATH", str(BASE_DIR / "db" / "country_asn.csv")))
ZIP_PATH = Path(os.getenv("COUNTRY_ASN_ZIP_PATH", str(BASE_DIR / "db" / "country_asn.zip")))
DB_PATH = Path(os.getenv("COUNTRY_ASN_DB_PATH", str(BASE_DIR / "db" / "country_asn.db")))
BATCH_SIZE = int(os.getenv("COUNTRY_ASN_BATCH_SIZE", "50000"))


CREATE_SQL = """
CREATE TABLE IF NOT EXISTS country_asn_ranges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_version INTEGER NOT NULL,
    start_int TEXT NOT NULL,
    end_int TEXT NOT NULL,
    start_ip TEXT NOT NULL,
    end_ip TEXT NOT NULL,
    country TEXT,
    country_name TEXT,
    continent TEXT,
    continent_name TEXT,
    asn TEXT,
    as_name TEXT,
    as_domain TEXT
);

CREATE INDEX IF NOT EXISTS idx_country_asn_v4_start_end
    ON country_asn_ranges (ip_version, start_int, end_int);

CREATE INDEX IF NOT EXISTS idx_country_asn_country
    ON country_asn_ranges (country);

CREATE INDEX IF NOT EXISTS idx_country_asn_asn
    ON country_asn_ranges (asn);
"""


INSERT_SQL = """
INSERT INTO country_asn_ranges (
    ip_version,
    start_int,
    end_int,
    start_ip,
    end_ip,
    country,
    country_name,
    continent,
    continent_name,
    asn,
    as_name,
    as_domain
)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


def normalize_code(value: str) -> str | None:
    v = value.strip()
    return v if v else None


def parse_ip_range(start_ip_raw: str, end_ip_raw: str) -> tuple[int, str, str, str, str]:
    start_ip = ipaddress.ip_address(start_ip_raw.strip())
    end_ip = ipaddress.ip_address(end_ip_raw.strip())

    if start_ip.version != end_ip.version:
        raise ValueError(f"range versions differ: {start_ip_raw} - {end_ip_raw}")

    start_int = int(start_ip)
    end_int = int(end_ip)
    if start_int > end_int:
        raise ValueError(f"range start > end: {start_ip_raw} - {end_ip_raw}")

    return (
        start_ip.version,
        str(start_int),
        str(end_int),
        str(start_ip),
        str(end_ip),
    )


def recreate_schema(con: sqlite3.Connection) -> None:
    cur = con.cursor()
    cur.execute("DROP TABLE IF EXISTS country_asn_ranges")
    cur.executescript(CREATE_SQL)
    con.commit()
    cur.close()


def ingest_csv(con: sqlite3.Connection, csv_path: Path, batch_size: int) -> tuple[int, int]:
    inserted = 0
    skipped = 0
    batch = []

    with open(csv_path, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)

        required_fields = {
            "start_ip",
            "end_ip",
            "country",
            "country_name",
            "continent",
            "continent_name",
            "asn",
            "as_name",
            "as_domain",
        }
        missing = required_fields - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"missing CSV fields: {', '.join(sorted(missing))}")

        for row in reader:
            try:
                ip_version, start_int, end_int, start_ip, end_ip = parse_ip_range(
                    row.get("start_ip", ""),
                    row.get("end_ip", ""),
                )
            except ValueError:
                skipped += 1
                continue

            batch.append(
                (
                    ip_version,
                    start_int,
                    end_int,
                    start_ip,
                    end_ip,
                    normalize_code(row.get("country", "")),
                    normalize_code(row.get("country_name", "")),
                    normalize_code(row.get("continent", "")),
                    normalize_code(row.get("continent_name", "")),
                    normalize_code(row.get("asn", "")),
                    normalize_code(row.get("as_name", "")),
                    normalize_code(row.get("as_domain", "")),
                )
            )

            if len(batch) >= batch_size:
                con.executemany(INSERT_SQL, batch)
                con.commit()
                inserted += len(batch)
                batch.clear()

    if batch:
        con.executemany(INSERT_SQL, batch)
        con.commit()
        inserted += len(batch)

    return inserted, skipped


def ensure_csv_extracted(zip_path: Path, csv_path: Path) -> Path:
    if not zip_path.exists():
        return csv_path

    with zipfile.ZipFile(zip_path, "r") as zf:
        # Prefer the exact expected name; fallback to first .csv in archive.
        names = zf.namelist()
        member = None

        for name in names:
            if Path(name).name == csv_path.name:
                member = name
                break

        if member is None:
            for name in names:
                if name.lower().endswith(".csv"):
                    member = name
                    break

        if member is None:
            raise ValueError(f"zip has no CSV file: {zip_path}")

        csv_path.parent.mkdir(parents=True, exist_ok=True)
        with zf.open(member, "r") as src, open(csv_path, "wb") as dst:
            dst.write(src.read())

    return csv_path


def main() -> None:
    try:
        effective_csv_path = ensure_csv_extracted(ZIP_PATH, CSV_PATH)
    except (OSError, zipfile.BadZipFile, ValueError) as exc:
        print(f"error: failed to extract zip: {exc}", file=sys.stderr)
        sys.exit(1)

    if not effective_csv_path.exists():
        print(f"error: CSV not found: {effective_csv_path}", file=sys.stderr)
        sys.exit(1)

    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    con = sqlite3.connect(DB_PATH)
    try:
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA synchronous=NORMAL")
        recreate_schema(con)
        inserted, skipped = ingest_csv(con, effective_csv_path, BATCH_SIZE)
    finally:
        con.close()

    print(f"db={DB_PATH} csv={effective_csv_path} inserted={inserted} skipped={skipped}")


if __name__ == "__main__":
    main()
