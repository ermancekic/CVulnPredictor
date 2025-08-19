"""
retrieve_oss_fuzz_data.py

This module extracts OSS project tuples with vulnerabilities from general metadata,
updates obsolete URLs, and converts OSS-Vulns YAML files into JSON format
for further analysis.
"""
import re
import time
import html
import os
import sqlite3
import ujson as json
import re
import yaml
import requests
import logging
from pathlib import Path
from urllib.parse import urljoin
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from concurrent.futures import ThreadPoolExecutor, as_completed

def get_project_tuples_with_vulns():
    """
    Return OSS project tuples with vulnerabilities, updating obsolete URLs.

    Args:
        None

    Returns:
        list[tuple[str, str]]: List of (project_name, project_url) pairs for projects with vulnerabilities.
    """
    with open("data/general/all_oss_projects.json", "r", encoding="utf-8") as f:
        all_project_names = json.load(f)

    # Load outdated links mapping
    with open("data/dependencies/outdated_links.json", "r", encoding="utf-8") as f:
        outdated_links = json.load(f)
    
    # Create a mapping dictionary from obsolete URL to updated URL
    url_mapping = {obsolete: updated for obsolete, updated in outdated_links}

    cwd = os.getcwd()
    path_to_vulns = os.path.join(cwd, "repositories", "OSS-Vulns", "vulns") 
    
    project_names_with_vulns = [name for name in os.listdir(path_to_vulns)]

    # Filter projects with vulnerabilities and update obsolete URLs
    result = []
    for name, url in all_project_names:
        if name in project_names_with_vulns:
            # Check if URL needs to be updated
            updated_url = url_mapping.get(url, url)  # Use updated URL if found, otherwise keep original
            result.append((name, updated_url))

    # Persist directly to JSON within this function
    out_dir = os.path.join(os.getcwd(), "data", "general")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "vulnerable_oss_projects.json")
    try:
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        logging.info(f"{len(result)} entries written to {out_path}")
    except Exception as e:
        logging.info(f"Fehler beim Schreiben von {out_path}: {e}")

    return result

def get_oss_vulns_data_as_json(skip_existing=True):
    """
    Convert OSS-Fuzz vulnerability YAML data to JSON files in data/vulns.

    Behavior change: Reads the vulnerable project tuples directly from
    data/general/vulnerable_oss_projects.json, so no parameter is required.

    Args:
        skip_existing (bool): If True, skip processing when a JSON file already exists. Default is True.

    Returns:
        None
    """
    cwd = os.getcwd()
    path_to_vulns = os.path.join(cwd, "repositories", "OSS-Vulns", "vulns")
    destination_dir = os.path.join(cwd, "data", "vulns")

    CRASH_RE = re.compile(r'Crash state:\s*\n([^\n]+)')

    # Load vulnerable projects list from JSON
    vulnerable_json = os.path.join(cwd, "data", "general", "vulnerable_oss_projects.json")
    if not os.path.exists(vulnerable_json):
        logging.info(f"Vulnerable projects JSON not found: {vulnerable_json}")
        return
    try:
        with open(vulnerable_json, "r", encoding="utf-8") as f:
            tuples_with_vulns = json.load(f)
    except Exception as e:
        logging.info(f"Failed to load {vulnerable_json}: {e}")
        return

    project_names_with_vulns = [t[0] for t in tuples_with_vulns]
    for project in os.listdir(path_to_vulns):

        if project not in project_names_with_vulns:
            continue

        project_path = os.path.join(path_to_vulns, project)
        if not os.path.isdir(project_path):
            continue

        destination_path = os.path.join(destination_dir, f"{project}.json")
        if skip_existing and os.path.exists(destination_path):
            continue  # Skip if destination file already exists and skip_existing is True

        reports_for_project = []

        for root, _, files in os.walk(project_path):
            for yaml_file in files:
                if not yaml_file.endswith((".yaml", ".yml")):
                    continue

                path = os.path.join(root, yaml_file)
                with open(path, encoding="utf-8") as f:
                    data = yaml.safe_load(f)

                summary = data.get("summary", "").strip()
                details = data.get("details", "")
                
                # Extract introduced commit from affected ranges if available
                introduced_commit = None
                if data.get("affected"):
                    for affected in data.get("affected", []):
                        for range_info in affected.get("ranges", []):
                            if range_info.get("type") == "GIT":
                                for event in range_info.get("events", []):
                                    if "introduced" in event:
                                        introduced_commit = event["introduced"]
                                        break
                                if introduced_commit:
                                    break
                        if introduced_commit:
                            break
                
                m = CRASH_RE.search(details)
                if m:
                    full = m.group(1).strip()
                    parts = full.split("::")
                    if len(parts) >= 2:
                        method_name = parts[-1]
                    else:
                        method_name = parts[0]
                else:
                    method_name = None

                # Extract OSS-Fuzz report ID from references
                oss_id = None
                for ref in data.get("references", []):
                    if ref.get("type") == "REPORT":
                        url_ref = ref.get("url", "")
                        m2 = re.search(r'id=(\d+)', url_ref)
                        if m2:
                            oss_id = m2.group(1)
                            break

                reports_for_project.append({
                    "id": data.get("id"),
                    "oss-id": oss_id,
                    "method": method_name,
                    "summary": summary,
                    "introduced_commit": introduced_commit
                })
    
        with open(destination_path, "w", encoding="utf-8") as out:
            json.dump(reports_for_project, out, indent=2, ensure_ascii=False)

def delete_unfixable_broken_commits():
    """
    Remove vulnerabilities whose introduced_commit appears in the unfixable_broken_commits list.
    Iterates over each JSON file in data/vulns, filters out entries matching unfixable commits,
    and deletes the file if no entries remain.
    """
    cwd = os.getcwd()
    vulns_dir = os.path.join(cwd, "data", "vulns")
    ubc_path = os.path.join(cwd, "data", "dependencies", "unfixable_broken_commits.json")
    # Load unfixable broken commits mapping: project_name -> set of commits
    ubc_map = {}
    if os.path.exists(ubc_path):
        try:
            with open(ubc_path, "r", encoding="utf-8") as f:
                ubc_list = json.load(f)
            for proj, commit in ubc_list:
                ubc_map.setdefault(proj, set()).add(commit)
        except Exception as e:
            logging.info(f"Fehler beim Laden von unfixable_broken_commits: {e}")
            return
    else:
        logging.info(f"Datei unfixable_broken_commits nicht gefunden: {ubc_path}")
        return
    # Process each vulnerability file
    for fname in os.listdir(vulns_dir):
        if not fname.endswith('.json'):
            continue
        proj = fname[:-5]
        path = os.path.join(vulns_dir, fname)
        try:
            with open(path, "r", encoding="utf-8") as f:
                entries = json.load(f)
            # Filter out unfixable entries
            filtered = [e for e in entries if not (proj in ubc_map and e.get('introduced_commit') in ubc_map[proj])]
            if filtered:
                with open(path, "w", encoding="utf-8") as out:
                    json.dump(filtered, out, indent=2, ensure_ascii=False)
                logging.info(f"Aktualisiert: {path}, {len(entries)-len(filtered)} Einträge entfernt.")
            else:
                os.remove(path)
                logging.info(f"Gelöscht leere Datei: {path}")
        except Exception as e:
            logging.info(f"Fehler beim Verarbeiten von {path}: {e}")

def update_missing_commits_in_vulns():
    """
    Identify vulnerabilities without introduced commits,
    retrieve them, and update the data/vulns JSON files.
    """
    cwd = os.getcwd()
    vulns_dir = os.path.join(cwd, "data", "vulns")
    missing_dir = os.path.join(cwd, "data", "dependencies", "missing_or_broken_commits")

    for fname in os.listdir(missing_dir):
        if not fname.endswith(".json"):
            continue
        project = fname[:-5]
        missing_file = os.path.join(missing_dir, fname)
        with open(missing_file, "r", encoding="utf-8") as f:
            missing_entries = json.load(f)
        if not missing_entries:
            continue
        vuln_file = os.path.join(vulns_dir, f"{project}.json")
        if not os.path.exists(vuln_file):
            continue
        with open(vuln_file, "r", encoding="utf-8") as f:
            reports = json.load(f)
        # Map report IDs to their found commit
        commit_map = {e.get("id"): e.get("introduced_commit") for e in missing_entries if e.get("introduced_commit")}
        # Update original reports with the retrieved commits
        for rep in reports:
            rid = rep.get("id")
            if rid in commit_map:
                rep["introduced_commit"] = commit_map[rid]
        # Write updated reports back to data/vulns
        with open(vuln_file, "w", encoding="utf-8") as f:
            json.dump(reports, f, indent=2, ensure_ascii=False)

def remove_vulns_that_are_not_in_arvo_repo():
    """
    Remove vulnerabilities that are not present in ARVO meta data,
    based on the presence of oss-id.
    """
    cwd = os.getcwd()
    vulns_dir = os.path.join(cwd, "data", "vulns")
    meta_dir = os.path.join(cwd, "repositories", "ARVO-Meta", "archive_data", "meta")
    # Collect available oss-ids from ARVO meta files
    available_ids = {fname[:-5] for fname in os.listdir(meta_dir) if fname.endswith(".json")}
    for fname in os.listdir(vulns_dir):
        if not fname.endswith(".json"):
            continue
        vuln_file = os.path.join(vulns_dir, fname)
        with open(vuln_file, "r", encoding="utf-8") as f:
            entries = json.load(f)
        # Filter entries whose oss-id exists in available_ids
        filtered = [e for e in entries if e.get("oss-id") in available_ids]
        if filtered:
            with open(vuln_file, "w", encoding="utf-8") as f:
                json.dump(filtered, f, indent=2, ensure_ascii=False)
        else:
            os.remove(vuln_file)

def get_new_oss_vuln_ids(max_workers: int | None = None):
    """
    Aktualisiert 'new-oss-id' parallel über alle JSON-Dateien in data/vulns.
    Standardmäßig wird die Anzahl Threads auf os.cpu_count() gesetzt.

    Args:
        max_workers: Anzahl paralleler Threads (default: os.cpu_count()).
    """
    logging.info("Get new oss vuln ids...")

    # robuste Muster (vorab kompilieren und an Worker übergeben)
    js_url_patterns = [
        re.compile(r'const\s+url\s*=\s*["\'](?P<url>https?://[^"\']+)["\']', re.I),
        re.compile(r'location\.(?:href|replace)\s*=\s*["\'](?P<url>https?://[^"\']+)["\']', re.I),
    ]
    meta_refresh_re = re.compile(
        r'<meta[^>]+http-equiv=["\']refresh["\'][^>]*content=["\'][^;]+;\s*url=(?P<url>[^"\'>\s]+)',
        re.I
    )
    canonical_re = re.compile(
        r'<link[^>]+rel=["\']canonical["\'][^>]*href=["\'](?P<url>https?://[^"\']+)["\']',
        re.I
    )
    id_re = re.compile(r'(?:[?&]id=|/issues/)(\d+)')

    base = Path("data") / "vulns"
    if not base.exists():
        print(f"Verzeichnis nicht gefunden: {base}")
        return

    paths = list(base.glob("*.json"))
    if not paths:
        print("Keine JSON-Dateien in data/vulns gefunden.")
        return

    workers = max_workers if isinstance(max_workers, int) and max_workers > 0 else (os.cpu_count() or 4)
    
    def process_file(path: Path) -> tuple[Path, int]:
        """Verarbeitet eine einzelne Projekt-JSON-Datei und gibt (path, anzahl_updates) zurück."""
        try:
            with path.open("r", encoding="utf-8") as f:
                reports = json.load(f)
        except Exception as e:
            print(f"Konnte {path} nicht laden: {e}")
            return (path, 0)

        if not isinstance(reports, list):
            return (path, 0)

        # Eigene Session pro Thread
        session = requests.Session()
        retries = Retry(
            total=3, backoff_factor=0.5,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset(["GET", "HEAD"])
        )
        session.mount("https://", HTTPAdapter(max_retries=retries))
        session.headers.update({"User-Agent": "oss-fuzz-id-sync/1.0 (+requests)"})

        updated = 0

        for rep in reports:
            oss_id = rep.get("oss-id")
            # Skip if no oss_id or if new-oss-id key already exists
            if not oss_id or 'new-oss-id' in rep:
                continue

            report_url = f"https://bugs.chromium.org/p/oss-fuzz/issues/detail?id={oss_id}"
            try:
                r = session.get(report_url, timeout=15)
                r.raise_for_status()
                final_url = r.url
                html_text = r.text

                # mögliche JS-/META-/canonical-Weiterleitung erkennen
                redirect_url = None
                for pat in js_url_patterns:
                    m = pat.search(html_text)
                    if m:
                        redirect_url = html.unescape(m.group("url"))
                        break
                if not redirect_url:
                    m = meta_refresh_re.search(html_text)
                    if m:
                        redirect_url = html.unescape(m.group("url"))
                if not redirect_url:
                    m = canonical_re.search(html_text)
                    if m:
                        redirect_url = html.unescape(m.group("url"))

                if redirect_url:
                    r2 = session.get(urljoin(final_url, redirect_url), timeout=15)
                    r2.raise_for_status()
                    final_url = r2.url
                    html_text = r2.text  # aktualisieren

                # Issue-ID aus finaler URL, ggf. Fallback: HTML
                m = id_re.search(final_url) or id_re.search(html_text)
                if m:
                    rep["new-oss-id"] = m.group(1)
                    updated += 1
                else:
                    print(f"Konnte keine Issue-ID extrahieren für oss-id {oss_id} (URL: {final_url})")

                # kleine Pause gegen Rate Limits
                time.sleep(0.1)

            except Exception as e:
                print(f"Error fetching new OSS-Fuzz id for {oss_id}: {e}")

        if updated:
            try:
                with path.open("w", encoding="utf-8") as out:
                    json.dump(reports, out, indent=2, ensure_ascii=False)
            except Exception as e:
                print(f"Konnte {path} nicht schreiben: {e}")

        return (path, updated)

    # Parallel über die Dateien
    total_updates = 0
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(process_file, p): p for p in paths}
        for fut in as_completed(futures):
            try:
                _, upd = fut.result()
                total_updates += upd
            except Exception as e:
                print(f"Fehler beim Verarbeiten von {futures[fut]}: {e}")

    print(f"Fertig. Aktualisierte Einträge: {total_updates}")

def remove_vulns_that_are_not_in_arvo_table():
    """
    Entfernt Einträge aus den JSON-Dateien in `data/vulns`, deren `new-oss-id`
    nicht in der `arvo.db` unter der Spalte `localId` vorkommt.

    Verhalten:
    - Lädt alle Werte der Spalte `localId` aus allen Tabellen der Datenbank (falls vorhanden).
    - Für jede JSON-Datei in `data/vulns` werden nur die Einträge behalten, deren
      `new-oss-id` in der Datenbank vorkommt.
    - Falls nach dem Filtern keine Einträge mehr übrig bleiben, wird die JSON-Datei gelöscht.
    """
    cwd = os.getcwd()
    db_path = os.path.join(cwd, "arvo.db")

    if not os.path.exists(db_path):
        print(f"arvo.db nicht gefunden: {db_path}")
        return

    available_ids = set()
    try:
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        # Liste aller Tabellen holen
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [r[0] for r in cur.fetchall()]

        for tbl in tables:
            try:
                cur.execute(f"PRAGMA table_info('{tbl}')")
                cols = [r[1] for r in cur.fetchall()]
                if 'localId' in cols:
                    # Alle nicht-null localId-Werte sammeln
                    cur.execute(f"SELECT localId FROM '{tbl}' WHERE localId IS NOT NULL")
                    for (lid,) in cur.fetchall():
                        if lid is None:
                            continue
                        available_ids.add(str(lid))
            except Exception as e:
                # Fehler bei einer Tabelle dürfen den Gesamtlauf nicht abbrechen
                print(f"Fehler beim Lesen der Tabelle {tbl}: {e}")

    except Exception as e:
        print(f"Fehler beim Öffnen von arvo.db: {e}")
        return
    finally:
        try:
            conn.close()
        except Exception:
            pass

    vulns_dir = os.path.join(cwd, "data", "vulns")
    if not os.path.isdir(vulns_dir):
        print(f"Verzeichnis nicht gefunden: {vulns_dir}")
        return

    for fname in os.listdir(vulns_dir):
        if not fname.endswith('.json'):
            continue

        vuln_file = os.path.join(vulns_dir, fname)
        try:
            with open(vuln_file, 'r', encoding='utf-8') as f:
                entries = json.load(f)
        except Exception as e:
            print(f"Konnte {vuln_file} nicht laden: {e}")
            continue

        if not isinstance(entries, list):
            print(f"Überspringe {vuln_file}: erwartet Liste, gefunden {type(entries)}")
            continue

        filtered = []
        for e in entries:
            new_id = e.get('new-oss-id')
            # Wenn kein new-oss-id vorhanden oder nicht in DB -> löschen (nicht in filtered aufnehmen)
            if new_id and str(new_id) in available_ids:
                filtered.append(e)

        if filtered:
            try:
                with open(vuln_file, 'w', encoding='utf-8') as out:
                    json.dump(filtered, out, indent=2, ensure_ascii=False)
            except Exception as e:
                print(f"Konnte {vuln_file} nicht schreiben: {e}")
        else:
            try:
                os.remove(vuln_file)
            except Exception as e:
                print(f"Konnte {vuln_file} nicht löschen: {e}")
