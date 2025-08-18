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
import ujson as json
import re
import yaml
import requests
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
    
    return result

def get_oss_vulns_data_as_json(tuples_with_vulns, skip_existing=True):
    """
    Convert OSS-Fuzz vulnerability YAML data to JSON files in data/vulns.

    Args:
        tuples_with_vulns (list[tuple[str, str]]): List of (project_name, project_url) pairs to process.
        skip_existing (bool): If True, skip processing when a JSON file already exists. Default is True.

    Returns:
        None
    """
    cwd = os.getcwd()
    path_to_vulns = os.path.join(cwd, "repositories", "OSS-Vulns", "vulns")
    destination_dir = os.path.join(cwd, "data", "vulns")

    CRASH_RE = re.compile(r'Crash state:\s*\n([^\n]+)')

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

def remove_vulns_that_are_not_in_arvo():
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