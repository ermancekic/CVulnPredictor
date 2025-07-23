import os
import ujson as json
import re
import requests

def get_missing_commits_in_vulns():
    """
    Identify vulnerabilities without introduced commits and save them in json.

    Args:
        None

    Returns:
        None
    """
    cwd = os.getcwd()
    path_to_vulns = os.path.join(cwd, "data", "vulns")
    # Directory to store missing commit entries
    missing_dir = os.path.join(cwd, "data", "missing_commits")

    # Iterate through each project JSON file
    for fname in os.listdir(path_to_vulns):
        if not fname.endswith(".json"):
            continue
        project = fname[:-5]
        file_path = os.path.join(path_to_vulns, fname)
        with open(file_path, "r", encoding="utf-8") as f:
            reports = json.load(f)

        # Collect reports missing introduced_commit
        missing = []
        for rep in reports:
            if not rep.get("introduced_commit"):
                missing.append({
                    "id": rep.get("id"),
                    "oss-id": rep.get("oss-id")
                })
        # Write missing entries for this project if any
        if missing:
            dest_path = os.path.join(missing_dir, f"{project}.json")
            with open(dest_path, "w", encoding="utf-8") as out:
                json.dump(missing, out, indent=2, ensure_ascii=False)

def get_revision_url():
    """
    Identify vulnerabilities without introduced commits,
    retrieve the introduced commit from OSS-Fuzz report,
    and update the missing_commits JSON files revision URLs.
    The missing commits are located in the revision URL and need to be added in the JSON files.
    The result must be copied in the data/dependencies/missing_or_broken_commits directory.
    """
    cwd = os.getcwd()
    missing_dir = os.path.join(cwd, "data", "missing_commits")

    # Pattern to capture the introduced commit after the colon in the 'range' parameter
    RANGE_RE = re.compile(r'range(?:=|%3D|\\u003d)(?P<start>[0-9A-Za-z]+):(?P<intro>[0-9A-ZaZ]+)')

    for fname in os.listdir(missing_dir):
        if not fname.endswith(".json"):
            continue
        file_path = os.path.join(missing_dir, fname)
        with open(file_path, "r", encoding="utf-8") as f:
            missing_entries = json.load(f)

        updated_entries = []
        for entry in missing_entries:
            oss_id = entry.get("oss-id")
            introduced_commit = None
            if oss_id:
                report_url = f"https://bugs.chromium.org/p/oss-fuzz/issues/detail?id={oss_id}"
                try:
                    resp = requests.get(report_url, timeout=10)
                    resp.raise_for_status()
                    text = resp.text

                    # Save the raw HTML of the OSS-Fuzz report for debugging if needed
                    debug_dir = os.path.join(cwd, "data", "debug_reports")
                    debug_path = os.path.join(debug_dir, f"{oss_id}.html")
                    with open(debug_path, "w", encoding="utf-8") as debug_file:
                        debug_file.write(text)

                    # Handle JavaScript redirect pages by extracting the real report URL and refetching
                    redirect_match = re.search(r'const url = ["\'](?P<url>https?://[^"\']+)["\']', text)
                    if redirect_match:
                        redirect_url = redirect_match.group('url')
                        try:
                            resp2 = requests.get(redirect_url, timeout=10)
                            resp2.raise_for_status()
                            text = resp2.text
                            
                            text = text.encode('utf-8').decode('unicode_escape')
                            
                            # Save the raw HTML of the redirected report for debugging
                            redirect_debug_path = os.path.join(debug_dir, f"{oss_id}_redirect.html")
                            with open(redirect_debug_path, "w", encoding="utf-8") as debug_file2:
                                debug_file2.write(text)
                        except Exception as e:
                            print(f"Error fetching redirected OSS-Fuzz report {redirect_url}: {e}")

                    # Extract revisions URL from text and use it for commit range parsing
                    rev_match = re.search(r'Regressed:\s*(https?://oss-fuzz\.com/revisions\?[^\s]+)', text)
                    if rev_match:
                        rev_url = rev_match.group(1)
                except Exception as e:
                    print(f"Error fetching OSS-Fuzz report {oss_id}: {e}")

            entry["revision_url"] = rev_url
            updated_entries.append(entry)

        # Overwrite the JSON file with the updated entries
        with open(file_path, "w", encoding="utf-8") as out:
            json.dump(updated_entries, out, indent=2, ensure_ascii=False)

def get_revision_url_for_id(oss_id):
    """
    Given an OSS-Fuzz oss-id, fetches and returns the revision URL.
    """
    # Construct report URL for the given OSS-Fuzz ID
    report_url = f"https://bugs.chromium.org/p/oss-fuzz/issues/detail?id={oss_id}"
    try:
        resp = requests.get(report_url, timeout=10)
        resp.raise_for_status()
        text = resp.text

        # Handle JavaScript redirect pages
        redirect_match = re.search(r'const url = ["\'](?P<url>https?://[^"\']+)["\']', text)
        if redirect_match:
            redirect_url = redirect_match.group('url')
            resp2 = requests.get(redirect_url, timeout=10)
            resp2.raise_for_status()
            text = resp2.text
            text = text.encode('utf-8').decode('unicode_escape')

        # Extract the revision URL from the report content
        rev_match = re.search(r'Regressed:\s*(https?://oss-fuzz\.com/revisions\?[^\s]+)', text)
        if rev_match:
            return rev_match.group(1)
    except Exception as e:
        print(f"Error fetching OSS-Fuzz report {oss_id}: {e}")

    return None

def find_zero_commits():
    """
    Find projects in data/vulns where introduced_commit is "0" and print them.
    """
    cwd = os.getcwd()
    path_to_vulns = os.path.join(cwd, "data", "vulns")
    # Iterate through each project JSON file
    for fname in os.listdir(path_to_vulns):
        if not fname.endswith(".json"):
            continue
        project = fname[:-5]
        file_path = os.path.join(path_to_vulns, fname)
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                reports = json.load(f)
        except Exception as e:
            print(f"Error reading {file_path}: {e}")
            continue

        # Filter vulnerabilities with introduced_commit == '0'
        zero_reports = [rep for rep in reports if rep.get("introduced_commit") == "0"]
        if zero_reports:
            print(f"{project} has {len(zero_reports)} vulnerabilities with introduced_commit '0'")
