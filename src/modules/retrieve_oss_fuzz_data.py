"""
retrieve_oss_fuzz_data.py

This module extracts OSS project tuples with vulnerabilities from general metadata,
updates obsolete URLs, and converts OSS-Vulns YAML files into JSON format
for further analysis.
"""

import os
import ujson as json
import re
import yaml

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

def get_oss_vulns_data_as_json(tuples_with_vulns):
    """
    Convert OSS-Fuzz vulnerability YAML data to JSON files in data/vulns.

    Args:
        tuples_with_vulns (list[tuple[str, str]]): List of (project_name, project_url) pairs to process.

    Returns:
        None
    """
    cwd = os.getcwd()
    path_to_vulns = os.path.join(cwd, "repositories", "OSS-Vulns", "vulns")
    destination_dir = os.path.join(cwd, "data", "vulns")
    
    # Ensure the destination directory exists
    os.makedirs(destination_dir, exist_ok=True)

    CRASH_RE = re.compile(r'Crash state:\s*\n([^\n]+)')

    project_names_with_vulns = [t[0] for t in tuples_with_vulns]
    for project in os.listdir(path_to_vulns):

        if project not in project_names_with_vulns:
            continue

        project_path = os.path.join(path_to_vulns, project)
        if not os.path.isdir(project_path):
            continue
    
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
                        class_name  = "::".join(parts[:-1])
                        method_name = parts[-1]
                    else:
                        class_name, method_name = None, parts[0]
                else:
                    class_name = method_name = None

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
                    "class": class_name,
                    "method": method_name,
                    "summary": summary,
                    "introduced_commit": introduced_commit
                })
    
        destination_path = os.path.join(destination_dir, f"{project}.json")
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