"""
prepare_projects.py

This module sets up necessary directories and clones OSS-Fuzz core, vulnerabilities,
and OSS-Fuzz projects repositories. It filters projects by language, handles commits
for vulnerable projects, and returns structured project tuples for analysis.
"""

import ujson as json
import os
import subprocess
import yaml
import logging
import shutil

def prepare_directories():
    """
    Create necessary project directories for metrics and repositories.

    Args:
        None

    Returns:
        None
    """
    current_dir = os.getcwd()
    directories = [
        os.path.join(current_dir, "logs"),
        os.path.join(current_dir, "data"),
        os.path.join(current_dir, "data", "general"),
        os.path.join(current_dir, "data", "metrics"),
        os.path.join(current_dir, "data", "vulns"),
        os.path.join(current_dir, "repositories"),
        os.path.join(current_dir, "repositories", "OSS-Projects"),
        os.path.join(current_dir, "repositories", "OSS-Repo"),
        os.path.join(current_dir, "repositories", "OSS-Vulns"),
        os.path.join(current_dir, "data", "single-metrics"),
        os.path.join(current_dir, "data", "single-metrics", "lines of code"),
        os.path.join(current_dir, "data", "single-metrics", "cyclomatic complexity"),
        os.path.join(current_dir, "data", "single-metrics", "number of loops"),
        os.path.join(current_dir, "data", "single-metrics", "number of nested loops"),
        os.path.join(current_dir, "data", "single-metrics", "max nesting loop depth"),
        os.path.join(current_dir, "data", "single-metrics", "number of parameter variables"),
        os.path.join(current_dir, "data", "single-metrics", "number of pointer arithmetic"),
        os.path.join(current_dir, "data", "single-metrics", "number of variables involved in pointer arithmetic"),
        os.path.join(current_dir, "data", "single-metrics", "max pointer arithmetic variable is involved in"),
        os.path.join(current_dir, "data", "single-metrics", "number of nested control structures"),
        os.path.join(current_dir, "data", "single-metrics", "maximum nesting level of control structures"),
        os.path.join(current_dir, "data", "single-metrics", "maximum of control dependent control structures"),
        os.path.join(current_dir, "data", "single-metrics", "maximum of data dependent control structures"),
        os.path.join(current_dir, "data", "single-metrics", "number of if structures without else"),
        os.path.join(current_dir, "data", "single-metrics", "number of variables involved in control predicates"),

    ]

    for directory in directories:
        if not os.path.exists(directory):
            os.makedirs(directory)
            logging.info(f"Verzeichnis erstellt: {directory}")
        else:
            logging.info(f"Verzeichnis existiert bereits: {directory}")

def get_oss_repo():
    """
    Clone the OSS-Fuzz repository into 'repositories/OSS-Repo'.

    Args:
        None

    Returns:
        None
    """
    
    logging.info("Klonen des OSS-Fuzz Repositories...")
    oss_repo_path = os.path.join(os.getcwd(), "repositories", "OSS-Repo")
    
    if len(os.listdir(oss_repo_path)) > 0:
        logging.info("OSS-Fuzz Repository existiert bereits, überspringe Klonen...")
        return
    
    cmd = ["git", "clone", "https://github.com/google/oss-fuzz", oss_repo_path]
    subprocess.run(cmd, check=True)
       
def get_oss_fuzz_vulns():
    """
    Clone the OSS-Fuzz-Vulns repository into 'repositories/OSS-Vulns'.

    Args:
        None

    Returns:
        None
    """
    
    oss_vulns_repo_path = os.path.join(os.getcwd(), "repositories", "OSS-Vulns")
    
    if len(os.listdir(oss_vulns_repo_path)) > 0:
        return
    
    cmd = ["git", "clone", "https://github.com/google/oss-fuzz-vulns.git", oss_vulns_repo_path]
    subprocess.run(cmd, check=True)

def filter_oss_projects() -> list[(str, str)]:
    """
    Return OSS-Fuzz project names and URLs for C/C++ projects.

    Args:
        None

    Returns:
        list[tuple[str, str]]: List of (project_name, project_url) pairs.
    """
    
    projects_root = os.path.join(os.getcwd(), "repositories", "OSS-Repo", "projects")
    filtered = []

    for entry in os.listdir(projects_root):
        project_yaml_path = os.path.join(projects_root, entry, "project.yaml")
        
        with open (project_yaml_path, "r", encoding="utf-8") as f:
            project_yaml = yaml.safe_load(f)
        
        if 'language' in project_yaml:
            lang = project_yaml['language']
        
        if lang in ('c', 'c++') and 'main_repo' in project_yaml:
            filtered.append((entry, project_yaml['main_repo']))

    return filtered

def get_oss_projects(project_tuple):
    """
    Clone OSS-Fuzz projects into 'repositories/OSS-Projects'. Supports specific commits.

    Args:
        project_tuple (tuple): Tuple containing project_name, project_url, and optional commit hashes.

    Returns:
        None
    """
    
    oss_projects_path = os.path.join(os.getcwd(), "repositories", "OSS-Projects")
    if not os.path.exists(oss_projects_path):
        os.mkdir(oss_projects_path)
    
    project_name = project_tuple[0]
    project_url = project_tuple[1]
    commits = list(project_tuple[2:]) if len(project_tuple) > 2 else []
    
    if not commits:
        project_dir = os.path.join(oss_projects_path, project_name)
        if os.path.exists(project_dir):
            logging.info(f"Projekt {project_name} existiert bereits, überspringe Klonen...")
            return
        logging.info(f"Klone Projekt {project_name}...")
        cmd = ["git", "clone", project_url, project_dir]
        subprocess.run(cmd, check=True)
    else:
        # Check for each commit if the project already exists
        all_commits_exist = True
        missing_commits = []
        for commit in commits:
            commit_dir = os.path.join(oss_projects_path, f"{project_name}_{commit}")
            if not os.path.exists(commit_dir):
                all_commits_exist = False
                missing_commits.append(commit)
        if all_commits_exist:
            logging.info(f"Projekt {project_name} mit allen {len(commits)} Commits existiert bereits, überspringe Klonen...")
            return
        for commit in missing_commits:
            commit_dir = os.path.join(oss_projects_path, f"{project_name}_{commit}")
            logging.info(f"Klone {project_name} für Commit {commit}...")
            cmd = ["git", "clone", project_url, commit_dir]
            subprocess.run(cmd, check=True)
            subprocess.run(["git", "-C", commit_dir, "fetch", "origin", commit], check=True)
            try:
                subprocess.run(["git", "-C", commit_dir, "checkout", commit], check=True)
            except Exception as e:
                logging.warning(f"Fehler beim Checkout des Commits {commit} für {project_name}: {e}")
                # Lösche den Ordner, wenn das Ändern des Commits scheitert
                try:
                    shutil.rmtree(commit_dir, ignore_errors=True)
                    logging.info(f"Ordner {commit_dir} wurde nach fehlgeschlagenem Checkout gelöscht.")
                except Exception as del_e:
                    logging.error(f"Fehler beim Löschen des Ordners {commit_dir}: {del_e}")

def get_vulnerable_projects_with_commits(vulnerable_projects):
    """
    Extract vulnerability commits for each project and extend project tuples.

    Args:
        vulnerable_projects (list[tuple[str, str]]): List of (project_name, project_url) tuples.

    Returns:
        list[tuple]: Tuples (project_name, project_url, commit1, ... ) for vulnerable projects.
    """
    vulnerable_projects_with_commits = []
    vulns_dir = os.path.join(os.getcwd(), "data", "vulns")
    zero_commits_path = os.path.join(os.getcwd(), "dependencies", "zero_commits.json")

    # 1) Load zero_commits.json and convert to Dict
    zero_mapping = {}
    if os.path.exists(zero_commits_path):
        try:
            with open(zero_commits_path, "r", encoding="utf-8") as zf:
                zero_list = json.load(zf)
            # erwartet: [ [projectUrl, commitHash], [...] ]
            for entry in zero_list:
                if len(entry) >= 2:
                    url, commit_hash = entry[0], entry[1]
                    zero_mapping[url] = commit_hash
        except Exception as e:
            logging.error(f"Fehler beim Laden von zero_commits.json: {e}")

    # 2) Collect commits for each vulnerable project
    for project_name, project_url in vulnerable_projects:
        json_path = os.path.join(vulns_dir, f"{project_name}.json")
        commits = []

        if os.path.exists(json_path):
            try:
                with open(json_path, "r", encoding="utf-8") as f:
                    vulns_data = json.load(f)

                for vuln in vulns_data:
                    ic = vuln.get("introduced_commit", None)
                    if not ic:
                        # kein Eintrag → skip
                        continue
                    if ic != "0":
                        # normaler Hash
                        if ic not in commits:
                            commits.append(ic)
                    else:
                        # special case "0" → Mapping versuchen
                        replacement = zero_mapping.get(project_url)
                        if replacement:
                            if replacement not in commits:
                                commits.append(replacement)
                                logging.info(f"Ersetze Commit '0' durch '{replacement}' für {project_name}")
                        else:
                            logging.warning(f"Kein Ersatz-Commit für '0' gefunden in zero_commits.json für {project_url}")
                # Tuple erzeugen (mit oder ohne Commits)
                if commits:
                    vulnerable_projects_with_commits.append((project_name, project_url, *commits))
                else:
                    vulnerable_projects_with_commits.append((project_name, project_url))
            except Exception as e:
                logging.error(f"Fehler beim Laden der Vulnerabilities für {project_name}: {e}")
                vulnerable_projects_with_commits.append((project_name, project_url))
        else:
            # keine JSON-Datei vorhanden
            logging.warning(f"Vulnerabilities-Datei nicht gefunden: {json_path}")
            vulnerable_projects_with_commits.append((project_name, project_url))

    return vulnerable_projects_with_commits

def get_clang_dependencies():
    """
    Download and extract LLVM 20.1.8 binary and source archives for dependency analysis.

    Performs these steps:
      1) Downloads the binary archive (LLVM-20.1.8-Linux-X64.tar.xz) and extracts it to './LLVM-20.1.8-Linux-X64'.
      2) Downloads the source archive (llvm-project-llvmorg-20.1.8.tar.gz) and extracts it to './llvm-project-llvmorg-20.1.8'.
    If the target directories already exist, downloading and extraction are skipped.

    Returns:
        dict: A dictionary with:
            'binary_dir' (str): Path to the extracted LLVM binary directory.
            'source_dir' (str): Path to the extracted LLVM source directory.

    Raises:
        subprocess.CalledProcessError: If any download or extraction command fails.
    """
    current_dir = os.getcwd()
    llvm_version = "20.1.8"

    # 1) Binärpaket (Linux X64 .tar.xz)
    bin_archive = f"LLVM-{llvm_version}-Linux-X64.tar.xz"
    bin_url     = f"https://github.com/llvm/llvm-project/releases/download/llvmorg-{llvm_version}/{bin_archive}"
    bin_target  = os.path.join(current_dir, bin_archive.replace('.tar.xz', ''))

    # 2) Quellcode-Archiv (.tar.gz)
    src_archive = f"llvm-project-llvmorg-{llvm_version}.tar.gz"
    src_url     = f"https://github.com/llvm/llvm-project/archive/refs/tags/llvmorg-{llvm_version}.tar.gz"
    src_target  = os.path.join(current_dir, f"llvm-project-llvmorg-{llvm_version}")

    def download_and_extract(url, archive_name, target_dir, tar_opts):
        if os.path.exists(target_dir):
            logging.info(f"{target_dir} existiert bereits, überspringe Download und Entpacken.")
            return
        logging.info(f"Lade herunter: {url}")
        subprocess.run(["wget", "-q", url, "-O", archive_name], check=True)
        logging.info(f"Entpacke {archive_name} nach {current_dir}...")
        subprocess.run(["tar", tar_opts, archive_name], check=True)
        try:
            os.remove(os.path.join(current_dir, archive_name))
        except Exception as e:
            logging.warning(f"Fehler beim Löschen des Archivs {archive_name}: {e}")

    # Binärpaket (.tar.xz)
    download_and_extract(
        url=bin_url,
        archive_name=bin_archive,
        target_dir=bin_target,
        tar_opts="-xf"
    )

    # Quellcode-Archiv (.tar.gz)
    download_and_extract(
        url=src_url,
        archive_name=src_archive,
        target_dir=src_target,
        tar_opts="-xzf"
    )

    return {
        "binary_dir": bin_target,
        "source_dir": src_target
    }
