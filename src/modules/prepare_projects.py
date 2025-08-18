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
import traceback

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
        os.path.join(current_dir, "repositories", "ARVO-Meta"),
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
        os.path.join(current_dir, "data", "found-methods"),
        os.path.join(current_dir, "data", "not-found-methods"),
        os.path.join(current_dir, "data", "missing_commits"),
        os.path.join(current_dir, "data", "debug_reports"),
        os.path.join(current_dir, "logs", "cloning_errors"),
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

    oss_repo_path = os.path.join(os.getcwd(), "repositories", "OSS-Repo")
    
    if len(os.listdir(oss_repo_path)) > 0:
        logging.info("OSS-Fuzz Repository existiert bereits, überspringe Klonen...")
        return
    
    logging.info("Klonen des OSS-Fuzz Repositories...")
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
    
    logging.info("Klonen des OSS-Fuzz-Vulns Repositories...")
    cmd = ["git", "clone", "https://github.com/google/oss-fuzz-vulns.git", oss_vulns_repo_path]
    subprocess.run(cmd, check=True)

def get_arvo_meta():
    """
    Clone the ARVO-Meta repository into the workspace root.

    Args:
        None

    Returns:
        None
    """
    
    arvo_meta_path = os.path.join(os.getcwd(), "repositories","ARVO-Meta")
    
    if os.path.exists(arvo_meta_path) and os.listdir(arvo_meta_path):
        logging.info("ARVO-Meta Repository existiert bereits, überspringe Klonen...")
        return
    
    logging.info("Klonen des ARVO-Meta Repositories...")
    cmd = ["git", "clone", "https://github.com/n132/ARVO-Meta.git", "--depth=1", arvo_meta_path]
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
    os.makedirs(oss_projects_path, exist_ok=True)

    project_name = project_tuple[0]
    project_url = project_tuple[1]
    commits = list(project_tuple[2:]) if len(project_tuple) > 2 else []

    # Ensure logs directory and cloning_errors subdirectory exist for error logs
    logs_dir = os.path.join(os.getcwd(), "logs")
    cloning_errors_dir = os.path.join(logs_dir, "cloning_errors")

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
        try:
            # Clone and checkout specific commit, capturing output
            # subprocess.run(["git", "clone", "--recursive", project_url, commit_dir], check=True, capture_output=True, text=True)
            # subprocess.run(["git", "-C", commit_dir, "fetch", "origin", commit], check=True, capture_output=True, text=True)
            # subprocess.run(["git", "-C", commit_dir, "checkout", commit], check=True, capture_output=True, text=True)

            if project_name == "cryptofuzz":
                subprocess.run(["git", "clone", project_url, commit_dir], check=True, capture_output=True, text=True)
                subprocess.run(["git", "-C", commit_dir, "fetch", "origin", commit], check=True, capture_output=True, text=True)
                subprocess.run(["git", "-C", commit_dir, "checkout", commit], check=True, capture_output=True, text=True)
            else:

                # 1. Clone repository without checking out to avoid populating the working tree
                subprocess.run(["git", "clone", "--recursive", "--no-checkout", project_url, commit_dir], check=True, capture_output=True, text=True)
                # 2. Fetch only the specific commit (depth=1) to minimize history download
                subprocess.run(["git", "-C", commit_dir, "fetch", "--depth", "1", "origin", commit], check=True, capture_output=True, text=True)
                # 3. Checkout the fetched commit directly by its hash
                subprocess.run(["git", "-C", commit_dir, "checkout", commit], check=True, capture_output=True, text=True)
                # 4. Initialize and update all submodules recursively to match the checked-out commit
                subprocess.run(["git", "-C", commit_dir, "submodule", "update", "--init", "--recursive"], check=True, capture_output=True, text=True)


        except subprocess.CalledProcessError as cpe:
            error_log = os.path.join(cloning_errors_dir, f"{project_name}_{commit}.log")
            tb = traceback.format_exc()
            with open(error_log, 'a', encoding='utf-8') as lf:
                lf.write(f"[CALLEDPROCESSERROR] {project_name}:{commit} return code={cpe.returncode}\n")
                lf.write(f"stdout:\n{cpe.stdout}\n")
                lf.write(f"stderr:\n{cpe.stderr}\n")
                lf.write(f"Traceback:\n{tb}\n")
            shutil.rmtree(commit_dir, ignore_errors=True)
            logging.info(f"Unvollständiger Ordner {commit_dir} wurde gelöscht.")
        except Exception as e:
            error_log = os.path.join(cloning_errors_dir, f"{project_name}_{commit}.log")
            tb = traceback.format_exc()
            with open(error_log, 'a', encoding='utf-8') as lf:
                lf.write(f"[EXCEPTION] {project_name}:{commit}: {e}\n")
                lf.write(f"Traceback:\n{tb}\n")
            shutil.rmtree(commit_dir, ignore_errors=True)
            logging.info(f"Unvollständiger Ordner {commit_dir} wurde gelöscht.")
         
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
    zero_commits_path = os.path.join(os.getcwd(), "data", "dependencies", "zero_commits.json")

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
            logging.info(f"Fehler beim Laden von zero_commits.json: {e}")

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
                            logging.info(f"Kein Ersatz-Commit für '0' gefunden in zero_commits.json für {project_url}")
                # Tuple erzeugen (mit oder ohne Commits)
                if commits:
                    vulnerable_projects_with_commits.append((project_name, project_url, *commits))
                else:
                    vulnerable_projects_with_commits.append((project_name, project_url))
            except Exception as e:
                logging.info(f"Fehler beim Laden der Vulnerabilities für {project_name}: {e}")
                vulnerable_projects_with_commits.append((project_name, project_url))
        else:
            # keine JSON-Datei vorhanden
            logging.info(f"Vulnerabilities-Datei nicht gefunden: {json_path}")
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
            logging.info(f"Fehler beim Löschen des Archivs {archive_name}: {e}")

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

def get_project_includes():
    """
    Extracts include files from all OSS projects and saves them in data/includes.
    """
    logging.info("Erzeuge Include-Listen für OSS-Projects...")
    cwd = os.getcwd()
    includes_path = os.path.join(cwd, "data", "includes")
    os.makedirs(includes_path, exist_ok=True)
    oss_projects_path = os.path.join(cwd, "repositories", "OSS-Projects")
    
    for entry in os.listdir(oss_projects_path):
        project_dir = os.path.join(oss_projects_path, entry)
        if not os.path.isdir(project_dir):
            continue
        # Skip if includes JSON already exists
        output_file = os.path.join(includes_path, f"{entry}.json")
        if os.path.exists(output_file):
            logging.info(f"Includes für Projekt {entry} existieren bereits, überspringe.")
            continue
        includes = []
        for root, dirs, files in os.walk(project_dir):
            for file in files:
                if file.endswith(('.h', '.hpp')):
                    # Use absolute paths for includes
                    abs_path = os.path.abspath(os.path.join(root, file))
                    includes.append(abs_path)
        output_file = os.path.join(includes_path, f"{entry}.json")
        try:
            with open(output_file, 'w', encoding='utf-8') as out_f:
                json.dump(includes, out_f, indent=2, ensure_ascii=False)
            logging.info(f"Includes für Projekt {entry} in {output_file} geschrieben.")
        except Exception as e:
            logging.info(f"Fehler beim Schreiben der Include-Datei für {entry}: {e}")

def get_general_includes():
    """
    Extracts general include files from clang installation and saves them in data/includes/general.json.
    """
    logging.info("Erzeuge allgemeine Include-Liste für LLVM Clang...")
    cwd = os.getcwd()
    includes_path = os.path.join(cwd, "data", "includes")
    os.makedirs(includes_path, exist_ok=True)
    # Pfad zum Clang Include-Verzeichnis
    clang_include_dir = os.path.join(cwd, "LLVM-20.1.8-Linux-X64", "lib", "clang", "20", "include")
    general_includes = []
    for root, dirs, files in os.walk(clang_include_dir):
        for file in files:
            if file.endswith('.h'):
                abs_path = os.path.abspath(os.path.join(root, file))
                general_includes.append(abs_path)
    output_file = os.path.join(includes_path, "general.json")
    try:
        with open(output_file, 'w', encoding='utf-8') as out_f:
            json.dump(general_includes, out_f, indent=2, ensure_ascii=False)
        logging.info(f"Allgemeine Includes in {output_file} geschrieben.")
    except Exception as e:
        logging.info(f"Fehler beim Schreiben der allgemeinen Include-Datei: {e}")
