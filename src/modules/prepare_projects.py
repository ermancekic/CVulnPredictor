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
        os.path.join(current_dir, "data", "includes"),
        os.path.join(current_dir, "data", "found-methods"),
        os.path.join(current_dir, "repositories"),
        os.path.join(current_dir, "data", "single-metrics"),
        os.path.join(current_dir, "data", "not-found-methods"),
        os.path.join(current_dir, "data", "times"),
    ]

    for directory in directories:
        if not os.path.exists(directory):
            os.makedirs(directory)
            logging.info(f"Directory created: {directory}")
        else:
            logging.info(f"Directory already exists: {directory}")

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
        logging.info("OSS-Fuzz Repository already exists, skipping cloning...")
        return
    
    logging.info("Cloning the OSS-Fuzz Repository...")
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
    
    logging.info("Cloning the OSS-Fuzz-Vulns Repository...")
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
        logging.info("ARVO-Meta Repository already exists, skipping cloning...")
        return
    
    logging.info("Cloning the ARVO-Meta Repository...")
    cmd = ["git", "clone", "https://github.com/n132/ARVO-Meta.git", "--depth=1", arvo_meta_path]
    subprocess.run(cmd, check=True)

def get_arvo_table():
    """
    Download the ARVO database (arvo.db) into the project root if it's missing.

    Source:
        https://github.com/n132/ARVO-Meta/releases/download/v2.0.0/arvo.db

    Behavior:
      - If arvo.db already exists in the CWD, skip download.
      - Otherwise, download quietly via wget and place it as ./arvo.db
      - Log progress and any errors.
    """
    current_dir = os.getcwd()
    target_path = os.path.join(current_dir, "arvo.db")
    url = "https://github.com/n132/ARVO-Meta/releases/download/v2.0.0/arvo.db"

    # Skip if file already exists and is non-empty
    if os.path.exists(target_path) and os.path.getsize(target_path) > 0:
        logging.info("arvo.db already exists, skipping download…")
        return

    try:
        logging.info("Downloading arvo.db…")
        subprocess.run(["wget", "-q", url, "-O", target_path], check=True)
        # Basic validation
        if not os.path.exists(target_path) or os.path.getsize(target_path) == 0:
            raise RuntimeError("Downloaded arvo.db is empty or missing.")
        logging.info(f"arvo.db successfully downloaded to {target_path}.")
    except subprocess.CalledProcessError as cpe:
        logging.info(f"Error downloading arvo.db: returncode={cpe.returncode}")
        # Cleanup incomplete file if present
        try:
            if os.path.exists(target_path) and os.path.getsize(target_path) == 0:
                os.remove(target_path)
        except Exception:
            pass
    except Exception as e:
        logging.info(f"Unexpected error downloading arvo.db: {e}")

def filter_oss_projects() -> list[(str, str)]:
    """
    Return OSS-Fuzz project names and URLs for C/C++ projects and persist them as JSON.

    Args:
        None

    Returns:
        list[tuple[str, str]]: List of (project_name, project_url) pairs.
    """

    projects_root = os.path.join(os.getcwd(), "repositories", "OSS-Repo", "projects")
    filtered = []

    for entry in os.listdir(projects_root):
        project_yaml_path = os.path.join(projects_root, entry, "project.yaml")

        with open(project_yaml_path, "r", encoding="utf-8") as f:
            project_yaml = yaml.safe_load(f)

        if 'language' in project_yaml:
            lang = project_yaml['language']
        else:
            # If language isn't defined, skip this entry
            continue

        if lang in ('c', 'c++') and 'main_repo' in project_yaml:
            filtered.append((entry, project_yaml['main_repo']))

    # Persist directly to JSON within this function
    out_dir = os.path.join(os.getcwd(), "data", "general")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "all_oss_projects.json")
    try:
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(filtered, f, indent=2, ensure_ascii=False)
        logging.info(f"{len(filtered)} entries written to {out_path}")
    except Exception as e:
        logging.info(f"Error writing {out_path}: {e}")

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
        logging.info(f"Project {project_name} with all {len(commits)} commits already exists, skipping cloning...")
        return

    for commit in missing_commits:
        commit_dir = os.path.join(oss_projects_path, f"{project_name}_{commit}")
        logging.info(f"Clone {project_name} for commit {commit}...")
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
            logging.info(f"Incomplete folder {commit_dir} was deleted.")
        except Exception as e:
            error_log = os.path.join(cloning_errors_dir, f"{project_name}_{commit}.log")
            tb = traceback.format_exc()
            with open(error_log, 'a', encoding='utf-8') as lf:
                lf.write(f"[EXCEPTION] {project_name}:{commit}: {e}\n")
                lf.write(f"Traceback:\n{tb}\n")
            shutil.rmtree(commit_dir, ignore_errors=True)
            logging.info(f"Incomplete folder {commit_dir} was deleted.")
         
def get_vulnerable_projects_with_commits():
    """
    Extract vulnerability commits for each project by reading from
    'data/general/vulnerable_oss_projects.json' and extend project tuples.

    Args:
        None

    Returns:
        list[tuple]: Tuples (project_name, project_url, commit1, ... ) for vulnerable projects
                      that have at least one commit. Also writes the same result to
                      'data/general/vulns_projects_with_commits.json'.
    """
    vulnerable_projects_with_commits = []
    vulns_dir = os.path.join(os.getcwd(), "data", "vulns")
    out_dir = os.path.join(os.getcwd(), "data", "general")
    out_path = os.path.join(out_dir, "vulns_projects_with_commits.json")
    zero_commits_path = os.path.join(os.getcwd(), "data", "dependencies", "zero_commits.json")
    vuln_projects_json = os.path.join(os.getcwd(), "data", "general", "vulnerable_oss_projects.json")

    # Load vulnerable projects list directly from JSON
    vulnerable_projects = []
    if os.path.exists(vuln_projects_json):
        try:
            with open(vuln_projects_json, "r", encoding="utf-8") as vf:
                # expected format: [ [projectName, projectUrl], ... ]
                vulnerable_projects = [tuple(item) for item in json.load(vf)]
        except Exception as e:
            logging.info(f"Error loading vulnerable_oss_projects.json: {e}")
            vulnerable_projects = []
    else:
        logging.info(f"Vulnerable OSS Projects JSON not found: {vuln_projects_json}")

    # 1) Load zero_commits.json and convert to Dict
    zero_mapping = {}
    if os.path.exists(zero_commits_path):
        try:
            with open(zero_commits_path, "r", encoding="utf-8") as zf:
                zero_list = json.load(zf)
            # expected: [ [projectUrl, commitHash], [...] ]
            for entry in zero_list:
                if len(entry) >= 2:
                    url, commit_hash = entry[0], entry[1]
                    zero_mapping[url] = commit_hash
        except Exception as e:
            logging.info(f"Error loading zero_commits.json: {e}")

    # 2) Collect commits for each vulnerable project
    total_projects = 0
    kept_projects = 0
    for project_name, project_url in vulnerable_projects:
        total_projects += 1
        json_path = os.path.join(vulns_dir, f"{project_name}.json")
        commits = []

        if os.path.exists(json_path):
            try:
                with open(json_path, "r", encoding="utf-8") as f:
                    vulns_data = json.load(f)

                for vuln in vulns_data:
                    ic = vuln.get("introduced_commit", None)
                    if not ic:
                        # no entry → skip
                        continue
                    if ic != "0":
                        # normal hash
                        if ic not in commits:
                            commits.append(ic)
                    else:
                        # special case "0" → try mapping
                        replacement = zero_mapping.get(project_url)
                        if replacement:
                            if replacement not in commits:
                                commits.append(replacement)
                                logging.info(f"Replace commit '0' with '{replacement}' for {project_name}")
                        else:
                            logging.info(f"No replacement commit for '0' found in zero_commits.json for {project_url}")
                # Keep only projects with at least one commit
                if commits:
                    kept_projects += 1
                    vulnerable_projects_with_commits.append((project_name, project_url, *commits))
            except Exception as e:
                logging.info(f"Error loading vulnerabilities for {project_name}: {e}")
                # no inclusion if commits could not be read
        else:
            # no JSON file present
            logging.info(f"Vulnerabilities file not found: {json_path}")
            # no inclusion if no data is available

    # Ergebnis als JSON persistieren (Liste von Listen statt Tuples)
    try:
        serializable = [list(t) for t in vulnerable_projects_with_commits]
        with open(out_path, "w", encoding="utf-8") as out_f:
            json.dump(serializable, out_f, indent=2, ensure_ascii=False)
        logging.info(
            f"{kept_projects}/{total_projects} projects with commits written to {out_path}."
        )
    except Exception as e:
        logging.info(f"Error writing {out_path}: {e}")

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
    llvm_version = "21.1.2"

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
            logging.info(f"{target_dir} already exists, skipping download and extraction.")
            return
        logging.info(f"Downloading: {url}")
        subprocess.run(["wget", "-q", url, "-O", archive_name], check=True)
        logging.info(f"Extracting {archive_name} to {current_dir}...")
        subprocess.run(["tar", tar_opts, archive_name], check=True)
        try:
            os.remove(os.path.join(current_dir, archive_name))
        except Exception as e:
            logging.info(f"Error deleting archive {archive_name}: {e}")

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

def get_project_includes():
    """
    Extracts include files from all OSS projects and saves them in data/includes.
    """
    logging.info("Generate include lists for OSS-Projects...")
    cwd = os.getcwd()
    includes_path = os.path.join(cwd, "data", "includes")
    oss_projects_path = os.path.join(cwd, "repositories")
    
    for entry in os.listdir(oss_projects_path):
        project_dir = os.path.join(oss_projects_path, entry)
        if not os.path.isdir(project_dir):
            continue
        # Skip if includes JSON already exists
        output_file = os.path.join(includes_path, f"{entry}.json")
        if os.path.exists(output_file):
            logging.info(f"Includes for project {entry} already exist, skipping.")
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
            logging.info(f"Includes for project {entry} written to {output_file}.")
        except Exception as e:
            logging.info(f"Error writing include file for {entry}: {e}")

def get_general_includes():
    """
    Extracts general include files from clang installation and saves them in data/includes/general.json.
    """
    logging.info("Generate general include list for LLVM Clang...")
    cwd = os.getcwd()
    includes_path = os.path.join(cwd, "data", "includes")
    # Path to Clang include directory
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
        logging.info(f"General includes written to {output_file}.")
    except Exception as e:
        logging.info(f"Error writing general include file: {e}")
