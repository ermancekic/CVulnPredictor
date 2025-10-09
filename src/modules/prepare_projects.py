"""
prepare_projects.py

This module sets up necessary directories and clones OSS-Fuzz core, vulnerabilities,
and OSS-Fuzz projects repositories. It filters projects by language, handles commits
for vulnerable projects, and returns structured project tuples for analysis.
"""

import ujson as json
import os
import subprocess
import logging

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
        os.path.join(current_dir, "repositories"),
        os.path.join(current_dir, "logs"),
        os.path.join(current_dir, "data"),
        os.path.join(current_dir, "data", "general"),
        os.path.join(current_dir, "data", "metrics"),
        os.path.join(current_dir, "data", "includes"),
        os.path.join(current_dir, "data", "found-methods"),
        os.path.join(current_dir, "data", "single-metrics"),
        os.path.join(current_dir, "data", "not-found-methods"),
        os.path.join(current_dir, "data", "times"),
        os.path.join(current_dir, "data", "arvo-projects"),
    ]

    for directory in directories:
        if not os.path.exists(directory):
            os.makedirs(directory)
            logging.info(f"Directory created: {directory}")
        else:
            logging.info(f"Directory already exists: {directory}")

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

def get_clang_dependencies():
    """
    Download and extract LLVM 21.1.2 binary and source archives for dependency analysis.

    Performs these steps:
      1) Downloads the binary archive (LLVM-21.1.2-Linux-X64.tar.xz) and extracts it to './LLVM-21.1.2-Linux-X64'.
      2) Downloads the source archive (llvm-project-llvmorg-21.1.2.tar.gz) and extracts it to './llvm-project-llvmorg-21.1.2'.
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
