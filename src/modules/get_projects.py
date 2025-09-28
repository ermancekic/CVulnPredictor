"""Utility to iterate all arvo-project JSON files, run their docker images, copy source & includes.

Für jedes JSON-File (Dateiname <projectname>.json) in data/arvo-projects werden alle localID-Werte gesammelt.
Für jede localID wird das Docker-Image "cr.cispa.de/d/n132/arvo:<localID>-vul" verarbeitet:

1. Zielordner repositories/<projectname>_<localID> wird erstellt.
2. Image wird gepullt (falls nötig) und ein Container erstellt.
3. 'arvo compile' wird im Container ausgeführt.
4. Die Pfade /src/<projectname>, /usr/include und /work werden in den Zielordner kopiert.
5. Container wird gestoppt/entfernt und (optional) das Image gelöscht.
6. Idempotenz: **Wenn der Zielordner bereits existiert, wird das Paar übersprungen.**
"""

from __future__ import annotations

import argparse
import json
import logging
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Iterable, Set, Dict, Any, List, Tuple, Optional

try:  # optional performance
    import ujson as _ujson  # type: ignore
    _json_load = _ujson.load
    _json_dump = _ujson.dump
except Exception:  # pragma: no cover
    _json_load = json.load
    _json_dump = json.dump


LOG = logging.getLogger(__name__)
DEFAULT_MAX_WORKERS = 10


def _run(cmd: List[str], *, check: bool = True, capture_output: bool = False) -> subprocess.CompletedProcess:
    """Run a subprocess command with logging."""
    LOG.debug("Running command: %s", " ".join(cmd))
    return subprocess.run(cmd, check=check, capture_output=capture_output, text=True)


def _collect_local_ids(json_path: Path) -> Set[int]:
    with json_path.open("r") as f:
        try:
            data = _json_load(f)
        except Exception as e:  # pragma: no cover
            LOG.error("Error reading %s: %s", json_path.name, e)
            return set()
    if not isinstance(data, list):  # pragma: no cover
        LOG.warning("Unexpected JSON format in %s (expected list)", json_path.name)
        return set()
    ids: Set[int] = set()
    for item in data:
        if isinstance(item, dict) and "localID" in item:
            try:
                ids.add(int(item["localID"]))
            except (TypeError, ValueError):  # pragma: no cover
                LOG.debug("Skipping invalid localID in %s: %r", json_path.name, item.get("localID"))
    return ids


def _marker_path(dest_dir: Path) -> Path:
    return dest_dir / ".extracted.json"


def _read_marker(dest_dir: Path) -> Optional[Dict[str, Any]]:
    mp = _marker_path(dest_dir)
    if not mp.exists():
        return None
    try:
        with mp.open("r") as f:
            return _json_load(f)
    except Exception:
        return None


def _write_marker(dest_dir: Path, payload: Dict[str, Any]) -> None:
    mp = _marker_path(dest_dir)
    try:
        with mp.open("w") as f:
            _json_dump(payload, f)
    except Exception as e:  # pragma: no cover
        LOG.debug("Marker konnte nicht geschrieben werden (%s): %s", mp, e)


def _dir_nonempty(p: Path) -> bool:
    return p.exists() and any(p.iterdir())


def _image_id(image_tag: str) -> Optional[str]:
    try:
        cp = _run(["docker", "inspect", "--format", "{{.Id}}", image_tag], capture_output=True)
        image_id = cp.stdout.strip()
        return image_id or None
    except subprocess.CalledProcessError:
        return None


def _copy_if_missing(container_id: str, src_in_container: str, dest_dir: Path) -> Tuple[str, bool, Optional[str]]:
    """
    Copy directory from container if not present or empty in target.
    Returns (name_in_target, copied_bool, error_msg_or_None).
    """
    name = Path(src_in_container).name  # e.g. "<project>", "include" or "work"
    target = dest_dir / name
    if _dir_nonempty(target):
        LOG.debug("Target already exists, skipping copy: %s", target)
        return name, False, None
    try:
        _run(["docker", "cp", f"{container_id}:{src_in_container}", str(dest_dir)])
        LOG.debug("Copied %s -> %s", src_in_container, dest_dir)
        return name, True, None
    except subprocess.CalledProcessError as e:
        LOG.warning("Path missing in image/container: %s (%s)", src_in_container, e)
        return name, False, str(e)


def _process_one(
    project: str,
    local_id: int,
    repositories_dir: Path,
    *,
    dry_run: bool,
    skip_existing: bool,
    remove_image: bool,
) -> Tuple[str, int, bool, str]:
    """
    Process a (project, local_id) pair.
    Idempotenz-Regel (neu): Wenn der Zielordner bereits existiert, wird übersprungen.
    Returns: (project, local_id, success, message)
    """
    image_tag = f"cr.cispa.de/d/n132/arvo:{local_id}-vul"
    dest_dir = repositories_dir / f"{project}_{local_id}"

    # *** WICHTIG: Skip-Check VOR dem mkdir, sonst würde der Ordner immer existieren. ***
    if skip_existing and dest_dir.exists():
        msg = f"Skipped (target folder already exists): {dest_dir}"
        LOG.info(msg)
        return project, local_id, True, msg

    if dry_run:
        msg = f"DRY-RUN: Would process {image_tag} -> {dest_dir} (incl. 'arvo compile' & /work)"
        LOG.info(msg)
        return project, local_id, True, msg

    # Ordner jetzt erst erstellen
    dest_dir.mkdir(parents=True, exist_ok=True)

    # Pull (idempotent)
    try:
        _run(["docker", "pull", image_tag])
    except subprocess.CalledProcessError as e:
        msg = f"Pull failed ({image_tag}): {e}"
        LOG.error(msg)
        return project, local_id, False, msg

    container_id = None
    copied_any = False
    errors: List[str] = []
    try:
        # Container erstellen
        create_cp = _run(["docker", "create", image_tag], capture_output=True)
        container_id = create_cp.stdout.strip()
        if not container_id:
            msg = f"Could not create container for {image_tag}"
            LOG.error(msg)
            return project, local_id, False, msg

        # Container starten und 'arvo compile' ausführen
        try:
            _run(["docker", "start", container_id])
            # genau wie gefordert: "arvo compile"
            _run(["docker", "exec", container_id, "bash", "-lc", "arvo compile"])
            LOG.info("%s: 'arvo compile' executed successfully", image_tag)
        except subprocess.CalledProcessError as e:
            err = f"'arvo compile' failed: {e}"
            LOG.warning("%s: %s", image_tag, err)
            errors.append(err)
            # Wir versuchen dennoch zu kopieren – /work könnte existieren.

        # Zielpfade kopieren (nur fehlende/leer)
        src_paths = [f"/src/{project}", "/usr/include", "/work"]
        for sp in src_paths:
            name, copied, err = _copy_if_missing(container_id, sp, dest_dir)
            copied_any = copied_any or copied
            if err:
                errors.append(f"{sp}: {err}")

        # Marker schreiben (nur informativ; NICHT mehr für Skip-Logik genutzt)
        payload = {
            "image_tag": image_tag,
            "image_id": _image_id(image_tag),
            "project": project,
            "local_id": local_id,
            "timestamp": int(time.time()),
            "paths": {
                project: _dir_nonempty(dest_dir / project),
                "include": _dir_nonempty(dest_dir / "include"),
                "work": _dir_nonempty(dest_dir / "work"),
            },
        }
        payload["completed"] = all(payload["paths"].values())
        _write_marker(dest_dir, payload)

        if errors and not payload["completed"]:
            msg = f"Partially copied/compiled, missing/errors: {', '.join(errors)}"
            LOG.warning(msg)
            return project, local_id, False, msg

        msg = "Copied (nothing to do)" if not copied_any else "Copied (new/supplemented)"
        LOG.info("%s: %s", image_tag, msg)
        return project, local_id, True, msg

    finally:
        if container_id:
            # sauber stoppen, dann entfernen
            try:
                _run(["docker", "stop", container_id], check=False)
            except subprocess.CalledProcessError:
                LOG.debug("Container stop failed: %s", container_id)
            try:
                _run(["docker", "rm", container_id])
            except subprocess.CalledProcessError:
                LOG.debug("Container remove failed: %s", container_id)
        if remove_image:
            try:
                _run(["docker", "rmi", "-f", image_tag])
            except subprocess.CalledProcessError:
                LOG.debug("Image remove failed: %s", image_tag)


def process_arvo_projects(
    arvo_dir: Path,
    repositories_dir: Path,
    *,
    dry_run: bool = False,
    stop_after: int | None = None,
    workers: int = DEFAULT_MAX_WORKERS,
    skip_existing: bool = True,
    remove_image: bool = True,
) -> Dict[str, List[int]]:
    """Process all projects in parallel.

    Args:
        arvo_dir: Directory with <project>.json files.
        repositories_dir: Base output directory.
        dry_run: Only display, do not execute.
        stop_after: Optionally limit the number of (project,localID) pairs (Debug / Test).
        workers: Number of parallel threads (IO-bound; Default based on CPU).
        skip_existing: **NEU** – Überspringe Paare, wenn der Zielordner bereits existiert.
        remove_image: After processing, run 'docker rmi -f' for the respective image.

    Returns:
        Mapping projectname -> List of successfully processed localIDs.
    """
    processed: Dict[str, List[int]] = {}
    if not arvo_dir.is_dir():  # pragma: no cover
        raise FileNotFoundError(f"arvo_dir does not exist: {arvo_dir}")
    repositories_dir.mkdir(parents=True, exist_ok=True)

    json_files = sorted(p for p in arvo_dir.glob("*.json") if p.is_file())
    LOG.info("Found project JSONs: %d", len(json_files))

    # Aufgabenliste erstellen
    tasks: List[Tuple[str, int]] = []
    for json_file in json_files:
        project = json_file.stem
        local_ids = _collect_local_ids(json_file)
        if not local_ids:
            LOG.debug("No localIDs in %s", json_file.name)
            continue
        LOG.info("Project %s: %d localIDs", project, len(local_ids))
        for local_id in sorted(local_ids):
            tasks.append((project, local_id))

    if stop_after is not None:
        tasks = tasks[:stop_after]
        LOG.info("Stop-After activated: Processing only %d pairs", len(tasks))

    # Parallel verarbeiten
    futures = []
    processed = {proj: [] for proj in {t[0] for t in tasks}}
    if not tasks:
        return processed

    LOG.info("Starting parallel processing with %d worker threads ...", workers)
    with ThreadPoolExecutor(max_workers=max(1, int(workers))) as ex:
        for project, local_id in tasks:
            futures.append(
                ex.submit(
                    _process_one,
                    project,
                    local_id,
                    repositories_dir,
                    dry_run=dry_run,
                    skip_existing=skip_existing,
                    remove_image=remove_image,
                )
            )

        for fut in as_completed(futures):
            try:
                project, local_id, ok, msg = fut.result()
                if ok:
                    processed.setdefault(project, []).append(local_id)
                LOG.debug("Result %s_%s: %s", project, local_id, msg)
            except Exception as e:
                LOG.exception("Unexpected error in task: %s", e)

    return processed


def _configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="[%(asctime)s] %(levelname)s %(name)s: %(message)s",
    )


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Extract sources & includes from n132/arvo images (parallel & idempotent, incl. 'arvo compile' & /work)"
    )
    parser.add_argument("--arvo-dir", type=Path, default=Path("data/arvo-projects"), help="Path to arvo-project JSONs")
    parser.add_argument("--repositories", type=Path, default=Path("repositories"), help="Target base directory")
    parser.add_argument("--dry-run", action="store_true", help="Only display, do nothing")
    parser.add_argument("--stop-after", type=int, help="Limit number of processed pairs")
    parser.add_argument("--workers", type=int, default=DEFAULT_MAX_WORKERS, help="Number of parallel workers (threads)")
    parser.add_argument("--no-skip-existing", dest="skip_existing", action="store_false", help="DO NOT skip, even if target folder exists")
    parser.add_argument("--keep-images", dest="remove_image", action="store_false", help="Keep Docker images after processing")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    args = parser.parse_args(list(argv) if argv is not None else None)

    _configure_logging(args.verbose)
    try:
        summary = process_arvo_projects(
            args.arvo_dir,
            args.repositories,
            dry_run=args.dry_run,
            stop_after=args.stop_after,
            workers=args.workers,
            skip_existing=args.skip_existing,
            remove_image=args.remove_image,
        )
    except FileNotFoundError as e:
        LOG.error(str(e))
        return 2

    total = sum(len(v) for v in summary.values())
    LOG.info("Done. %d projects, %d (project,localID) pairs successful.", len(summary), total)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
