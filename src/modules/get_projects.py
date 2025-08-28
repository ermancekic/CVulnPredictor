"""Utility to iterate all arvo-project JSON files, run their docker images, copy source & includes.

Für jedes JSON (Dateiname <projektname>.json) in data/arvo-projects werden alle localID Werte
gesammelt. Für jede localID wird das Docker Image "cr.cispa.de/d/n132/arvo:<localID>-vul" verarbeitet:

1. Zielordner repositories/<projektname>_<localID> wird erstellt.
2. Image wird (falls nötig) gepullt und ein Container erzeugt.
3. Aus dem Container werden die Pfade /src/<projektname> und /usr/include in den Zielordner kopiert.
4. Container wird entfernt und Image wieder gelöscht (konfigurierbar).
5. Idempotenz: Wenn bereits vollständig extrahiert wurde, wird das Paar übersprungen.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
import sys
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
DEFAULT_MAX_WORKERS = max(4, (os.cpu_count() or 8))  # IO-bound: eher mehr Threads


def _run(cmd: List[str], *, check: bool = True, capture_output: bool = False) -> subprocess.CompletedProcess:
    """Run a subprocess command with logging."""
    LOG.debug("Running command: %s", " ".join(cmd))
    return subprocess.run(cmd, check=check, capture_output=capture_output, text=True)


def _collect_local_ids(json_path: Path) -> Set[int]:
    with json_path.open("r") as f:
        try:
            data = _json_load(f)
        except Exception as e:  # pragma: no cover
            LOG.error("Fehler beim Lesen %s: %s", json_path.name, e)
            return set()
    if not isinstance(data, list):  # pragma: no cover
        LOG.warning("Unerwartetes JSON Format in %s (erwarte Liste)", json_path.name)
        return set()
    ids: Set[int] = set()
    for item in data:
        if isinstance(item, dict) and "localID" in item:
            try:
                ids.add(int(item["localID"]))
            except (TypeError, ValueError):  # pragma: no cover
                LOG.debug("Überspringe ungültige localID in %s: %r", json_path.name, item.get("localID"))
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


def _already_extracted(dest_dir: Path, project: str, require_both: bool = True) -> bool:
    """Bestimme, ob wir dieses Paar überspringen können."""
    marker = _read_marker(dest_dir)
    expected_src = dest_dir / project
    expected_inc = dest_dir / "include"
    src_ok = _dir_nonempty(expected_src)
    inc_ok = _dir_nonempty(expected_inc)

    # Wenn Marker "completed" ist, vertrauen wir ihm (schnellster Check)
    if marker and marker.get("completed") is True:
        return True

    # Fallback: Wenn beide (oder mind. einer) Pfade vorhanden sind
    if require_both:
        return src_ok and inc_ok
    return src_ok or inc_ok


def _image_id(image_tag: str) -> Optional[str]:
    try:
        cp = _run(["docker", "inspect", "--format", "{{.Id}}", image_tag], capture_output=True)
        image_id = cp.stdout.strip()
        return image_id or None
    except subprocess.CalledProcessError:
        return None


def _copy_if_missing(container_id: str, src_in_container: str, dest_dir: Path) -> Tuple[str, bool, Optional[str]]:
    """
    Kopiere Verzeichnis aus Container, falls im Ziel noch nicht vorhanden oder leer.
    Gibt (name_im_ziel, copied_bool, error_msg_or_None) zurück.
    """
    name = Path(src_in_container).name  # z.B. "<project>" oder "include"
    target = dest_dir / name
    if _dir_nonempty(target):
        LOG.debug("Ziel bereits vorhanden, überspringe Copy: %s", target)
        return name, False, None
    try:
        _run(["docker", "cp", f"{container_id}:{src_in_container}", str(dest_dir)])
        LOG.debug("Kopiert %s -> %s", src_in_container, dest_dir)
        return name, True, None
    except subprocess.CalledProcessError as e:
        LOG.warning("Pfad fehlt im Image: %s (%s)", src_in_container, e)
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
    Verarbeite ein (project, local_id) Paar.
    Rückgabe: (project, local_id, success, message)
    """
    image_tag = f"cr.cispa.de/d/n132/arvo:{local_id}-vul"
    dest_dir = repositories_dir / f"{project}_{local_id}"
    dest_dir.mkdir(parents=True, exist_ok=True)

    if skip_existing and _already_extracted(dest_dir, project, require_both=True):
        msg = f"Übersprungen (bereits extrahiert): {image_tag}"
        LOG.info(msg)
        return project, local_id, True, msg

    if dry_run:
        msg = f"DRY-RUN: Würde verarbeiten {image_tag} -> {dest_dir}"
        LOG.info(msg)
        return project, local_id, True, msg

    # Pull (idempotent)
    try:
        _run(["docker", "pull", image_tag])
    except subprocess.CalledProcessError as e:
        msg = f"Pull fehlgeschlagen ({image_tag}): {e}"
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
            msg = f"Konnte Container nicht erstellen für {image_tag}"
            LOG.error(msg)
            return project, local_id, False, msg

        # Ziele kopieren (nur fehlende)
        src_paths = [f"/src/{project}", "/usr/include"]
        for sp in src_paths:
            name, copied, err = _copy_if_missing(container_id, sp, dest_dir)
            copied_any = copied_any or copied
            if err:
                errors.append(f"{sp}: {err}")

        # Marker schreiben (completed nur, wenn beide Ziele vorhanden)
        payload = {
            "image_tag": image_tag,
            "image_id": _image_id(image_tag),
            "project": project,
            "local_id": local_id,
            "timestamp": int(time.time()),
            "paths": {
                project: _dir_nonempty(dest_dir / project),
                "include": _dir_nonempty(dest_dir / "include"),
            },
        }
        payload["completed"] = bool(payload["paths"][project] and payload["paths"]["include"])
        _write_marker(dest_dir, payload)

        if errors and not payload["completed"]:
            msg = f"Teilweise kopiert, fehlende Pfade: {', '.join(errors)}"
            LOG.warning(msg)
            return project, local_id, False, msg

        msg = "Kopiert (nichts zu tun)" if not copied_any else "Kopiert (neu/ergänzt)"
        LOG.info("%s: %s", image_tag, msg)
        return project, local_id, True, msg

    finally:
        if container_id:
            try:
                _run(["docker", "rm", container_id])
            except subprocess.CalledProcessError:
                LOG.debug("Container Remove fehlgeschlagen: %s", container_id)
        if remove_image:
            try:
                _run(["docker", "rmi", "-f", image_tag])
            except subprocess.CalledProcessError:
                LOG.debug("Image Entfernen fehlgeschlagen: %s", image_tag)


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
    """Verarbeite alle Projekte parallel.

    Args:
        arvo_dir: Verzeichnis mit <projekt>.json Dateien.
        repositories_dir: Basis-Ausgabeordner.
        dry_run: Nur anzeigen, nichts ausführen.
        stop_after: Optional Anzahl der (projekt,localID) Paare begrenzen (Debug / Test).
        workers: Anzahl paralleler Threads (IO-bound; Default basiert auf CPU).
        skip_existing: Bereits vollständig extrahierte Paare überspringen.
        remove_image: Nach Verarbeitung 'docker rmi -f' für das jeweilige Image ausführen.

    Returns:
        Mapping projektname -> Liste erfolgreich verarbeiteter localIDs.
    """
    processed: Dict[str, List[int]] = {}
    if not arvo_dir.is_dir():  # pragma: no cover
        raise FileNotFoundError(f"arvo_dir existiert nicht: {arvo_dir}")
    repositories_dir.mkdir(parents=True, exist_ok=True)

    json_files = sorted(p for p in arvo_dir.glob("*.json") if p.is_file())
    LOG.info("Gefundene Projekt JSONs: %d", len(json_files))

    # Aufgabenliste erstellen
    tasks: List[Tuple[str, int]] = []
    for json_file in json_files:
        project = json_file.stem
        local_ids = _collect_local_ids(json_file)
        if not local_ids:
            LOG.debug("Keine localIDs in %s", json_file.name)
            continue
        LOG.info("Projekt %s: %d localIDs", project, len(local_ids))
        for local_id in sorted(local_ids):
            tasks.append((project, local_id))

    if stop_after is not None:
        tasks = tasks[:stop_after]
        LOG.info("Stop-After aktiviert: Verarbeite nur %d Paare", len(tasks))

    # Parallel verarbeiten
    futures = []
    processed = {proj: [] for proj in {t[0] for t in tasks}}
    if not tasks:
        return processed

    LOG.info("Starte parallele Verarbeitung mit %d Worker-Threads ...", workers)
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
                LOG.debug("Ergebnis %s_%s: %s", project, local_id, msg)
            except Exception as e:
                LOG.exception("Unerwarteter Fehler bei Task: %s", e)

    return processed


def _configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="[%(asctime)s] %(levelname)s %(name)s: %(message)s",
    )


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Extrahiere Quellen & Includes aus n132/arvo Images (parallel & idempotent)")
    parser.add_argument("--arvo-dir", type=Path, default=Path("data/arvo-projects"), help="Pfad zu arvo-project JSONs")
    parser.add_argument("--repositories", type=Path, default=Path("repositories"), help="Zielbasisordner")
    parser.add_argument("--dry-run", action="store_true", help="Nur anzeigen, nichts ausführen")
    parser.add_argument("--stop-after", type=int, help="Begrenze Anzahl verarbeiteter Paare")
    parser.add_argument("--workers", type=int, default=DEFAULT_MAX_WORKERS, help="Anzahl paralleler Worker (Threads)")
    parser.add_argument("--no-skip-existing", dest="skip_existing", action="store_false", help="NICHT überspringen, auch wenn bereits extrahiert")
    parser.add_argument("--keep-images", dest="remove_image", action="store_false", help="Docker Images nach Verarbeitung behalten")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose Logging")
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
    LOG.info("Fertig. %d Projekte, %d (projekt,localID) Paare erfolgreich.", len(summary), total)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
