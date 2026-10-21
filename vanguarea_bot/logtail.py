"""Lecture incrémentale de fichiers de logs (gère la rotation)."""

from __future__ import annotations

import os
from pathlib import Path

MAX_READ = 20 * 1024 * 1024  # on ne lit jamais plus de 20 Mo par passage


def read_new_lines(path: Path, positions: dict) -> list[str]:
    """Retourne les lignes ajoutées depuis le dernier appel.

    ``positions`` est un dict persistant {chemin: {"inode": .., "offset": ..}}.
    Au premier passage on se place en fin de fichier pour ne pas rejouer l'historique.
    """
    key = str(path)
    try:
        st = os.stat(path)
    except OSError:
        positions.pop(key, None)
        return []

    pos = positions.get(key)
    if pos is None:
        positions[key] = {"inode": st.st_ino, "offset": st.st_size}
        return []

    offset = pos["offset"]
    if pos["inode"] != st.st_ino or st.st_size < offset:
        offset = 0  # fichier tourné ou tronqué
    if st.st_size - offset > MAX_READ:
        offset = st.st_size - MAX_READ

    with open(path, "rb") as fh:
        fh.seek(offset)
        data = fh.read(st.st_size - offset)
    # On ne consomme que les lignes complètes.
    end = data.rfind(b"\n")
    if end == -1:
        positions[key] = {"inode": st.st_ino, "offset": offset}
        return []
    positions[key] = {"inode": st.st_ino, "offset": offset + end + 1}
    return data[: end + 1].decode("utf-8", errors="replace").splitlines()
