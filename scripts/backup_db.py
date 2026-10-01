#!/usr/bin/env python3
"""
Database Backup Script for AI Guardrails Demo

This script creates a backup of the SQLite database with timestamp.

The database holds the saved Settings (API keys encrypted at rest; backups made
before the settings upgrade can hold them in plain text), so backups are
owner-only: the backups/ folder is created with mode 0700 and every backup file
with mode 0600. Existing backups are tightened to the same modes on each run.
(On Windows the modes are best effort; protect the folder with its ACL.)
"""

import os
import shutil
from datetime import datetime
from pathlib import Path

DIR_MODE = 0o700
FILE_MODE = 0o600


def _tighten(path, mode):
    """Set ``mode`` on ``path`` (best effort: some filesystems ignore it)."""
    try:
        os.chmod(path, mode)
    except OSError as exc:
        print(f"  Could not set mode {oct(mode)} on {path}: {exc.strerror or exc}")


def _copy_private(src, dst):
    """Copy ``src`` to a new file ``dst`` created with mode 0600 (never wider, even
    for a moment, and whatever the umask or the source's mode)."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    with open(src, "rb") as fin:
        fd = os.open(str(dst), flags, FILE_MODE)
        try:
            with os.fdopen(fd, "wb") as fout:
                shutil.copyfileobj(fin, fout)
        except BaseException:
            try:
                os.unlink(str(dst))   # no half-written backup
            except OSError:
                pass
            raise
    _tighten(dst, FILE_MODE)   # an umask cannot widen it, but be explicit
    stat = os.stat(src)
    os.utime(dst, (stat.st_atime, stat.st_mtime))


def backup_database():
    """Create a timestamped backup of the database."""
    # Paths
    db_path = Path("instance/demo_logs.db")
    backup_dir = Path("backups")

    # Create backup directory if it doesn't exist (owner-only)
    backup_dir.mkdir(mode=DIR_MODE, exist_ok=True)
    _tighten(backup_dir, DIR_MODE)

    # Generate backup filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_filename = f"demo_logs_backup_{timestamp}.db"
    backup_path = backup_dir / backup_filename

    try:
        if db_path.exists():
            _copy_private(db_path, backup_path)
            print(f"✓ Database backed up successfully to: {backup_path}")
            print(f"  Backup size: {backup_path.stat().st_size / 1024:.2f} KB")

            # Backups written by older versions of this script may be world-readable.
            for old in backup_dir.glob("demo_logs_backup_*.db"):
                _tighten(old, FILE_MODE)

            # Clean up old backups (keep last 10)
            cleanup_old_backups(backup_dir, keep=10)
        else:
            print(f"✗ Database not found at: {db_path}")
            return False
    except Exception as e:
        print(f"✗ Backup failed: {e}")
        return False

    return True


def cleanup_old_backups(backup_dir, keep=10):
    """Remove old backups, keeping only the specified number of most recent ones."""
    backups = sorted(
        backup_dir.glob("demo_logs_backup_*.db"),
        key=lambda x: x.stat().st_mtime,
        reverse=True,
    )

    if len(backups) > keep:
        for old_backup in backups[keep:]:
            old_backup.unlink()
            print(f"  Removed old backup: {old_backup.name}")


if __name__ == "__main__":
    print("AI Guardrails Demo - Database Backup")
    print("=" * 50)
    backup_database()
