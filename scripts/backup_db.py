#!/usr/bin/env python3
"""
Database Backup Script for AI Guardrails Demo

This script creates a backup of the SQLite database with timestamp.
"""

import os
import shutil
from datetime import datetime
from pathlib import Path


def backup_database():
    """Create a timestamped backup of the database."""
    # Paths
    db_path = Path("instance/demo_logs.db")
    backup_dir = Path("backups")

    # Create backup directory if it doesn't exist
    backup_dir.mkdir(exist_ok=True)

    # Generate backup filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_filename = f"demo_logs_backup_{timestamp}.db"
    backup_path = backup_dir / backup_filename

    try:
        if db_path.exists():
            shutil.copy2(db_path, backup_path)
            print(f"✓ Database backed up successfully to: {backup_path}")
            print(f"  Backup size: {backup_path.stat().st_size / 1024:.2f} KB")

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
