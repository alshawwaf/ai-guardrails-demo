import unittest
import os
import sys
import json
from datetime import datetime

import logging

# Use the same directory and file name the app reads (LOGS_DIR / LOG_FILENAME;
# tests/conftest.py points LOGS_DIR at a temp dir, standalone runs use ./logs).
logs_dir = os.environ.get('LOGS_DIR', 'logs')
log_file = os.path.join(logs_dir, os.environ.get('LOG_FILENAME', 'application.log'))

# Set test DB URL
db_file = os.path.join(os.path.abspath(logs_dir), 'test_logs.db')
db_path = db_file.replace('\\', '/')
os.environ['DATABASE_URL'] = f'sqlite:///{db_path}'

# Add parent dir to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def write_fixture_log():
    os.makedirs(logs_dir, exist_ok=True)
    with open(log_file, 'w') as f:
        f.write('2023-10-27 10:00:00\tTest Prompt 1\tSuccess\t{"breakdown": [{"detected": true, "detector_type": "moderated_content/crime"}]}\n')
        f.write('2023-10-27 10:05:00\tTest Prompt 2\tError\tSome error message\n')


# Create dummy log file
write_fixture_log()

# Under pytest another test module may have imported the app first; its
# import-time migration then ran before this fixture file existed.
APP_ALREADY_IMPORTED = 'app' in sys.modules

# Import app after setting env var and creating log file
from app import app, db, Log, migrate_logs_from_file

if not APP_ALREADY_IMPORTED:
    with app.app_context():
        IMPORT_TIME_ROWS = Log.query.count()


class TestMigration(unittest.TestCase):
    def setUp(self):
        self.app_context = app.app_context()
        self.app_context.push()
        if not APP_ALREADY_IMPORTED:
            # The import above performed the migration.
            self.assertEqual(IMPORT_TIME_ROWS, 2)
        # Other tests in the same pytest run may have imported the app earlier
        # or written rows since, so run the same contract on a clean table:
        # the fixture log file is rewritten and migrate_logs_from_file() ingests it.
        db.create_all()
        Log.query.delete()
        db.session.commit()
        write_fixture_log()
        migrate_logs_from_file()

    def tearDown(self):
        # Close logging handlers to release file lock
        logger = logging.getLogger()
        for handler in logger.handlers[:]:
            handler.close()
            logger.removeHandler(handler)

        db.session.remove()
        db.drop_all()
        db.engine.dispose()
        self.app_context.pop()
        # Clean up files
        if os.path.exists(db_file):
            os.remove(db_file)
        # We don't remove application.log here because other tests might need it or it's fine to leave empty
        # But for cleanliness:
        if os.path.exists(log_file):
            os.remove(log_file)

    def test_migration(self):
        # Check if logs are in DB
        logs = Log.query.all()
        self.assertEqual(len(logs), 2)

        # Verify first log
        log1 = Log.query.filter_by(prompt='Test Prompt 1').first()
        self.assertIsNotNone(log1)
        self.assertIn('crime', log1.attack_vectors)

        # Verify second log
        log2 = Log.query.filter_by(prompt='Test Prompt 2').first()
        self.assertIsNotNone(log2)
        self.assertEqual(log2.error, 'Some error message')

        # Verify file is truncated
        with open(log_file, 'r') as f:
            content = f.read()
        self.assertEqual(content, '')

if __name__ == '__main__':
    unittest.main()
