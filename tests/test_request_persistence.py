import unittest
import os
import sys
import json
import logging
from datetime import datetime

# Set test DB URL (under LOGS_DIR, which tests/conftest.py points at a temp dir)
logs_dir = os.environ.get('LOGS_DIR', 'logs')
os.makedirs(logs_dir, exist_ok=True)
db_file = os.path.join(os.path.abspath(logs_dir), 'test_request_persistence.db')
db_path = db_file.replace('\\', '/')
os.environ['DATABASE_URL'] = f'sqlite:///{db_path}'

# Add parent dir to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, db, Log, save_log_to_db

class TestRequestPersistence(unittest.TestCase):
    def setUp(self):
        self.app_context = app.app_context()
        self.app_context.push()
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        db.engine.dispose()
        self.app_context.pop()
        if os.path.exists(db_file):
            try:
                os.remove(db_file)
            except PermissionError:
                pass

    def test_save_request(self):
        entry = {
            'id': 'test-uuid',
            'timestamp': '2023-10-27 12:00:00',
            'prompt': 'test prompt',
            'attack_vectors': [],
            'result': {'flagged': False},
            'request': {'messages': [{'role': 'user', 'content': 'test prompt'}]},
            'error': None
        }
        save_log_to_db(entry)

        log = Log.query.filter_by(uuid='test-uuid').first()
        self.assertIsNotNone(log)
        self.assertIsNotNone(log.request_json)
        self.assertEqual(log.request_json['messages'][0]['content'], 'test prompt')

        # Verify to_dict
        log_dict = log.to_dict()
        self.assertIn('request', log_dict)
        self.assertEqual(log_dict['request']['messages'][0]['content'], 'test prompt')

if __name__ == '__main__':
    unittest.main()
