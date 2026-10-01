import os

import pytest
import requests

# Live-server test: it talks to a running app over HTTP. It is skipped
# automatically unless that server answers /health. Override the address with
# EXPORTS_BASE_URL. The export endpoints require sign-in; to exercise them,
# export EXPORTS_ADMIN_EMAIL / EXPORTS_ADMIN_PASSWORD for that server.
BASE_URL = os.environ.get("EXPORTS_BASE_URL", "http://127.0.0.1:5000").rstrip("/")


def _server_is_up(base_url):
    try:
        r = requests.get(f"{base_url}/health", timeout=1)
        return r.status_code == 200 and r.json().get("status") == "healthy"
    except (requests.RequestException, ValueError):
        return False


pytestmark = pytest.mark.skipif(
    not _server_is_up(BASE_URL),
    reason=f"no AI Guardrails demo server answering {BASE_URL}/health",
)


def test_export_headers():
    base_url = BASE_URL
    session = requests.Session()
    email = os.environ.get("EXPORTS_ADMIN_EMAIL")
    password = os.environ.get("EXPORTS_ADMIN_PASSWORD")
    if email and password:
        session.post(
            f"{base_url}/login",
            data={"email": email, "password": password},
            headers={"Origin": base_url},
            timeout=10,
            allow_redirects=False,
        )

    # Test JSON Export
    try:
        r_json = session.get(f"{base_url}/api/logs/export/json", timeout=10)
        print(f"JSON Status: {r_json.status_code}")
        print(f"JSON Content-Disposition: {r_json.headers.get('Content-Disposition')}")
        if "filename=" in r_json.headers.get('Content-Disposition', '') and ".json" in r_json.headers.get('Content-Disposition', ''):
            print("JSON Export Header: PASS")
        else:
            print("JSON Export Header: FAIL")
    except Exception as e:
        print(f"JSON Export Error: {e}")

    # Test CSV Export
    try:
        r_csv = session.get(f"{base_url}/api/logs/export/csv", timeout=10)
        print(f"CSV Status: {r_csv.status_code}")
        print(f"CSV Content-Disposition: {r_csv.headers.get('Content-Disposition')}")
        if "filename=" in r_csv.headers.get('Content-Disposition', '') and ".csv" in r_csv.headers.get('Content-Disposition', ''):
            print("CSV Export Header: PASS")
        else:
            print("CSV Export Header: FAIL")
    except Exception as e:
        print(f"CSV Export Error: {e}")

if __name__ == "__main__":
    test_export_headers()
