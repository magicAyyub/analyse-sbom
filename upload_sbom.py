#!/usr/bin/env python3
"""
Upload SBOM to Dependency-Track
"""

import requests
import sys
import os
from pathlib import Path

def upload_sbom(sbom_path, api_key=None, server_url='http://localhost:8081'):
    if not Path(sbom_path).exists():
        print(f"File not found: {sbom_path}")
        return False

    url = f"{server_url}/api/v1/bom"

    headers = {}
    if api_key:
        headers['X-API-Key'] = api_key
    project_name = Path(sbom_path).stem
    data = {
        'projectName': project_name,
        'projectVersion': '1.0',
        'autoCreate': 'true'
    }

    # Use context manager to ensure file is closed
    try:
        with open(sbom_path, 'rb') as bom_file:
            files = {'bom': bom_file}
            response = requests.post(url, headers=headers, data=data, files=files)

        # Print status and body for better debugging (Dependency-Track returns import details)
        print(f"HTTP {response.status_code}")
        # Try to pretty-print JSON response when possible
        try:
            json_resp = response.json()
            import json as _json
            print(_json.dumps(json_resp, indent=2, ensure_ascii=False))
        except Exception:
            print(response.text)

        if response.status_code == 200:
            print("SBOM uploaded successfully")
            return True
        else:
            if response.status_code == 401:
                print("Erreur 401: Vérifiez que la clé API est correcte et que l'équipe a les permissions BOM_UPLOAD")
            return False
    except Exception as e:
        print(f"Error: {str(e)}")
        return False

def main():
    if len(sys.argv) < 2:
        print("Usage: python upload_sbom.py <sbom_file> [api_key]")
        sys.exit(1)

    sbom_path = sys.argv[1]

    # Allow API key and server url to be provided via args or environment variables
    api_key = sys.argv[2] if len(sys.argv) > 2 else os.environ.get('DEPENDENCY_TRACK_API_KEY')
    server_url = os.environ.get('DEPENDENCY_TRACK_URL', 'http://localhost:8081')

    success = upload_sbom(sbom_path, api_key=api_key, server_url=server_url)

    if not success:
        sys.exit(1)

if __name__ == "__main__":
    main()