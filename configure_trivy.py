#!/usr/bin/env python3
"""
Automatically configure Trivy analyzer in Dependency-Track
"""
import os
import sys
import requests
import time
import subprocess
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("DEPENDENCY_TRACK_API_KEY")
BASE_URL = os.getenv("DEPENDENCY_TRACK_URL", "http://localhost:8081")

def wait_for_api():
    """Wait for Dependency-Track API to be ready"""
    print("[INFO] Waiting for Dependency-Track to start...")
    max_attempts = 30
    for attempt in range(max_attempts):
        try:
            response = requests.get(f"{BASE_URL}/api/version", timeout=2)
            if response.status_code == 200:
                version = response.json()
                print(f"[OK] Dependency-Track {version.get('version', 'unknown')} is ready")
                return True
        except requests.exceptions.RequestException:
            pass
        
        if attempt < max_attempts - 1:
            time.sleep(2)
    
    print("[ERROR] Timeout: Dependency-Track did not start")
    return False

def configure_trivy():
    """Configure Trivy analyzer"""
    if not API_KEY:
        print("[ERROR] DEPENDENCY_TRACK_API_KEY not defined in .env")
        return False
    
    headers = {
        "X-Api-Key": API_KEY,
        "Content-Type": "application/json"
    }
    
    # Trivy configuration properties
    properties = [
        {
            "groupName": "scanner",
            "propertyName": "trivy.enabled",
            "propertyValue": "true"
        },
        {
            "groupName": "scanner",
            "propertyName": "trivy.base.url",
            "propertyValue": "http://trivy-server:4954"
        },
        {
            "groupName": "scanner",
            "propertyName": "trivy.scanner.scanLibrary",
            "propertyValue": "true"
        },
        {
            "groupName": "scanner",
            "propertyName": "trivy.scanner.scanOs",
            "propertyValue": "true"
        }
    ]
    
    print("[INFO] Configuring Trivy analyzer...")
    
    success = True
    for prop in properties:
        try:
            response = requests.post(
                f"{BASE_URL}/api/v1/configProperty",
                headers=headers,
                json=prop,
                timeout=10
            )
            
            if response.status_code in [200, 201, 204]:
                print(f"[OK] {prop['propertyName']} = {prop['propertyValue']}")
            else:
                print(f"[ERROR] Failed for {prop['propertyName']} (HTTP {response.status_code})")
                success = False
                
        except requests.exceptions.RequestException as e:
            print(f"[ERROR] Error for {prop['propertyName']}: {e}")
            success = False
    
    if success:
        print("[INFO] Configuration:")
        print(f"  - Enabled: True")
        print(f"  - Base URL: http://trivy-server:4954")
        print(f"  - Library scanning: Enabled")
        print(f"  - OS scanning: Enabled")
    
    return success

def restart_apiserver():
    """Restart API server to apply configuration"""
    print("\n[INFO] Restarting API server to apply configuration...")
    try:
        result = subprocess.run(
            ["docker", "restart", "analyse-sbom-dtrack-apiserver-1"],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            print("[OK] Server restarted")
            print("[INFO] Waiting for restart (15 seconds)...")
            time.sleep(15)
            
            # Check if API is available again
            if wait_for_api():
                print("[OK] Server ready")
                return True
        else:
            print(f"[ERROR] Restart failed: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        print("[ERROR] Timeout during restart")
        return False
    except Exception as e:
        print(f"[ERROR] Error during restart: {e}")
        return False

def main():
    print("=== Automatic Trivy Configuration ===\n")
    
    # Wait for API to be ready
    if not wait_for_api():
        sys.exit(1)
    
    # Small pause to ensure everything is initialized
    time.sleep(2)
    
    # Configure Trivy
    if configure_trivy():
        # Restart to apply configuration
        if restart_apiserver():
            print("\n[OK] Configuration completed successfully")
            print("[INFO] Trivy analyzer is now active")
            print("[INFO] New uploaded SBOMs will be automatically analyzed")
            sys.exit(0)
        else:
            print("\n[WARNING] Configuration succeeded but restart failed")
            print("[INFO] Restart manually: docker restart analyse-sbom-dtrack-apiserver-1")
            sys.exit(1)
    else:
        print("\n[ERROR] Configuration failed")
        print("[INFO] You will need to configure Trivy manually via the web interface")
        sys.exit(1)

if __name__ == "__main__":
    main()
