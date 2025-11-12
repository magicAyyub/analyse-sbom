#!/usr/bin/env python3
"""
Script to delete a Dependency-Track project by its UUID
Usage: python delete_project.py <project_uuid>
"""

import sys
import requests
import os
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

# Configuration
API_KEY = os.getenv("DEPENDENCY_TRACK_API_KEY")
API_URL = os.getenv("DEPENDENCY_TRACK_URL", "http://localhost:8081")

def list_projects():
    """List all projects"""
    response = requests.get(
        f"{API_URL}/api/v1/project",
        headers={"X-Api-Key": API_KEY}
    )
    
    if response.status_code == 200:
        projects = response.json()
        print("\nCurrent projects:\n")
        for i, project in enumerate(projects, 1):
            metrics = project.get('metrics', {})
            print(f"{i}. {project['name']}")
            print(f"   UUID: {project['uuid']}")
            print(f"   Components: {metrics.get('components', 0)}, "
                  f"Vulnerabilities: {metrics.get('vulnerabilities', 0)}\n")
        return projects
    else:
        print(f"[ERROR] Error retrieving projects: {response.status_code}")
        return []

def delete_project(uuid):
    """Delete a project by its UUID"""
    print(f"[INFO] Deleting project {uuid}...")
    response = requests.delete(
        f'{API_URL}/api/v1/project/{uuid}',
        headers={'X-Api-Key': API_KEY},
        timeout=10
    )
    if response.status_code == 204:
        print(f"[OK] Project {uuid} successfully deleted")
    else:
        print(f"[ERROR] Failed to delete project: {response.status_code}")

def main():
    if not API_KEY:
        print("[ERROR] DEPENDENCY_TRACK_API_KEY not defined in .env")
        sys.exit(1)

    if len(sys.argv) < 2:
        print("Usage:")
        print("  python delete_project.py --list           # List all projects")
        print("  python delete_project.py <uuid>           # Delete a project")
        sys.exit(1)
    
    if sys.argv[1] == "--list":
        list_projects()
    else:
        project_uuid = sys.argv[1]
        delete_project(project_uuid)

if __name__ == "__main__":
    main()
