#!/usr/bin/env python3
"""
Script pour supprimer un projet Dependency-Track par son UUID
Usage: python delete_project.py <project_uuid>
"""

import sys
import requests
import os

# Configuration
API_KEY = os.getenv("DEPENDENCY_TRACK_API_KEY", "odt_AfwXiC3Z_UWHdg8Vl7sU3yOt7ORkat9pQJr0hxp9w")
API_URL = os.getenv("DEPENDENCY_TRACK_URL", "http://localhost:8081")

def list_projects():
    """Liste tous les projets"""
    response = requests.get(
        f"{API_URL}/api/v1/project",
        headers={"X-API-Key": API_KEY}
    )
    
    if response.status_code == 200:
        projects = response.json()
        print("\n📋 Projets actuels:\n")
        for i, project in enumerate(projects, 1):
            metrics = project.get('metrics', {})
            print(f"{i}. {project['name']}")
            print(f"   UUID: {project['uuid']}")
            print(f"   Composants: {metrics.get('components', 0)}, "
                  f"Vulnérabilités: {metrics.get('vulnerabilities', 0)}\n")
        return projects
    else:
        print(f"❌ Erreur lors de la récupération des projets: {response.status_code}")
        return []

def delete_project(uuid):
    """Supprime un projet par son UUID"""
    response = requests.delete(
        f"{API_URL}/api/v1/project/{uuid}",
        headers={"X-API-Key": API_KEY}
    )
    
    if response.status_code == 204:
        print(f"✅ Projet {uuid} supprimé avec succès")
        return True
    else:
        print(f"❌ Erreur lors de la suppression: HTTP {response.status_code}")
        print(response.text)
        return False

def main():
    if len(sys.argv) < 2:
        print("Usage: python delete_project.py <project_uuid>")
        print("       python delete_project.py --list")
        print("\nOu utilisez --list pour voir tous les projets")
        sys.exit(1)
    
    if sys.argv[1] == "--list":
        list_projects()
    else:
        uuid = sys.argv[1]
        print(f"🗑️  Suppression du projet {uuid}...")
        delete_project(uuid)

if __name__ == "__main__":
    main()
