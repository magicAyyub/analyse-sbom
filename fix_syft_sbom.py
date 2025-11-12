#!/usr/bin/env python3
"""
Script pour corriger les SBOMs générés par Syft afin qu'ils soient mieux reconnus par Dependency-Track.
Le problème principal est que les SBOMs Syft ont un metadata.component minimal qui fait que 
Dependency-Track les classe comme "file" au lieu de "application" ou "library".
"""

import json
import sys
import argparse
from pathlib import Path


def fix_syft_sbom(input_file, output_file=None, project_name=None, project_version=None):
    """
    Corrige un SBOM généré par Syft pour qu'il soit mieux reconnu par Dependency-Track.
    
    Args:
        input_file: Chemin vers le fichier SBOM à corriger
        output_file: Chemin vers le fichier de sortie (optionnel)
        project_name: Nom du projet (optionnel, déduit du fichier sinon)
        project_version: Version du projet (optionnel, utilise "1.0.0" par défaut)
    """
    # Lire le SBOM
    with open(input_file, 'r', encoding='utf-8') as f:
        sbom = json.load(f)
    
    # Déduire le nom du projet si non fourni
    if not project_name:
        project_name = Path(input_file).stem.replace('sbom', '').replace('_', ' ').strip()
        if not project_name:
            project_name = "iOS Application"
    
    # Utiliser une version par défaut si non fournie
    if not project_version:
        project_version = "1.0.0"
    
    # Améliorer le metadata.component
    if 'metadata' not in sbom:
        sbom['metadata'] = {}
    
    # Conserver les outils existants
    existing_tools = sbom['metadata'].get('tools', {})
    
    # Créer un composant principal amélioré
    sbom['metadata']['component'] = {
        "type": "application",
        "name": project_name,
        "version": project_version,
        "bom-ref": sbom.get('metadata', {}).get('component', {}).get('bom-ref', 'root-component')
    }
    
    # Ajouter des métadonnées supplémentaires si disponibles
    if 'components' in sbom and sbom['components']:
        # Compter les dépendances par langage
        languages = {}
        for component in sbom['components']:
            props = component.get('properties', [])
            for prop in props:
                if prop.get('name') == 'syft:package:language':
                    lang = prop.get('value', 'unknown')
                    languages[lang] = languages.get(lang, 0) + 1
        
        # Ajouter des propriétés au composant principal
        if 'properties' not in sbom['metadata']['component']:
            sbom['metadata']['component']['properties'] = []
        
        # Ajouter les langages détectés
        for lang, count in languages.items():
            sbom['metadata']['component']['properties'].append({
                "name": f"cdx:ecosystem:{lang}",
                "value": f"{count} components"
            })
    
    # Ajouter des informations de dépendances si elles n'existent pas
    if 'dependencies' not in sbom and 'components' in sbom:
        dependencies = []
        
        # Ajouter une dépendance racine qui référence tous les composants
        root_deps = []
        for component in sbom['components']:
            if 'bom-ref' in component:
                root_deps.append(component['bom-ref'])
        
        dependencies.append({
            "ref": sbom['metadata']['component']['bom-ref'],
            "dependsOn": root_deps
        })
        
        sbom['dependencies'] = dependencies
    
    # Formater le JSON de manière lisible
    output_json = json.dumps(sbom, indent=2, ensure_ascii=False)
    
    # Déterminer le fichier de sortie
    if not output_file:
        base_path = Path(input_file)
        output_file = base_path.parent / f"{base_path.stem}_fixed{base_path.suffix}"
    
    # Écrire le SBOM corrigé
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(output_json)
    
    print(f"SBOM corrigé créé : {output_file}")
    print(f"   Nom du projet : {project_name}")
    print(f"   Version : {project_version}")
    print(f"   Composants : {len(sbom.get('components', []))}")
    
    return output_file


def main():
    parser = argparse.ArgumentParser(
        description='Corriger les SBOMs générés par Syft pour Dependency-Track',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples:
  # Corriger un SBOM avec détection automatique du nom
  python fix_syft_sbom.py sbomiOS.json
  
  # Corriger avec un nom et version personnalisés
  python fix_syft_sbom.py sbomiOS.json -n "My iOS App" -v "2.1.0"
  
  # Spécifier le fichier de sortie
  python fix_syft_sbom.py sbomiOS.json -o sbomiOS_corrected.json
        """
    )
    
    parser.add_argument('input', help='Fichier SBOM à corriger')
    parser.add_argument('-o', '--output', help='Fichier de sortie (optionnel)')
    parser.add_argument('-n', '--name', help='Nom du projet')
    parser.add_argument('-v', '--version', default='1.0.0', help='Version du projet (défaut: 1.0.0)')
    
    args = parser.parse_args()
    
    try:
        fix_syft_sbom(
            input_file=args.input,
            output_file=args.output,
            project_name=args.name,
            project_version=args.version
        )
    except FileNotFoundError:
        print(f"Erreur : Le fichier '{args.input}' n'existe pas.", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"Erreur : Le fichier '{args.input}' n'est pas un JSON valide.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Erreur : {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
