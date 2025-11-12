#!/usr/bin/env python3
"""
Script de vérification rapide pour diagnostiquer les SBOMs
"""

import json
import sys
from pathlib import Path

def check_sbom(sbom_path):
    """Vérifie le contenu d'un SBOM et affiche un diagnostic"""
    
    if not Path(sbom_path).exists():
        print(f"❌ Fichier non trouvé: {sbom_path}")
        return False
    
    try:
        with open(sbom_path, 'r') as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"❌ Erreur JSON dans {sbom_path}: {e}")
        return False
    
    print(f"\n{'='*60}")
    print(f"📄 Analyse de: {Path(sbom_path).name}")
    print(f"{'='*60}")
    
    # Détecter le format (CycloneDX ou SPDX)
    is_cyclonedx = 'bomFormat' in data
    is_spdx = 'spdxVersion' in data
    
    if is_cyclonedx:
        bom_format = data.get('bomFormat', 'Unknown')
        spec_version = data.get('specVersion', 'Unknown')
        print(f"Format: {bom_format} {spec_version}")
        
        # Métadonnées CycloneDX
        metadata = data.get('metadata', {})
        component = metadata.get('component', {})
        print(f"Projet: {component.get('name', 'N/A')} v{component.get('version', 'N/A')}")
        
        # Composants CycloneDX
        components = data.get('components', [])
        count = len(components)
        
    elif is_spdx:
        spdx_version = data.get('spdxVersion', 'Unknown')
        print(f"Format: SPDX {spdx_version}")
        
        # Métadonnées SPDX
        doc_name = data.get('name', 'N/A')
        print(f"Projet: {doc_name}")
        
        # Packages SPDX (équivalent aux composants)
        components = data.get('packages', [])
        count = len(components)
        
    else:
        print(f"Format: Inconnu (ni CycloneDX ni SPDX)")
        return False
    
    if count == 0:
        print(f"\n❌ PROBLÈME: 0 composants détectés!")
        print(f"   → Dependency-Track n'aura rien à analyser")
        print(f"   → Aucune vulnérabilité ne sera détectée")
        print(f"\n💡 Solution:")
        print(f"   - Pour Android: Scanner l'APK/AAB après compilation")
        print(f"     ./gradlew assembleRelease")
        print(f"     syft app/build/outputs/apk/release/app-release.apk -o cyclonedx-json > sbom.json")
        print(f"   - Pour iOS: Scanner le Podfile.lock")
        print(f"     syft Podfile.lock -o cyclonedx-json > sbom.json")
        return False
    else:
        print(f"\n✅ {count} composants détectés")
    
    # Analyser les types de composants
    types = {}
    ecosystems = {}
    
    for comp in components:
        # CycloneDX utilise 'type', SPDX peut avoir des purls dans externalRefs
        comp_type = comp.get('type', 'package')
        types[comp_type] = types.get(comp_type, 0) + 1
        
        # Extraire l'écosystème depuis le purl
        purl = comp.get('purl', '')
        
        # Pour SPDX, chercher le purl dans externalRefs
        if not purl and 'externalRefs' in comp:
            for ref in comp.get('externalRefs', []):
                if ref.get('referenceType') == 'purl':
                    purl = ref.get('referenceLocator', '')
                    break
        
        if purl and purl.startswith('pkg:'):
            ecosystem = purl.split('/')[0].replace('pkg:', '')
            ecosystems[ecosystem] = ecosystems.get(ecosystem, 0) + 1
    
    print(f"\n📊 Types de composants:")
    for comp_type, count in sorted(types.items(), key=lambda x: x[1], reverse=True):
        print(f"   - {comp_type}: {count}")
    
    if ecosystems:
        print(f"\n🌍 Écosystèmes:")
        for eco, count in sorted(ecosystems.items(), key=lambda x: x[1], reverse=True):
            print(f"   - {eco}: {count}")
    
    # Afficher quelques exemples de composants
    print(f"\n📦 Exemples de composants (5 premiers):")
    for i, comp in enumerate(components[:5]):
        name = comp.get('name', 'N/A')
        # CycloneDX: version, SPDX: versionInfo
        version = comp.get('version') or comp.get('versionInfo', 'N/A')
        purl = comp.get('purl', '')
        
        # Pour SPDX, chercher le purl dans externalRefs
        if not purl and 'externalRefs' in comp:
            for ref in comp.get('externalRefs', []):
                if ref.get('referenceType') == 'purl':
                    purl = ref.get('referenceLocator', '')
                    break
        
        print(f"   {i+1}. {name} @ {version}")
        if purl:
            print(f"      {purl}")
    
    if count > 5:
        print(f"   ... et {count - 5} autres composants")
    
    print(f"\n{'='*60}")
    print(f"✅ Ce SBOM est valide et prêt pour Dependency-Track")
    print(f"{'='*60}\n")
    
    return True

def main():
    if len(sys.argv) < 2:
        print("Usage: python check_sbom.py <sbom_file> [sbom_file2 ...]")
        print("\nExemple:")
        print("  python check_sbom.py sbomAndroid.json")
        print("  python check_sbom.py sbomAndroid.json sbomiOS.json")
        sys.exit(1)
    
    all_valid = True
    
    for sbom_path in sys.argv[1:]:
        valid = check_sbom(sbom_path)
        if not valid:
            all_valid = False
    
    if not all_valid:
        print("\n⚠️  Certains SBOMs ont des problèmes - voir ci-dessus")
        print("📖 Consultez DIAGNOSTIC_ET_BONNES_PRATIQUES.md pour plus d'infos")
        sys.exit(1)
    else:
        print("\n✅ Tous les SBOMs sont valides!")
        print("🚀 Vous pouvez les uploader vers Dependency-Track")

if __name__ == "__main__":
    main()
