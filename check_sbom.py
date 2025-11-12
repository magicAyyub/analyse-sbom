#!/usr/bin/env python3
"""
Quick verification script for SBOM diagnostics
"""

import json
import sys
from pathlib import Path

def check_sbom(sbom_path):
    """Checks SBOM content and displays diagnostics"""
    
    if not Path(sbom_path).exists():
        print(f"[ERROR] File not found: {sbom_path}")
        return False
    
    try:
        with open(sbom_path, 'r') as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"[ERROR] JSON error in {sbom_path}: {e}")
        return False
    
    print(f"\n{'='*60}")
    print(f"Analyzing: {Path(sbom_path).name}")
    print(f"{'='*60}")
    
    # Detect format (CycloneDX or SPDX)
    is_cyclonedx = 'bomFormat' in data
    is_spdx = 'spdxVersion' in data
    
    if is_cyclonedx:
        bom_format = data.get('bomFormat', 'Unknown')
        spec_version = data.get('specVersion', 'Unknown')
        print(f"Format: {bom_format} {spec_version}")
        
        # CycloneDX metadata
        metadata = data.get('metadata', {})
        component = metadata.get('component', {})
        print(f"Project: {component.get('name', 'N/A')} v{component.get('version', 'N/A')}")
        
        # CycloneDX components
        components = data.get('components', [])
        count = len(components)
        
    elif is_spdx:
        print(f"\n[ERROR] SPDX format detected - NOT SUPPORTED")
        print(f"[ERROR] Dependency-Track requires CycloneDX format")
        print(f"\n[INFO] Solution: Regenerate SBOM with '-o cyclonedx-json'")
        print(f"   Example: syft <target> -o cyclonedx-json > sbom.json")
        return False
        
    else:
        print(f"Format: Unknown (neither CycloneDX nor SPDX)")
        return False
    
    if count == 0:
        print(f"\n[ERROR] PROBLEM: 0 components detected!")
        print(f"   -> Dependency-Track will have nothing to analyze")
        print(f"   -> No vulnerabilities will be detected")
        print(f"\n[INFO] Solution:")
        print(f"   - For Android: Scan the APK/AAB after compilation")
        print(f"     ./gradlew assembleRelease")
        print(f"     syft app/build/outputs/apk/release/app-release.apk -o cyclonedx-json > sbom.json")
        print(f"   - For iOS: Scan the Podfile.lock")
        print(f"     syft Podfile.lock -o cyclonedx-json > sbom.json")
        return False
    else:
        print(f"\n[OK] {count} components detected")
    
    # Analyze component types
    types = {}
    ecosystems = {}
    
    for comp in components:
        # CycloneDX uses 'type', SPDX may have purls in externalRefs
        comp_type = comp.get('type', 'package')
        types[comp_type] = types.get(comp_type, 0) + 1
        
        # Extract ecosystem from purl
        purl = comp.get('purl', '')
        
        # For SPDX, search for purl in externalRefs
        if not purl and 'externalRefs' in comp:
            for ref in comp.get('externalRefs', []):
                if ref.get('referenceType') == 'purl':
                    purl = ref.get('referenceLocator', '')
                    break
        
        if purl and purl.startswith('pkg:'):
            ecosystem = purl.split('/')[0].replace('pkg:', '')
            ecosystems[ecosystem] = ecosystems.get(ecosystem, 0) + 1
    
    print(f"\nComponent types:")
    for comp_type, count in sorted(types.items(), key=lambda x: x[1], reverse=True):
        print(f"   - {comp_type}: {count}")
    
    if ecosystems:
        print(f"\nEcosystems:")
        for eco, count in sorted(ecosystems.items(), key=lambda x: x[1], reverse=True):
            print(f"   - {eco}: {count}")
    
    # Display some component examples
    print(f"\nComponent examples (first 5):")
    for i, comp in enumerate(components[:5]):
        name = comp.get('name', 'N/A')
        # CycloneDX: version, SPDX: versionInfo
        version = comp.get('version') or comp.get('versionInfo', 'N/A')
        purl = comp.get('purl', '')
        
        # For SPDX, search for purl in externalRefs
        if not purl and 'externalRefs' in comp:
            for ref in comp.get('externalRefs', []):
                if ref.get('referenceType') == 'purl':
                    purl = ref.get('referenceLocator', '')
                    break
        
        print(f"   {i+1}. {name} @ {version}")
        if purl:
            print(f"      {purl}")
    
    if count > 5:
        print(f"   ... and {count - 5} other components")
    
    print(f"\n{'='*60}")
    print(f"[OK] This SBOM is valid and ready for Dependency-Track")
    print(f"{'='*60}\n")
    
    return True

def main():
    if len(sys.argv) < 2:
        print("Usage: python check_sbom.py <sbom_file> [sbom_file2 ...]")
        print("\nExample:")
        print("  python check_sbom.py sbomAndroid.json")
        print("  python check_sbom.py sbomAndroid.json sbomiOS.json")
        sys.exit(1)
    
    all_valid = True
    
    for sbom_path in sys.argv[1:]:
        valid = check_sbom(sbom_path)
        if not valid:
            all_valid = False
    
    if not all_valid:
        print("\n[WARNING] Some SBOMs have issues - see above")
        sys.exit(1)
    else:
        print("\n[OK] All SBOMs are valid!")
        print("[INFO] You can upload them to Dependency-Track")

if __name__ == "__main__":
    main()
