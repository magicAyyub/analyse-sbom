# CVE Speed

Analysez vos SBOM avec Dependency-Track et Trivy.

## 🚀 Démarrage rapide

```bash
# 1. Lancer Dependency-Track + Trivy
docker-compose up -d

# 2. Installer les dépendances Python
pip install -r requirements.txt
```

Interface web: http://localhost:8080

## 🔑 Configuration initiale

### 1. Créer une clé API
1. Ouvrez http://localhost:8080
2. Connectez-vous avec `admin` / `admin` puis **changez le mot de passe**
3. Allez dans **Administration** → **Access Management** → **Teams**
4. Cliquez sur l'équipe **"Administrators"**
5. Générez une clé API en cliquant sur le **+** à droite de "API Keys"
6. Copiez la clé (format: `odt_...`)

### 2. Activer Trivy (analyseur de vulnérabilités)
1. Allez dans **Administration** → **Analyzers** → **Trivy**
2. Configurez :
   - ✅ **Enable Trivy analyzer**
   - **Base URL**: `http://trivy-server:4954`
   - **API Token**: (laissez vide)
   - ✅ **Enable library scanning**
   - ✅ **Enable OS scanning**
3. Cliquez **Update**
4. Redémarrez: `docker restart analyse-sbom-dtrack-apiserver-1`

## 📤 Upload SBOM

```bash
python upload_sbom.py chemin/vers/sbom.json VOTRE_CLE_API
```

## 🔍 Vérifier un SBOM

```bash
python check_sbom.py sbom.json
```

## 🗑️ Supprimer un projet

```bash
python delete_project.py --list                # Lister tous les projets
python delete_project.py <project-uuid>        # Supprimer un projet
```

## 📦 Générer des SBOMs

### Android

```bash
# ❌ NE PAS FAIRE (génère un SBOM vide)
syft . -o cyclonedx-json > sbomAndroid.json

# ✅ À FAIRE (génère un SBOM avec les vraies dépendances)
./gradlew assembleDebug
syft app/build/outputs/apk/debug/app-debug.apk -o spdx-json > sbomAndroid.json
python check_sbom.py sbomAndroid.json
```

### iOS

```bash
# Méthode correcte (Podfile.lock présent)
syft Podfile.lock -o spdx-json > sbomiOS.json
python check_sbom.py sbomiOS.json
```

## 💡 Note importante

Scanner le répertoire racine (`.`) d'un projet Android/iOS **sans build** ne trouve aucune dépendance.

- Syft cherche des **artefacts analysables** (binaires, lockfiles, manifests)
- Pour **iOS**: `Podfile.lock` existe → Syft trouve les dépendances CocoaPods
- Pour **Android**: pas de lockfile standard Gradle → Syft ne trouve rien sans APK
- Scanner juste le code source (`.java`, `.kt`) sans build ne révèle pas les dépendances Maven/Gradle

## 🔒 Analyseurs de vulnérabilités

Ce projet utilise **Trivy** comme analyseur principal :
- ✅ 100% gratuit et open-source
- ✅ Aucun compte utilisateur requis
- ✅ Auto-hébergé (confidentialité des données)
- ✅ Excellente couverture : OS + bibliothèques (Maven, npm, PyPI, etc.)
- ✅ Pas de limite de requêtes


## Générer des SBOMs 

### Android

```bash
# ❌ NE PAS FAIRE (génère un SBOM vide)
syft . -o cyclonedx-json > sbomAndroid.json

# ✅ À FAIRE (génère un SBOM avec les vraies dépendances)
./gradlew assembleDebug
syft app/build/outputs/apk/debug/app-debug.apk -o spdx-json > sbomAndroid.json
python check_sbom.py sbomAndroid.json  
```

### iOS

```bash
# Méthode correcte (Podfile.lock présent)
syft Podfile.lock -o spdx-json > sbomiOS.json
```

## NB

Scanner le répertoire racine (`.`) d'un projet Android/iOS **sans build** ne trouve aucune dépendance.

- Syft cherche des **artefacts analysables** (binaires, lockfiles, manifests)
- Pour **iOS**: `Podfile.lock` existe → Syft trouve les dépendances CocoaPods 
- Pour **Android**: pas de lockfile standard Gradle dans le repo → Syft ne trouve rien 
- Scanner juste le code source (`.java`, `.kt`) sans build ne révèle pas les dépendances Maven/Gradle