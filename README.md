# CVE Speed

Analyze your SBOMs with Dependency-Track and Trivy.

## Quick Start

```bash
docker-compose up -d

pip install -r requirements.txt
```

Web interface: http://localhost:8080

## Initial Configuration

### 1. Create an API Key
1. Open http://localhost:8080
2. Login with `admin` / `admin` then **change the password**
3. Go to **Administration** → **Access Management** → **Teams**
4. Click on the **"Administrators"** team
5. Generate an API key by clicking the **+** on the right of "API Keys"
6. Copy the key (format: `odt_...`)

### 2. Configure the .env file

Copy the `.env.example` file as a template:

```bash
cp .env.example .env
```

Edit the `.env` file and configure:
```
DEPENDENCY_TRACK_API_KEY=odt_YOUR_API_KEY_HERE
DEPENDENCY_TRACK_URL=http://localhost:8081
```

[WARNING] **NEVER commit the `.env` file to git** (it's already in `.gitignore`)

### 3. Enable Trivy (vulnerability analyzer)

**Automatic method (recommended)**:
```bash
python3 configure_trivy.py
```

**Manual method** (if the script fails):
1. Go to **Administration** → **Analyzers** → **Trivy**
2. Configure:
   - [x] **Enable Trivy analyzer**
   - **Base URL**: `http://trivy-server:4954`
   - **API Token**: (leave empty)
   - [x] **Enable library scanning**
   - [x] **Enable OS scanning**
3. Click **Update**

## Upload SBOM

```bash
python upload_sbom.py path/to/sbom.json
```

The API key and URL are automatically loaded from the `.env` file.

**Note**: Use the **CycloneDX** format for your SBOMs (better compatibility with Dependency-Track)

## Verify an SBOM

```bash
python check_sbom.py sbom.json
```

## Delete a Project

```bash
python delete_project.py --list                # List all projects
python delete_project.py <project-uuid>        # Delete a project
```

## Generate SBOMs

Use the **CycloneDX** format (recommended):

### Android
```bash
./gradlew assembleDebug
syft app/build/outputs/apk/debug/app-debug.apk -o cyclonedx-json > sbomAndroid.json
```

### iOS
```bash
syft Podfile.lock -o cyclonedx-json > sbomiOS.json
```