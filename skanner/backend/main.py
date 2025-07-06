
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import logging
import subprocess
import json
import os
import shutil
import tempfile
import requests
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI()

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins (or specify your frontend URL, e.g., "http://localhost:3000")
    allow_credentials=True,
    allow_methods=["*"],  # Allow all methods (GET, POST, etc.)
    allow_headers=["*"],  # Allow all headers
)

# Pydantic models
class RepoURL(BaseModel):
    repo_url: str

class Secret(BaseModel):
    description: str
    file: str
    line: str
    secret: str

class ScanResponse(BaseModel):
    secrets: list
    scan_successful: bool
    error: str = None
    report_path: str = None

def validate_repo_url(repo_url: str) -> bool:
    """Validate repository URL format and existence."""
    try:
        if not repo_url.startswith(("https://github.com/", "git@github.com:")):
            return False

        if repo_url.startswith("https://github.com/"):
            parts = repo_url.strip("/").split("/")
            if len(parts) < 5:
                return False
            owner, repo = parts[-2], parts[-1]
        else:
            parts = repo_url.split(":")
            if len(parts) != 2:
                return False
            owner_repo = parts[1].rstrip(".git")
            owner, repo = owner_repo.split("/") if "/" in owner_repo else (None, None)

        api_url = f"https://api.github.com/repos/{owner}/{repo}"
        response = requests.head(api_url, timeout=10)
        return response.status_code == 200
    except Exception as e:
        logger.error(f"Validation error: {e}")
        return False

def run_gitleaks_with_file_output(repo_path: str, report_path: str) -> dict:
    """Run GitLeaks scan with output to file."""
    try:
        cmd = [
            "gitleaks",
            "detect",
            "--source", repo_path,
            "--report-path", report_path,
            "--report-format", "json",
            "--redact",
            "--no-git",
            "--verbose",
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,
        )

        # GitLeaks returns 0 when no leaks found, 1 when leaks found
        if result.returncode not in (0, 1):
            return {
                "success": False,
                "error": f"GitLeaks failed with error: {result.stderr}",
            }

        # Verify report file was created
        if not os.path.exists(report_path):
            return {
                "success": False,
                "error": "GitLeaks did not generate report file",
            }

        return {"success": True}

    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Scan timed out"}
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.post("/scan-secrets", response_model=ScanResponse)
async def scan_secrets(repo_data: RepoURL):
    """Scan endpoint that uses file output from GitLeaks."""
    repo_url = repo_data.repo_url.strip()
    logger.info(f"Scanning repository: {repo_url}")

    if not repo_url:
        raise HTTPException(status_code=400, detail="Repository URL required")

    if not validate_repo_url(repo_url):
        raise HTTPException(status_code=400, detail="Invalid repository URL")

    temp_dir = tempfile.mkdtemp(prefix="repo-scan-")
    report_path = os.path.join(temp_dir, "gitleaks_report.json")
    logger.info(f"Created temp dir: {temp_dir}, report will be at: {report_path}")

    try:
        # Clone repository
        clone_cmd = ["git", "clone", "--depth", "1", repo_url, temp_dir]
        clone_result = subprocess.run(
            clone_cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )

        if clone_result.returncode != 0:
            error_msg = f"Clone failed: {clone_result.stderr}"
            logger.error(error_msg)
            return ScanResponse(
                secrets=[],
                scan_successful=False,
                error=error_msg,
            )

        # Run scan with file output
        scan_result = run_gitleaks_with_file_output(temp_dir, report_path)

        if not scan_result["success"]:
            return ScanResponse(
                secrets=[],
                scan_successful=False,
                error=scan_result.get("error", "Scan failed"),
                report_path=None,
            )

        # Read and parse the report file
        try:
            with open(report_path, "r") as f:
                report_data = json.load(f)

            if not isinstance(report_data, list):
                report_data = [report_data] if report_data else []

            secrets = [
                Secret(
                    description=item.get("Description", "Unknown"),
                    file=item.get("File", "Unknown"),
                    line=str(item.get("StartLine", "Unknown")),
                    secret=item.get("Secret", "Redacted"),
                )
                for item in report_data
            ]

            return ScanResponse(
                secrets=secrets,
                scan_successful=True,
                report_path=report_path,
            )

        except json.JSONDecodeError as e:
            error_msg = f"Failed to parse report file: {e}"
            logger.error(error_msg)
            return ScanResponse(
                secrets=[],
                scan_successful=False,
                error=error_msg,
                report_path=report_path,
            )
        except Exception as e:
            error_msg = f"Error reading report: {e}"
            logger.error(error_msg)
            return ScanResponse(
                secrets=[],
                scan_successful=False,
                error=error_msg,
                report_path=report_path,
            )

    except Exception as e:
        logger.error(f"Scan error: {e}", exc_info=True)
        return ScanResponse(
            secrets=[],
            scan_successful=False,
            error=str(e),
        )
    finally:
        try:
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)
                logger.info(f"Cleaned up temp dir: {temp_dir}")
        except Exception as e:
            logger.error(f"Cleanup error: {e}")


# Serve static files (frontend)
app.mount("/", StaticFiles(directory="static", html=True), name="static")

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
