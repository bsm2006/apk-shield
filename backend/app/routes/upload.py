import os
import hashlib
import logging
import shutil
from pathlib import Path
from fastapi import APIRouter, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)
router = APIRouter()

UPLOAD_DIR = "uploads"
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB
ALLOWED_EXTENSIONS = {".apk", ".xapk"}

os.makedirs(UPLOAD_DIR, exist_ok=True)


@router.post("/")
async def upload_apk(file: UploadFile = File(...)):
    """Upload an APK file for analysis."""

    # Validate file extension
    filename = file.filename or "unknown.apk"
    ext = Path(filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file type '{ext}'. Only APK files are accepted.",
        )

    # Read file content
    content = await file.read()
    file_size = len(content)

    if file_size == 0:
        raise HTTPException(status_code=400, detail="File is empty.")

    if file_size > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=400,
            detail=f"File too large ({file_size / 1024 / 1024:.1f} MB). Maximum allowed: 100 MB.",
        )

    # Compute hash
    file_hash = hashlib.sha256(content).hexdigest()

    # Save file
    safe_filename = f"{file_hash[:16]}_{Path(filename).stem[:30]}{ext}"
    save_path = os.path.join(UPLOAD_DIR, safe_filename)

    with open(save_path, "wb") as f:
        f.write(content)

    logger.info(f"File uploaded: {filename} ({file_size} bytes, hash: {file_hash[:16]}...)")

    return {
        "message": "File uploaded successfully",
        "file_id": file_hash,
        "filename": filename,
        "saved_as": safe_filename,
        "file_size": file_size,
        "file_hash": file_hash,
        "upload_path": save_path,
    }
