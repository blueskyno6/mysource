from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from pathlib import Path
import hashlib
import json
import subprocess
import tempfile
import zipfile
import re

app = FastAPI(title="SO Analyzer MVP")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

WORK = Path("/tmp/so_analyzer")
WORK.mkdir(parents=True, exist_ok=True)


class AnalyzeRequest(BaseModel):
    so_path: str


def sha256_bytes(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()


def run_cmd(cmd: list[str]) -> str:
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
        return out[:50000]
    except Exception as e:
        return f"error: {e}"


def extract_jni_hints(symbol_text: str) -> list[str]:
    hints = []
    for line in symbol_text.splitlines():
        if " Java_" in line or "JNI_OnLoad" in line or "RegisterNatives" in line:
            hints.append(line.strip())
    return hints[:100]


def extract_key_strings(strings_text: str) -> list[str]:
    patterns = [r"https?://", r"AES|RSA|SHA", r"debug|root|frida|ptrace", r"token|key|sign"]
    rows = strings_text.splitlines()
    out = []
    for row in rows:
        if any(re.search(p, row, flags=re.IGNORECASE) for p in patterns):
            out.append(row.strip())
    return out[:200]


def analyze_so_file(so_file: Path) -> dict:
    readelf_header = run_cmd(["readelf", "-h", str(so_file)])
    symbols = run_cmd(["readelf", "-Ws", str(so_file)])
    strings_preview = run_cmd(["strings", "-n", "6", str(so_file)])
    jni_hints = extract_jni_hints(symbols)
    key_strings = extract_key_strings(strings_preview)
    return {
        "file": str(so_file),
        "size": so_file.stat().st_size,
        "sha256": sha256_bytes(so_file.read_bytes()),
        "readelf_header": readelf_header,
        "symbols": symbols,
        "strings_preview": strings_preview,
        "jni_hints": jni_hints,
        "key_strings": key_strings,
        "ai_summary": {
            "summary": "检测到 native 符号与字符串特征，建议结合 JNI 映射和动态 trace 做进一步确认。",
            "confidence": 0.58,
            "evidence": [
                f"JNI/注册相关命中 {len(jni_hints)} 条",
                f"关键字符串命中 {len(key_strings)} 条",
            ],
        },
    }


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/report/{apk_hash}")
def read_report(apk_hash: str):
    p = WORK / f"{apk_hash}.json"
    if not p.exists():
        raise HTTPException(status_code=404, detail="report not found")
    return json.loads(p.read_text())


@app.post("/upload-apk")
async def upload_apk(file: UploadFile = File(...)):
    if not file.filename.endswith(".apk"):
        raise HTTPException(status_code=400, detail="only .apk is allowed")

    data = await file.read()
    apk_hash = sha256_bytes(data)
    with tempfile.TemporaryDirectory() as td:
        apk_path = Path(td) / file.filename
        apk_path.write_bytes(data)
        out = Path(td) / "unzipped"
        with zipfile.ZipFile(apk_path, "r") as zf:
            zf.extractall(out)
        so_files = list(out.glob("lib/**/*.so"))
        results = [analyze_so_file(p) for p in so_files]

    report_obj = {"apk_hash": apk_hash, "so_count": len(results), "results": results}
    saved = WORK / f"{apk_hash}.json"
    saved.write_text(json.dumps(report_obj, ensure_ascii=False, indent=2))
    return {"apk_hash": apk_hash, "so_count": len(results), "report": str(saved)}


@app.post("/analyze-so")
def analyze_so(req: AnalyzeRequest):
    p = Path(req.so_path)
    if not p.exists():
        raise HTTPException(status_code=404, detail="so 文件不存在")
    if p.suffix != ".so":
        raise HTTPException(status_code=400, detail="only .so is allowed")
    return analyze_so_file(p)
