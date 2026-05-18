# SO Analyzer Desktop (Electron + FastAPI)

## 当前实现
- Electron 桌面端：选择 `.apk` / `.so` 文件，调用 FastAPI 进行分析。
- FastAPI 后端：
  - `GET /health`
  - `POST /analyze-so`：输入本地 `.so` 路径并分析
  - `POST /upload-apk`：上传 APK 后自动提取 `lib/**/*.so` 并分析
  - `GET /report/{apk_hash}`：读取分析报告
- 基础分析项：ELF 头、符号表、字符串、JNI 线索、关键字符串命中。

## 启动步骤
### 1) 启动后端
```bash
cd app/backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --host 127.0.0.1 --port 8000
```

### 2) 启动桌面端
```bash
cd app/frontend
npm install
npm start
```

## 说明
- 当前 MVP 的 APK 上传在 Electron 渲染层存在本地文件读取限制，推荐先使用 `.so` 路径分析验证主流程。
- 下一步可通过 Electron IPC 增加 `readFile` 能力，实现 APK 真正“一键上传分析”。
