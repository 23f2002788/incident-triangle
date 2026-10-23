# GA5 Q4 Observable Incident Triage

## Run locally
```bash
python -m venv .venv
# Windows PowerShell:
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:OPENAI_API_KEY="your-key"
uvicorn main:app --host 0.0.0.0 --port 8000
```

Open http://127.0.0.1:8000/docs.

## Deploy
Push to GitHub and deploy as a Render Web Service. Set `OPENAI_API_KEY` in Render's environment settings. A persistent disk is configured in `render.yaml`.

## Important
This is a starter implementation, not a verified full-mark solution. Before using the grader, validate exact tool schemas and the assignment's expected receipt/trace behavior. Do not use real production secrets or logs.
