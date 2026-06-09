# Hybrid IDS - Simplified Beginner-Friendly Version

This is a cleaner and easier-to-understand version of the Hybrid Intrusion Detection System project.

It keeps the same main idea:

```text
Packet -> Signature Engine -> ML Engine -> Database -> Dashboard
```

## What is simplified?

The code is rewritten with:

- easier function names
- smaller files
- clear comments
- one simple project flow
- same API routes expected by the frontend

## What is kept the same?

The project still keeps:

- Signature-based detection
- PKNN engine
- OSVM engine
- Probability fusion between PKNN and OSVM
- Synthetic CICIDS-style training dataset logic
- SQLite database
- FastAPI backend
- Frontend dashboard
- Mock JSON fallback files

## Folder Structure

```text
hybrid_ids_simple/
├── backend/
│   ├── main.py
│   ├── requirements.txt
│   ├── modules/
│   ├── routers/
│   └── data/
│       ├── signatures.json
│       ├── ids.db
│       └── models/
│           ├── pknn.pkl
│           ├── svm.pkl
│           └── meta.pkl
│
└── frontend/
    ├── index.html
    ├── style.css
    ├── app.js
    ├── api.js
    └── mock-data/
```

## How to Run Backend

Open terminal in the backend folder:

```bash
cd backend
python -m venv venv
```

Activate venv:

Windows:

```bash
venv\Scripts\activate
```

Mac/Linux:

```bash
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Start backend:

```bash
uvicorn main:app --reload --host 0.0.0.0 --port 5000
```

Backend will run at:

```text
http://localhost:5000
```

API docs:

```text
http://localhost:5000/docs
```

## How to Run Frontend

Open another terminal in the frontend folder:

```bash
cd frontend
python -m http.server 5500
```

Open in browser:

```text
http://localhost:5500
```

## Simple Logic Explanation

### 1. Frontend

The dashboard asks backend for:

- stats
- alerts
- logs
- traffic chart data

### 2. Backend

The backend receives requests and calls the correct router.

### 3. Decision Engine

This is the main controller.

```text
If signature matches -> attack alert
Else if ML says attack -> anomaly alert
Else -> benign log
```

### 4. Signature Engine

Checks fixed rules from `data/signatures.json`.

Example:

```text
port 3306 + TCP = SQL Injection
```

### 5. ML Engine

Uses two models:

- PKNN
- OSVM

Then combines their probabilities:

```text
final_probability = (PKNN_probability + OSVM_probability) / 2
```

### 6. Database

Stores alerts, logs, and traffic history.

## Viva Explanation

Say this:

> My project is a Hybrid Intrusion Detection System. It first checks known attacks using signature rules. If no rule matches, it sends the packet to the machine learning engine. The ML engine uses PKNN and OSVM. Their results are combined using probability fusion. Finally, the result is stored in SQLite and displayed on the frontend dashboard.
