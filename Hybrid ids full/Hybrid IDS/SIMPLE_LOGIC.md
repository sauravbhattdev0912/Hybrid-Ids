# Simple Logic of Hybrid IDS

## One-line idea

This project checks network packets and decides whether they are safe or attack packets.

## Main flow

```text
Packet comes in
     |
     v
Signature Engine checks known attacks
     |
     |-- Matched? -> Save alert as Signature attack
     |
     v
ML Engine checks unknown/anomaly attack
     |
     |-- Attack? -> Save alert as Anomaly attack
     |
     v
Otherwise save as Benign
```

## Why two engines?

### Signature Engine

Good for known attacks.

Example:

```text
If packet goes to MySQL port 3306, it may be SQL Injection.
```

### ML Engine

Good for unknown or new attacks.

It learns traffic patterns using:

- PKNN
- OSVM

## Most important file

The easiest file to explain is:

```text
backend/modules/decision_engine.py
```

Because it connects both engines.

## Frontend routes

The frontend calls:

```text
/api/stats
/api/alerts
/api/logs
/api/traffic
/api/analyze
/api/simulate
/api/train
```

## Backend startup

When backend starts:

```text
1. database tables are created
2. ML models are loaded
3. if models are missing, training starts
4. API becomes ready
```
