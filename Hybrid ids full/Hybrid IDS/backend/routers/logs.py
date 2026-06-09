from fastapi import APIRouter, Query
from modules.database import get_logs

router = APIRouter()


@router.get("/logs")
def logs(limit: int = Query(100, ge=1, le=1000), method: str | None = None):
    """Return log records for frontend."""
    rows = get_logs(limit=limit, method=method)
    return [
        {
            "type": row.get("type", "Unknown"),
            "ip": row.get("ip", "-"),
            "method": row.get("method", "-"),
            "timestamp": row.get("timestamp", ""),
            "port": row.get("port", 0),
            "protocol": row.get("protocol", "-"),
        }
        for row in rows
    ]
