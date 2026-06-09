from fastapi import APIRouter, Query
from modules.database import get_traffic_series

router = APIRouter()


@router.get("/traffic")
def traffic(n: int = Query(20, ge=5, le=200)):
    """Return chart data."""
    return get_traffic_series(n=n)
