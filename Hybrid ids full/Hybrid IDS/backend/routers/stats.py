from fastapi import APIRouter
from modules.database import get_stats

router = APIRouter()


@router.get("/stats")
def stats():
    """Return dashboard counters."""
    return get_stats()
