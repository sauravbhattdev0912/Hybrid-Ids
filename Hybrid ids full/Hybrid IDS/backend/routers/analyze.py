from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from modules.decision_engine import analyse
from modules import packet_capture


router = APIRouter()


class PacketIn(BaseModel):
    ip: str = Field("192.168.1.1")
    port: int = Field(80, ge=0, le=65535)
    protocol: str = Field("TCP")
    packet_size: int = Field(512, ge=0)
    flags: str = Field("")


class SimulateIn(BaseModel):
    action: str = Field(..., description="start or stop")
    rate_hz: float = Field(2.0, ge=0.1, le=50)
    attack_prob: float = Field(0.15, ge=0.0, le=1.0)


@router.post("/analyze")
def analyze_packet(packet: PacketIn):
    """Manually test one packet."""
    return analyse(packet.model_dump())


@router.post("/simulate")
async def simulate(body: SimulateIn):
    """Start or stop fake live traffic."""
    if body.action == "start":
        await packet_capture.start_simulation(body.rate_hz, body.attack_prob)
        return {"status": "started", "rate_hz": body.rate_hz, "attack_prob": body.attack_prob}

    if body.action == "stop":
        await packet_capture.stop_simulation()
        return {"status": "stopped"}

    raise HTTPException(status_code=400, detail="action must be start or stop")


@router.get("/simulate/status")
def simulation_status():
    return {"running": packet_capture.is_running()}
