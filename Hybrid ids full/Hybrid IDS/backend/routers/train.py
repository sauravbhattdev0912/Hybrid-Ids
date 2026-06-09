from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel, Field

from modules.ml_engine import ml_engine


router = APIRouter()
training_status = {"training": False, "last_result": None}


class TrainIn(BaseModel):
    n_benign: int = Field(800, ge=100)
    n_attack_each: int = Field(120, ge=20)
    n_neighbors: int = Field(7, ge=1, le=25)


def train_in_background(config: TrainIn):
    training_status["training"] = True
    try:
        X, y = ml_engine._generate_synthetic_data(config.n_benign, config.n_attack_each)
        result = ml_engine.train(X, y)
        training_status["last_result"] = result
    except Exception as error:
        training_status["last_result"] = {"error": str(error)}
    finally:
        training_status["training"] = False


@router.post("/train")
def train_model(config: TrainIn, background_tasks: BackgroundTasks):
    """Retrain ML models in background."""
    if training_status["training"]:
        raise HTTPException(status_code=409, detail="Training already running")
    background_tasks.add_task(train_in_background, config)
    return {"status": "training_started", "config": config.model_dump()}


@router.get("/train/status")
def train_status():
    """Check ML training status."""
    return {
        "training": training_status["training"],
        "model_trained": ml_engine.trained,
        "last_result": training_status["last_result"],
    }
