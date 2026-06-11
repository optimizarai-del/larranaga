from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from .. import models, schemas
from ..database import get_db
from .auth import get_current_user

router = APIRouter(
    prefix="/cuentas-corrientes",
    tags=["cuentas_corrientes"]
)

@router.get("/client/{client_id}", response_model=List[schemas.MovimientoCCOut])
def read_movimientos(
    client_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    # Check if client exists
    client = db.query(models.Client).filter(models.Client.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    movimientos = db.query(models.MovimientoCuentaCorriente)\
        .filter(models.MovimientoCuentaCorriente.client_id == client_id)\
        .order_by(models.MovimientoCuentaCorriente.fecha.desc(), models.MovimientoCuentaCorriente.created_at.desc())\
        .all()
    return movimientos

@router.post("/", response_model=schemas.MovimientoCCOut, status_code=status.HTTP_201_CREATED)
def create_movimiento(
    movimiento: schemas.MovimientoCCCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    # Check if client exists
    client = db.query(models.Client).filter(models.Client.id == movimiento.client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
        
    db_movimiento = models.MovimientoCuentaCorriente(**movimiento.model_dump())
    db.add(db_movimiento)
    db.commit()
    db.refresh(db_movimiento)
    return db_movimiento

@router.get("/client/{client_id}/saldo", response_model=float)
def get_saldo(
    client_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    client = db.query(models.Client).filter(models.Client.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    movimientos = db.query(models.MovimientoCuentaCorriente).filter(models.MovimientoCuentaCorriente.client_id == client_id).all()

    # Ingreso = we receive money from client = increases their balance (favorable to them or reduces debt)
    # Egreso = we charge client for services = decreases their balance (increases their debt)
    # So saldo = sum(ingresos) - sum(egresos). Positive saldo means they have money in favor, negative means they owe.
    saldo = 0.0
    for mov in movimientos:
        if mov.tipo.lower() == 'ingreso':
            saldo += float(mov.monto)
        else:
            saldo -= float(mov.monto)

    return saldo
