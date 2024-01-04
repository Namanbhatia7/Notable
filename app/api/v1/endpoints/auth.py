from fastapi import APIRouter
from app.core.database import get_db
from app.models.user import User, UserCreate
from app.core.config import settings
from app.schemas.token import Token

from datetime import timedelta

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm

from app.services.auth import get_password_hash, authenticate_user, create_access_token

router = APIRouter()


@router.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db = Depends(get_db)
):
    user = await authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@router.post("/signup", response_model=User)
async def create_user(user: UserCreate, db = Depends(get_db)):
    db_user = await db["users"].find_one({"username": user.username})
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = get_password_hash(user.password)
    db_user = await db["users"].insert_one({"username": user.username, "email": user.email, "disabled": False, "hashed_password": hashed_password})
    return User(username=user.username, email=user.email, id=str(db_user.inserted_id))

