from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import psycopg2
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from jose import jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise ValueError("DATABASE_URL environment variable is not set. Check your .env file.")

SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "10080"))

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI(title="SpecialVidhya Auth API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


class AuthRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=6, max_length=128)


class ChildDetailsRequest(BaseModel):
    user_id: int
    child_name: str = Field(min_length=1, max_length=100)
    child_age: int = Field(ge=1, le=15)
    child_grade: str | None = Field(None, max_length=50)


class ChildDetailsResponse(BaseModel):
    id: int
    child_name: str
    child_age: int
    child_grade: str | None


class UserResponse(BaseModel):
    id: int
    username: str


class AuthResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(subject: str) -> str:
    expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    expire_at = datetime.now(timezone.utc) + expires_delta
    payload = {"sub": subject, "exp": expire_at}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def get_db_connection():
    try:
        connection = psycopg2.connect(DATABASE_URL)
        return connection
    except psycopg2.OperationalError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database connection failed",
        ) from exc


def init_db() -> None:
    connection = get_db_connection()
    cursor = connection.cursor()
    try:
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS child_details (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
                child_name VARCHAR(100) NOT NULL,
                child_age INTEGER NOT NULL,
                child_grade VARCHAR(50),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        connection.commit()
    finally:
        cursor.close()
        connection.close()


def get_user_by_username(username: str):
    connection = get_db_connection()
    cursor = connection.cursor()
    try:
        cursor.execute(
            "SELECT id, username, password_hash FROM users WHERE username = %s",
            (username,),
        )
        return cursor.fetchone()
    finally:
        cursor.close()
        connection.close()


def create_user(username: str, password: str, child_name: str | None = None, child_age: int | None = None, child_grade: str | None = None) -> dict:
    password_hash = hash_password(password)
    connection = get_db_connection()
    cursor = connection.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (username, password_hash) VALUES (%s, %s) RETURNING id, username",
            (username, password_hash),
        )
        row = cursor.fetchone()
        connection.commit()
        if row:
            user_id = row[0]
            user_data = {"id": user_id, "username": row[1]}
            
            # Store child details if provided
            if child_name:
                store_child_details(user_id, child_name, child_age or 5, child_grade)
            
            return user_data
    except psycopg2.IntegrityError as exc:
        connection.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already exists",
        ) from exc
    finally:
        cursor.close()
        connection.close()


def authenticate_user(username: str, password: str) -> dict:
    user = get_user_by_username(username)
    if user is None or not verify_password(password, user[2]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return {"id": user[0], "username": user[1]}


def store_child_details(user_id: int, child_name: str, child_age: int, child_grade: str | None) -> dict:
    connection = get_db_connection()
    cursor = connection.cursor()
    try:
        cursor.execute(
            """
            INSERT INTO child_details (user_id, child_name, child_age, child_grade)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (user_id) DO UPDATE SET child_name = %s, child_age = %s, child_grade = %s, updated_at = CURRENT_TIMESTAMP
            RETURNING id, child_name, child_age, child_grade
            """,
            (user_id, child_name, child_age, child_grade, child_name, child_age, child_grade),
        )
        row = cursor.fetchone()
        connection.commit()
        if row:
            return {"id": row[0], "child_name": row[1], "child_age": row[2], "child_grade": row[3]}
    except psycopg2.Error as exc:
        connection.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to store child details",
        ) from exc
    finally:
        cursor.close()
        connection.close()


def get_child_details(user_id: int):
    connection = get_db_connection()
    cursor = connection.cursor()
    try:
        cursor.execute(
            "SELECT id, child_name, child_age, child_grade FROM child_details WHERE user_id = %s",
            (user_id,),
        )
        return cursor.fetchone()
    finally:
        cursor.close()
        connection.close()


def build_auth_response(user: dict) -> AuthResponse:
    token = create_access_token(subject=user["username"])
    return AuthResponse(
        access_token=token,
        user=UserResponse(id=user["id"], username=user["username"]),
    )


@app.on_event("startup")
def on_startup() -> None:
    init_db()


@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.post("/auth/signup", response_model=AuthResponse, status_code=status.HTTP_201_CREATED)
def signup(payload: AuthRequest):
    user = create_user(payload.username.strip(), payload.password)
    return build_auth_response(user)


@app.post("/auth/login", response_model=AuthResponse)
def login(payload: AuthRequest):
    user = authenticate_user(payload.username.strip(), payload.password)
    return build_auth_response(user)


@app.post("/child/details", response_model=ChildDetailsResponse)
def save_child_details(payload: ChildDetailsRequest):
    """
    Store or update child details for a user.
    """
    child_info = store_child_details(
        payload.user_id, payload.child_name, payload.child_age, payload.child_grade
    )
    return ChildDetailsResponse(**child_info)


@app.get("/child/details/{user_id}", response_model=ChildDetailsResponse)
def get_child_info(user_id: int):
    """
    Retrieve child details for a user.
    """
    child = get_child_details(user_id)
    if child is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Child details not found for this user",
        )
    return ChildDetailsResponse(
        id=child[0], child_name=child[1], child_age=child[2], child_grade=child[3]
    )