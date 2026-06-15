from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from contextlib import asynccontextmanager

import psycopg
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


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="SpecialVidhya Auth API", version="1.0.0", lifespan=lifespan)

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


class SignupRequest(BaseModel):
    # Account
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=6, max_length=128)

    # Child (Screen 1)
    child_name: str = Field(min_length=1, max_length=100)
    child_dob: str | None = None
    child_gender: str | None = None
    child_class: str | None = None
    child_school: str | None = None
    child_board: str | None = None
    child_languages: str | None = None

    # Academics (Screen 2)
    subject_marks: dict[str, str] | None = None
    academic_concerns: list[str] | None = None

    # Observations (Screen 3) — dict of question id to 'Yes'/'No'
    observations: dict[str, str] | None = None

    # Parent (Screen 4)
    parent_name: str | None = None
    parent_phone: str | None = None
    parent_email: str | None = None
    parent_role: str | None = None


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
        connection = psycopg.connect(DATABASE_URL)
        return connection
    except psycopg.OperationalError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database connection failed",
        ) from exc


def init_db() -> None:
    connection = get_db_connection()
    cursor = connection.cursor()
    try:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS child_details (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
                child_name VARCHAR(100) NOT NULL,
                child_dob VARCHAR(30),
                child_gender VARCHAR(20),
                child_class VARCHAR(50),
                child_school VARCHAR(100),
                child_board VARCHAR(50),
                child_languages TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS academic_details (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
                english_marks VARCHAR(10),
                maths_marks VARCHAR(10),
                social_studies_marks VARCHAR(10),
                science_marks VARCHAR(10),
                second_language_marks VARCHAR(10),
                academic_concerns TEXT[],
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS observations (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
                lang1 VARCHAR(5), lang2 VARCHAR(5), lang3 VARCHAR(5),
                read1 VARCHAR(5), read2 VARCHAR(5), read3 VARCHAR(5),
                read4 VARCHAR(5), read5 VARCHAR(5), read6 VARCHAR(5),
                read7 VARCHAR(5), read8 VARCHAR(5), read9 VARCHAR(5),
                read10 VARCHAR(5), read11 VARCHAR(5), read12 VARCHAR(5),
                comp1 VARCHAR(5),
                spell1 VARCHAR(5), spell2 VARCHAR(5), spell3 VARCHAR(5),
                spell4 VARCHAR(5), spell5 VARCHAR(5),
                gen1 VARCHAR(5), gen2 VARCHAR(5), gen3 VARCHAR(5),
                gen4 VARCHAR(5), gen5 VARCHAR(5), gen6 VARCHAR(5),
                gen7 VARCHAR(5), gen8 VARCHAR(5), gen9 VARCHAR(5),
                gen10 VARCHAR(5), gen11 VARCHAR(5), gen12 VARCHAR(5),
                gen13 VARCHAR(5),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS parent_details (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
                parent_name VARCHAR(100),
                parent_phone VARCHAR(20),
                parent_email VARCHAR(100),
                parent_role VARCHAR(50),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
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


def authenticate_user(username: str, password: str) -> dict:
    user = get_user_by_username(username)
    if user is None or not verify_password(password, user[2]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return {"id": user[0], "username": user[1]}


def build_auth_response(user: dict) -> AuthResponse:
    token = create_access_token(subject=user["username"])
    return AuthResponse(
        access_token=token,
        user=UserResponse(id=user["id"], username=user["username"]),
    )


def create_full_user(payload: SignupRequest) -> dict:
    password_hash = hash_password(payload.password)
    connection = get_db_connection()
    cursor = connection.cursor()
    try:
        # 1. users
        cursor.execute(
            "INSERT INTO users (username, password_hash) VALUES (%s, %s) RETURNING id, username",
            (payload.username.strip(), password_hash),
        )
        row = cursor.fetchone()
        if not row:
            raise psycopg.Error("Failed to create user")
        user_data = {"id": row[0], "username": row[1]}

        # 2. child_details
        cursor.execute(
            """
            INSERT INTO child_details
            (user_id, child_name, child_dob, child_gender, child_class, child_school, child_board, child_languages)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                user_data["id"],
                payload.child_name,
                payload.child_dob,
                payload.child_gender,
                payload.child_class,
                payload.child_school,
                payload.child_board,
                payload.child_languages,
            ),
        )

        # 3. academic_details
        marks = payload.subject_marks or {}
        cursor.execute(
            """
            INSERT INTO academic_details
            (user_id, english_marks, maths_marks, social_studies_marks, science_marks, second_language_marks, academic_concerns)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
            (
                user_data["id"],
                marks.get("English"),
                marks.get("Maths"),
                marks.get("Social Studies"),
                marks.get("Science"),
                marks.get("2nd Language"),
                payload.academic_concerns or [],
            ),
        )

        # 4. observations
        obs = payload.observations or {}
        cursor.execute(
            """
            INSERT INTO observations
            (user_id,
             lang1, lang2, lang3,
             read1, read2, read3, read4, read5, read6, read7, read8, read9, read10, read11, read12,
             comp1,
             spell1, spell2, spell3, spell4, spell5,
             gen1, gen2, gen3, gen4, gen5, gen6, gen7, gen8, gen9, gen10, gen11, gen12, gen13)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            (
                user_data["id"],
                obs.get("lang1"), obs.get("lang2"), obs.get("lang3"),
                obs.get("read1"), obs.get("read2"), obs.get("read3"), obs.get("read4"),
                obs.get("read5"), obs.get("read6"), obs.get("read7"), obs.get("read8"),
                obs.get("read9"), obs.get("read10"), obs.get("read11"), obs.get("read12"),
                obs.get("comp1"),
                obs.get("spell1"), obs.get("spell2"), obs.get("spell3"), obs.get("spell4"), obs.get("spell5"),
                obs.get("gen1"), obs.get("gen2"), obs.get("gen3"), obs.get("gen4"), obs.get("gen5"),
                obs.get("gen6"), obs.get("gen7"), obs.get("gen8"), obs.get("gen9"), obs.get("gen10"),
                obs.get("gen11"), obs.get("gen12"), obs.get("gen13"),
            ),
        )

        # 5. parent_details
        cursor.execute(
            """
            INSERT INTO parent_details (user_id, parent_name, parent_phone, parent_email, parent_role)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (
                user_data["id"],
                payload.parent_name,
                payload.parent_phone,
                payload.parent_email,
                payload.parent_role,
            ),
        )

        connection.commit()
        return user_data
    except psycopg.IntegrityError as exc:
        connection.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already exists",
        ) from exc
    except psycopg.Error as exc:
        connection.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Signup failed",
        ) from exc
    finally:
        cursor.close()
        connection.close()


@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.post("/auth/signup", response_model=AuthResponse, status_code=status.HTTP_201_CREATED)
def signup(payload: SignupRequest):
    user = create_full_user(payload)
    return build_auth_response(user)


@app.post("/auth/login", response_model=AuthResponse)
def login(payload: AuthRequest):
    user = authenticate_user(payload.username.strip(), payload.password)
    return build_auth_response(user)
