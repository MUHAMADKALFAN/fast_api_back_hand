from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from jose import jwt
from passlib.context import CryptContext
import time
from fastapi.middleware.cors import CORSMiddleware

# ------------------------------------------------------
# FASTAPI APP
# ------------------------------------------------------
app = FastAPI()

# ------------------------------------------------------
# ENABLE CORS (REQUIRED FOR FLUTTER)
# ------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],        # Flutter / mobile accepted
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------------------------------------------
# JWT SETTINGS
# ------------------------------------------------------
SECRET_KEY = "MY_SECRET_KEY_123"
ALGORITHM = "HS256"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Fake in-memory DB
users = {}   # { email: { name, password_hash } }

# ------------------------------------------------------
# MODELS
# ------------------------------------------------------
class UserSignup(BaseModel):
    name: str
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

# ------------------------------------------------------
# SIGNUP ROUTE
# ------------------------------------------------------
@app.post("/signup")
def signup(data: UserSignup):
    if data.email in users:
        raise HTTPException(status_code=400, detail="Email already exists")

    hashed_password = pwd_context.hash(data.password)

    users[data.email] = {
        "name": data.name,
        "password": hashed_password,
    }

    return {
        "success": True,
        "message": "Signup successful!"
    }

# ------------------------------------------------------
# LOGIN ROUTE
# ------------------------------------------------------
@app.post("/login")
def login(data: UserLogin):
    if data.email not in users:
        raise HTTPException(status_code=400, detail="Invalid email or password")

    user = users[data.email]

    if not pwd_context.verify(data.password, user["password"]):
        raise HTTPException(status_code=400, detail="Invalid email or password")

    # Create JWT Token
    token = jwt.encode(
        {
            "email": data.email,
            "name": user["name"],
            "exp": int(time.time()) + 3600,   # 1 hour expiry
        },
        SECRET_KEY,
        algorithm=ALGORITHM,
    )

    return {
        "success": True,
        "message": "Login successful!",
        "token": token,
    }

