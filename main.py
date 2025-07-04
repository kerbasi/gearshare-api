import os
import pyodbc
from fastapi import FastAPI, HTTPException, status, Depends
from pydantic import BaseModel
from passlib.context import CryptContext

# --- Configuration & Setup ---

app = FastAPI()

# Password hashing setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# --- Database Connection ---
# Getting credentials from environment variables is a security best practice.
DB_HOST = os.environ.get("DB_HOST", "your_rds_endpoint_here")
DB_DATABASE = os.environ.get("DB_DATABASE", "gearshareios")
DB_USER = os.environ.get("DB_USER", "admin")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "your_db_password_here")
DRIVER = '{ODBC Driver 17 for SQL Server}' # Or the version you have installed

def get_db_connection():
    """Establishes and returns a database connection for MS SQL Server."""
    conn_str = f'DRIVER={DRIVER};SERVER={DB_HOST};DATABASE={DB_DATABASE};UID={DB_USER};PWD={DB_PASSWORD}'
    try:
        conn = pyodbc.connect(conn_str)
        yield conn
    finally:
        if 'conn' in locals():
            conn.close()

# --- Pydantic Models (for request data validation) ---

class UserCreate(BaseModel):
    username: str
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

# --- API Endpoints ---

@app.post("/register/", status_code=status.HTTP_201_CREATED)
def register_user(user: UserCreate, db: pyodbc.Connection = Depends(get_db_connection)):
    """Registers a new user, hashes their password, and stores it."""
    hashed_password = pwd_context.hash(user.password)
    
    try:
        cursor = db.cursor()
        # Note: Use ? for parameter placeholders with pyodbc
        query = "INSERT INTO Users (username, email, password_hash) VALUES (?, ?, ?)"
        cursor.execute(query, user.username, user.email, hashed_password)
        db.commit()
        return {"message": f"User '{user.username}' created successfully"}
    except pyodbc.IntegrityError as err:
        # Check for duplicate entry error (2627 or 2601 for MS SQL)
        raise HTTPException(status_code=400, detail="Email already registered")
    except pyodbc.Error as err:
        raise HTTPException(status_code=500, detail=str(err))
    finally:
        if 'cursor' in locals():
            cursor.close()

@app.post("/login/")
def login_user(form_data: UserLogin, db: pyodbc.Connection = Depends(get_db_connection)):
    """Authenticates a user and returns a success message."""
    try:
        cursor = db.cursor()
        query = "SELECT username, password_hash FROM Users WHERE email = ?"
        cursor.execute(query, form_data.email)
        user_row = cursor.fetchone()

        # Check if user exists and if the provided password matches the stored hash
        if not user_row or not pwd_context.verify(form_data.password, user_row.password_hash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password",
            )
        
        # In a real app, you would generate and return a JWT token here
        return {"message": "Login successful", "username": user_row.username}
        
    except pyodbc.Error as err:
        raise HTTPException(status_code=500, detail=str(err))
    finally:
        if 'cursor' in locals():
            cursor.close()