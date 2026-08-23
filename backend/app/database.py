import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./cirt_lens.db")
if DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL="postgresql+psycopg://"+DATABASE_URL.removeprefix("postgresql://")
engine = create_engine(DATABASE_URL,connect_args={"check_same_thread":False} if DATABASE_URL.startswith("sqlite") else {},pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

class Base(DeclarativeBase):
    pass

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
