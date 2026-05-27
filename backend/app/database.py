import os

# On Render, /app/data is a persistent disk mount — store DB there
_default_db = (
    "sqlite:////app/data/apk_analysis.db"
    if os.path.isdir("/app/data")
    else "sqlite:///./apk_analysis.db"
)
DATABASE_URL = os.getenv("DATABASE_URL", _default_db)

# Handle PostgreSQL URL scheme for SQLAlchemy
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {},
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
