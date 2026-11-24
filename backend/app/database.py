import os
from sqlmodel import create_engine, Session, SQLModel

database_url = os.getenv("DATABASE_URL")

if database_url:
    # Railway and cloud providers give 'postgres://', but SQLAlchemy 2.0 requires 'postgresql://'
    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)
    engine = create_engine(
        database_url,
        echo=False,
        pool_pre_ping=True,
        pool_size=10,
        max_overflow=20,
        pool_recycle=300,
    )
else:
    # Local fallback to SQLite with WAL mode for non-blocking concurrent reads
    from sqlalchemy import event

    sqlite_file_name = "sentinelx.db"
    sqlite_url = f"sqlite:///{sqlite_file_name}"
    connect_args = {"check_same_thread": False}
    engine = create_engine(sqlite_url, echo=False, connect_args=connect_args)

    @event.listens_for(engine, "connect")
    def _set_sqlite_pragma(dbapi_connection, _connection_record):
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
        finally:
            cursor.close()

def init_db():
    # Explicitly import all models so SQLModel registers table schemas
    import app.models.core  # noqa: F401
    from sqlalchemy import text
    SQLModel.metadata.create_all(engine)
    # Safely migrate existing tables with any new columns
    for stmt in (
        "ALTER TABLE threatevent ADD COLUMN destination VARCHAR",
        "ALTER TABLE threatevent ADD COLUMN confidence FLOAT",
        "ALTER TABLE threatevent ADD COLUMN simulated BOOLEAN NOT NULL DEFAULT FALSE",
    ):
        try:
            with engine.begin() as conn:
                conn.execute(text(stmt))
        except Exception:
            pass


def get_session():
    with Session(engine) as session:
        yield session
