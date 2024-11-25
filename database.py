from sqlalchemy import create_engine, MetaData
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

SQLALCHEMY_DATABASE_URL = "postgresql://postgres:postgres@db:5432/postgres"

engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Создаем метаданные с параметром extend_existing
metadata = MetaData()
Base = declarative_base(metadata=metadata)

# Устанавливаем параметр extend_existing для всех таблиц
metadata.reflect(bind=engine, extend_existing=True)
