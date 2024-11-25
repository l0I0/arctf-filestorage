from sqlalchemy import Boolean, Column, Integer, String, ForeignKey, BigInteger
from sqlalchemy.orm import relationship
from database import Base

class User(Base):
    __tablename__ = "users"
    __table_args__ = {'extend_existing': True}

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_admin = Column(Boolean, default=False)
    storage_used = Column(BigInteger, default=0)  # в байтах
    
    files = relationship("FileStorage", back_populates="user")

class FileStorage(Base):
    __tablename__ = "files"
    __table_args__ = {'extend_existing': True}

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String, index=True)
    filepath = Column(String)
    size = Column(Integer)  # size in bytes
    is_deletable = Column(Boolean, default=True)  # новое поле
    user_id = Column(Integer, ForeignKey("users.id"))
    
    user = relationship("User", back_populates="files")
