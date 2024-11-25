from pydantic import BaseModel
from typing import Optional, List

class UserBase(BaseModel):
    username: str

class UserCreate(UserBase):
    password: str

class User(UserBase):
    id: int
    is_admin: bool
    storage_used: int

    class Config:
        orm_mode = True

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class FileBase(BaseModel):
    filename: str
    size: int

class FileCreate(FileBase):
    pass

class File(FileBase):
    id: int
    user_id: int

    class Config:
        orm_mode = True

class SizeInfo(BaseModel):
    value: int
    formatted: dict

class StorageInfo(BaseModel):
    used: SizeInfo
    total: SizeInfo
    files_count: int
