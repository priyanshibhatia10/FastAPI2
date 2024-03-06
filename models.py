from sqlalchemy import Column, Integer, String, Boolean, Float, Date
from sqlalchemy.ext.declarative import declarative_base
from pydantic import BaseModel

Base = declarative_base()

class User(Base):
    __tablename__ = "user"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True)
    email = Column(String, unique=True)
    password = Column(String)
    is_verified = Column(Boolean, default=False)

class Products(Base):
    __tablename__ = "products"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String)
    description = Column(String)
    price = Column(Float)
    quantity = Column(Integer)
    created_at = Column(Date)
    in_stock = Column(Boolean, default=True)
    category = Column(String)
    manufacturer = Column(String)
