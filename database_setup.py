import os
import sys
from sqlalchemy import Column, ForeignKey, Integer, String, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()


class Category(Base):
    __tablename__ = 'category'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)


class Item(Base):
    __tablename__ = 'item'

    name = Column(String(250), nullable=False)
    id = Column(Integer, primary_key=True)
    description = Column(Text)
    category_id = Column(Integer, ForeignKey('category.id'))
    category = relationship(Category)


engine = create_engine('sqlite:///catalog.db')
Base.metadata.create_all(engine)
