from sqlalchemy import Column, Integer, String, Text, ForeignKey, DateTime
from sqlalchemy.orm import relationship, declarative_base
import datetime

Base = declarative_base()


class Case(Base):
    __tablename__ = 'cases'
    id          = Column(Integer, primary_key=True)
    case_number = Column(String(50), unique=True, nullable=False)
    examiner    = Column(String(100))
    description = Column(Text)
    created_at  = Column(DateTime, default=datetime.datetime.now)

    evidence = relationship('Evidence', back_populates='case')


class Evidence(Base):
    __tablename__ = 'evidence'
    id         = Column(Integer, primary_key=True)
    case_id    = Column(Integer, ForeignKey('cases.id'))
    image_path = Column(String(512), nullable=False)
    added_at   = Column(DateTime, default=datetime.datetime.now)

    case      = relationship('Case', back_populates='evidence')
    artifacts = relationship('Artifact', back_populates='evidence')
    bookmarks = relationship('Bookmark', back_populates='evidence')


class Artifact(Base):
    __tablename__ = 'artifacts'
    id            = Column(Integer, primary_key=True)
    evidence_id   = Column(Integer, ForeignKey('evidence.id'))
    file_path     = Column(String(512), nullable=False)
    md5           = Column(String(32))
    sha256        = Column(String(64))
    analysis_type = Column(String(50))
    results       = Column(Text)
    analyzed_at   = Column(DateTime, default=datetime.datetime.now)

    evidence = relationship('Evidence', back_populates='artifacts')


class Bookmark(Base):
    __tablename__ = 'bookmarks'
    id          = Column(Integer, primary_key=True)
    evidence_id = Column(Integer, ForeignKey('evidence.id'), nullable=False)
    file_path   = Column(String(512), nullable=False)
    tag_name    = Column(String(80), default='')
    tag_color   = Column(String(7),  default='#FFDD00')
    notes       = Column(Text,       default='')
    created_at  = Column(DateTime,   default=datetime.datetime.now)

    evidence = relationship('Evidence', back_populates='bookmarks')
