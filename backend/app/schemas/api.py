from enum import Enum

from pydantic import BaseModel, Field


class IncidentStatus(str, Enum):
    NEW = "NEW"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"


class Disposition(str, Enum):
    UNSET = "UNSET"
    TRUE_POSITIVE = "TRUE_POSITIVE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    BENIGN_POSITIVE = "BENIGN_POSITIVE"


class DemoRequest(BaseModel):
    scenario: str


class ActionRequest(BaseModel):
    action: str = Field(min_length=2, max_length=100)
    analyst: str = Field(default="analyst@demo", max_length=100)


class AskRequest(BaseModel):
    question: str = Field(min_length=2, max_length=500)


class StatusRequest(BaseModel):
    status: IncidentStatus


class NoteRequest(BaseModel):
    analyst: str = Field(default="analyst@demo", max_length=100)
    text: str = Field(min_length=1, max_length=2000)


class BookmarkRequest(BaseModel):
    event_id: str = Field(min_length=3, max_length=80)
    analyst: str = Field(default="analyst@demo", max_length=100)
    note: str = Field(default="", max_length=500)


class DispositionRequest(BaseModel):
    disposition: Disposition
    analyst: str = Field(default="analyst@demo", max_length=100)
