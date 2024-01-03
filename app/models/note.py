from bson import ObjectId
from bson.errors import InvalidId
from pydantic import BaseModel, Field
from typing import Optional

class NoteBase(BaseModel):
    title: str
    content: str

class NoteCreate(NoteBase):
    pass

class OID(str):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        try:
            return ObjectId(str(v))
        except InvalidId:
            raise ValueError("Not a valid ObjectId")

class Note(NoteBase):
    id: Optional[OID] = Field(alias="_id")

    class Config:
        orm_mode = True
        arbitrary_types_allowed = True
        allow_population_by_field_name = True
        json_encoders = {
            ObjectId: str
        }