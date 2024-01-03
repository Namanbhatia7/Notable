from bson import ObjectId
from fastapi import Depends, APIRouter, HTTPException
from typing import List
from app.core.database import get_db
from app.models.note import Note, NoteCreate
from app.api.v1.endpoints.auth import get_current_active_user
from app.models.user import User

router = APIRouter()

@router.get("/notes", response_model=List[Note])
async def read_notes(current_user: User = Depends(get_current_active_user), db = Depends(get_db)):
    notes = await db["notes"].find({"owner_id": current_user.username}).to_list(length=100)
    return notes

@router.get("/notes/{note_id}", response_model=Note)
async def read_note(note_id: str, current_user: User = Depends(get_current_active_user), db = Depends(get_db)):
    note = await db["notes"].find_one({"_id": ObjectId(note_id), "owner_id": current_user.username})
    if note is None:
        raise HTTPException(status_code=404, detail="Note not found")
    return note

@router.post("/notes", response_model=Note)
async def create_note(note: NoteCreate, current_user: User = Depends(get_current_active_user), db = Depends(get_db)):
    note_dict = note.dict()
    note_dict["owner_id"] = current_user.username
    result = await db["notes"].insert_one(note_dict)
    created_note = await db["notes"].find_one({"_id": result.inserted_id})

    return created_note

@router.put("/notes/{note_id}", response_model=Note)
async def update_note(note_id: str, note: NoteCreate, current_user: User = Depends(get_current_active_user), db = Depends(get_db)):
    note_dict = note.dict()
    note_dict["owner_id"] = current_user.username
    result = await db["notes"].update_one({"_id": ObjectId(note_id), "owner_id": current_user.username}, {"$set": note_dict})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Note not found")
    updated_note = await db["notes"].find_one({"_id": ObjectId(note_id)})
    return updated_note

@router.delete("/notes/{note_id}")
async def delete_note(note_id: str, current_user: User = Depends(get_current_active_user), db = Depends(get_db)):
    result = await db["notes"].delete_one({"_id": ObjectId(note_id), "owner_id": current_user.username})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Note not found")
    return {"detail": "Note deleted"}

@router.delete("/notes", response_model=dict)
async def delete_all_notes(current_user: User = Depends(get_current_active_user), db = Depends(get_db)):
    result = await db["notes"].delete_many({"owner_id": current_user.username})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="No notes found for the user")
    return {"detail": f"{result.deleted_count} notes deleted"}
