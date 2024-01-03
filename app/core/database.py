from motor.motor_asyncio import AsyncIOMotorClient
from app.core.config import settings

async def get_db():
    client = AsyncIOMotorClient(settings.MONGODB_URL)
    return client.fastapi_auth