import asyncio
from typing import Generator

from httpx import AsyncClient

import pytest

from fastapi.testclient import TestClient
from .main import app
from .models import User, User_Pydantic, UserIn_Pydantic, Record, Record_Pydantic, RecordIn_Pydantic

from tortoise.contrib.test import finalizer, initializer

from passlib.hash import bcrypt


@pytest.mark.asyncio
async def test_testpost():
    async with AsyncClient(app=app, base_url="http://test") as ac:
        response = await ac.post("/users", json={
            "username": "testuser888",
            "password_hash": bcrypt.hash("testpass888")})
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == "testuser888"




"""
@pytest.fixture(scope="module")
def client() -> Generator:
    initializer(["models"])
    with TestClient(app) as c:
        yield c
    finalizer()


@pytest.fixture(scope="module")
def event_loop(client: TestClient) -> Generator:
    yield asyncio.get_event_loop()


def test_create_user(client: TestClient, event_loop: asyncio.AbstractEventLoop):
    response = client.post("/users", json={
        "username": "testuser888",
        "password_hash": bcrypt.hash("testpass888")})
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["username"] == "testuser888"
    assert "id" in data
    user_id = data["id"]

    async def get_user_by_db():
        user = await User.get(id=user_id)
        return user

    user_obj = event_loop.run_until_complete(get_user_by_db())
    assert user_obj.id == user_id
"""
