import asyncio
from typing import Generator

from httpx import AsyncClient

import pytest

import jwt

from fastapi.testclient import TestClient
from .main import app
from .models import User, User_Pydantic, UserIn_Pydantic, Record, Record_Pydantic, RecordIn_Pydantic

from tortoise.contrib.test import finalizer, initializer

from passlib.hash import bcrypt

JWT_SECRET = 'myjwtsecret'


@pytest.mark.asyncio
async def test_usercreate():
    token = jwt.encode({"id": 1,
                        "username": "testuser888",
                        "password_hash": bcrypt.hash("testpass888")}, JWT_SECRET)
    async with AsyncClient(app=app, base_url="http://test") as ac:
        response = await ac.post("/users", json={
            "username": "testuser888",
            "password_hash": bcrypt.hash("testpass888")})
        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "testuser888"
        assert "id" in data
        user_id = data["id"]
        assert user_id == 1
        response = await ac.post("/records",
                                 json={"record": "string66"},
                                 headers={"Authorization": f"Bearer {token}"}
                                 )
        assert response.status_code == 200
        data = response.json()
        assert data["record"] == "string66"
        response = await ac.get("/records/my",
                                headers={"Authorization": f"Bearer {token}"}
                                )
        data = response.json()
        assert data[0]["record"] == "string66"


