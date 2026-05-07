from fastapi.testclient import TestClient
from main import app, load_users, users_lock
import os
import pytest

client = TestClient(app)

def test_read_root():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"status": "online", "system": "Evidence Protector Pro"}

def test_register_weak_password():
    response = client.post("/register", data={"username": "testuser", "password": "123"})
    assert response.status_code == 400
    assert "Password must be at least 8 characters" in response.json()["detail"]

def test_register_and_login():
    # Remove existing user for clean test
    if os.path.exists("users.json"):
        os.remove("users.json")
    
    # Register
    res_reg = client.post("/register", data={"username": "agent007", "password": "SecurePassword123"})
    assert res_reg.status_code == 200
    assert "access_token" in res_reg.json()

    # Login
    res_login = client.post("/login", data={"username": "agent007", "password": "SecurePassword123"})
    assert res_login.status_code == 200
    assert "access_token" in res_login.json()
    
    # Bad Login
    res_bad = client.post("/login", data={"username": "agent007", "password": "WrongPassword"})
    assert res_bad.status_code == 401

def test_logout():
    res_login = client.post("/login", data={"username": "agent007", "password": "SecurePassword123"})
    token = res_login.json()["access_token"]
    
    res_logout = client.post("/logout", headers={"Authorization": f"Bearer {token}"})
    assert res_logout.status_code == 200
    
    # Check if token is invalid after logout
    res_analyze = client.get("/chain-status", headers={"Authorization": f"Bearer {token}"})
    assert res_analyze.status_code == 401
    assert "revoked" in res_analyze.json()["detail"]
