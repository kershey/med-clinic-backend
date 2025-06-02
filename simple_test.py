#!/usr/bin/env python3
"""
Simple test script to diagnose endpoint issues.
"""
import requests
import json

BASE_URL = "http://localhost:8000"

def test_root():
    """Test root endpoint."""
    try:
        response = requests.get(f"{BASE_URL}/")
        print(f"Root endpoint: {response.status_code}")
        print(f"Response: {response.json()}")
        return True
    except Exception as e:
        print(f"Root endpoint failed: {e}")
        return False

def test_docs():
    """Test docs endpoint."""
    try:
        response = requests.get(f"{BASE_URL}/docs")
        print(f"Docs endpoint: {response.status_code}")
        return response.status_code == 200
    except Exception as e:
        print(f"Docs endpoint failed: {e}")
        return False

def test_simple_auth():
    """Test simple auth endpoint."""
    try:
        # Test logout (simple endpoint that doesn't require database)
        response = requests.post(f"{BASE_URL}/auth/logout")
        print(f"Logout endpoint: {response.status_code}")
        print(f"Response: {response.json()}")
        return True
    except Exception as e:
        print(f"Logout endpoint failed: {e}")
        return False

def test_patient_registration():
    """Test patient registration."""
    try:
        data = {
            "email": "test@example.com",
            "full_name": "Test User",
            "password": "TestPass123!"
        }
        response = requests.post(
            f"{BASE_URL}/auth/register/patient",
            json=data,
            headers={"Content-Type": "application/json"}
        )
        print(f"Patient registration: {response.status_code}")
        print(f"Response: {response.text}")
        return response.status_code in [200, 201, 400]  # 400 might be validation error
    except Exception as e:
        print(f"Patient registration failed: {e}")
        return False

if __name__ == "__main__":
    print("🔍 Simple Endpoint Testing\n")
    
    print("1. Testing root endpoint...")
    test_root()
    print()
    
    print("2. Testing docs endpoint...")
    test_docs()
    print()
    
    print("3. Testing simple auth endpoint...")
    test_simple_auth()
    print()
    
    print("4. Testing patient registration...")
    test_patient_registration()
    print()
    
    print("✅ Simple testing complete!") 