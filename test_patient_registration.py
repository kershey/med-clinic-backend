#!/usr/bin/env python3
"""
Test script specifically for patient registration and email verification.
"""
import asyncio
import httpx
import json
import sys
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

async def test_patient_registration():
    """Test patient registration with a unique email."""
    import time
    test_email = f"test{int(time.time())}@example.com"
    
    patient_data = {
        "email": test_email,
        "full_name": "Test Patient",
        "gender": "Male",
        "address": "123 Test Street",
        "contact": "1234567890",
        "password": "testpass123"
    }
    
    print(f"🧪 Testing patient registration with email: {test_email}")
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "http://localhost:8000/auth/register/patient",
                json=patient_data,
                timeout=30.0
            )
            
            print(f"Status Code: {response.status_code}")
            print(f"Response: {json.dumps(response.json(), indent=2)}")
            
            if response.status_code == 201:
                result = response.json()
                if "error" in result:
                    print(f"⚠️  Registration succeeded but email failed: {result['error']}")
                    return False
                else:
                    print("✅ Registration and email successful!")
                    return True
            else:
                print(f"❌ Registration failed: {response.json()}")
                return False
                
    except httpx.ConnectError:
        print("❌ Cannot connect to FastAPI server. Make sure it's running on http://localhost:8000")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {str(e)}")
        return False

async def test_email_direct():
    """Test direct email sending to compare with API."""
    print("\n📧 Testing direct email sending...")
    
    try:
        # Add current directory to path to import app modules
        sys.path.append('.')
        from app.api.utils.email import send_verification_email
        
        test_email = os.getenv("MAIL_USERNAME", "jnsnaragon01@gmail.com")
        test_code = "DIRECT123"
        
        await send_verification_email(test_email, test_code)
        print(f"✅ Direct email sending successful with code: {test_code}")
        return True
        
    except Exception as e:
        print(f"❌ Direct email sending failed: {str(e)}")
        return False

async def main():
    """Run all tests."""
    print("🚀 Patient Registration Email Test")
    print("=" * 50)
    
    # Test 1: Direct email (should work)
    direct_result = await test_email_direct()
    
    # Test 2: API registration (problematic)
    api_result = await test_patient_registration()
    
    print("\n" + "=" * 50)
    print("📊 Results:")
    print(f"Direct Email: {'✅ PASS' if direct_result else '❌ FAIL'}")
    print(f"API Registration: {'✅ PASS' if api_result else '❌ FAIL'}")
    
    if direct_result and not api_result:
        print("\n🔍 Diagnosis: Email works directly but fails in API context")
        print("Possible causes:")
        print("- Environment variables not loaded in FastAPI")
        print("- Database connection issues")
        print("- FastAPI async context issues")
        print("- Import/module loading issues")

if __name__ == "__main__":
    asyncio.run(main()) 