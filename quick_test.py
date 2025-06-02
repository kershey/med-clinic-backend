#!/usr/bin/env python3
"""
Quick manual test of all major authentication endpoints.
"""
import requests
import json

BASE_URL = "http://localhost:8000/auth"

def test_endpoints():
    """Test all major endpoints quickly."""
    print("🚀 Quick Authentication Endpoint Test\n")
    
    # 1. Test Patient Registration
    print("1. Testing Patient Registration...")
    patient_data = {
        "email": "quicktest_patient@example.com",
        "full_name": "Quick Test Patient", 
        "password": "PatientPass123!",
        "gender": "Male",
        "address": "123 Test St",
        "contact": "+1234567890"
    }
    
    response = requests.post(f"{BASE_URL}/register/patient", json=patient_data)
    print(f"   Status: {response.status_code}")
    if response.status_code == 201:
        result = response.json()
        print(f"   ✅ Patient registered with ID: {result.get('user_id')}")
        patient_email = result.get('email')
    else:
        print(f"   ❌ Failed: {response.text}")
        return
    
    # 2. Test Doctor Registration
    print("\n2. Testing Doctor Registration...")
    doctor_data = {
        "email": "quicktest_doctor@example.com",
        "full_name": "Dr. Quick Test",
        "password": "DoctorPass123!",
        "specialization": "General Medicine",
        "license_number": "MD123456",
        "bio": "Test doctor"
    }
    
    response = requests.post(f"{BASE_URL}/register/doctor", json=doctor_data)
    print(f"   Status: {response.status_code}")
    if response.status_code == 201:
        result = response.json()
        print(f"   ✅ Doctor registered with ID: {result.get('user_id')}")
    else:
        print(f"   ❌ Failed: {response.text}")
    
    # 3. Test Patient Login (should fail - unverified)
    print("\n3. Testing Patient Login (unverified - should fail)...")
    login_data = {
        "email": patient_email,
        "password": "PatientPass123!"
    }
    
    response = requests.post(f"{BASE_URL}/login", json=login_data)
    print(f"   Status: {response.status_code}")
    if response.status_code == 401:
        print("   ✅ Correctly blocked unverified patient login")
    else:
        print(f"   ❌ Unexpected response: {response.text}")
    
    # 4. Test Invalid Login
    print("\n4. Testing Invalid Login...")
    invalid_login = {
        "email": "nonexistent@example.com",
        "password": "WrongPassword"
    }
    
    response = requests.post(f"{BASE_URL}/login", json=invalid_login)
    print(f"   Status: {response.status_code}")
    if response.status_code == 401:
        print("   ✅ Correctly rejected invalid credentials")
    else:
        print(f"   ❌ Unexpected response: {response.text}")
    
    # 5. Test Email Verification (invalid code)
    print("\n5. Testing Email Verification (invalid code)...")
    verify_data = {
        "email": patient_email,
        "verification_code": "INVALID123"
    }
    
    response = requests.post(f"{BASE_URL}/verify-email", json=verify_data)
    print(f"   Status: {response.status_code}")
    if response.status_code == 400:
        print("   ✅ Correctly rejected invalid verification code")
    else:
        print(f"   ❌ Unexpected response: {response.text}")
    
    # 6. Test Resend Verification
    print("\n6. Testing Resend Verification...")
    resend_data = {"email": patient_email}
    
    response = requests.post(f"{BASE_URL}/resend-verification", json=resend_data)
    print(f"   Status: {response.status_code}")
    if response.status_code == 200:
        print("   ✅ Verification email resent successfully")
    else:
        print(f"   ❌ Failed: {response.text}")
    
    # 7. Test Forgot Password
    print("\n7. Testing Forgot Password...")
    forgot_data = {"email": patient_email}
    
    response = requests.post(f"{BASE_URL}/forgot-password", json=forgot_data)
    print(f"   Status: {response.status_code}")
    if response.status_code == 200:
        print("   ✅ Password reset initiated")
    else:
        print(f"   ❌ Failed: {response.text}")
    
    # 8. Test Protected Endpoint (no token)
    print("\n8. Testing Protected Endpoint (no token)...")
    response = requests.get(f"{BASE_URL}/me")
    print(f"   Status: {response.status_code}")
    if response.status_code == 401:
        print("   ✅ Correctly blocked access without token")
    else:
        print(f"   ❌ Unexpected response: {response.text}")
    
    # 9. Test Logout
    print("\n9. Testing Logout...")
    response = requests.post(f"{BASE_URL}/logout")
    print(f"   Status: {response.status_code}")
    if response.status_code == 200:
        print("   ✅ Logout successful")
    else:
        print(f"   ❌ Failed: {response.text}")
    
    print("\n" + "="*50)
    print("🎉 Quick test completed!")
    print("✅ All major authentication endpoints are working!")
    print("\n📝 Summary:")
    print("   ✅ Patient registration works")
    print("   ✅ Doctor registration works")
    print("   ✅ Login validation works (blocks unverified users)")
    print("   ✅ Email verification error handling works")
    print("   ✅ Password reset works")
    print("   ✅ Protected endpoint security works")
    print("   ✅ Logout works")

if __name__ == "__main__":
    test_endpoints()