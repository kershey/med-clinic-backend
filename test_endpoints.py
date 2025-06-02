#!/usr/bin/env python3
"""
Comprehensive endpoint testing script for Role-Based Authentication API.

This script tests all authentication endpoints to ensure they work correctly.
"""
import requests
import json
import time
import sys
from typing import Dict, Optional

# Configuration
BASE_URL = "http://localhost:8000"
AUTH_URL = f"{BASE_URL}/auth"

class APITester:
    def __init__(self):
        self.session = requests.Session()
        self.tokens = {}
        self.users = {}
        self.test_results = []
        
    def log_test(self, test_name: str, success: bool, details: str = ""):
        """Log test result."""
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} {test_name}")
        if details:
            print(f"   {details}")
        
        self.test_results.append({
            "test": test_name,
            "success": success,
            "details": details
        })
        
    def make_request(self, method: str, endpoint: str, data: Dict = None, 
                    token: str = None, expected_status: int = 200) -> Optional[Dict]:
        """Make HTTP request and handle response."""
        url = f"{AUTH_URL}{endpoint}"
        headers = {"Content-Type": "application/json"}
        
        if token:
            headers["Authorization"] = f"Bearer {token}"
            
        try:
            if method.upper() == "GET":
                response = self.session.get(url, headers=headers)
            elif method.upper() == "POST":
                response = self.session.post(url, json=data, headers=headers)
            elif method.upper() == "PUT":
                response = self.session.put(url, json=data, headers=headers)
            else:
                raise ValueError(f"Unsupported method: {method}")
                
            # Check if response status matches expected
            if response.status_code != expected_status:
                print(f"   Expected status {expected_status}, got {response.status_code}")
                if response.text:
                    print(f"   Response: {response.text}")
                return None
                
            # Try to parse JSON response
            try:
                return response.json()
            except:
                return {"status_code": response.status_code, "text": response.text}
                
        except requests.exceptions.RequestException as e:
            print(f"   Request failed: {e}")
            return None
            
    def test_server_connection(self):
        """Test if server is running."""
        try:
            response = requests.get(f"{BASE_URL}/", timeout=5)
            if response.status_code == 200:
                self.log_test("Server Connection", True, "FastAPI server is running")
                return True
            else:
                self.log_test("Server Connection", False, f"Server returned {response.status_code}")
                return False
        except Exception as e:
            self.log_test("Server Connection", False, f"Cannot connect to server: {e}")
            return False
            
    def test_patient_registration(self):
        """Test patient registration endpoint."""
        data = {
            "email": "testpatient@example.com",
            "full_name": "Test Patient",
            "password": "PatientPass123!",
            "gender": "Male",
            "address": "123 Patient St",
            "contact": "+1234567890"
        }
        
        response = self.make_request("POST", "/register/patient", data, expected_status=201)
        if response and "user_id" in response:
            self.users["patient"] = response
            self.log_test("Patient Registration", True, 
                         f"Patient registered with ID: {response['user_id']}")
            return True
        else:
            self.log_test("Patient Registration", False, "Failed to register patient")
            return False
            
    def test_doctor_registration(self):
        """Test doctor registration endpoint."""
        data = {
            "email": "testdoctor@example.com",
            "full_name": "Dr. Test Doctor",
            "password": "DoctorPass123!",
            "specialization": "General Medicine",
            "license_number": "MD123456",
            "bio": "Test doctor for API testing"
        }
        
        response = self.make_request("POST", "/register/doctor", data, expected_status=201)
        if response and "user_id" in response:
            self.users["doctor"] = response
            self.log_test("Doctor Registration", True, 
                         f"Doctor registered with ID: {response['user_id']}")
            return True
        else:
            self.log_test("Doctor Registration", False, "Failed to register doctor")
            return False
            
    def test_patient_login_before_verification(self):
        """Test patient login before email verification (should fail)."""
        data = {
            "email": "testpatient@example.com",
            "password": "PatientPass123!"
        }
        
        response = self.make_request("POST", "/login", data, expected_status=401)
        if response and "Email not verified" in response.get("detail", ""):
            self.log_test("Patient Login (Before Verification)", True, 
                         "Correctly blocked unverified patient login")
            return True
        else:
            self.log_test("Patient Login (Before Verification)", False, 
                         "Should have blocked unverified patient login")
            return False
            
    def test_email_verification(self):
        """Test email verification endpoint."""
        # Note: In a real test, we'd need the actual verification code from the email
        # For testing purposes, we'll simulate this by directly updating the database
        # or using a test verification code
        
        # First, let's try with an invalid code to test error handling
        data = {
            "email": "testpatient@example.com",
            "verification_code": "INVALID123"
        }
        
        response = self.make_request("POST", "/verify-email", data, expected_status=400)
        if response and "Invalid verification code" in response.get("detail", ""):
            self.log_test("Email Verification (Invalid Code)", True, 
                         "Correctly rejected invalid verification code")
            
            # For testing purposes, we'll manually activate the patient
            # In production, this would use the actual code sent via email
            print("   Note: In production, verification code would be sent via email")
            return True
        else:
            self.log_test("Email Verification (Invalid Code)", False, 
                         "Should have rejected invalid verification code")
            return False
            
    def test_doctor_login_before_approval(self):
        """Test doctor login before admin approval (should fail)."""
        data = {
            "email": "testdoctor@example.com",
            "password": "DoctorPass123!"
        }
        
        response = self.make_request("POST", "/login", data, expected_status=403)
        if response and "pending administrator approval" in response.get("detail", ""):
            self.log_test("Doctor Login (Before Approval)", True, 
                         "Correctly blocked unapproved doctor login")
            return True
        else:
            self.log_test("Doctor Login (Before Approval)", False, 
                         "Should have blocked unapproved doctor login")
            return False
            
    def test_invalid_login(self):
        """Test login with invalid credentials."""
        data = {
            "email": "nonexistent@example.com",
            "password": "WrongPassword123!"
        }
        
        response = self.make_request("POST", "/login", data, expected_status=401)
        if response and "Invalid email or password" in response.get("detail", ""):
            self.log_test("Invalid Login", True, "Correctly rejected invalid credentials")
            return True
        else:
            self.log_test("Invalid Login", False, "Should have rejected invalid credentials")
            return False
            
    def test_resend_verification(self):
        """Test resend verification endpoint."""
        data = {"email": "testpatient@example.com"}
        
        response = self.make_request("POST", "/resend-verification", data)
        if response and "resent successfully" in response.get("message", ""):
            self.log_test("Resend Verification", True, "Verification email resent")
            return True
        else:
            self.log_test("Resend Verification", False, "Failed to resend verification")
            return False
            
    def test_forgot_password(self):
        """Test forgot password endpoint."""
        data = {"email": "testpatient@example.com"}
        
        response = self.make_request("POST", "/forgot-password", data)
        if response and "password reset link" in response.get("message", ""):
            self.log_test("Forgot Password", True, "Password reset initiated")
            return True
        else:
            self.log_test("Forgot Password", False, "Failed to initiate password reset")
            return False
            
    def test_logout(self):
        """Test logout endpoint."""
        response = self.make_request("POST", "/logout")
        if response and "Logged out successfully" in response.get("message", ""):
            self.log_test("Logout", True, "Logout successful")
            return True
        else:
            self.log_test("Logout", False, "Logout failed")
            return False
            
    def test_protected_endpoint_without_token(self):
        """Test accessing protected endpoint without token."""
        response = self.make_request("GET", "/me", expected_status=401)
        if response and "detail" in response:
            self.log_test("Protected Endpoint (No Token)", True, 
                         "Correctly blocked access without token")
            return True
        else:
            self.log_test("Protected Endpoint (No Token)", False, 
                         "Should have blocked access without token")
            return False
            
    def test_openapi_docs(self):
        """Test if OpenAPI documentation is accessible."""
        try:
            response = requests.get(f"{BASE_URL}/docs")
            if response.status_code == 200:
                self.log_test("OpenAPI Documentation", True, 
                             "API documentation is accessible at /docs")
                return True
            else:
                self.log_test("OpenAPI Documentation", False, 
                             f"Documentation not accessible: {response.status_code}")
                return False
        except Exception as e:
            self.log_test("OpenAPI Documentation", False, f"Error accessing docs: {e}")
            return False
            
    def run_all_tests(self):
        """Run all endpoint tests."""
        print("🚀 Starting Authentication API Endpoint Tests\n")
        print("=" * 70)
        
        # Test basic connectivity
        if not self.test_server_connection():
            print("\n❌ Server not accessible. Make sure FastAPI server is running.")
            return False
            
        print()
        
        # Test registration endpoints
        print("📝 Testing Registration Endpoints:")
        self.test_patient_registration()
        self.test_doctor_registration()
        print()
        
        # Test authentication flow
        print("🔑 Testing Authentication Flow:")
        self.test_patient_login_before_verification()
        self.test_email_verification()
        self.test_doctor_login_before_approval()
        self.test_invalid_login()
        print()
        
        # Test utility endpoints
        print("🔧 Testing Utility Endpoints:")
        self.test_resend_verification()
        self.test_forgot_password()
        self.test_logout()
        self.test_protected_endpoint_without_token()
        print()
        
        # Test documentation
        print("📚 Testing Documentation:")
        self.test_openapi_docs()
        print()
        
        # Summary
        print("=" * 70)
        total_tests = len(self.test_results)
        passed_tests = sum(1 for result in self.test_results if result["success"])
        
        print(f"🎯 Test Results: {passed_tests}/{total_tests} tests passed")
        
        if passed_tests == total_tests:
            print("🎉 All tests passed! The authentication API is working correctly.")
            return True
        else:
            print("⚠️  Some tests failed. Check the implementation.")
            
            # Show failed tests
            failed_tests = [result for result in self.test_results if not result["success"]]
            if failed_tests:
                print("\n❌ Failed Tests:")
                for test in failed_tests:
                    print(f"   - {test['test']}: {test['details']}")
            
            return False

def main():
    """Main function to run the tests."""
    print("Waiting for server to start...")
    time.sleep(3)  # Give server time to start
    
    tester = APITester()
    success = tester.run_all_tests()
    
    print(f"\n📋 Test Summary:")
    print(f"   Server: FastAPI at {BASE_URL}")
    print(f"   Total Tests: {len(tester.test_results)}")
    print(f"   Passed: {sum(1 for r in tester.test_results if r['success'])}")
    print(f"   Failed: {sum(1 for r in tester.test_results if not r['success'])}")
    
    if success:
        print("\n✅ All authentication endpoints are working correctly!")
    else:
        print("\n❌ Some endpoints need attention.")
        
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main()) 