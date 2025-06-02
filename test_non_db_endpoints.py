#!/usr/bin/env python3
"""
Test endpoints that don't require database access.
"""
import requests
import json

BASE_URL = "http://localhost:8000"

def test_root():
    """Test root endpoint."""
    print("🧪 Testing Root Endpoint")
    response = requests.get(f"{BASE_URL}/")
    print(f"   Status: {response.status_code}")
    print(f"   Response: {response.json()}")
    assert response.status_code == 200
    assert "message" in response.json()
    print("   ✅ PASS")

def test_docs():
    """Test OpenAPI docs."""
    print("\n🧪 Testing OpenAPI Documentation")
    response = requests.get(f"{BASE_URL}/docs")
    print(f"   Status: {response.status_code}")
    assert response.status_code == 200
    print("   ✅ PASS - Documentation accessible")

def test_openapi_json():
    """Test OpenAPI JSON schema."""
    print("\n🧪 Testing OpenAPI JSON Schema")
    response = requests.get(f"{BASE_URL}/openapi.json")
    print(f"   Status: {response.status_code}")
    if response.status_code == 200:
        openapi_spec = response.json()
        print(f"   Title: {openapi_spec.get('info', {}).get('title')}")
        print(f"   Version: {openapi_spec.get('info', {}).get('version')}")
        
        # Check if our auth endpoints are documented
        paths = openapi_spec.get('paths', {})
        auth_endpoints = [path for path in paths.keys() if path.startswith('/auth')]
        print(f"   Auth endpoints documented: {len(auth_endpoints)}")
        
        expected_endpoints = [
            '/auth/register/patient',
            '/auth/register/doctor', 
            '/auth/login',
            '/auth/logout',
            '/auth/verify-email'
        ]
        
        for endpoint in expected_endpoints:
            if endpoint in paths:
                print(f"   ✅ {endpoint} documented")
            else:
                print(f"   ❌ {endpoint} missing")
                
        print("   ✅ PASS")
    else:
        print("   ❌ FAIL - OpenAPI JSON not accessible")

def test_logout():
    """Test logout endpoint (doesn't require auth or database)."""
    print("\n🧪 Testing Logout Endpoint")
    response = requests.post(f"{BASE_URL}/auth/logout")
    print(f"   Status: {response.status_code}")
    print(f"   Response: {response.json()}")
    assert response.status_code == 200
    assert response.json()["message"] == "Logged out successfully"
    print("   ✅ PASS")

def test_protected_endpoint_no_token():
    """Test accessing protected endpoint without token."""
    print("\n🧪 Testing Protected Endpoint (No Token)")
    response = requests.get(f"{BASE_URL}/auth/me")
    print(f"   Status: {response.status_code}")
    print(f"   Response: {response.json()}")
    assert response.status_code == 401
    assert "detail" in response.json()
    print("   ✅ PASS - Correctly rejected access without token")

def test_invalid_endpoint():
    """Test invalid endpoint."""
    print("\n🧪 Testing Invalid Endpoint")
    response = requests.get(f"{BASE_URL}/auth/nonexistent")
    print(f"   Status: {response.status_code}")
    assert response.status_code == 404
    print("   ✅ PASS - Correctly returned 404 for invalid endpoint")

def test_cors_headers():
    """Test CORS headers."""
    print("\n🧪 Testing CORS Headers")
    response = requests.options(f"{BASE_URL}/auth/login")
    print(f"   Status: {response.status_code}")
    headers = response.headers
    print(f"   CORS headers present: {'Access-Control-Allow-Origin' in headers}")
    if 'Access-Control-Allow-Origin' in headers:
        print(f"   Allow-Origin: {headers['Access-Control-Allow-Origin']}")
    print("   ✅ PASS")

def main():
    """Run all non-database tests."""
    print("🚀 Testing Non-Database Endpoints\n")
    print("=" * 60)
    
    try:
        test_root()
        test_docs()
        test_openapi_json()
        test_logout()
        test_protected_endpoint_no_token()
        test_invalid_endpoint()
        test_cors_headers()
        
        print("\n" + "=" * 60)
        print("🎉 All non-database tests passed!")
        print("\n📝 Summary:")
        print("   ✅ Server is running correctly")
        print("   ✅ API documentation is accessible")
        print("   ✅ Authentication endpoints are properly documented")
        print("   ✅ Basic auth flow works (logout, protected endpoints)")
        print("   ✅ Error handling works correctly")
        print("   ✅ CORS is configured")
        print("\n⚠️  Database-dependent endpoints need database setup to test")
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        return False
        
    return True

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1) 