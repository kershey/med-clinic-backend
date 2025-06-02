#!/usr/bin/env python3
"""
Comprehensive test script for the improved email verification system.
Tests both the direct email function and the FastAPI endpoints.
"""
import asyncio
import sys
import os
import time
import json
import httpx

# Add the project root to Python path
sys.path.append('.')

from app.api.utils.email import send_verification_email, validate_email_config

async def test_email_config():
    """Test email configuration validation."""
    print("🔧 Testing email configuration...")
    try:
        is_valid = validate_email_config()
        if is_valid:
            print("✅ Email configuration is valid")
            return True
        else:
            print("❌ Email configuration is invalid")
            return False
    except Exception as e:
        print(f"❌ Configuration test failed: {e}")
        return False

async def test_verification_email():
    """Test the improved verification email function."""
    print("\n📧 Testing verification email sending...")
    test_email = "jnsnaragon01@gmail.com"
    test_code = "TEST" + str(int(time.time() % 10000))
    
    try:
        await send_verification_email(test_email, test_code)
        print(f"✅ Verification email sent successfully with code: {test_code}")
        return True
    except Exception as e:
        print(f"❌ Verification email failed: {e}")
        return False

async def test_resend_endpoint():
    """Test the resend verification endpoint."""
    print("\n🔄 Testing resend verification endpoint...")
    
    email_data = {
        "email": "jnsnaragon01@gmail.com"
    }
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "http://localhost:8000/auth/resend-verification", 
                json=email_data,
                timeout=30.0
            )
            
            if response.status_code == 200:
                result = response.json()
                print(f"✅ Resend endpoint successful: {result.get('message')}")
                return True
            else:
                print(f"❌ Resend endpoint failed: {response.status_code} - {response.text}")
                return False
    except httpx.ConnectError:
        print("⚠️  FastAPI server not running. Skipping endpoint test.")
        return None
    except Exception as e:
        print(f"❌ Resend endpoint test failed: {e}")
        return False

async def test_error_handling():
    """Test error handling with invalid configuration."""
    print("\n🛡️  Testing error handling...")
    
    # Temporarily modify environment to test error handling
    original_username = os.environ.get('MAIL_USERNAME')
    os.environ['MAIL_USERNAME'] = ''
    
    try:
        # Import after modifying environment
        from importlib import reload
        import app.api.utils.email as email_module
        reload(email_module)
        
        # Test with invalid config
        await email_module.send_verification_email("test@example.com", "TEST123")
        print("❌ Error handling test failed - should have raised exception")
        return False
        
    except Exception as e:
        if "configuration is incomplete" in str(e):
            print("✅ Error handling working correctly")
            return True
        else:
            print(f"❌ Unexpected error: {e}")
            return False
    finally:
        # Restore original environment
        if original_username:
            os.environ['MAIL_USERNAME'] = original_username
        else:
            os.environ.pop('MAIL_USERNAME', None)

async def run_all_tests():
    """Run all email tests."""
    print("🚀 Starting Email Service Tests")
    print("=" * 50)
    
    results = []
    
    # Test 1: Configuration validation
    results.append(await test_email_config())
    
    # Test 2: Direct email function
    results.append(await test_verification_email())
    
    # Test 3: FastAPI endpoint
    endpoint_result = await test_resend_endpoint()
    if endpoint_result is not None:
        results.append(endpoint_result)
    
    # Test 4: Error handling
    results.append(await test_error_handling())
    
    # Summary
    print("\n" + "=" * 50)
    print("📊 Test Results Summary:")
    passed = sum(1 for r in results if r is True)
    failed = sum(1 for r in results if r is False)
    total = len(results)
    
    print(f"✅ Passed: {passed}")
    print(f"❌ Failed: {failed}")
    print(f"📈 Total:  {total}")
    
    if failed == 0:
        print("\n🎉 All tests passed! Email verification is working correctly.")
    else:
        print(f"\n⚠️  {failed} test(s) failed. Please check the error messages above.")
    
    return failed == 0

if __name__ == "__main__":
    success = asyncio.run(run_all_tests())
    sys.exit(0 if success else 1) 