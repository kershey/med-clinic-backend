"""
Test script to try the resend verification endpoint.
"""
import json
import httpx
import asyncio
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get email from environment variables
TEST_EMAIL = os.getenv("MAIL_USERNAME")

async def test_resend_verification():
    # Create email data
    email_data = {
        "email": TEST_EMAIL
    }
    
    # Print test data
    print(f"Testing resend verification with email: {TEST_EMAIL}")
    
    try:
        # Send resend verification request
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "http://localhost:8000/api/v1/auth/resend-verification", 
                json=email_data
            )
            
            # Print response
            print(f"Status code: {response.status_code}")
            print(f"Response: {json.dumps(response.json(), indent=2) if response.status_code < 300 else response.text}")
    
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    asyncio.run(test_resend_verification()) 