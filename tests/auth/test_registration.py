"""
Test script to try the registration endpoint directly.
"""
import json
import random
import string
import httpx
import asyncio
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get email from environment variables (just for testing purposes)
TEST_EMAIL = os.getenv("MAIL_USERNAME")

# Generate random data for testing
def generate_random_string(length=8):
    return ''.join(random.choices(string.ascii_lowercase, k=length))

async def test_registration():
    # Create random email
    random_email = f"{generate_random_string(8)}@example.com"
    
    # Create random user data
    user_data = {
        "email": random_email,  # Use a random email to avoid conflicts
        "full_name": f"Test User {generate_random_string(4)}",
        "gender": "Male",
        "address": "123 Test Street",
        "contact": "123-456-7890",
        "password": "Password123!"
    }
    
    # Print test data
    print(f"Testing registration with email: {random_email}")
    
    try:
        # Send registration request
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "http://localhost:8000/api/v1/auth/register/patient", 
                json=user_data
            )
            
            # Print response
            print(f"Status code: {response.status_code}")
            print(f"Response: {json.dumps(response.json(), indent=2)}")
    
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    asyncio.run(test_registration()) 