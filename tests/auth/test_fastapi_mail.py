"""
Test script for FastAPI-Mail to verify if email sending works with the current configuration.
"""
import os
import asyncio
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig, MessageType
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

async def test_email():
    # Email connection configuration using environment variables
    email_conf = ConnectionConfig(
        MAIL_USERNAME=os.getenv("MAIL_USERNAME"),
        MAIL_PASSWORD=os.getenv("MAIL_PASSWORD"),
        MAIL_FROM=os.getenv("MAIL_FROM"),
        MAIL_PORT=int(os.getenv("MAIL_PORT", 587)),
        MAIL_SERVER=os.getenv("MAIL_SERVER"),
        MAIL_STARTTLS=True,  # Use STARTTLS for Gmail
        MAIL_SSL_TLS=False,  # Must be False when using STARTTLS
        USE_CREDENTIALS=True,
        VALIDATE_CERTS=False  # Disable certificate validation to avoid SSL issues on macOS
    )

    # Print configuration (without password)
    print(f"Email Configuration:")
    print(f"- Server: {os.getenv('MAIL_SERVER')}")
    print(f"- Port: {os.getenv('MAIL_PORT')}")
    print(f"- Username: {os.getenv('MAIL_USERNAME')}")
    print(f"- From: {os.getenv('MAIL_FROM')}")
    print(f"- STARTTLS: True")
    print(f"- SSL/TLS: False")
    print(f"- USE_CREDENTIALS: True")
    print(f"- VALIDATE_CERTS: False")

    # Initialize FastMail instance
    mail = FastMail(email_conf)

    # Create test email content
    html_content = """
    <html>
        <body>
            <h1>Test Email from FastAPI-Mail</h1>
            <p>This is a test email to verify if FastAPI-Mail is working correctly.</p>
        </body>
    </html>
    """

    # Create message schema for email
    message = MessageSchema(
        subject="Test Email from FastAPI-Mail",
        recipients=[os.getenv("MAIL_USERNAME")],  # Send to yourself for testing
        body=html_content,
        subtype=MessageType.html
    )

    try:
        # Send the email
        print("\nSending email with FastAPI-Mail...")
        await mail.send_message(message)
        print("Email sent successfully!")
    except Exception as e:
        print(f"Error sending email: {str(e)}")

# Run the async function
if __name__ == "__main__":
    asyncio.run(test_email()) 