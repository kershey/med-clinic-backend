"""
Test script to verify if email sending works with the current configuration.
"""
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Email settings from .env file
username = os.getenv("MAIL_USERNAME")
password = os.getenv("MAIL_PASSWORD")
mail_server = os.getenv("MAIL_SERVER")
mail_port = int(os.getenv("MAIL_PORT", 587))

# Email content
sender_email = os.getenv("MAIL_FROM")
receiver_email = username  # Send to yourself for testing
subject = "Test Email from Medical Clinic"
message = "This is a test email to verify if email sending works correctly."

# Create multipart message
msg = MIMEMultipart()
msg["From"] = sender_email
msg["To"] = receiver_email
msg["Subject"] = subject

# Add message body
msg.attach(MIMEText(message, "plain"))

# Print configuration (without password)
print(f"Email Configuration:")
print(f"- Server: {mail_server}")
print(f"- Port: {mail_port}")
print(f"- Username: {username}")
print(f"- From: {sender_email}")
print(f"- To: {receiver_email}")

try:
    # Create SMTP session
    print("\nConnecting to SMTP server...")
    with smtplib.SMTP(mail_server, mail_port) as server:
        # Start TLS for security
        print("Starting TLS...")
        server.starttls()
        
        # Login with credentials
        print("Logging in...")
        server.login(username, password)
        
        # Send email
        print("Sending email...")
        server.send_message(msg)
        
    print("\nEmail sent successfully!")
    
except Exception as e:
    print(f"\nError sending email: {str(e)}")
    
    # Additional debugging information for common issues
    if "Authentication" in str(e):
        print("\nPossible solutions:")
        print("1. Check if your email and password are correct")
        print("2. For Gmail: Make sure you're using an App Password")
        print("   - Go to Google Account > Security > 2-Step Verification")
        print("   - At the bottom, select 'App passwords'")
        print("   - Create a new app password for your application")
        print("3. Gmail may require less secure app access")
    
    if "SMTP connect" in str(e):
        print("\nPossible solutions:")
        print("1. Check if your MAIL_SERVER and MAIL_PORT are correct")
        print("2. Make sure your network allows connections to the mail server") 