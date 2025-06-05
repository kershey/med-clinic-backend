"""
Test script to test Gmail's specific email requirements.
"""
import os
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Gmail settings from .env file
username = os.getenv("MAIL_USERNAME")
password = os.getenv("MAIL_PASSWORD")
mail_server = "smtp.gmail.com"  # Use hardcoded Gmail server
mail_port = 587  # Use standard port for Gmail

# Email content
sender_email = username
receiver_email = username  # Send to yourself for testing
subject = "Test Email with Debug Information"
message = "This is a test email to verify if Gmail-specific configuration works correctly."

# Create multipart message
msg = MIMEMultipart()
msg["From"] = sender_email
msg["To"] = receiver_email
msg["Subject"] = subject

# Add message body
msg.attach(MIMEText(message, "plain"))

# Print configuration (without password)
print(f"Gmail-Specific Configuration:")
print(f"- Server: {mail_server}")
print(f"- Port: {mail_port}")
print(f"- Username: {username}")
print(f"- From: {sender_email}")
print(f"- To: {receiver_email}")
print(f"- Password length: {len(password) if password else 0}")
print(f"- Password with spaces: {'Yes' if ' ' in password else 'No'}")

try:
    # Create SMTP session with detailed debugging
    print("\nConnecting to Gmail SMTP server...")
    smtp = smtplib.SMTP(mail_server, mail_port)
    smtp.set_debuglevel(2)  # Enable verbose debug output
    
    # Start TLS for security
    print("Starting TLS...")
    context = ssl.create_default_context()
    smtp.starttls(context=context)
    
    # Login with credentials
    print("Logging in...")
    smtp.login(username, password)
    
    # Send email
    print("Sending email...")
    smtp.send_message(msg)
    
    # Close the connection
    smtp.quit()
    
    print("\nEmail sent successfully!")
    
except Exception as e:
    print(f"\nError sending email: {str(e)}")
    
    # Additional debugging for Gmail-specific issues
    if "Application-specific password required" in str(e):
        print("\nGmail is rejecting your password. You need to use an App Password:")
        print("1. Go to your Google Account: https://myaccount.google.com/")
        print("2. Select Security > 2-Step Verification > App passwords")
        print("3. Create a new app password for 'Mail'")
        print("4. Use the generated password in your .env file (no spaces)")
    
    if "Username and Password not accepted" in str(e):
        print("\nPossible solutions:")
        print("1. Double-check your email and password")
        print("2. Make sure you're using an App Password if 2FA is enabled")
        print("3. Remove any spaces from the App Password")
        print("4. Check if 'Less secure app access' needs to be enabled")
    
    if "SMTP connect" in str(e):
        print("\nPossible solutions:")
        print("1. Check your network connection")
        print("2. Make sure port 587 is not blocked by firewall") 