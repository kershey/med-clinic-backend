"""
Email utilities for sending verification emails and other notifications.
Uses a custom SMTP implementation to avoid SSL certificate issues on macOS.
"""
import os
import random
import string
import logging
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List
from pydantic import EmailStr
from fastapi import BackgroundTasks
from dotenv import load_dotenv

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()

# Get email settings from environment variables
MAIL_USERNAME = os.getenv("MAIL_USERNAME")
MAIL_PASSWORD = os.getenv("MAIL_PASSWORD")
MAIL_FROM = os.getenv("MAIL_FROM")
MAIL_PORT = int(os.getenv("MAIL_PORT", 587))
MAIL_SERVER = os.getenv("MAIL_SERVER")

# Log email configuration (without password)
logger.info(f"Email Configuration: SERVER={MAIL_SERVER}, PORT={MAIL_PORT}, FROM={MAIL_FROM}, USERNAME={MAIL_USERNAME}")

def generate_verification_code(length: int = 6) -> str:
    """
    Generates a random verification code of specified length.
    
    Args:
        length: Length of the verification code (default: 6)
        
    Returns:
        A random string containing uppercase letters and digits
    """
    # Create a verification code using uppercase letters and digits
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

async def send_verification_email(email: EmailStr, code: str) -> None:
    """
    Sends a verification email to the user using direct SMTP.
    
    Args:
        email: User's email address
        code: Verification code to be sent
        
    Returns:
        None
    """
    logger.info(f"Attempting to send verification email to {email} with code {code}")
    
    # Create HTML body for verification email
    html_content = f"""
    <html>
        <head>
            <title>Java Medical Clinic - Email Verification</title>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background-color: #4CAF50; color: white; padding: 10px; text-align: center; }}
                .content {{ padding: 20px; border: 1px solid #ddd; }}
                .code {{ font-size: 24px; font-weight: bold; text-align: center; 
                        margin: 20px 0; padding: 10px; background-color: #f5f5f5; }}
                .footer {{ text-align: center; margin-top: 20px; font-size: 12px; color: #777; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Java Medical Clinic</h1>
                </div>
                <div class="content">
                    <p>Hello,</p>
                    <p>Thank you for registering with Java Medical Clinic. To verify your email address, please use the following verification code:</p>
                    <div class="code">{code}</div>
                    <p>Please enter this code in the verification page to complete your registration.</p>
                    <p>If you did not request this code, please ignore this email.</p>
                    <p>Best regards,<br>Java Medical Clinic Team</p>
                </div>
                <div class="footer">
                    &copy; 2023 Java Medical Clinic. All rights reserved.
                </div>
            </div>
        </body>
    </html>
    """
    
    # Create multipart message
    msg = MIMEMultipart()
    msg["From"] = MAIL_FROM
    msg["To"] = email
    msg["Subject"] = "Java Medical Clinic - Email Verification"
    
    # Attach HTML content
    msg.attach(MIMEText(html_content, "html"))
    
    try:
        # Create SMTP session
        logger.info(f"Connecting to SMTP server {MAIL_SERVER}:{MAIL_PORT}...")
        
        # Create a secure SSL context that works on macOS
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with smtplib.SMTP(MAIL_SERVER, MAIL_PORT) as server:
            server.ehlo()
            server.starttls(context=context)
            server.ehlo()
            
            # Login to server
            logger.info(f"Logging in with username: {MAIL_USERNAME}")
            server.login(MAIL_USERNAME, MAIL_PASSWORD)
            
            # Send email
            logger.info(f"Sending email to {email}...")
            server.send_message(msg)
            
        logger.info(f"Email sent successfully to {email}")
    except Exception as e:
        logger.error(f"Failed to send email: {str(e)}")
        raise

async def send_verification_email_background(background_tasks: BackgroundTasks, email: EmailStr, code: str) -> None:
    """
    Adds email sending to background tasks for asynchronous processing.
    
    Args:
        background_tasks: FastAPI BackgroundTasks instance
        email: User's email address
        code: Verification code to be sent
        
    Returns:
        None
    """
    logger.info(f"Adding email verification task to background for {email}")
    # Add email sending to background tasks
    background_tasks.add_task(send_verification_email, email, code)

async def send_password_reset_email(email: EmailStr, token: str) -> None:
    """
    Sends a password reset email with a reset link.
    
    Args:
        email: User's email address
        token: Password reset token
        
    Returns:
        None
    """
    # Create HTML body for password reset email
    reset_link = f"{os.getenv('FRONTEND_URL', 'http://localhost:3000')}/reset-password?token={token}"
    html_content = f"""
    <html>
        <head>
            <title>Java Medical Clinic - Password Reset</title>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background-color: #4CAF50; color: white; padding: 10px; text-align: center; }}
                .content {{ padding: 20px; border: 1px solid #ddd; }}
                .button {{ display: inline-block; background-color: #4CAF50; color: white; 
                         padding: 10px 20px; text-decoration: none; border-radius: 4px; }}
                .footer {{ text-align: center; margin-top: 20px; font-size: 12px; color: #777; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Java Medical Clinic</h1>
                </div>
                <div class="content">
                    <p>Hello,</p>
                    <p>We received a request to reset your password. Click the button below to reset it:</p>
                    <p style="text-align: center;">
                        <a href="{reset_link}" class="button">Reset Password</a>
                    </p>
                    <p>If you did not request a password reset, please ignore this email.</p>
                    <p>This link will expire in 30 minutes.</p>
                    <p>Best regards,<br>Java Medical Clinic Team</p>
                </div>
                <div class="footer">
                    &copy; 2023 Java Medical Clinic. All rights reserved.
                </div>
            </div>
        </body>
    </html>
    """
    
    # Create multipart message
    msg = MIMEMultipart()
    msg["From"] = MAIL_FROM
    msg["To"] = email
    msg["Subject"] = "Java Medical Clinic - Password Reset"
    
    # Attach HTML content
    msg.attach(MIMEText(html_content, "html"))
    
    try:
        # Create SMTP session
        logger.info(f"Connecting to SMTP server {MAIL_SERVER}:{MAIL_PORT}...")
        
        # Create a secure SSL context that works on macOS
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with smtplib.SMTP(MAIL_SERVER, MAIL_PORT) as server:
            server.ehlo()
            server.starttls(context=context)
            server.ehlo()
            
            # Login to server
            server.login(MAIL_USERNAME, MAIL_PASSWORD)
            
            # Send email
            logger.info(f"Sending password reset email to {email}...")
            server.send_message(msg)
            
        logger.info(f"Password reset email sent successfully to {email}")
    except Exception as e:
        logger.error(f"Failed to send password reset email: {str(e)}")
        raise 