"""
Authentication utility functions for email verification and notifications.
"""
import os
import random
import string
import logging
import smtplib
import ssl
import socket
import time
import asyncio
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List
from pydantic import EmailStr
from fastapi import BackgroundTasks
from datetime import datetime

from ..config import settings

# Set up logging
logger = logging.getLogger(__name__)

# Connection timeout settings
SMTP_TIMEOUT = 30  # 30 seconds timeout
MAX_RETRIES = 3
RETRY_DELAY = 2  # 2 seconds between retries

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

def validate_email_config() -> bool:
    """
    Validates that all required email configuration variables are set.
    
    Returns:
        bool: True if all required config is present, False otherwise
    """
    required_configs = [
        settings.mail_username,
        settings.mail_password,
        settings.mail_from,
        settings.mail_server
    ]
    
    missing_configs = [config for config in required_configs if not config]
    
    if missing_configs:
        logger.error(f"Missing email configuration: {len(missing_configs)} items")
        return False
    
    return True

async def send_verification_email(email: EmailStr, code: str) -> None:
    """
    Sends a verification email to the user using direct SMTP with retry logic.
    
    Args:
        email: User's email address
        code: Verification code to be sent
        
    Returns:
        None
        
    Raises:
        Exception: If email sending fails after all retries
    """
    if not validate_email_config():
        raise Exception("Email configuration is incomplete")
    
    logger.info(f"Attempting to send verification email to {email} with code {code}")
    
    # Create HTML body for verification email
    html_content = f"""
    <html>
        <head>
            <title>Medical Clinic - Email Verification</title>
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
                    <h1>Medical Clinic</h1>
                </div>
                <div class="content">
                    <p>Hello,</p>
                    <p>Thank you for registering with our Medical Clinic. To verify your email address, please use the following verification code:</p>
                    <div class="code">{code}</div>
                    <p>Please enter this code in the verification page to complete your registration.</p>
                    <p>If you did not request this code, please ignore this email.</p>
                    <p>Best regards,<br>Medical Clinic Team</p>
                </div>
                <div class="footer">
                    &copy; {datetime.now().year} Medical Clinic. All rights reserved.
                </div>
            </div>
        </body>
    </html>
    """
    
    # Create multipart message
    msg = MIMEMultipart()
    msg["From"] = settings.mail_from
    msg["To"] = email
    msg["Subject"] = "Medical Clinic - Email Verification"
    
    # Attach HTML content
    msg.attach(MIMEText(html_content, "html"))
    
    # Retry logic for email sending
    last_exception = None
    
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            logger.info(f"Email send attempt {attempt}/{MAX_RETRIES} to {email}")
            
            # Create SMTP session with timeout
            logger.info(f"Connecting to SMTP server {settings.mail_server}:{settings.mail_port}...")
            
            # Create a secure SSL context that works on macOS
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Set socket timeout
            socket.setdefaulttimeout(SMTP_TIMEOUT)
            
            with smtplib.SMTP(settings.mail_server, settings.mail_port, timeout=SMTP_TIMEOUT) as server:
                # Enable debug output for troubleshooting
                server.set_debuglevel(0)  # Set to 1 for detailed debug output
                
                server.ehlo()
                logger.info("Starting TLS...")
                server.starttls(context=context)
                server.ehlo()
                
                # Login to server
                logger.info(f"Logging in with username: {settings.mail_username}")
                server.login(settings.mail_username, settings.mail_password)
                
                # Send email
                logger.info(f"Sending email to {email}...")
                server.send_message(msg)
                
            logger.info(f"Email sent successfully to {email} on attempt {attempt}")
            return  # Success, exit function
            
        except smtplib.SMTPAuthenticationError as e:
            logger.error(f"SMTP Authentication failed on attempt {attempt}: {str(e)}")
            logger.error("Check your email App Password. You may need to generate a new one.")
            last_exception = e
            break  # Don't retry authentication errors
            
        except smtplib.SMTPRecipientsRefused as e:
            logger.error(f"SMTP Recipients refused on attempt {attempt}: {str(e)}")
            last_exception = e
            break  # Don't retry recipient errors
            
        except smtplib.SMTPServerDisconnected as e:
            logger.warning(f"SMTP server disconnected on attempt {attempt}: {str(e)}")
            last_exception = e
            if attempt < MAX_RETRIES:
                logger.info(f"Retrying in {RETRY_DELAY} seconds...")
                time.sleep(RETRY_DELAY)
                
        except (smtplib.SMTPConnectError, socket.timeout, socket.gaierror) as e:
            logger.warning(f"SMTP connection error on attempt {attempt}: {str(e)}")
            last_exception = e
            if attempt < MAX_RETRIES:
                logger.info(f"Retrying in {RETRY_DELAY} seconds...")
                time.sleep(RETRY_DELAY)
                
        except Exception as e:
            logger.error(f"Unexpected error on attempt {attempt}: {str(e)}")
            last_exception = e
            if attempt < MAX_RETRIES:
                logger.info(f"Retrying in {RETRY_DELAY} seconds...")
                time.sleep(RETRY_DELAY)
    
    # All retries failed
    error_msg = f"Failed to send email after {MAX_RETRIES} attempts. Last error: {str(last_exception)}"
    logger.error(error_msg)
    raise Exception(error_msg)

async def send_password_reset_email(email: EmailStr, full_name: str, reset_url: str, expires_at: datetime) -> None:
    """
    Send enhanced password reset email with secure link and clear instructions.
    
    Args:
        email: User's email address
        full_name: User's full name for personalization
        reset_url: Complete reset URL with token
        expires_at: When the reset token expires
        
    Returns:
        None
        
    Raises:
        Exception: If email sending fails after all retries
    """
    if not validate_email_config():
        raise Exception("Email configuration is incomplete")
    
    logger.info(f"Attempting to send password reset email to {email}")
    
    # Format expiry time in a user-friendly way
    expiry_time = expires_at.strftime("%I:%M %p")
    expiry_date = expires_at.strftime("%B %d, %Y")
    
    # Create HTML body for password reset email
    html_content = f"""
    <html>
        <head>
            <title>Medical Clinic - Password Reset</title>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background-color: #3498db; color: white; padding: 10px; text-align: center; }}
                .content {{ padding: 20px; border: 1px solid #ddd; }}
                .button {{ display: inline-block; padding: 10px 20px; background-color: #3498db; 
                        color: white; text-decoration: none; border-radius: 5px; margin: 20px 0; }}
                .warning {{ color: #e74c3c; font-weight: bold; }}
                .expiry {{ background-color: #f8f9fa; padding: 10px; border-left: 4px solid #3498db; margin: 15px 0; }}
                .footer {{ text-align: center; margin-top: 20px; font-size: 12px; color: #777; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Medical Clinic</h1>
                </div>
                <div class="content">
                    <p>Hello {full_name},</p>
                    <p>We received a request to reset your password for your Medical Clinic account. Please click the button below to reset your password:</p>
                    <p style="text-align: center;">
                        <a href="{reset_url}" class="button">Reset Password</a>
                    </p>
                    <div class="expiry">
                        <p><strong>Important:</strong> This link will expire on {expiry_date} at {expiry_time}.</p>
                    </div>
                    <p>If you can't click the button, copy and paste this link into your browser:</p>
                    <p style="word-break: break-all;">{reset_url}</p>
                    <p class="warning">If you did not request a password reset, please ignore this email or contact support if you have concerns.</p>
                    <p>Best regards,<br>Medical Clinic Team</p>
                </div>
                <div class="footer">
                    &copy; {datetime.now().year} Medical Clinic. All rights reserved.
                </div>
            </div>
        </body>
    </html>
    """
    
    # Create multipart message
    msg = MIMEMultipart()
    msg["From"] = settings.mail_from
    msg["To"] = email
    msg["Subject"] = "Medical Clinic - Password Reset Request"
    
    # Attach HTML content
    msg.attach(MIMEText(html_content, "html"))
    
    # Retry logic for email sending (similar to verification email)
    last_exception = None
    
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            logger.info(f"Password reset email send attempt {attempt}/{MAX_RETRIES} to {email}")
            
            # Create a secure SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Set socket timeout
            socket.setdefaulttimeout(SMTP_TIMEOUT)
            
            with smtplib.SMTP(settings.mail_server, settings.mail_port, timeout=SMTP_TIMEOUT) as server:
                server.ehlo()
                server.starttls(context=context)
                server.ehlo()
                server.login(settings.mail_username, settings.mail_password)
                server.send_message(msg)
                
            logger.info(f"Password reset email sent successfully to {email}")
            return
            
        except Exception as e:
            logger.error(f"Error sending password reset email on attempt {attempt}: {str(e)}")
            last_exception = e
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY)
    
    # All retries failed
    error_msg = f"Failed to send password reset email after {MAX_RETRIES} attempts"
    logger.error(error_msg)
    raise Exception(error_msg)

async def send_password_changed_notification(email: EmailStr, full_name: str) -> None:
    """
    Send notification when password has been changed.
    
    Args:
        email: User's email address
        full_name: User's full name for personalization
        
    Returns:
        None
        
    Raises:
        Exception: If email sending fails after all retries
    """
    if not validate_email_config():
        raise Exception("Email configuration is incomplete")
    
    logger.info(f"Attempting to send password changed notification to {email}")
    
    # Create HTML body for password changed notification
    html_content = f"""
    <html>
        <head>
            <title>Medical Clinic - Password Changed</title>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background-color: #2ecc71; color: white; padding: 10px; text-align: center; }}
                .content {{ padding: 20px; border: 1px solid #ddd; }}
                .alert {{ background-color: #f8f9fa; padding: 10px; border-left: 4px solid #2ecc71; margin: 15px 0; }}
                .warning {{ color: #e74c3c; font-weight: bold; }}
                .footer {{ text-align: center; margin-top: 20px; font-size: 12px; color: #777; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Medical Clinic</h1>
                </div>
                <div class="content">
                    <p>Hello {full_name},</p>
                    <div class="alert">
                        <p><strong>Your password has been successfully changed.</strong></p>
                    </div>
                    <p>This email confirms that your password for your Medical Clinic account has been changed.</p>
                    <p class="warning">If you did not make this change, please contact support immediately.</p>
                    <p>Best regards,<br>Medical Clinic Team</p>
                </div>
                <div class="footer">
                    &copy; {datetime.now().year} Medical Clinic. All rights reserved.
                </div>
            </div>
        </body>
    </html>
    """
    
    # Create multipart message
    msg = MIMEMultipart()
    msg["From"] = settings.mail_from
    msg["To"] = email
    msg["Subject"] = "Medical Clinic - Password Changed"
    
    # Attach HTML content
    msg.attach(MIMEText(html_content, "html"))
    
    # Retry logic for email sending (similar to other email functions)
    last_exception = None
    
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            logger.info(f"Password changed notification send attempt {attempt}/{MAX_RETRIES} to {email}")
            
            # Create a secure SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Set socket timeout
            socket.setdefaulttimeout(SMTP_TIMEOUT)
            
            with smtplib.SMTP(settings.mail_server, settings.mail_port, timeout=SMTP_TIMEOUT) as server:
                server.ehlo()
                server.starttls(context=context)
                server.ehlo()
                server.login(settings.mail_username, settings.mail_password)
                server.send_message(msg)
                
            logger.info(f"Password changed notification sent successfully to {email}")
            return
            
        except Exception as e:
            logger.error(f"Error sending password changed notification on attempt {attempt}: {str(e)}")
            last_exception = e
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY)
    
    # All retries failed
    error_msg = f"Failed to send password changed notification after {MAX_RETRIES} attempts"
    logger.error(error_msg)
    raise Exception(error_msg)
