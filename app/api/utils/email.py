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
import socket
import time
import asyncio
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List
from pydantic import EmailStr
from fastapi import BackgroundTasks
from dotenv import load_dotenv
from datetime import datetime

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

# Connection timeout settings
SMTP_TIMEOUT = 30  # 30 seconds timeout
MAX_RETRIES = 3
RETRY_DELAY = 2  # 2 seconds between retries

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

def validate_email_config() -> bool:
    """
    Validates that all required email configuration variables are set.
    
    Returns:
        bool: True if all required config is present, False otherwise
    """
    required_configs = [MAIL_USERNAME, MAIL_PASSWORD, MAIL_FROM, MAIL_SERVER]
    missing_configs = [config for config in required_configs if not config]
    
    if missing_configs:
        logger.error(f"Missing email configuration: {missing_configs}")
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
    
    # Retry logic for email sending
    last_exception = None
    
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            logger.info(f"Email send attempt {attempt}/{MAX_RETRIES} to {email}")
            
            # Create SMTP session with timeout
            logger.info(f"Connecting to SMTP server {MAIL_SERVER}:{MAIL_PORT}...")
            
            # Create a secure SSL context that works on macOS
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Set socket timeout
            socket.setdefaulttimeout(SMTP_TIMEOUT)
            
            with smtplib.SMTP(MAIL_SERVER, MAIL_PORT, timeout=SMTP_TIMEOUT) as server:
                # Enable debug output for troubleshooting
                server.set_debuglevel(0)  # Set to 1 for detailed debug output
                
                server.ehlo()
                logger.info("Starting TLS...")
                server.starttls(context=context)
                server.ehlo()
                
                # Login to server
                logger.info(f"Logging in with username: {MAIL_USERNAME}")
                server.login(MAIL_USERNAME, MAIL_PASSWORD)
                
                # Send email
                logger.info(f"Sending email to {email}...")
                server.send_message(msg)
                
            logger.info(f"Email sent successfully to {email} on attempt {attempt}")
            return  # Success, exit function
            
        except smtplib.SMTPAuthenticationError as e:
            logger.error(f"SMTP Authentication failed on attempt {attempt}: {str(e)}")
            logger.error("Check your Gmail App Password. You may need to generate a new one.")
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
    
    # Create enhanced HTML content
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Password Reset - Java Medical Clinic</title>
    </head>
    <body style="font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 0; background-color: #f4f4f4;">
        <div style="max-width: 600px; margin: 0 auto; background-color: white; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
            <!-- Header -->
            <div style="background-color: #4CAF50; color: white; padding: 30px 20px; text-align: center; border-radius: 8px 8px 0 0;">
                <h1 style="margin: 0; font-size: 28px;">Java Medical Clinic</h1>
                <p style="margin: 10px 0 0 0; font-size: 16px; opacity: 0.9;">Password Reset Request</p>
            </div>
            
            <!-- Content -->
            <div style="padding: 40px 30px;">
                <p style="font-size: 16px; margin-bottom: 20px;">Hello {full_name},</p>
                
                <p style="font-size: 16px; margin-bottom: 20px;">
                    We received a request to reset your password for your Java Medical Clinic account. 
                    If you made this request, click the button below to reset your password.
                </p>
                
                <!-- Expiry Warning -->
                <div style="background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 20px; border-radius: 8px; margin: 25px 0;">
                    <p style="margin: 0; font-size: 14px; color: #856404;">
                        <strong>⏰ Important:</strong> This link expires at <strong>{expiry_time}</strong> on <strong>{expiry_date}</strong> (15 minutes from now)
                    </p>
                </div>
                
                <!-- Reset Button -->
                <div style="text-align: center; margin: 35px 0;">
                    <a href="{reset_url}" 
                       style="background-color: #4CAF50; color: white; padding: 16px 32px; 
                              text-decoration: none; border-radius: 8px; display: inline-block; 
                              font-weight: bold; font-size: 16px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                              transition: background-color 0.3s;">
                        Reset My Password
                    </a>
                </div>
                
                <!-- Alternative Link -->
                <div style="margin: 30px 0;">
                    <p style="font-size: 14px; margin-bottom: 10px;"><strong>Can't click the button?</strong> Copy and paste this link into your browser:</p>
                    <div style="background-color: #f8f9fa; border: 1px solid #dee2e6; padding: 15px; border-radius: 4px; word-break: break-all;">
                        <p style="margin: 0; font-family: 'Courier New', monospace; font-size: 12px; color: #495057;">
                            {reset_url}
                        </p>
                    </div>
                </div>
                
                <!-- Security Notice -->
                <div style="background-color: #d1ecf1; border: 1px solid #bee5eb; padding: 20px; border-radius: 8px; margin-top: 30px;">
                    <h3 style="margin: 0 0 15px 0; font-size: 16px; color: #0c5460;">🔒 Security Notice</h3>
                    <ul style="margin: 0; padding-left: 20px; color: #0c5460;">
                        <li style="margin-bottom: 8px;">If you didn't request this password reset, please ignore this email and your account will remain secure</li>
                        <li style="margin-bottom: 8px;">This reset link can only be used once</li>
                        <li style="margin-bottom: 8px;">Never share this link with anyone</li>
                        <li>If you're having trouble, contact our support team</li>
                    </ul>
                </div>
            </div>
            
            <!-- Footer -->
            <div style="background-color: #f8f9fa; padding: 25px 30px; text-align: center; border-top: 1px solid #dee2e6;">
                <p style="margin: 0; font-size: 12px; color: #6c757d;">
                    © 2024 Java Medical Clinic. All rights reserved.<br>
                    This is an automated message, please do not reply to this email.
                </p>
            </div>
        </div>
    </body>
    </html>
    """
    
    # Create multipart message
    msg = MIMEMultipart()
    msg["From"] = MAIL_FROM
    msg["To"] = email
    msg["Subject"] = "Password Reset Request - Java Medical Clinic"
    
    # Attach HTML content
    msg.attach(MIMEText(html_content, "html"))
    
    # Retry logic for email sending
    last_exception = None
    
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            logger.info(f"Password reset email send attempt {attempt}/{MAX_RETRIES} to {email}")
            
            # Create SMTP session with timeout
            logger.info(f"Connecting to SMTP server {MAIL_SERVER}:{MAIL_PORT}...")
            
            # Create a secure SSL context that works on macOS
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Set socket timeout
            socket.setdefaulttimeout(SMTP_TIMEOUT)
            
            with smtplib.SMTP(MAIL_SERVER, MAIL_PORT, timeout=SMTP_TIMEOUT) as server:
                server.set_debuglevel(0)  # Set to 1 for detailed debug output
                
                server.ehlo()
                logger.info("Starting TLS...")
                server.starttls(context=context)
                server.ehlo()
                
                # Login to server
                logger.info(f"Logging in with username: {MAIL_USERNAME}")
                server.login(MAIL_USERNAME, MAIL_PASSWORD)
                
                # Send email
                logger.info(f"Sending password reset email to {email}...")
                server.send_message(msg)
                
            logger.info(f"Password reset email sent successfully to {email} on attempt {attempt}")
            return  # Success, exit function
            
        except smtplib.SMTPAuthenticationError as e:
            logger.error(f"SMTP Authentication failed on attempt {attempt}: {str(e)}")
            logger.error("Check your Gmail App Password. You may need to generate a new one.")
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
    error_msg = f"Failed to send password reset email after {MAX_RETRIES} attempts. Last error: {str(last_exception)}"
    logger.error(error_msg)
    raise Exception(error_msg)

async def send_password_changed_notification(email: EmailStr, full_name: str) -> None:
    """
    Send notification email after successful password change.
    
    Args:
        email: User's email address
        full_name: User's full name for personalization
        
    Returns:
        None
    """
    if not validate_email_config():
        logger.warning("Email configuration incomplete, skipping password change notification")
        return
    
    logger.info(f"Sending password change notification to {email}")
    
    # Current timestamp for the notification
    change_time = datetime.utcnow().strftime("%B %d, %Y at %I:%M %p UTC")
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>Password Changed - Java Medical Clinic</title>
    </head>
    <body style="font-family: Arial, sans-serif; line-height: 1.6; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="background-color: #4CAF50; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0;">
            <h1 style="margin: 0;">Java Medical Clinic</h1>
            <p style="margin: 5px 0 0 0;">Password Successfully Changed</p>
        </div>
        
        <div style="background-color: #f9f9f9; padding: 30px; border-radius: 0 0 8px 8px;">
            <p>Hello {full_name},</p>
            
            <p>This email confirms that your password was successfully changed on {change_time}.</p>
            
            <div style="background-color: #d4edda; border: 1px solid #c3e6cb; padding: 15px; border-radius: 4px; margin: 20px 0;">
                <p style="margin: 0;"><strong>✅ Your account is secure</strong></p>
                <p style="margin: 10px 0 0 0;">You can now use your new password to log into your account.</p>
            </div>
            
            <div style="background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 4px; margin: 20px 0;">
                <p style="margin: 0;"><strong>⚠️ Didn't change your password?</strong></p>
                <p style="margin: 10px 0 0 0;">If you didn't make this change, please contact our support team immediately.</p>
            </div>
            
            <p>Best regards,<br>Java Medical Clinic Team</p>
            
            <hr style="margin: 30px 0; border: none; border-top: 1px solid #ddd;">
            <p style="font-size: 12px; color: #666; text-align: center;">
                © 2024 Java Medical Clinic. All rights reserved.
            </p>
        </div>
    </body>
    </html>
    """
    
    try:
        # Create and send email
        msg = MIMEMultipart()
        msg["From"] = MAIL_FROM
        msg["To"] = email
        msg["Subject"] = "Password Changed Successfully - Java Medical Clinic"
        msg.attach(MIMEText(html_content, "html"))
        
        # Send with simplified retry (just one attempt for notifications)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with smtplib.SMTP(MAIL_SERVER, MAIL_PORT, timeout=SMTP_TIMEOUT) as server:
            server.starttls(context=context)
            server.login(MAIL_USERNAME, MAIL_PASSWORD)
            server.send_message(msg)
        
        logger.info(f"Password change notification sent successfully to {email}")
        
    except Exception as e:
        logger.error(f"Failed to send password change notification to {email}: {e}")
        # Don't raise exception for notification failures

def send_password_reset_email_sync(email: EmailStr, full_name: str, reset_url: str, expires_at: datetime) -> None:
    """
    Synchronous wrapper for send_password_reset_email to work with FastAPI background tasks.
    
    Args:
        email: User's email address
        full_name: User's full name for personalization
        reset_url: Complete reset URL with token
        expires_at: When the reset token expires
        
    Returns:
        None
    """
    import asyncio
    import threading
    import time
    
    # Add comprehensive logging
    logger.info(f"🔄 SYNC WRAPPER CALLED: email={email}, thread={threading.current_thread().name}")
    logger.info(f"🔄 SYNC WRAPPER: reset_url={reset_url}")
    logger.info(f"🔄 SYNC WRAPPER: expires_at={expires_at}")
    
    try:
        start_time = time.time()
        logger.info("🔄 SYNC WRAPPER: Creating new event loop...")
        
        # Run the async function in a new event loop
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            logger.info("🔄 SYNC WRAPPER: Running async email function...")
            result = loop.run_until_complete(send_password_reset_email(email, full_name, reset_url, expires_at))
            elapsed = time.time() - start_time
            logger.info(f"✅ SYNC WRAPPER SUCCESS: Email sent in {elapsed:.2f} seconds")
            return result
        finally:
            logger.info("🔄 SYNC WRAPPER: Closing event loop...")
            loop.close()
            
    except Exception as e:
        elapsed = time.time() - start_time
        logger.error(f"❌ SYNC WRAPPER FAILED after {elapsed:.2f}s: {e}")
        logger.error(f"❌ SYNC WRAPPER ERROR TYPE: {type(e).__name__}")
        import traceback
        logger.error(f"❌ SYNC WRAPPER TRACEBACK: {traceback.format_exc()}")
        raise

def send_password_changed_notification_sync(email: EmailStr, full_name: str) -> None:
    """
    Synchronous wrapper for send_password_changed_notification to work with FastAPI background tasks.
    
    Args:
        email: User's email address
        full_name: User's full name for personalization
        
    Returns:
        None
    """
    try:
        # Run the async function in a new event loop
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(send_password_changed_notification(email, full_name))
        finally:
            loop.close()
    except Exception as e:
        logger.error(f"Failed to send password changed notification via sync wrapper: {e}")
        raise 