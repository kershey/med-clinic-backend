# Email Verification Troubleshooting Guide

## Overview

This guide helps diagnose and fix email verification issues in the FastAPI Appointment System.

## Quick Diagnostics

### 1. Test Email Configuration

```bash
python test_verification_fix.py
```

### 2. Run Comprehensive Tests

```bash
python test_email_fixes.py
```

### 3. Check Email Health (Admin only)

```bash
curl -X GET "http://localhost:8000/auth/email-health" \
     -H "Authorization: Bearer YOUR_ADMIN_TOKEN"
```

## Common Issues and Solutions

### ❌ "Email service unavailable"

**Possible Causes:**

- Gmail app password expired
- Network connectivity issues
- SMTP server temporarily down
- SSL/TLS connection problems

**Solutions:**

1. **Update Gmail App Password:**

   - Go to Google Account → Security → 2-Step Verification → App Passwords
   - Generate new app password
   - Update `MAIL_PASSWORD` in `.env` file

2. **Check Network Connection:**

   ```bash
   telnet smtp.gmail.com 587
   ```

3. **Test SMTP Connection:**
   ```bash
   python app/tests/test_gmail_specific.py
   ```

### ❌ "SMTP Authentication failed"

**Solution:**

1. Verify Gmail credentials in `.env`
2. Ensure using App Password (not regular password)
3. Check for extra spaces in password
4. Regenerate App Password if needed

### ❌ "Email configuration is incomplete"

**Solution:**
Check that all required environment variables are set in `.env`:

```env
MAIL_USERNAME=your-gmail@gmail.com
MAIL_PASSWORD=your-app-password
MAIL_FROM=your-gmail@gmail.com
MAIL_PORT=587
MAIL_SERVER=smtp.gmail.com
```

### ❌ "Connection timeout" / "SMTP connect error"

**Solutions:**

1. Check firewall settings (allow port 587)
2. Verify internet connection
3. Try different network (corporate networks may block SMTP)
4. Check if Gmail SMTP is accessible from your location

## Email Service Improvements

### ✅ Enhanced Features (v2.0)

- **Retry Logic:** Automatically retries failed emails up to 3 times
- **Better Error Messages:** Specific error details for different failure types
- **Connection Timeout:** 30-second timeout prevents hanging
- **Configuration Validation:** Validates all required settings before sending
- **Health Check Endpoint:** Admin can check email service status

### ✅ Error Handling

- Authentication errors → Don't retry (fix credentials)
- Network errors → Retry with delay
- Timeout errors → Retry with delay
- Configuration errors → Don't retry (fix config)

## Patient Registration Flow

### Normal Flow:

1. Patient registers → Account created (user_id assigned)
2. Verification email sent → Success message
3. Patient enters code → Account activated

### Error Flow:

1. Patient registers → Account created (user_id assigned)
2. Email fails → Error message with retry option
3. Patient uses "Resend Verification" → Retry email sending
4. Patient enters code → Account activated

## Testing Commands

### Basic Email Test

```bash
cd app/tests
python test_email.py
```

### Gmail-Specific Test

```bash
cd app/tests
python test_gmail_specific.py
```

### FastAPI-Mail Test

```bash
cd app/tests
python test_fastapi_mail.py
```

### Resend Verification Test

```bash
cd app/tests
python test_resend_verification.py
```

## Environment Variables Reference

```env
# Required Email Settings
MAIL_USERNAME=your-gmail@gmail.com     # Gmail address
MAIL_PASSWORD=app-password-here        # Gmail App Password (16 chars)
MAIL_FROM=your-gmail@gmail.com         # Sender address
MAIL_SERVER=smtp.gmail.com             # SMTP server
MAIL_PORT=587                          # SMTP port

# Optional Email Settings
MAIL_STARTTLS=True                     # Use STARTTLS
MAIL_SSL_TLS=False                     # SSL/TLS setting
USE_CREDENTIALS=True                   # Use authentication
VALIDATE_CERTS=False                   # Validate certificates
```

## Monitoring and Logs

### Check Logs

```bash
tail -f server.log
```

### Enable Debug Mode

Set `server.set_debuglevel(1)` in `app/api/utils/email.py` for detailed SMTP logs.

## Alternative Email Providers

If Gmail continues to have issues, consider switching to:

### SendGrid (Recommended)

```env
MAIL_SERVER=smtp.sendgrid.net
MAIL_PORT=587
MAIL_USERNAME=apikey
MAIL_PASSWORD=your-sendgrid-api-key
```

### AWS SES

```env
MAIL_SERVER=email-smtp.us-east-1.amazonaws.com
MAIL_PORT=587
MAIL_USERNAME=your-aws-access-key
MAIL_PASSWORD=your-aws-secret-key
```

## Support

If issues persist:

1. Run comprehensive tests: `python test_email_fixes.py`
2. Check health endpoint (admin): `/auth/email-health`
3. Review server logs for detailed error messages
4. Consider switching to a more reliable email provider
