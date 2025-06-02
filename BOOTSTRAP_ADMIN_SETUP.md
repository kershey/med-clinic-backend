# Environment Bootstrap Admin Setup

## 🚀 Quick Setup Guide

### 1. Add Bootstrap Credentials to .env File

Add these lines to your `.env` file to create the first admin automatically:

```bash
# Bootstrap Admin (First Admin Creation)
BOOTSTRAP_ADMIN_EMAIL=admin@yourclinic.com
BOOTSTRAP_ADMIN_PASSWORD=YourSecurePassword123
```

### 2. Start the Server

```bash
python -m uvicorn app.api.main:app --reload
```

### 3. Bootstrap Process (Automatic)

The server will automatically:

- ✅ Check if any admin users exist
- ✅ If no admins found, create first admin from environment variables
- ✅ Log the bootstrap process for verification

### 4. Login & Update Credentials

```bash
# Login with bootstrap credentials
POST /auth/login
{
  "email": "admin@yourclinic.com",
  "password": "YourSecurePassword123"
}

# Change password (recommended)
PUT /auth/change-password
{
  "current_password": "YourSecurePassword123",
  "new_password": "MyNewSecurePassword"
}
```

### 5. Cleanup (Optional but Recommended)

After successful login, remove bootstrap credentials from .env:

```bash
# Remove these lines from .env after bootstrap
# BOOTSTRAP_ADMIN_EMAIL=admin@yourclinic.com
# BOOTSTRAP_ADMIN_PASSWORD=YourSecurePassword123
```

## 📋 Bootstrap Process Details

### What Happens During Bootstrap:

1. **Server Startup** - Reads .env file for bootstrap credentials
2. **Admin Check** - Queries database for existing admin users
3. **Creation** - If no admins exist AND bootstrap credentials provided, creates first admin
4. **Activation** - Bootstrap admin is immediately ACTIVE (no approval needed)
5. **Logging** - Process is logged for verification and debugging

### Bootstrap Admin Properties:

- **Role**: ADMIN
- **Status**: ACTIVE (immediately usable)
- **Verified**: True (no email verification needed)
- **Full Name**: "System Administrator" (can be changed later)
- **Created By**: NULL (system created)

### Safety Features:

- ✅ Only runs if NO admin users exist
- ✅ Validates environment variables before creation
- ✅ Checks for email conflicts before creation
- ✅ Uses secure password hashing
- ✅ Includes error handling and rollback

## 🔧 Environment Variables

### Required for Bootstrap:

```bash
BOOTSTRAP_ADMIN_EMAIL=your_admin_email@domain.com
BOOTSTRAP_ADMIN_PASSWORD=your_secure_password
```

### Complete .env Example:

```bash
# Database
DATABASE_URL=postgresql://username:password@localhost/clinic_db

# JWT
SECRET_KEY=your_jwt_secret_key_here
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Email (SMTP)
MAIL_USERNAME=your_email@gmail.com
MAIL_PASSWORD=your_app_password
MAIL_FROM=your_email@gmail.com
MAIL_PORT=587
MAIL_SERVER=smtp.gmail.com
MAIL_STARTTLS=true
MAIL_SSL_TLS=false
USE_CREDENTIALS=true
VALIDATE_CERTS=true

# Frontend
FRONTEND_URL=http://localhost:3000

# Bootstrap Admin (First Admin Creation)
BOOTSTRAP_ADMIN_EMAIL=admin@yourclinic.com
BOOTSTRAP_ADMIN_PASSWORD=YourSecurePassword123
```

## 🔄 Normal Operation After Bootstrap

Once the first admin is created:

1. **Admin Management** - Use existing admin endpoints to create more admins
2. **Credential Updates** - Use standard auth endpoints to update email/password
3. **Role Management** - Bootstrap admin has full permissions like any admin
4. **Environment Cleanup** - Bootstrap variables can be removed from .env

## 🚨 Important Notes

- **One-Time Process** - Bootstrap only runs if NO admins exist
- **Security** - Bootstrap credentials should be strong and changed after first login
- **Environment** - Different credentials can be used for dev/staging/production
- **Cleanup** - Remove bootstrap credentials from .env after successful setup
- **Standard Flow** - After bootstrap, all admin management uses normal API endpoints

## 📝 Log Messages

### Successful Bootstrap:

```
🔍 Checking for existing admin users...
🚀 No admin users found. Attempting bootstrap admin creation...
✅ Bootstrap admin created successfully: admin@yourclinic.com (ID: 1)
🎉 Bootstrap admin creation completed successfully!
💡 You can now log in with the bootstrap credentials and change them if needed.
```

### Bootstrap Skipped (Admin Exists):

```
🔍 Checking for existing admin users...
✅ Admin users found (2 total). Bootstrap not needed.
```

### Bootstrap Skipped (No Credentials):

```
🔍 Checking for existing admin users...
🚀 No admin users found. Attempting bootstrap admin creation...
⚠️  Bootstrap admin creation skipped.
💡 To create the first admin, set BOOTSTRAP_ADMIN_EMAIL and BOOTSTRAP_ADMIN_PASSWORD in your .env file.
```
