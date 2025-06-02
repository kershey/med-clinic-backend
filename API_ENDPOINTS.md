# 🔐 Authentication API Endpoints

## Overview

This document outlines the Role-Based Authentication API endpoints following production best practices and industry standards.

## Base URL

```
http://localhost:8000/auth
```

---

## 📝 Registration Endpoints

### 1. Patient Registration

```http
POST /auth/register/patient
```

**Request Body:**

```json
{
  "email": "patient@example.com",
  "full_name": "John Patient",
  "password": "SecurePassword123!",
  "gender": "Male",
  "address": "123 Patient St",
  "contact": "+1234567890"
}
```

**Response (201):**

```json
{
  "message": "Patient account created successfully. Please check your email for verification code.",
  "user_id": 1,
  "email": "patient@example.com",
  "next_step": "verify_email"
}
```

### 2. Doctor Registration

```http
POST /auth/register/doctor
```

**Request Body:**

```json
{
  "email": "doctor@example.com",
  "full_name": "Dr. Jane Smith",
  "password": "DoctorPassword123!",
  "specialization": "Cardiology",
  "license_number": "MD123456",
  "bio": "Experienced cardiologist with 10 years of practice"
}
```

**Response (201):**

```json
{
  "message": "Doctor account created successfully. Your account is pending administrator approval.",
  "user_id": 2,
  "email": "doctor@example.com",
  "status": "pending_approval",
  "next_step": "wait_for_admin_approval"
}
```

### 3. Staff Registration (Admin Only)

```http
POST /auth/register/staff
Authorization: Bearer <admin_token>
```

**Request Body:**

```json
{
  "email": "staff@example.com",
  "full_name": "Alice Staff",
  "password": "StaffPassword123!",
  "department": "Administration",
  "employee_id": "EMP001"
}
```

**Response (201):**

```json
{
  "message": "Staff account created successfully.",
  "user_id": 3,
  "email": "staff@example.com",
  "temporary_password": "ABC123XYZ",
  "status": "pending_activation",
  "created_by": "admin@example.com"
}
```

### 4. Admin Registration (Admin Only)

```http
POST /auth/register/admin
Authorization: Bearer <admin_token>
```

**Request Body:**

```json
{
  "email": "newadmin@example.com",
  "full_name": "Bob Admin",
  "password": "AdminPassword123!",
  "admin_level": 3
}
```

**Response (201):**

```json
{
  "message": "Admin account created successfully. Account requires activation.",
  "user_id": 4,
  "email": "newadmin@example.com",
  "status": "disabled",
  "created_by": "admin@example.com",
  "admin_level": 3
}
```

---

## 🔑 Authentication Endpoints

### 1. Universal Login

```http
POST /auth/login
```

**Request Body:**

```json
{
  "email": "user@example.com",
  "password": "UserPassword123!"
}
```

**Response (200):**

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "user": {
    "id": 1,
    "email": "user@example.com",
    "full_name": "John User",
    "role": "patient",
    "account_status": "active",
    "is_verified": true,
    "created_at": "2024-01-01T00:00:00Z"
  },
  "permissions": [
    "read:profile",
    "update:profile",
    "read:doctors",
    "create:appointment",
    "read:appointments",
    "update:appointments",
    "read:medical_records",
    "create:payment",
    "read:payments"
  ]
}
```

### 2. Logout

```http
POST /auth/logout
Authorization: Bearer <token>
```

**Response (200):**

```json
{
  "message": "Logged out successfully"
}
```

### 3. Refresh Token

```http
POST /auth/refresh-token
Authorization: Bearer <token>
```

**Response (200):**

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "user": { ... },
  "permissions": [ ... ]
}
```

---

## ✉️ Email Verification

### 1. Verify Email

```http
POST /auth/verify-email
```

**Request Body:**

```json
{
  "email": "user@example.com",
  "verification_code": "ABC123"
}
```

**Response (200):**

```json
{
  "message": "Email verified successfully",
  "account_status": "active"
}
```

### 2. Resend Verification

```http
POST /auth/resend-verification
```

**Request Body:**

```json
{
  "email": "user@example.com"
}
```

**Response (200):**

```json
{
  "message": "Verification email resent successfully"
}
```

---

## 🔐 Password Management

### 1. Forgot Password

```http
POST /auth/forgot-password
```

**Request Body:**

```json
{
  "email": "user@example.com"
}
```

**Response (200):**

```json
{
  "message": "If the email exists, a password reset link has been sent"
}
```

### 2. Reset Password

```http
POST /auth/reset-password
```

**Request Body:**

```json
{
  "email": "user@example.com",
  "reset_token": "XYZ789",
  "new_password": "NewPassword123!"
}
```

**Response (200):**

```json
{
  "message": "Password reset successfully"
}
```

---

## 👤 User Profile

### Get Current User Profile

```http
GET /auth/me
Authorization: Bearer <token>
```

**Response (200):**

```json
{
  "id": 1,
  "email": "user@example.com",
  "full_name": "John User",
  "gender": "Male",
  "address": "123 User St",
  "contact": "+1234567890",
  "role": "patient",
  "account_status": "active",
  "is_verified": true,
  "profile_image": null,
  "created_at": "2024-01-01T00:00:00Z",
  "updated_at": "2024-01-01T00:00:00Z"
}
```

---

## 🛡️ Admin Management

### Update User Status

```http
PUT /auth/users/{user_id}/status
Authorization: Bearer <admin_token>
```

**Request Body:**

```json
{
  "new_status": "active",
  "reason": "Account approved after verification"
}
```

**Response (200):**

```json
{
  "message": "Account status updated to active",
  "user_email": "user@example.com",
  "old_status": "disabled",
  "new_status": "active",
  "updated_by": "admin@example.com"
}
```

---

## 📊 Account Status Types

| Status                 | Description                                       | Allowed Actions              |
| ---------------------- | ------------------------------------------------- | ---------------------------- |
| `pending_verification` | New account awaiting email verification           | Email verification only      |
| `pending_activation`   | Account created by admin awaiting first login     | First login to activate      |
| `disabled`             | Account created but not approved for access       | None (admin approval needed) |
| `active`               | Account verified and approved for system access   | All role-based permissions   |
| `deactivated`          | Previously active account that has been suspended | None                         |
| `red_tag`              | Account flagged for investigation                 | None                         |

---

## 🎯 Role-Based Permissions

### Patient Permissions

- `read:profile`, `update:profile`
- `read:doctors`
- `create:appointment`, `read:appointments`, `update:appointments`
- `read:medical_records`
- `create:payment`, `read:payments`

### Doctor Permissions

- `read:profile`, `update:profile`
- `read:appointments`, `update:appointments`
- `read:medical_records`, `create:medical_records`, `update:medical_records`
- `read:patients`
- `update:availability`

### Staff Permissions

- `read:profile`, `update:profile`
- `read:appointments`, `create:appointments`, `update:appointments`, `delete:appointments`
- `read:patients`, `update:patients`
- `read:doctors`, `update:doctors`
- `read:payments`, `update:payments`
- `create:notifications`
- `read:reports`

### Admin Permissions

- `read:profile`, `update:profile`
- `read:*`, `create:*`, `update:*`, `delete:*`
- `manage:users`, `manage:system`
- `read:logs`, `create:backups`

---

## 🚨 Error Responses

### 400 Bad Request

```json
{
  "detail": "Email already registered"
}
```

### 401 Unauthorized

```json
{
  "detail": "Invalid email or password"
}
```

### 403 Forbidden

```json
{
  "detail": "Account status: disabled. Your account is pending administrator approval."
}
```

### 404 Not Found

```json
{
  "detail": "User not found"
}
```

---

## 🔧 Implementation Notes

1. **Universal Login**: All users (patients, doctors, staff, admins) use the same `/auth/login` endpoint
2. **JWT Tokens**: Include user ID, email, role, account status, and permissions
3. **Role Validation**: Built into the login endpoint with role-specific checks
4. **Account Status**: Managed through the authentication flow and admin endpoints
5. **Security**: Passwords are hashed with bcrypt, tokens expire based on configuration

## 📚 Usage Examples

### Frontend Login Flow

```javascript
// Universal login for any role
const response = await fetch('/auth/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    email: 'user@example.com',
    password: 'password123',
  }),
});

const { access_token, user, permissions } = await response.json();

// Store token and user info
localStorage.setItem('token', access_token);
localStorage.setItem('user', JSON.stringify(user));
localStorage.setItem('permissions', JSON.stringify(permissions));
```

### Role-Specific Registration

```javascript
// Patient registration
const patientResponse = await fetch('/auth/register/patient', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    email: 'patient@example.com',
    full_name: 'John Patient',
    password: 'password123',
    gender: 'Male',
    address: '123 Patient St',
    contact: '+1234567890',
  }),
});
```

This production-standard API design provides a clean, intuitive, and secure authentication system that follows industry best practices. 🚀
