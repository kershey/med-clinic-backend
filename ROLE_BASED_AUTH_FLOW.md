# Role-Based Authentication Flow

## User Role: Patient

- **Registration**
  - Completes patient registration form
  - Account created with status "Pending Verification"
  - Email verification sent
- **Verification**
  - Verifies email to change status to "Active"
  - No admin approval required for basic access
- **Login**
  - Logs in with verified credentials
  - System confirms "User" role and "Active" status
  - Granted access to patient portal
- **Account Management**
  - Can update personal profile information
  - Can book and manage appointments
  - Cannot access restricted medical areas

## User Role: Doctor

- **Registration**
  - Completes doctor registration with professional details
  - Account created with status "Disabled"
  - Cannot access system until approved
- **Admin Approval**
  - Admin reviews doctor credentials and qualifications
  - Admin changes status from "Disabled" to "Active"
- **Login**
  - Logs in with credentials
  - System confirms "Doctor" role and "Active" status
  - Granted access to doctor portal
- **Availability Management**
  - Admin sets "onhire" status to make doctor visible to patients
- **Clinical Access**
  - Can view assigned patient records
  - Can create diagnoses and prescriptions
  - Access limited to own patients only

## User Role: Staff

- **Registration**
  - Admin creates staff account through dashboard
  - Staff's professional details entered by admin
  - Account created with status "Pending Activation"
  - System generates temporary access credentials
- **Account Activation**
  - Staff receives secure email with activation instructions
  - Staff sets permanent password on first login
  - Account status automatically changes to "Active" upon completion
  - System logs activation time and admin who created the account
- **Login**
  - Staff logs in with credentials
  - System confirms "Staff" role and "Active" status
  - Granted access to administrative functions
- **Administrative Tasks**
  - Can manage appointment scheduling
  - Can process patient check-ins
  - Limited ability to update patient records

## User Role: Admin

### **First Admin Creation (Environment Bootstrap)**

- **Bootstrap Setup**
  - System administrator sets `BOOTSTRAP_ADMIN_EMAIL` and `BOOTSTRAP_ADMIN_PASSWORD` in environment variables
  - Server automatically detects if no admin users exist during startup
  - First admin account created automatically with "Active" status
  - Bootstrap admin immediately functional with full permissions
- **Bootstrap Security**
  - Environment credentials are temporary and should be changed after first login
  - Bootstrap process only runs once when no admins exist
  - Environment variables can be removed after successful admin creation
- **First Login**
  - Bootstrap admin logs in with environment credentials
  - Changes password using standard password change endpoints
  - Can immediately create additional admin accounts

### **Subsequent Admin Creation (Normal Flow)**

- **Registration**
  - Existing admin uses admin registration form in dashboard application
  - Account created with "Admin" role and "Disabled" status
- **Activation**
  - Existing admin reviews and activates the new admin account
  - Account status changed from "Disabled" to "Active"
  - Full permissions granted upon activation
- **Approval Process**
  - Created by existing admin through secure admin panel
  - Requires admin approval before account becomes functional
  - Audit trail maintained of who created which admin accounts

### **Admin Login & Operations**

- **Login**
  - Logs in with credentials (bootstrap or regular)
  - System confirms "Admin" role and "Active" status
  - Granted access to all system functions
- **Privileges**
  - Can manage all other user accounts
  - Can activate/deactivate accounts
  - Can assign roles and permissions
  - Can create additional admin, staff, and approve doctor accounts
- **System Management**
  - Full access to system configuration
  - Can generate system-wide reports
  - Can audit user activities
  - Access to environment bootstrap logs and security settings

### **Admin Account Security**

- **Bootstrap Admin Features**
  - Created automatically from environment variables
  - Immediately active (no approval required)
  - Full name defaults to "System Administrator" (can be updated)
  - No creator reference (system-generated)
- **Regular Admin Features**
  - Created by existing admin through normal registration
  - Requires activation by existing admin
  - Creator tracked for audit purposes
  - Follow standard approval workflow

## Account Status Types

- **Pending Verification** - New account awaiting email verification
- **Pending Activation** - Account created by admin awaiting first login
- **Disabled** - Account created but not yet approved for access
- **Active** - Account verified and approved for system access
- **Deactivated** - Previously active account that has been suspended
- **Red Tag** - Account flagged for investigation or special handling

## Bootstrap vs Normal Admin Creation

| Aspect                | Bootstrap Admin (First)                  | Normal Admin (Additional)         |
| --------------------- | ---------------------------------------- | --------------------------------- |
| **Creation Method**   | Environment variables                    | Admin dashboard                   |
| **Initial Status**    | Active (immediate)                       | Disabled (requires approval)      |
| **Approval Required** | No                                       | Yes (by existing admin)           |
| **Creator Reference** | None (system)                            | Admin who created account         |
| **When Available**    | Only when no admins exist                | Anytime after first admin         |
| **Security Setup**    | Environment → Login → Change credentials | Register → Admin approval → Login |
| **Use Case**          | System initialization                    | Ongoing admin management          |

## Implementation Notes

### **Environment Bootstrap Process**

1. **Server Startup**: System checks for existing admin accounts
2. **Bootstrap Check**: If no admins found, reads environment variables
3. **Auto-Creation**: Creates first admin if credentials provided
4. **Immediate Access**: Bootstrap admin can log in immediately
5. **Credential Management**: Admin should change password after first login
6. **Cleanup**: Environment variables can be removed after setup

### **Security Considerations**

- **Bootstrap credentials should be strong and temporary**
- **Environment variables should be removed after successful setup**
- **All admin creation activities are logged for audit purposes**
- **Bootstrap process only runs once during system initialization**
- **Regular admin creation follows standard approval workflows**
