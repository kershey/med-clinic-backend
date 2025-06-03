#!/usr/bin/env python3
"""
Script to check if admin accounts are registered in the system.
This script connects to the database and checks for users with ADMIN role.
"""
import sys
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Add the app directory to Python path to import modules
sys.path.append(os.path.join(os.path.dirname(__file__), 'app'))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.api.models.user import User, UserRole, AccountStatus

def check_admin_accounts():
    """Check if admin accounts exist in the database."""
    try:
        # Get database URL from environment
        database_url = os.getenv("DATABASE_URL")
        if not database_url:
            print("❌ DATABASE_URL not found in environment variables")
            print("💡 Make sure you have a .env file with DATABASE_URL configured")
            return False
        
        # Create database connection
        engine = create_engine(database_url)
        SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
        
        # Create database session
        db = SessionLocal()
        
        print("🔍 Checking for admin accounts in the database...")
        print("=" * 50)
        
        # Query for admin users
        admin_users = db.query(User).filter(User.role == UserRole.ADMIN).all()
        
        if not admin_users:
            print("❌ No admin accounts found in the database")
            print("\n💡 To create the first admin account:")
            print("   1. Add bootstrap credentials to your .env file:")
            print("      BOOTSTRAP_ADMIN_EMAIL=admin@yourclinic.com")
            print("      BOOTSTRAP_ADMIN_PASSWORD=YourSecurePassword123")
            print("   2. Restart the FastAPI server")
            print("   3. The system will automatically create the first admin")
            return False
        
        print(f"✅ Found {len(admin_users)} admin account(s):")
        print()
        
        for i, admin in enumerate(admin_users, 1):
            print(f"Admin {i}:")
            print(f"  📧 Email: {admin.email}")
            print(f"  👤 Name: {admin.full_name}")
            print(f"  🆔 ID: {admin.id}")
            print(f"  📊 Status: {admin.status.value}")
            print(f"  ✅ Verified: {'Yes' if admin.is_verified else 'No'}")
            print(f"  🕒 Created: {admin.created_at}")
            if admin.created_by:
                creator = db.query(User).filter(User.id == admin.created_by).first()
                creator_name = creator.full_name if creator else "Unknown"
                print(f"  👤 Created by: {creator_name} (ID: {admin.created_by})")
            else:
                print(f"  👤 Created by: System (Bootstrap)")
            print()
        
        # Check account statuses
        active_admins = [admin for admin in admin_users if admin.status == AccountStatus.ACTIVE]
        pending_admins = [admin for admin in admin_users if admin.status != AccountStatus.ACTIVE]
        
        print("📊 Admin Account Summary:")
        print(f"  • Total Admin Accounts: {len(admin_users)}")
        print(f"  • Active Admin Accounts: {len(active_admins)}")
        print(f"  • Pending/Inactive Admin Accounts: {len(pending_admins)}")
        
        if pending_admins:
            print("\n⚠️  Some admin accounts are not active:")
            for admin in pending_admins:
                print(f"     - {admin.email}: {admin.status.value}")
        
        db.close()
        return True
        
    except Exception as e:
        print(f"❌ Error checking admin accounts: {str(e)}")
        return False

if __name__ == "__main__":
    print("🔍 Admin Account Checker")
    print("=" * 50)
    
    success = check_admin_accounts()
    
    if success:
        print("\n✅ Admin account check completed successfully!")
    else:
        print("\n❌ Admin account check failed!")
        sys.exit(1) 