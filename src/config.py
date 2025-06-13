"""
Application configuration settings loaded from environment variables.
Uses pydantic_settings for validation and type conversion.
"""
from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    """
    Application settings class with environment variable validation.
    
    Attributes:
        database_url: PostgreSQL connection string
        secret_key: Secret key for JWT token encoding
        algorithm: Algorithm used for JWT encoding (typically HS256)
        access_token_expire_minutes: Access token expiration time in minutes
        
        # Email settings
        mail_username: SMTP server username
        mail_password: SMTP server password
        mail_from: Sender email address
        mail_port: SMTP server port
        mail_server: SMTP server hostname
        mail_starttls: Whether to use STARTTLS
        mail_ssl_tls: Whether to use SSL/TLS
        use_credentials: Whether to use credentials for SMTP
        validate_certs: Whether to validate certificates
        
        # Frontend settings
        frontend_url: URL of the frontend application
        
        # Bootstrap admin settings (optional)
        bootstrap_admin_email: Optional admin email for first admin creation
        bootstrap_admin_password: Optional admin password for first admin creation
    """
    # Database settings
    database_url: str
    
    # JWT settings
    secret_key: str
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    
    # Email settings
    mail_username: str
    mail_password: str
    mail_from: str
    mail_port: int = 587
    mail_server: str
    mail_starttls: bool = True
    mail_ssl_tls: bool = False
    use_credentials: bool = True
    validate_certs: bool = True
    
    # Frontend settings
    frontend_url: str = "http://localhost:3000"
    
    # Bootstrap admin settings (optional - only used for first admin creation)
    bootstrap_admin_email: Optional[str] = None
    bootstrap_admin_password: Optional[str] = None

    class Config:
        """Configuration for environment variables loading"""
        env_file = ".env"
        case_sensitive = False

    # Cloudinary settings
    cloudinary_cloud_name: str
    cloudinary_api_key: str
    cloudinary_api_secret: str

# Create settings instance
settings = Settings()
