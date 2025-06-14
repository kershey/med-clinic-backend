import cloudinary
import cloudinary.uploader
import cloudinary.exceptions
import logging
from src.config import settings

# Set up logger for this module
logger = logging.getLogger(__name__)

cloudinary.config(
    cloud_name=settings.cloudinary_cloud_name,
    api_key=settings.cloudinary_api_key,
    api_secret=settings.cloudinary_api_secret
)

def upload_profile_image(file):
    """
    Uploads a profile image to Cloudinary and returns the URL.
    Returns None if the upload fails.
    """
    try:
        result = cloudinary.uploader.upload(
            file,
            folder="profile_images",
            overwrite=True,
            resource_type="image"
        )
        secure_url = result.get("secure_url")
        if not secure_url:
            logger.error("Cloudinary upload result did not contain a secure_url.")
            return None
        logger.info(f"Successfully uploaded image to Cloudinary. URL: {secure_url}")
        return secure_url
    except cloudinary.exceptions.Error as e:
        logger.error(f"Cloudinary API error during profile image upload: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error during profile image upload to Cloudinary: {str(e)}")
        return None
