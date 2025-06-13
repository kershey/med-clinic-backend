import cloudinary
import cloudinary.uploader
from src.config import settings

cloudinary.config(
    cloud_name=settings.cloudinary_cloud_name,
    api_key=settings.cloudinary_api_key,
    api_secret=settings.cloudinary_api_secret
)

def upload_profile_image(file):
    """
    Uploads a profile image to Cloudinary and returns the URL.
    """
    result = cloudinary.uploader.upload(
        file,
        folder="profile_images",
        overwrite=True,
        resource_type="image"
    )
    return result.get("secure_url")
