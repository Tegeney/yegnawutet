import os
import shutil
import logging
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
import requests
from models import User, db
from PIL import Image
from io import BytesIO

logger = logging.getLogger(__name__)

class PhotoManager:
    # Use absolute path for photos directory
    PHOTOS_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.dirname(__file__)), 'static', 'photos'))
    ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png'}
    MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB
    
    @classmethod
    def initialize_photo_directory(cls):
        """Create photos directory with proper permissions"""
        try:
            logger.info(f"Initializing photos directory at: {cls.PHOTOS_DIR}")
            if not os.path.exists(cls.PHOTOS_DIR):
                os.makedirs(cls.PHOTOS_DIR, mode=0o755)
                logger.info(f"Created photos directory at {cls.PHOTOS_DIR}")
            
            # Set proper permissions even if directory exists
            os.chmod(cls.PHOTOS_DIR, 0o755)
            logger.info(f"Set proper permissions for photos directory at {cls.PHOTOS_DIR}")
            return True
        except Exception as e:
            logger.error(f"Failed to initialize photos directory: {e}")
            return False

    @classmethod
    def is_valid_image(cls, image):
        """Check if file is a valid image and within size limit"""
        try:
            # First, try to load the image
            img = Image.open(image)
            img.load()  # Force load the image data
            
            # Get image format
            image_format = img.format.lower() if img.format else ''
            if image_format not in ['jpeg', 'jpg', 'png']:
                logger.error(f"Invalid image format: {image_format}")
                return False
                
            # Check file size (approximate)
            image_size = len(img.tobytes())
            if image_size > cls.MAX_FILE_SIZE:
                logger.error(f"Image too large: {image_size} bytes")
                return False
                
            return True
        except Exception as e:
            logger.error(f"Error validating image: {e}")
            return False

    @classmethod
    def save_student_photo(cls, photo_url: str, student_id: str) -> str:
        """This method is now deprecated. All photos are managed locally."""
        logger.info("save_student_photo is deprecated. All photos should be managed locally.")
        return f"/static/photos/{student_id}.jpg"

    @classmethod
    def cleanup_unused_photos(cls, days_old=30):
        """Remove photos of students who haven't logged in for specified days"""
        try:
            # Get list of all student IDs with active photos
            active_students = User.query.with_entities(User.username).filter(
                User.profile_image.like('/static/photos/%')
            ).all()
            active_student_ids = {student.username for student in active_students}
            
            # Get all files in photos directory
            for filename in os.listdir(cls.PHOTOS_DIR):
                if not filename.startswith('student_'):
                    continue
                    
                filepath = os.path.join(cls.PHOTOS_DIR, filename)
                file_age = datetime.now() - datetime.fromtimestamp(os.path.getmtime(filepath))
                
                # Extract student ID from filename
                student_id = filename.replace('student_', '').replace('.jpg', '')
                
                # Remove if student not active and file is old
                if (student_id not in active_student_ids and 
                    file_age > timedelta(days=days_old)):
                    os.remove(filepath)
                    logger.info(f"Removed unused photo: {filename}")
            
            return True
        except Exception as e:
            logger.error(f"Error during photo cleanup: {e}")
            return False

    @classmethod
    def get_storage_stats(cls):
        """Get statistics about photo storage"""
        try:
            total_size = 0
            file_count = 0
            for filename in os.listdir(cls.PHOTOS_DIR):
                if filename.startswith('student_'):
                    filepath = os.path.join(cls.PHOTOS_DIR, filename)
                    total_size += os.path.getsize(filepath)
                    file_count += 1
                    
            return {
                'total_size_mb': round(total_size / (1024 * 1024), 2),
                'file_count': file_count
            }
        except Exception as e:
            logger.error(f"Error getting storage stats: {e}")
            return None 
