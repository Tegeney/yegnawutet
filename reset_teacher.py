from app import create_app
from models import db, User
from flask_bcrypt import Bcrypt

def reset_teacher():
    app = create_app()
    bcrypt = Bcrypt(app)
    
    with app.app_context():
        # Delete existing teacher
        User.query.filter_by(username='tegene').delete()
        db.session.commit()
        
        # Create new teacher account
        teacher = User(
            username='tegene',
            password=bcrypt.generate_password_hash('kaffa@2024').decode('utf-8'),
            role='teacher',
            first_name='Tegene',
            full_name='Tegene Wondimu'
        )
        db.session.add(teacher)
        db.session.commit()
        print("Teacher account has been reset successfully!")
        
        # Verify the teacher account
        teacher = User.query.filter_by(username='tegene').first()
        if teacher:
            print(f"Teacher account verified:")
            print(f"Username: {teacher.username}")
            print(f"Role: {teacher.role}")
            print(f"Name: {teacher.full_name}")
        else:
            print("Error: Teacher account not found after creation!")

if __name__ == '__main__':
    reset_teacher() 