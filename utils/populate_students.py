import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from models import db, User
from flask_bcrypt import Bcrypt
from sqlalchemy import func

student_names = [
    "Abel Adayo Agilo",
    "Abgiya Tariku Leta",
    "Abisalat Habitamu Habite",
    "Dagemawit Tesfaye Alemayehu",
    "Dagimawi Tegene Tilahun",
    "Ekiram Ahimed Mohamed",
    "Eleroi Mesfin Mamo",
    "Elidana Habitamu Haile",
    "Elishaday Ashebir  Asifaw",
    "Eliyana Endalkachew Debebe",
    "Eyasu Tamiru Gebire",
    "Fikir Dereje Alemayehu",
    "Fikire worku Egata",
    "Firetsinat mesefin Adimasu",
    "Gelila Mulugeta Abebe",
    "Godoliyas Tamiru W/michael",
    "Hanos Tafese Alemu",
    "Hibist Getachew Kefyalew",
    "Juliyana Yohannis T/michael",
    "Kalkidan mititku G/mariam",
    "Kedija Abdela Abagero",
    "Kinifemichael Bekele Gebire",
    "Kirubel Fikadu Belete",
    "Koket Abiyot Alemayehu",
    "Marita Gadisa",
    "Mariya Birhanu Haile",
    "Mekilit Asefa Mamo",
    "Meron Adane Alemayehu",
    "Namiya Samson Teshome",
    "Nobel Ayele Adeko",
    "Rediat Tariku W/mariam",
    "Shukuren tmame Seyid",
    "Sofoniyas Kinfe H/mariam",
    "Sofoniyas Wasihun Tamene",
    "Tsedeniya Samuel G/mikael",
    "Tsinukal Bdelu G/kidan",
    "Tsinukal Dereje",
    "Yeabwork Habitamu Siyum",
    "Yordanos Akililu Ademe",
    "Yordanos Gereyo Gebire"
]

def get_registration_number(full_name, index):
    if full_name == "Yordanos Akililu Ademe":
        return "0099639"
    elif full_name == "Yordanos Gereyo Gebire":
        return "0099640"
    else:
        return f"00996{index+1:02d}"

def main():
    app = create_app()
    bcrypt = Bcrypt(app)
    with app.app_context():
        # Delete existing students
        User.query.filter_by(role='student').delete()
        db.session.commit()
        print("All students deleted.")
        
        # Add new students
        for i, full_name in enumerate(student_names):
            reg_num = get_registration_number(full_name, i)
            # Check if student already exists
            existing = User.query.filter_by(username=reg_num).first()
            if existing:
                print(f"Student {reg_num} already exists. Skipping.")
                continue
                
            # Hash the registration number for both password and content_password
            hashed_password = bcrypt.generate_password_hash(reg_num).decode('utf-8')
            
            student = User(
                username=reg_num,
                password=hashed_password,
                content_password=hashed_password,  # Set content_password same as password
                role='student',
                first_name=full_name.split()[0].lower().strip(),  # Store lowercase and trimmed
                full_name=full_name,
                profile_image=f"/static/photos/{reg_num}.jpg",
                age=14,
                nationality='Ethiopian',
                school='KAFFA CHATOLIC NO2',
                woreda='BONGA',
                zone='KAFA'
            )
            db.session.add(student)
            print(f"Added student: {reg_num} - {full_name}")
        
        db.session.commit()
        print("All students added with content passwords set.")

if __name__ == "__main__":
    main()

app = create_app()
with app.app_context():
    reg_num = '0099640'  # Registration number for Yordanos Gereyo Gebire
    first_name = 'yordanos'  # Lowercase
    user = User.query.filter(
        User.username == reg_num,
        func.lower(func.trim(User.first_name)) == first_name.strip().lower()
    ).first()
    print(user)
    if user:
        print("Found:", user.username, user.first_name, user.full_name)
    else:
        print("Not found")

    # Show all first names for this reg_num
    users = User.query.filter(User.username == reg_num).all()
    for u in users:
        print(f"'{u.first_name}'")

    students = User.query.filter_by(role='student').all()
    for s in students:
        print(f"reg: {s.username}, first_name: '{s.first_name}'")

    for s in students:
        s.first_name = s.first_name.strip().lower()
    db.session.commit()
    print("All first names normalized to lowercase and trimmed.") 