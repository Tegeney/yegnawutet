from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    role = db.Column(db.String(10), nullable=False)  # 'admin', 'teacher', or 'student'
    first_name = db.Column(db.String(50), nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    profile_image = db.Column(db.String(500), nullable=True, default=None)  # URL to profile image
    content_password = db.Column(db.String(60), nullable=True)  # Hashed content access password
    # New student information fields
    age = db.Column(db.Integer, nullable=True)
    nationality = db.Column(db.String(50), nullable=True)
    school = db.Column(db.String(100), nullable=True)
    woreda = db.Column(db.String(50), nullable=True)
    zone = db.Column(db.String(50), nullable=True)

    def __repr__(self):
        return f'<User {self.username}>'

class TeacherPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    posted_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    grade_id = db.Column(db.Integer, db.ForeignKey('grade.id'), nullable=True)
    subject_id = db.Column(db.Integer, db.ForeignKey('subject.id'), nullable=True)
    teacher = db.relationship('User', backref=db.backref('posts', lazy=True))
    grade = db.relationship('Grade', backref=db.backref('posts', lazy=True))
    subject = db.relationship('Subject', backref=db.backref('posts', lazy=True))

    def __repr__(self):
        return f'<TeacherPost {self.title}>'

class Grade(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    
    def __repr__(self):
        return f'<Grade {self.name}>'

class Subject(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    
    def __repr__(self):
        return f'<Subject {self.name}>'

class Score(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    subject = db.Column(db.String(50), nullable=False)
    exam_name = db.Column(db.String(50), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    max_score = db.Column(db.Integer, nullable=False, default=10)  # Default to 10, can be 10 or 60
    student = db.relationship('User', backref=db.backref('scores', lazy=True))

    def __repr__(self):
        return f'<Score {self.subject}: {self.score}/{self.max_score}>'

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    read = db.Column(db.Boolean, default=False)
    cleared_by_sender = db.Column(db.Boolean, default=False)
    cleared_by_receiver = db.Column(db.Boolean, default=False)

    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='received_messages')

    def __repr__(self):
        return f'<Message {self.id}>' 