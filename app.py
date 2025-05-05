import os
import json
import logging
from datetime import datetime
from base64 import b64decode
import requests
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from cachetools import TTLCache
from tenacity import retry, stop_after_attempt, wait_exponential
import sqlalchemy.exc
from functools import wraps
from models import db, User, TeacherPost, Score, Message, Grade, Subject
from utils.photo_manager import PhotoManager
from sqlalchemy import func, create_engine, text

print("Using database:", os.environ.get("DATABASE_URL"))

def content_auth_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role == 'teacher':
            return f(*args, **kwargs)
        if not current_user.content_password:
            return redirect(url_for('content_auth'))
        return f(*args, **kwargs)
    return decorated_function

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Initialize extensions
bcrypt = Bcrypt()
login_manager = LoginManager()
login_manager.login_view = 'login'

# Hardcoded keys for testing - MOVE TO ENVIRONMENT VARIABLES IN PRODUCTION
ZYTE_API_KEY = os.getenv('ZYTE_API_KEY', "10d1991606c540669fc91202a70ba7e0")
FLASK_SECRET_KEY = os.getenv('FLASK_SECRET_KEY', "93d45be5e0c45a778cb2821debe4eb4b42ab81aa6ca8004e0bce40501adb1530")
ZYTE_PROXY_URL = "https://api.zyte.com/v1/extract"

print("Using database: postgresql://postgres:tegenepro@db.ksgkcuitgxytrrhusfcv.supabase.co:5432/postgres")

def create_app():
    """Factory function to create and configure the Flask app."""
    app = Flask(__name__)
    app.secret_key = os.urandom(24)

    # Database configuration
    database_url = os.environ.get('DATABASE_URL', 'postgresql://school-db_owner:npg_oYJtpXrN5DV8@ep-icy-rice-a4umzozc-pooler.us-east-1.aws.neon.tech/school-db?sslmode=require')
    print("\nDatabase Configuration:")
    print("====================")
    print(f"Database URL: {database_url}")
    print("====================\n")
    
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'pool_size': 10,
        'max_overflow': 20,
        'pool_timeout': 30,
        'pool_recycle': 1800
    }

    # Initialize extensions
    db.init_app(app)
    print("SQLAlchemy initialized successfully")
    
    bcrypt = Bcrypt(app)
    print("Bcrypt initialized successfully")
    
    login_manager = LoginManager(app)
    login_manager.login_view = 'login'
    print("Login manager initialized successfully")
    
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    logger.info("All extensions initialized successfully")

    app.TeacherPostModel = TeacherPost
    app.ScoreModel = Score
    app.MessageModel = Message
    app.GradeModel = Grade
    app.SubjectModel = Subject

    # Initialize database tables and data
    with app.app_context():
        try:
            print("\nCreating database tables...")
            db.create_all()
            print("Database tables created successfully")
            
            # Always check for and create teacher account
            teacher = User.query.filter_by(username='tegene').first()
            if not teacher:
                print("\nCreating teacher account...")
                teacher = User(
                    username='tegene',
                    password=bcrypt.generate_password_hash('kaffa@2024').decode('utf-8'),
                    role='teacher',
                    first_name='Tegene',
                    full_name='Tegene Wondimu'
                )
                db.session.add(teacher)
                db.session.commit()
                print("Teacher account created successfully")
            
            # Check if we need to initialize default data
            admin_exists = User.query.filter_by(role='admin').first() is not None
            if not admin_exists:
                print("\nInitializing default data...")
                # Create initial grades
                grades = [
                    Grade(name='Grade 9'),
                    Grade(name='Grade 10'),
                    Grade(name='Grade 11'),
                    Grade(name='Grade 12')
                ]
                for grade in grades:
                    db.session.add(grade)
                print("Added default grades")
                
                # Create initial subjects
                subjects = [
                    Subject(name='Mathematics'),
                    Subject(name='Physics'),
                    Subject(name='Chemistry'),
                    Subject(name='Biology'),
                    Subject(name='English'),
                    Subject(name='Amharic'),
                    Subject(name='History'),
                    Subject(name='Geography'),
                    Subject(name='Civics'),
                    Subject(name='ICT')
                ]
                for subject in subjects:
                    db.session.add(subject)
                print("Added default subjects")
                
                # Create default admin user
                admin = User(
                    username='admin',
                    password=bcrypt.generate_password_hash('admin123').decode('utf-8'),
                    role='admin',
                    first_name='Admin',
                    full_name='System Administrator'
                )
                db.session.add(admin)
                print("Added default admin user")
                
                db.session.commit()
                print("Default data initialization complete")
            else:
                print("Default data already exists, skipping initialization")
                
        except Exception as e:
            print(f"Error during database initialization: {e}")
            logger.error(f"Database initialization failed: {e}")
            db.session.rollback()
            raise

    # Initialize photos directory
    PhotoManager.initialize_photo_directory()

    # Initialize student cache
    student_cache = TTLCache(maxsize=100, ttl=300)  # Cache up to 100 items for 300 seconds

    # Helper functions
    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
    def fetch_student_data(registration_number, first_name):
        user = User.query.filter(
            User.username == registration_number,
            func.lower(User.first_name) == first_name.lower()
        ).first()
        if user:
            return {
                'student': {
                    'name': user.full_name,
                    'registration_number': user.username,
                    'photo': user.profile_image,
                    'age': user.age,
                    'nationality': user.nationality,
                    'school': user.school,
                    'woreda': user.woreda,
                    'zone': user.zone
                }
            }
        else:
            return {'error': 'Student not found'}

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # Routes
    @app.route('/')
    def index():
        return redirect(url_for('login'))

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if current_user.is_authenticated:
            if current_user.role == 'teacher':
                return redirect(url_for('dashboard'))
            return redirect(url_for('content_auth'))

        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']

            # First check if this is a teacher/admin login
            user = db.session.query(User).filter_by(username=username).first()
            if user and user.role in ['teacher', 'admin']:
                if bcrypt.check_password_hash(user.password, password):
                    login_user(user)
                    logger.info(f"User {username} logged in as {user.role}")
                    if user.role == 'teacher':
                        return redirect(url_for('dashboard'))
                    return redirect(url_for('content_auth'))
                else:
                    flash('የተሳሳተ የይለፍ ቃል', 'danger')
                    return render_template('login.html')

            # If not teacher/admin, try student login
            first_name = username
            registration_number = password
            student_data = fetch_student_data(registration_number, first_name)

            if isinstance(student_data, dict) and "error" in student_data:
                flash(f"የተማሪ መረጃ መግኘት አልተቻለም፡ {student_data['error']}", 'danger')
                return render_template('login.html')

            if student_data and student_data.get('student'):
                fetched_name = student_data['student']['name'].lower()
                input_first_name = first_name.lower()
                if input_first_name not in fetched_name:
                    flash('የመጀመሪያ ስም ከምዝገባ ቁጥር ጋር አይዛመድም', 'danger')
                    return render_template('login.html')

                try:
                    user = db.session.query(User).filter_by(username=registration_number).first()
                    if not user:
                        flash('ተማሪ አልተገኘም', 'danger')
                        return render_template('login.html')
                    # Check password (registration number)
                    if not bcrypt.check_password_hash(user.password, registration_number):
                        flash('የተሳሳተ የምዝገባ ቁጥር', 'danger')
                        return render_template('login.html')
                    login_user(user)
                    logger.info(f"Student {registration_number} logged in")
                    return redirect(url_for('content_auth'))
                except Exception as e:
                    db.session.rollback()
                    logger.error(f"Error during student login: {e}")
                    flash('ያልተጠበቀ ስህተት ተከስቷል', 'danger')
                    return render_template('login.html')

            flash('የተሳሳተ የመጀመሪያ ስም ወይም የምዝገባ ቁጥር', 'danger')
            return render_template('login.html')

        return render_template('login.html')

    @app.route('/dashboard', methods=['GET'])
    @login_required
    @content_auth_required
    def dashboard():
        logger.debug(f"Dashboard accessed by {current_user.username}, role: {current_user.role}, method: {request.method}")
        if request.method == 'POST':
            logger.warning(f"Unexpected POST to /dashboard by {current_user.username}: {request.form}")
            flash('የተሳሳተ መዳረሻ። እባክዎ ትክክለኛውን ቅጽ ይጠቀሙ', 'danger')
            return redirect(url_for('dashboard'))
        try:
            if current_user.role == 'student':
                student_data = fetch_student_data(current_user.username, current_user.first_name)
                logger.info(f"Fetching scores for student ID: {current_user.id}")
                scores = db.session.query(Score).filter_by(student_id=current_user.id).all()
                logger.info(f"Found {len(scores)} scores for student {current_user.username}")
                
                # Get all teacher posts
                teacher_posts = db.session.query(TeacherPost).order_by(TeacherPost.posted_date.desc()).all()
                logger.info(f"Found {len(teacher_posts)} announcements for student {current_user.username}")
                
                # Group scores by subject
                scores_by_subject = {}
                for score in scores:
                    logger.debug(f"Processing score: {score.subject} - {score.exam_name} - {score.score}")
                    if score.subject not in scores_by_subject:
                        scores_by_subject[score.subject] = []
                    scores_by_subject[score.subject].append({
                        'id': score.id,
                        'exam_name': score.exam_name,
                        'score': score.score,
                        'max_score': 10  # Assuming max score is 100
                    })
                
                logger.info(f"Grouped scores by subject: {scores_by_subject}")
                
                if isinstance(student_data, dict) and "error" in student_data:
                    flash(f"ውጤቶችን መግኘት ላይ ስህተት፡ {student_data['error']}", 'danger')
                    return render_template('student_dashboard.html', user=current_user, scores_by_subject=scores_by_subject, teacher_posts=teacher_posts, current_year=2025)
                return render_template('student_dashboard.html', user=current_user, student_data=student_data, scores_by_subject=scores_by_subject, teacher_posts=teacher_posts, current_year=2025)
            elif current_user.role == 'teacher':
                posts = db.session.query(TeacherPost).order_by(TeacherPost.posted_date.desc()).all()
                students = db.session.query(User).filter_by(role='student').all()
                
                # Get all scores for all students
                all_scores = {}
                for student in students:
                    scores = Score.query.filter_by(student_id=student.id).all()
                    if scores:
                        scores_by_subject = {}
                        for score in scores:
                            if score.subject not in scores_by_subject:
                                scores_by_subject[score.subject] = []
                            scores_by_subject[score.subject].append({
                                'id': score.id,
                                'exam_name': score.exam_name,
                                'score': score.score,
                                'max_score': score.max_score
                            })
                        all_scores[student.id] = scores_by_subject
                
                logger.info(f"Teacher {current_user.username} viewed dashboard with {len(students)} students")
                return render_template('teacher_dashboard.html', 
                                     user=current_user, 
                                     posts=posts, 
                                     students=students, 
                                     all_scores=all_scores,
                                     current_year=2025)
            else:  # admin
                students = db.session.query(User).filter_by(role='student').all()
                logger.info(f"Admin {current_user.username} viewed dashboard with {len(students)} students")
                return render_template('teacher_dashboard.html', user=current_user, students=students, current_year=2025)
        except Exception as e:
            logger.error(f"Error loading dashboard: {e}")
            flash('ዳሽቦርዱን መጫን ላይ ስህተት ተከስቷል', 'danger')
            return redirect(url_for('login'))

    @app.route('/logout')
    @login_required
    def logout():
        username = current_user.username
        logout_user()
        flash('ከመለያዎ ወጥተዋል', 'success')
        logger.info(f"User {username} logged out")
        return redirect(url_for('login'))

    @app.route('/post', methods=['GET', 'POST'])
    @login_required
    def post():
        if current_user.role != 'teacher':
            flash('ማስታወቂያ መለጠፍ የሚችሉት መምህራን ብቻ ናቸው', 'danger')
            return redirect(url_for('dashboard'))

        if request.method == 'POST':
            title = request.form['title'].strip()
            content = request.form['content'].strip()
            grade_id = request.form.get('grade')
            subject_id = request.form.get('subject')
            
            if not title or not content:
                flash('ርዕስ እና ይዘት መሞላት አለባቸው', 'danger')
                return render_template('create_post.html', grades=Grade.query.all(), subjects=Subject.query.all())
                
            try:
                post = TeacherPost(
                    title=title,
                    content=content,
                    teacher_id=current_user.id,
                    grade_id=grade_id,
                    subject_id=subject_id
                )
                db.session.add(post)
                db.session.commit()
                flash('ማስታወቂያ በተሳካ ሁኔታ ተለጠፈ', 'success')
                logger.info(f"Teacher {current_user.username} created post: {title}")
                return redirect(url_for('dashboard'))
            except Exception as e:
                db.session.rollback()
                logger.error(f"Error creating post: {e}")
                flash('ማስታወቂያ መለጠፍ ላይ ስህተት ተከስቷል', 'danger')
        
        return render_template('create_post.html', grades=Grade.query.all(), subjects=Subject.query.all())

    @app.route('/add_score', methods=['GET', 'POST'])
    @login_required
    def add_score():
        if current_user.role != 'teacher':
            flash('ውጤት መጨመር የሚችሉት መምህራን ብቻ ናቸው', 'danger')
            return redirect(url_for('dashboard'))

        if request.method == 'POST':
            logger.debug(f"Add score form submitted: {request.form}")
            try:
                student_id = request.form['student_id'].strip()
                subject = request.form['subject'].strip()
                exam_name = request.form['exam_name'].strip()
                score = request.form['score'].strip()
                max_score = int(request.form['score_type'])  # Get the selected score type (10 or 60)
                
                logger.info(f"Adding score for student {student_id}: {subject} - {exam_name} - {score}/{max_score}")
                
                if not all([student_id, subject, exam_name, score]):
                    flash('ሁሉም መስኮች መሞላት አለባቸው', 'danger')
                    return redirect(url_for('dashboard'))
                
                score = int(score)
                if score < 0 or score > max_score:
                    flash(f'ውጤት ከ0 እስከ {max_score} መሆን አለበት', 'danger')
                    return redirect(url_for('dashboard'))
                
                student = db.session.query(User).filter_by(id=student_id, role='student').first()
                if not student:
                    flash('ተማሪ አልተገኘም', 'danger')
                    return redirect(url_for('dashboard'))
                
                new_score = Score(
                    student_id=student_id,
                    subject=subject,
                    exam_name=exam_name,
                    score=score,
                    max_score=max_score
                )
                db.session.add(new_score)
                db.session.commit()
                logger.info(f"Successfully added score for student {student_id}: {subject} - {exam_name} - {score}/{max_score}")
                flash('የፈተና ውጤት በተሳካ ሁኔታ ተጨምሯል', 'success')
                return redirect(url_for('dashboard'))
            except ValueError:
                flash('ውጤት ቁጥር መሆን አለበት', 'danger')
                logger.warning(f"Invalid score format: {request.form.get('score')}")
                return redirect(url_for('dashboard'))
            except sqlalchemy.exc.IntegrityError:
                db.session.rollback()
                flash('የተማሪ መረጃ ልክ አይደለም', 'danger')
                logger.warning(f"Invalid student_id: {request.form.get('student_id')}")
                return redirect(url_for('dashboard'))
            except Exception as e:
                db.session.rollback()
                logger.error(f"Error adding score: {e}")
                flash('ያልተጠበቀ ስህተት ተከስቷል', 'danger')
                return redirect(url_for('dashboard'))
        
        students = db.session.query(User).filter_by(role='student').all()
        return render_template('add_score.html', students=students, current_year=2025)

    @app.route('/chat')
    @login_required
    def chat():
        if current_user.role == 'student':
            # Get all teachers for students to chat with
            users = User.query.filter_by(role='teacher').all()
        else:
            # Get all students for teachers to chat with
            users = User.query.filter_by(role='student').all()
        return render_template('chat.html', users=users)

    @app.route('/chat/<int:room_id>', methods=['GET', 'POST'])
    @login_required
    def chat_room(room_id):
        # Get the other user in the chat
        if current_user.role == 'student':
            other_user = User.query.get(room_id)
            if not other_user or other_user.role != 'teacher':
                flash('Invalid chat room', 'error')
                return redirect(url_for('dashboard'))
        else:  # teacher
            other_user = User.query.get(room_id)
            if not other_user or other_user.role != 'student':
                flash('Invalid chat room', 'error')
                return redirect(url_for('dashboard'))

        if request.method == 'POST':
            message = request.form.get('message')
            if not message:
                return jsonify({'success': False, 'error': 'Message cannot be empty'})
            
            try:
                # Create new message
                new_message = Message(
                    sender_id=current_user.id,
                    receiver_id=other_user.id,
                    message=message
                )
                db.session.add(new_message)
                db.session.commit()
                
                return jsonify({
                    'success': True,
                    'message': {
                        'content': message,
                        'timestamp': new_message.timestamp.strftime('%I:%M %p')
                    }
                })
            except Exception as e:
                logger.error(f"Error sending message: {e}")
                return jsonify({'success': False, 'error': str(e)})

        # Get chat history, filtering out cleared messages
        messages = Message.query.filter(
            ((Message.sender_id == current_user.id) & (Message.receiver_id == other_user.id) & (Message.cleared_by_sender == False)) |
            ((Message.sender_id == other_user.id) & (Message.receiver_id == current_user.id) & (Message.cleared_by_receiver == False))
        ).order_by(Message.timestamp.asc()).all()

        # Mark messages as read
        for message in messages:
            if message.receiver_id == current_user.id and not message.read:
                message.read = True
        db.session.commit()

        return render_template('chat_room.html', 
                             other_user=other_user, 
                             messages=messages)

    @app.route('/chat/<int:room_id>/clear', methods=['POST'])
    @login_required
    def clear_chat_history(room_id):
        if current_user.role != 'student':
            return jsonify({'success': False, 'error': 'Only students can clear their chat history'})
        
        try:
            # Get the other user in the chat
            other_user = User.query.get(room_id)
            if not other_user or other_user.role != 'teacher':
                return jsonify({'success': False, 'error': 'Invalid chat room'})
            
            # Mark messages as cleared for the student
            messages = Message.query.filter(
                ((Message.sender_id == current_user.id) & (Message.receiver_id == other_user.id)) |
                ((Message.sender_id == other_user.id) & (Message.receiver_id == current_user.id))
            ).all()
            
            for message in messages:
                if message.receiver_id == current_user.id:
                    message.cleared_by_receiver = True
                elif message.sender_id == current_user.id:
                    message.cleared_by_sender = True
            
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': 'Chat history cleared successfully'
            })
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error clearing chat history: {e}")
            return jsonify({'success': False, 'error': str(e)})

    @app.route('/content_auth', methods=['GET', 'POST'])
    @login_required
    def content_auth():
        # Skip content auth for teachers
        if current_user.role == 'teacher':
            return redirect(url_for('dashboard'))

        is_first_time = current_user.content_password is None

        if request.method == 'POST':
            content_password = request.form.get('content_password')
            confirm_password = request.form.get('confirm_password')

            if is_first_time:
                # Set password for the first time
                if not content_password:
                    flash('Password is required', 'danger')
                    return redirect(url_for('content_auth'))
                if confirm_password and content_password != confirm_password:
                    flash('Passwords do not match', 'danger')
                    return redirect(url_for('content_auth'))
                hashed_password = bcrypt.generate_password_hash(content_password).decode('utf-8')
                current_user.content_password = hashed_password
                db.session.commit()
                flash('Content access password set successfully', 'success')
                return redirect(url_for('dashboard'))
            else:
                # Authenticate with existing password
                if not content_password:
                    flash('Password is required', 'danger')
                    return redirect(url_for('content_auth'))
                if not bcrypt.check_password_hash(current_user.content_password, content_password):
                    flash('Incorrect content access password', 'danger')
                    return redirect(url_for('content_auth'))
                # Password correct, allow access
                session['content_authenticated'] = True
                return redirect(url_for('dashboard'))

        return render_template('content_auth.html', is_first_time=is_first_time)

    @app.route('/verify_master_password', methods=['POST'])
    @login_required
    def verify_master_password():
        try:
            data = request.get_json()
            password = data.get('password')
            
            if not password:
                return jsonify({'success': False, 'error': 'Password is required'}), 400
                
            # Use the same master password as the reset function
            if password == os.getenv('MASTER_PASSWORD', 'kaffa@2024'):
                # Store master access in session
                session['has_master_access'] = True
                return jsonify({'success': True})
            else:
                return jsonify({'success': False, 'error': 'Invalid master password'}), 401
                
        except Exception as e:
            logger.error(f"Error verifying master password: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500
            
    @app.route('/admin/reset_password', methods=['POST'])
    @login_required
    def admin_reset_password():
        logger.info("Admin reset password request received")
        try:
            master_password = request.form.get('master_password')
            username = request.form.get('username')
            new_password = request.form.get('new_password')
            
            logger.info(f"Reset attempt for user: {username}")
            
            # Validate inputs
            if not all([master_password, username, new_password]):
                logger.warning("Missing required fields in reset password request")
                return jsonify({'error': 'All fields are required'}), 400
                
            # Check master password
            expected_password = os.getenv('MASTER_PASSWORD', 'kaffa@2024')
            if master_password != expected_password:
                logger.warning(f"Invalid master password attempt for user: {username}")
                return jsonify({'error': 'Invalid master password'}), 401
                
            # Find user
            user = User.query.filter_by(username=username).first()
            if not user:
                logger.warning(f"User not found: {username}")
                return jsonify({'error': 'User not found'}), 404
                
            # Update main password
            user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            
            # If student, also update content_password
            if user.role == 'student':
                user.content_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
                logger.info(f"Updated content password for student: {username}")
            
            db.session.commit()
            logger.info(f"Successfully reset password for user: {username}")
            
            return jsonify({'success': True, 'message': 'Password reset successful'}), 200
                
        except Exception as e:
            logger.error(f"Error resetting password: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/admin/master_login', methods=['POST'])
    @login_required
    def admin_master_login():
        try:
            data = request.get_json()
            master_password = data.get('master_password')
            username = data.get('username')
            
            # Validate inputs
            if not all([master_password, username]):
                return jsonify({'error': 'Master password and username are required'}), 400
                
            # Check master password
            if master_password != os.getenv('MASTER_PASSWORD', 'kaffa@2024'):
                return jsonify({'error': 'Invalid master password'}), 401
                
            # Check if user exists and is a student
            user = User.query.filter_by(username=username).first()
            if not user:
                return jsonify({'error': 'User not found'}), 404
            
            if user.role != 'student':
                return jsonify({'error': 'Can only login as students'}), 403
                
            # Log in as the student
            logout_user()
            login_user(user)
            
            return jsonify({'success': True, 'message': 'Login successful'}), 200
                
        except Exception as e:
            logger.error(f"Error during master login: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/view_scores/<int:student_id>')
    @login_required
    def view_student_scores(student_id):
        if current_user.role not in ['teacher', 'admin']:
            flash('ይህን ገጽ ለመጠቀም መብት የለዎትም', 'danger')
            return redirect(url_for('dashboard'))

        # Get all students
        students = User.query.filter_by(role='student').all()
        
        # Get scores for all students
        all_scores = {}
        for student in students:
            scores = Score.query.filter_by(student_id=student.id).all()
            if scores:
                scores_by_subject = {}
                for score in scores:
                    if score.subject not in scores_by_subject:
                        scores_by_subject[score.subject] = []
                    scores_by_subject[score.subject].append({
                        'id': score.id,
                        'exam_name': score.exam_name,
                        'score': score.score,
                        'max_score': score.max_score
                    })
                all_scores[student.id] = scores_by_subject

        return render_template('view_student_scores.html', 
                             students=students,
                             all_scores=all_scores,
                             current_student_id=student_id)

    @app.route('/delete_score/<int:score_id>', methods=['POST'])
    @login_required
    def delete_score(score_id):
        if current_user.role not in ['teacher', 'admin']:
            return jsonify({'success': False, 'error': 'Only teachers can delete scores'})
        
        try:
            score = Score.query.get_or_404(score_id)
            student_id = score.student_id
            db.session.delete(score)
            db.session.commit()
            flash('ውጤት በተሳካ ሁኔታ ተሰርዟል', 'success')
            return redirect(url_for('view_student_scores', student_id=student_id))
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error deleting score: {e}")
            flash('ያልተጠበቀ ስህተት ተከስቷል', 'danger')
            return redirect(url_for('view_student_scores', student_id=score.student_id))

    @app.route('/update_score/<int:score_id>', methods=['GET', 'POST', 'PUT'])
    @login_required
    def update_score(score_id):
        if current_user.role not in ['teacher', 'admin']:
            flash('ውጤት ለመለወጥ መብት የለዎትም', 'danger')
            return redirect(url_for('dashboard'))

        try:
            score = Score.query.get_or_404(score_id)
            
            if request.method in ['POST', 'PUT']:
                try:
                    # For PUT requests from AJAX
                    if request.method == 'PUT':
                        data = request.form
                        new_score = float(data['score'])
                        max_score = int(data['score_type'])
                        if new_score < 0 or new_score > max_score:
                            return jsonify({
                                'success': False, 
                                'error': f'ውጤት ከ0 እስከ {max_score} መሆን አለበት'
                            }), 400
                        
                        score.score = new_score
                        score.max_score = max_score
                        score.exam_name = data['exam_name']
                        score.subject = data['subject']
                        db.session.commit()
                        return jsonify({'success': True})
                    
                    # For regular POST requests from form
                    new_score = float(request.form['score'])
                    if new_score < 0 or new_score > score.max_score:
                        flash(f'ውጤት ከ0 እስከ {score.max_score} መሆን አለበት', 'danger')
                        return redirect(url_for('update_score', score_id=score_id))
                    
                    score.score = new_score
                    db.session.commit()
                    flash('ውጤት በተሳካ ሁኔታ ተሻሽሏል', 'success')
                    return redirect(url_for('view_student_scores', student_id=score.student_id))
                    
                except ValueError:
                    flash('ውጤት ቁጥር መሆን አለበት', 'danger')
                    return redirect(url_for('update_score', score_id=score_id))
                except Exception as e:
                    db.session.rollback()
                    logger.error(f"Error updating score: {e}")
                    flash('ያልተጠበቀ ስህተት ተከስቷል', 'danger')
                    return redirect(url_for('update_score', score_id=score_id))
            
            return render_template('update_score.html', score=score)
        except Exception as e:
            logger.error(f"Error accessing score: {e}")
            flash('ውጤቱን ማግኘት አልተቻለም', 'danger')
            return redirect(url_for('dashboard'))

    @app.route('/get_unread_count')
    @login_required
    def get_unread_count():
        try:
            if current_user.role == 'student':
                # Count unread messages from teachers
                count = Message.query.filter(
                    Message.receiver_id == current_user.id,
                    Message.sender_id.in_(
                        User.query.filter_by(role='teacher').with_entities(User.id)
                    ),
                    Message.read == False,
                    Message.cleared_by_receiver == False
                ).count()
            else:
                # Count unread messages from students
                count = Message.query.filter(
                    Message.receiver_id == current_user.id,
                    Message.sender_id.in_(
                        User.query.filter_by(role='student').with_entities(User.id)
                    ),
                    Message.read == False,
                    Message.cleared_by_receiver == False
                ).count()
            
            return jsonify({'count': count})
        except Exception as e:
            logger.error(f"Error getting unread count: {e}")
            return jsonify({'count': 0})

    @app.route('/edit_announcement/<int:post_id>', methods=['POST'])
    @login_required
    def edit_announcement(post_id):
        if current_user.role != 'teacher':
            return jsonify({'success': False, 'error': 'Only teachers can edit announcements'})
        
        try:
            data = request.get_json()
            if not data or 'title' not in data or 'content' not in data:
                return jsonify({'success': False, 'error': 'Title and content are required'})
            
            post = TeacherPost.query.get_or_404(post_id)
            if post.teacher_id != current_user.id:
                return jsonify({'success': False, 'error': 'You can only edit your own announcements'})
            
            post.title = data['title'].strip()
            post.content = data['content'].strip()
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': 'Announcement updated successfully'
            })
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error updating announcement: {e}")
            return jsonify({'success': False, 'error': str(e)})

    @app.route('/delete_announcement/<int:post_id>', methods=['POST'])
    @login_required
    def delete_announcement(post_id):
        if current_user.role != 'teacher':
            return jsonify({'success': False, 'error': 'Only teachers can delete announcements'})
        
        try:
            post = TeacherPost.query.get_or_404(post_id)
            if post.teacher_id != current_user.id:
                return jsonify({'success': False, 'error': 'You can only delete your own announcements'})
            
            db.session.delete(post)
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': 'Announcement deleted successfully'
            })
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error deleting announcement: {e}")
            return jsonify({'success': False, 'error': str(e)})

    @app.route('/admin/cleanup_photos', methods=['POST'])
    @login_required
    def cleanup_photos():
        if current_user.role != 'admin':
            return jsonify({'error': 'Unauthorized'}), 403
        days = request.form.get('days', 30, type=int)
        if PhotoManager.cleanup_unused_photos(days):
            stats = PhotoManager.get_storage_stats()
            return jsonify({'success': True, 'message': 'Cleanup completed', 'stats': stats})
        return jsonify({'error': 'Cleanup failed'}), 500

    @app.route('/admin/photo_stats')
    @login_required
    def photo_stats():
        if current_user.role != 'admin':
            return jsonify({'error': 'Unauthorized'}), 403
        stats = PhotoManager.get_storage_stats()
        return jsonify({'stats': stats})

    @app.route('/admin/reset_content_password', methods=['POST'])
    @login_required
    def admin_reset_content_password():
        logger.info("Admin reset content password request received")
        try:
            master_password = request.form.get('master_password')
            username = request.form.get('username')
            new_password = request.form.get('new_password')
            
            logger.info(f"Content password reset attempt for user: {username}")
            
            # Validate inputs
            if not all([master_password, username, new_password]):
                logger.warning("Missing required fields in reset content password request")
                return jsonify({'success': False, 'error': 'All fields are required'}), 400
                
            # Check master password
            expected_password = os.getenv('MASTER_PASSWORD', 'kaffa@2024')
            if master_password != expected_password:
                logger.warning(f"Invalid master password attempt for user: {username}")
                return jsonify({'success': False, 'error': 'Invalid master password'}), 401
                
            # Find user
            user = User.query.filter_by(username=username).first()
            if not user:
                logger.warning(f"User not found: {username}")
                return jsonify({'success': False, 'error': 'User not found'}), 404
                
            # Update content password
            user.content_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            logger.info(f"Updated content password for student: {username}")
            
            db.session.commit()
            return jsonify({'success': True, 'message': 'Content password reset successful'}), 200
            
        except Exception as e:
            logger.error(f"Error resetting content password: {e}")
            return jsonify({'success': False, 'error': 'An error occurred while resetting the content password'}), 500

    @app.route('/change_content_password', methods=['POST'])
    @login_required
    def change_content_password():
        if current_user.role != 'student':
            flash('Only students can change their content password', 'danger')
            return redirect(url_for('dashboard'))
            
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if not all([current_password, new_password, confirm_password]):
            flash('All fields are required', 'danger')
            return redirect(url_for('dashboard'))
            
        if new_password != confirm_password:
            flash('New passwords do not match', 'danger')
            return redirect(url_for('dashboard'))
            
        if not bcrypt.check_password_hash(current_user.content_password, current_password):
            flash('Current password is incorrect', 'danger')
            return redirect(url_for('dashboard'))
            
        current_user.content_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        db.session.commit()
        
        flash('Content password changed successfully', 'success')
        return redirect(url_for('dashboard'))

    return app

# Create the app instance
app = create_app()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
