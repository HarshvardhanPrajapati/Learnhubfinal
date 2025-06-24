from flask import Flask, render_template, request, redirect, url_for, flash, abort, make_response, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
from flask_wtf.csrf import CSRFProtect, generate_csrf
from datetime import datetime
import traceback
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_jwt_extended import (
    JWTManager,
    jwt_required,
    create_access_token,
    set_access_cookies,
    unset_jwt_cookies
)
from pymongo import MongoClient
from bson import ObjectId
from dotenv import load_dotenv
from functools import wraps
import random

load_dotenv()  # Load environment variables from .env file

app = Flask(__name__)
csrf = CSRFProtect(app)

# Configuration
app.config['SECRET_KEY'] = os.urandom(24).hex()
app.config['JWT_SECRET_KEY'] = os.urandom(24).hex()
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_COOKIE_SECURE'] = False
app.config['JWT_COOKIE_CSRF_PROTECT'] = True
app.config['JWT_CSRF_CHECK_FORM'] = True
app.config['UPLOAD_FOLDER'] = 'static/images'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Initialize extensions
jwt = JWTManager(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# MongoDB connection
mongo_uri = os.getenv('MONGO_URI')
client = MongoClient(mongo_uri)
db = client['learnhub']

# Collections
users_collection = db['users']
courses_collection = db['courses']
enrollments_collection = db['enrollments']
reviews_collection = db['reviews']
course_content_collection = db['course_content']
user_progress_collection = db['user_video_progress']
testimonials_collection = db['testimonials']

# Ensure upload directories exist
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'profile_pics'), exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'course_thumbnails'), exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Helper functions
def capitalize_first(text):
    return text[0].upper() + text[1:] if text else ''

def capitalize_name(text):
    if text:
        return ' '.join(word.capitalize() for word in text.split())
    return ''

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, user_data):
        self.user_data = user_data
        
    def get_id(self):
        return str(self.user_data['_id'])
    
    @property
    def user_id(self):
        return self.user_data['_id']
    
    @property
    def username(self):
        return self.user_data['username']
    
    @property
    def email(self):
        return self.user_data['email']
    
    @property
    def user_type(self):
        return self.user_data['user_type']
    
    @property
    def first_name(self):
        return self.user_data.get('first_name', '')
    
    @property
    def last_name(self):
        return self.user_data.get('last_name', '')
    
    @property
    def bio(self):
        return self.user_data.get('bio', '')
    
    @property
    def profile_pic(self):
        return self.user_data.get('profile_pic', '')
    
    @property
    def created_at(self):
        return self.user_data.get('created_at', datetime.utcnow())
    
    def check_password(self, password):
        return check_password_hash(self.user_data['password_hash'], password)

@login_manager.user_loader
def load_user(user_id):
    user_data = users_collection.find_one({'_id': ObjectId(user_id)})
    if not user_data:
        return None
    return User(user_data)

@app.after_request
def inject_csrf_token(response):
    response.set_cookie('csrf_token', generate_csrf())
    return response

# Custom decorator for teacher-only routes
def teacher_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.user_type != 'teacher':
            flash('You must be a teacher to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Main routes
@app.route('/')
def home():
    # Featured courses (highest rated and most popular)
    pipeline = [
        {
            "$lookup": {
                "from": "reviews",
                "localField": "_id",
                "foreignField": "course_id",
                "as": "reviews"
            }
        },
        {
            "$lookup": {
                "from": "enrollments",
                "localField": "_id",
                "foreignField": "course_id",
                "as": "enrollments"
            }
        },
        {
            "$addFields": {
                "avg_rating": {"$avg": "$reviews.rating"},
                "enrollment_count": {"$size": "$enrollments"}
            }
        },
        {"$sort": {"avg_rating": -1, "enrollment_count": -1}},
        {"$limit": 6}
    ]
    featured_courses = list(courses_collection.aggregate(pipeline))

    # Get testimonials (positive reviews with rating >= 4)
    testimonials = list(reviews_collection.aggregate([
        {"$match": {"rating": {"$gte": 4}}},
        {"$sample": {"size": 3}},
        {
            "$lookup": {
                "from": "users",
                "localField": "student_id",
                "foreignField": "_id",
                "as": "author"
            }
        },
        {"$unwind": "$author"},
        {
            "$lookup": {
                "from": "courses",
                "localField": "course_id",
                "foreignField": "_id",
                "as": "course"
            }
        },
        {"$unwind": "$course"}
    ]))

    return render_template('main/home.html',
                         featured_courses=featured_courses,
                         testimonials=testimonials)

@app.route('/about')
def about():
    return render_template('main/about.html')

@app.route('/contact')
def contact():
    return render_template('main/contact.html')

@app.route('/get-csrf')
def get_csrf():
    return jsonify({'csrf_token': generate_csrf()})

@app.route('/courses')
def courses():
    courses = list(courses_collection.find())
    return render_template('main/courses.html', courses=courses)

@app.route('/teachers')
def teachers():
    teachers = list(users_collection.find({'user_type': 'teacher'}))
    return render_template('main/teachers.html', teachers=teachers)

@app.route('/testimonials')
def testimonials():
    testimonials = list(testimonials_collection.find())
    return render_template('main/testimonials.html', testimonials=testimonials)

@app.route('/teachers/<teacher_id>')
def public_teacher_profile(teacher_id):
    try:
        teacher_id_obj = ObjectId(teacher_id)
    except:
        abort(404)
        
    teacher = users_collection.find_one({'_id': teacher_id_obj, 'user_type': 'teacher'})
    if not teacher:
        abort(404)
        
    courses = list(courses_collection.find({'teacher_id': teacher_id_obj}))
    
    # Calculate statistics
    course_ids = [course['_id'] for course in courses]
    
    total_students = enrollments_collection.count_documents({
        'course_id': {'$in': course_ids}
    })
    
    reviews = list(reviews_collection.find({
        'course_id': {'$in': course_ids}
    }))
    
    total_reviews = len(reviews)
    avg_rating = 0
    
    if reviews:
        avg_rating = sum(review['rating'] for review in reviews) / total_reviews
        
    return render_template('main/teacher_profile.html',
        teacher=teacher,
        courses=courses,
        total_students=total_students,
        total_reviews=total_reviews,
        avg_rating=round(avg_rating, 1)
    )

# Auth routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user_data = users_collection.find_one({'email': email})
        
        if user_data:
            user = User(user_data)
            if user.check_password(password):
                login_user(user)
                access_token = create_access_token(identity=str(user.user_id))
                response = make_response(redirect(url_for('student_dashboard' if user.user_type == 'student' else 'teacher_dashboard')))
                set_access_cookies(response, access_token)
                flash('Logged in successfully!', 'success')
                return response
        flash('Invalid email or password', 'danger')
    return render_template('auth/login.html')

@app.route('/logout')
@login_required
def logout():
    response = make_response(redirect(url_for('home')))
    logout_user()
    unset_jwt_cookies(response)
    flash('You have been logged out', 'success')
    return response

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')
            user_type = request.form.get('user_type')
            
            if password != confirm_password:
                flash('Passwords do not match', 'danger')
                return redirect(url_for('register'))
            
            if not all([username, email, password, user_type]):
                flash('All fields are required', 'danger')
                return redirect(url_for('register'))
            
            existing_user = users_collection.find_one({
                '$or': [
                    {'username': username},
                    {'email': email}
                ]
            })
            
            if existing_user:
                flash('Username or email already exists', 'danger')
                return redirect(url_for('register'))
            
            new_user = {
                'username': username,
                'email': email,
                'password_hash': generate_password_hash(password),
                'user_type': user_type,
                'first_name': '',
                'last_name': '',
                'bio': '',
                'profile_pic': '',
                'created_at': datetime.utcnow()
            }
            result = users_collection.insert_one(new_user)
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            print(f"Error during registration: {str(e)}")
            print(traceback.format_exc())
            flash('Registration failed. Please try again.', 'danger')
    return render_template('auth/register.html')

# Student dashboard routes
@app.route('/student/dashboard')
@login_required
@jwt_required()
def student_dashboard():
    if current_user.user_type != 'student':
        return redirect(url_for('home'))
    
    # Get enrolled courses with course details
    enrollments = list(enrollments_collection.find({
        'student_id': current_user.user_id
    }))
    
    course_ids = [enrollment['course_id'] for enrollment in enrollments]
    courses = list(courses_collection.find({
        '_id': {'$in': course_ids}
    }))
    
    # Calculate completed courses
    completed_courses = sum(1 for enrollment in enrollments if enrollment.get('completed', False))
    
    # Get reviews for each course
    course_reviews = {}
    for course in courses:
        reviews = list(reviews_collection.find({
            'course_id': course['_id']
        }))
        course_reviews[str(course['_id'])] = reviews
    
    return render_template('dashboard/student/home.html', 
        enrollments=enrollments,
        courses=courses,
        completed_courses=completed_courses,
        course_reviews=course_reviews)

@app.route('/student/courses')
@login_required
def student_courses():
    if current_user.user_type != 'student':
        return redirect(url_for('home'))
    
    enrollments = list(enrollments_collection.find({
        'student_id': current_user.user_id
    }))
    
    course_ids = [enrollment['course_id'] for enrollment in enrollments]
    courses = list(courses_collection.find({
        '_id': {'$in': course_ids}
    }))
    
    # Pair courses with their enrollment info
    enrolled_courses = []
    for course in courses:
        enrollment = next((e for e in enrollments if e['course_id'] == course['_id']), None)
        if enrollment:
            enrolled_courses.append((course, enrollment))
            
    return render_template('dashboard/student/courses.html', enrolled_courses=enrolled_courses)

@app.route('/student/profile', methods=['GET', 'POST'])
@login_required
def student_profile():
    if current_user.user_type != 'student':
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        try:
            update_data = {
                'first_name': request.form.get('first_name'),
                'last_name': request.form.get('last_name'),
                'bio': request.form.get('bio')
            }
            
            if 'profile_pic' in request.files:
                file = request.files['profile_pic']
                if file and allowed_file(file.filename):
                    filename = secure_filename(f"user_{current_user.user_id}_{file.filename}")
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], 'profile_pics', filename))
                    update_data['profile_pic'] = f"images/profile_pics/{filename}"
            
            # Handle password change
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')
            
            if current_password and new_password and confirm_password:
                if not current_user.check_password(current_password):
                    flash('Current password is incorrect', 'danger')
                    return redirect(url_for('student_profile'))
                
                if new_password != confirm_password:
                    flash('New passwords do not match', 'danger')
                    return redirect(url_for('student_profile'))
                
                update_data['password_hash'] = generate_password_hash(new_password)
            
            users_collection.update_one(
                {'_id': current_user.user_id},
                {'$set': update_data}
            )
            flash('Profile updated successfully!', 'success')
        except Exception as e:
            flash('Failed to update profile.', 'danger')
        return redirect(url_for('student_profile'))
    
    # Get student statistics
    enrollments = list(enrollments_collection.find({
        'student_id': current_user.user_id
    }))
    
    total_courses = len(enrollments)
    completed_courses = sum(1 for e in enrollments if e.get('completed', False))
    in_progress_courses = total_courses - completed_courses
    avg_progress = sum(e.get('progress', 0) for e in enrollments) / total_courses if total_courses > 0 else 0
    
    return render_template('dashboard/student/profile.html',
        stats={
            'total_courses': total_courses,
            'completed_courses': completed_courses,
            'in_progress_courses': in_progress_courses,
            'avg_progress': round(avg_progress, 1)
        }
    )

# Teacher dashboard routes
@app.route('/teacher/dashboard')
@login_required
def teacher_dashboard():
    if current_user.user_type != 'teacher':
        return redirect(url_for('home'))
    
    # Get all courses by this teacher
    courses = list(courses_collection.find({
        'teacher_id': current_user.user_id
    }))
    
    # Calculate total students, earnings, and ratings
    total_students = 0
    total_earnings = 0
    
    for course in courses:
        # Get enrollments for this course
        enrollments_count = enrollments_collection.count_documents({
            'course_id': course['_id']
        })
        
        # Get reviews and calculate average rating
        reviews = list(reviews_collection.find({
            'course_id': course['_id']
        }))
        
        # Calculate average rating
        if reviews:
            total_rating = sum(review['rating'] for review in reviews)
            course['average_rating'] = total_rating / len(reviews)
        else:
            course['average_rating'] = 0
            
        course['reviews'] = reviews
        total_students += enrollments_count
        total_earnings += course['price'] * enrollments_count
    
    stats = {
        'total_courses': len(courses),
        'total_students': total_students,
        'total_earnings': total_earnings,
        'courses': courses
    }
    
    return render_template('dashboard/teacher/home.html', stats=stats)

@app.route('/teacher/earnings')
@login_required
@teacher_required
def teacher_earnings():
    courses = list(courses_collection.find({
        'teacher_id': current_user.user_id
    }))
    
    # Calculate earnings per course and total
    course_earnings = []
    total_earnings = 0
    total_students = 0
    
    for course in courses:
        enrollments_count = enrollments_collection.count_documents({
            'course_id': course['_id']
        })
        
        course_total = course['price'] * enrollments_count
        course_earnings.append({
            'course': course,
            'student_count': enrollments_count,
            'total': course_total
        })
        
        total_earnings += course_total
        total_students += enrollments_count
    
    return render_template('dashboard/teacher/earnings.html',
        course_earnings=course_earnings,
        total_earnings=total_earnings,
        total_students=total_students
    )

@app.route('/teacher/courses')
@login_required
def teacher_courses():
    if current_user.user_type != 'teacher':
        return redirect(url_for('home'))
    courses = list(courses_collection.find({
        'teacher_id': current_user.user_id
    }))
    return render_template('dashboard/teacher/manage_courses.html', courses=courses)

@app.route('/teacher/courses/add', methods=['GET', 'POST'])
@login_required
def add_course():
    if current_user.user_type != 'teacher':
        return redirect(url_for('home'))
        
    if request.method == 'POST':
        try:
            title = request.form.get('title')
            description = request.form.get('description')
            price = request.form.get('price')
            category = request.form.get('category')
            
            if not all([title, description, price, category]):
                flash('All fields are required', 'danger')
                return redirect(url_for('add_course'))
            
            # Capitalize title
            title = capitalize_first(title)
            
            thumbnail_url = None
            if 'thumbnail' in request.files:
                file = request.files['thumbnail']
                if file and allowed_file(file.filename):
                    filename = secure_filename(f"course_{datetime.now().strftime('%Y%m%d%H%M%S')}_{file.filename}")
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], 'course_thumbnails', filename))
                    thumbnail_url = f"images/course_thumbnails/{filename}"
            
            new_course = {
                'teacher_id': current_user.user_id,
                'title': title,
                'description': description,
                'price': float(price),
                'thumbnail_url': thumbnail_url,
                'category': category,
                'created_at': datetime.utcnow(),
                'is_published': False
            }
            result = courses_collection.insert_one(new_course)
            flash('Course created successfully! Now add your content.', 'success')
            return redirect(url_for('manage_course_content', course_id=result.inserted_id))
        except Exception as e:
            flash('Failed to create course', 'danger')
            print(f"Error creating course: {str(e)}")
    return render_template('dashboard/teacher/add_course.html')

@app.route('/teacher/courses/<course_id>/edit', methods=['GET', 'POST'])
@login_required
@teacher_required
def edit_course(course_id):
    try:
        course_id_obj = ObjectId(course_id)
    except:
        abort(404)
        
    course = courses_collection.find_one({
        '_id': course_id_obj,
        'teacher_id': current_user.user_id
    })
    if not course:
        abort(404)
    
    if request.method == 'POST':
        try:
            update_data = {
                'title': capitalize_first(request.form.get('title')),
                'description': request.form.get('description'),
                'price': float(request.form.get('price')),
                'category': request.form.get('category')
            }
            
            if 'thumbnail' in request.files:
                file = request.files['thumbnail']
                if file and allowed_file(file.filename):
                    filename = secure_filename(f"course_{datetime.now().strftime('%Y%m%d%H%M%S')}_{file.filename}")
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], 'course_thumbnails', filename))
                    # Delete old thumbnail if exists
                    if course.get('thumbnail_url'):
                        old_path = os.path.join('static', course['thumbnail_url'])
                        if os.path.exists(old_path):
                            os.remove(old_path)
                    update_data['thumbnail_url'] = f"images/course_thumbnails/{filename}"
            
            courses_collection.update_one(
                {'_id': course_id_obj},
                {'$set': update_data}
            )
            flash('Course updated successfully!', 'success')
            return redirect(url_for('teacher_courses'))
        except Exception as e:
            flash('Failed to update course.', 'danger')
            print(f"Error updating course: {str(e)}")
    
    return render_template('dashboard/teacher/edit_course.html', course=course)

@app.route('/teacher/courses/<course_id>/delete', methods=['POST'])
@login_required
@teacher_required
def delete_course(course_id):
    try:
        course_id_obj = ObjectId(course_id)
    except:
        abort(404)
        
    course = courses_collection.find_one({
        '_id': course_id_obj,
        'teacher_id': current_user.user_id
    })
    if not course:
        abort(404)
    
    try:
        # Delete course thumbnail if exists
        if course.get('thumbnail_url'):
            thumbnail_path = os.path.join('static', course['thumbnail_url'])
            if os.path.exists(thumbnail_path):
                os.remove(thumbnail_path)
        
        # Delete all associated data
        course_content_collection.delete_many({'course_id': course_id_obj})
        enrollments_collection.delete_many({'course_id': course_id_obj})
        reviews_collection.delete_many({'course_id': course_id_obj})
        user_progress_collection.delete_many({'course_id': course_id_obj})
        
        # Finally delete the course
        courses_collection.delete_one({'_id': course_id_obj})
        
        flash('Course has been permanently deleted.', 'success')
    except Exception as e:
        flash('An error occurred while deleting the course.', 'error')
        print(f"Error deleting course {course_id}: {str(e)}")
    
    return redirect(url_for('teacher_dashboard'))

@app.route('/teacher/profile', methods=['GET', 'POST'])
@login_required
def teacher_profile():
    if current_user.user_type != 'teacher':
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        try:
            update_data = {
                'first_name': request.form.get('first_name'),
                'last_name': request.form.get('last_name'),
                'bio': request.form.get('bio')
            }
            
            if 'profile_pic' in request.files:
                file = request.files['profile_pic']
                if file and allowed_file(file.filename):
                    filename = secure_filename(f"profile_{current_user.user_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}_{file.filename}")
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], 'profile_pics', filename))
                    # Delete old profile picture if exists
                    if current_user.profile_pic:
                        old_path = os.path.join('static', current_user.profile_pic)
                        if os.path.exists(old_path):
                            os.remove(old_path)
                    update_data['profile_pic'] = f"images/profile_pics/{filename}"
            
            # Handle password change
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')
            
            if current_password and new_password and confirm_password:
                if not current_user.check_password(current_password):
                    flash('Current password is incorrect', 'danger')
                    return redirect(url_for('teacher_profile'))
                
                if new_password != confirm_password:
                    flash('New passwords do not match', 'danger')
                    return redirect(url_for('teacher_profile'))
                
                update_data['password_hash'] = generate_password_hash(new_password)
            
            users_collection.update_one(
                {'_id': current_user.user_id},
                {'$set': update_data}
            )
            flash('Profile updated successfully!', 'success')
        except Exception as e:
            flash('Failed to update profile', 'danger')
            print(f"Error updating profile: {str(e)}")
        return redirect(url_for('teacher_profile'))
    
    # Get teacher statistics
    courses = list(courses_collection.find({
        'teacher_id': current_user.user_id
    }))
    
    course_ids = [course['_id'] for course in courses]
    
    total_students = enrollments_collection.count_documents({
        'course_id': {'$in': course_ids}
    })
    
    total_reviews = reviews_collection.count_documents({
        'course_id': {'$in': course_ids}
    })
    
    avg_rating_result = reviews_collection.aggregate([
        {'$match': {'course_id': {'$in': course_ids}}},
        {'$group': {'_id': None, 'avg': {'$avg': '$rating'}}}
    ])
    avg_rating = next(avg_rating_result, {'avg': 0})['avg']
    
    return render_template('dashboard/teacher/profile.html',
        stats={
            'total_courses': len(courses),
            'total_students': total_students,
            'total_reviews': total_reviews,
            'avg_rating': round(avg_rating, 1)
        }
    )

# Course routes
@app.route('/course/<course_id>')
def view_course(course_id):
    try:
        course_id_obj = ObjectId(course_id)
    except:
        abort(404)
        
    course = courses_collection.find_one({'_id': course_id_obj})
    if not course:
        abort(404)
    
    content = list(course_content_collection.find({
        'course_id': course_id_obj
    }).sort('position', 1))
    
    reviews = list(reviews_collection.find({
        'course_id': course_id_obj
    }).sort('created_at', -1))
    
    # Calculate average rating
    avg_rating = reviews_collection.aggregate([
        {'$match': {'course_id': course_id_obj}},
        {'$group': {'_id': None, 'avg': {'$avg': '$rating'}}}
    ])
    avg_rating = next(avg_rating, {'avg': 0})['avg']
    
    enrollment = None
    if current_user.is_authenticated and current_user.user_type == 'student':
        enrollment = enrollments_collection.find_one({
            'student_id': current_user.user_id,
            'course_id': course_id_obj
        })
    
    return render_template('main/course_detail.html',
        course=course,
        content=content,
        reviews=reviews,
        avg_rating=round(avg_rating, 1) if avg_rating else 0,
        enrollment=enrollment
    )

@app.route('/course/<course_id>/enroll', methods=['POST'])
@login_required
def enroll_course(course_id):
    if current_user.user_type != 'student':
        flash('Only students can enroll in courses', 'danger')
        return redirect(url_for('view_course', course_id=course_id))
    
    try:
        course_id_obj = ObjectId(course_id)
    except:
        abort(404)
    
    existing = enrollments_collection.find_one({
        'student_id': current_user.user_id,
        'course_id': course_id_obj
    })
    
    if existing:
        flash('You are already enrolled in this course', 'info')
        return redirect(url_for('view_course', course_id=course_id))
    
    try:
        enrollments_collection.insert_one({
            'student_id': current_user.user_id,
            'course_id': course_id_obj,
            'progress': 0,
            'completed': False,
            'enrolled_at': datetime.utcnow()
        })
        flash('Successfully enrolled in the course!', 'success')
    except Exception as e:
        flash('Failed to enroll in the course', 'danger')
        print(f"Error enrolling in course: {str(e)}")
    return redirect(url_for('view_course', course_id=course_id))

@app.route('/course/<course_id>/review', methods=['GET', 'POST'])
@login_required
def add_review(course_id):
    if current_user.user_type != 'student':
        flash('Only students can submit reviews', 'danger')
        return redirect(url_for('view_course', course_id=course_id))
    
    try:
        course_id_obj = ObjectId(course_id)
    except:
        abort(404)
    
    is_enrolled = enrollments_collection.find_one({
        'student_id': current_user.user_id,
        'course_id': course_id_obj
    })
    
    if not is_enrolled:
        flash('You must enroll in the course before submitting a review', 'warning')
        return redirect(url_for('view_course', course_id=course_id))
    
    existing_review = reviews_collection.find_one({
        'student_id': current_user.user_id,
        'course_id': course_id_obj
    })
    
    if existing_review:
        flash('You have already reviewed this course', 'info')
        return redirect(url_for('view_course', course_id=course_id))
    
    if request.method == 'POST':
        try:
            rating = int(request.form.get('rating'))
            comment = request.form.get('comment', '').strip()
            
            if not (1 <= rating <= 5):
                flash('Invalid rating value', 'danger')
                return redirect(url_for('add_review', course_id=course_id))
            
            reviews_collection.insert_one({
                'student_id': current_user.user_id,
                'course_id': course_id_obj,
                'rating': rating,
                'comment': comment if comment else None,
                'created_at': datetime.utcnow()
            })
            flash('Thank you for your review!', 'success')
            return redirect(url_for('view_course', course_id=course_id))
        except ValueError:
            flash('Invalid rating value', 'danger')
        except Exception as e:
            flash('Failed to submit review. Please try again.', 'danger')
            print(f"Error submitting review: {str(e)}")
    return render_template('main/add_review.html', course_id=course_id)

# Content management routes
@app.route('/course/<course_id>/content/<content_id>')
@login_required
def view_course_content(course_id, content_id):
    try:
        course_id_obj = ObjectId(course_id)
        content_id_obj = ObjectId(content_id)
    except:
        abort(404)
    
    enrollment = enrollments_collection.find_one({
        'student_id': current_user.user_id,
        'course_id': course_id_obj
    })
    
    if not enrollment:
        flash('You need to enroll in this course first', 'warning')
        return redirect(url_for('view_course', course_id=course_id))
    
    content = course_content_collection.find_one({
        '_id': content_id_obj,
        'course_id': course_id_obj
    })
    
    if not content:
        abort(404)
    
    all_content = list(course_content_collection.find({
        'course_id': course_id_obj
    }).sort('position', 1))
    
    progress = user_progress_collection.find_one({
        'user_id': current_user.user_id,
        'content_id': content_id_obj
    })
    
    return render_template('course/video_player.html',
        course_id=course_id,
        content=content,
        all_content=all_content,
        progress=progress
    )

@app.route('/course/<course_id>/content/<content_id>/progress', methods=['POST'])
@login_required
def update_content_progress(course_id, content_id):
    try:
        course_id_obj = ObjectId(course_id)
        content_id_obj = ObjectId(content_id)
    except:
        return jsonify({'success': False, 'error': 'Invalid ID'}), 400
    
    enrollment = enrollments_collection.find_one({
        'student_id': current_user.user_id,
        'course_id': course_id_obj
    })
    
    if not enrollment:
        return jsonify({'success': False, 'error': 'Not enrolled'}), 403
    
    try:
        progress_data = request.json.get('progress', 0)
        
        progress = user_progress_collection.find_one({
            'user_id': current_user.user_id,
            'content_id': content_id_obj
        })
        
        if not progress:
            new_progress = {
                'user_id': current_user.user_id,
                'content_id': content_id_obj,
                'progress': progress_data,
                'last_watched': datetime.utcnow()
            }
            user_progress_collection.insert_one(new_progress)
        else:
            # Only update if new progress is higher
            if progress_data > progress.get('progress', 0):
                user_progress_collection.update_one(
                    {'_id': progress['_id']},
                    {'$set': {
                        'progress': progress_data,
                        'last_watched': datetime.utcnow()
                    }}
                )
        
        return jsonify({
            'success': True,
            'progress': progress_data
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/course/<course_id>/content/<content_id>/complete', methods=['POST'])
@login_required
def mark_content_completed(course_id, content_id):
    try:
        course_id_obj = ObjectId(course_id)
        content_id_obj = ObjectId(content_id)
    except:
        return jsonify({'success': False, 'error': 'Invalid ID'}), 400
    
    enrollment = enrollments_collection.find_one({
        'student_id': current_user.user_id,
        'course_id': course_id_obj
    })
    
    if not enrollment:
        return jsonify({'success': False, 'error': 'Not enrolled'}), 403
    
    try:
        progress = user_progress_collection.find_one({
            'user_id': current_user.user_id,
            'content_id': content_id_obj
        })
        
        if not progress:
            user_progress_collection.insert_one({
                'user_id': current_user.user_id,
                'content_id': content_id_obj,
                'completed': True,
                'last_watched': datetime.utcnow()
            })
        else:
            user_progress_collection.update_one(
                {'_id': progress['_id']},
                {'$set': {
                    'completed': True,
                    'last_watched': datetime.utcnow()
                }}
            )
        
        # Update overall progress
        all_content_count = course_content_collection.count_documents({
            'course_id': course_id_obj
        })
        
        completed_count = user_progress_collection.count_documents({
            'user_id': current_user.user_id,
            'content_id': {'$in': doc['_id'] for doc in course_content_collection.find(
                {'course_id': course_id_obj}, 
                {'_id': 1}
            )},
            'completed': True
        })
        
        new_progress = int((completed_count / all_content_count) * 100) if all_content_count else 0
        
        enrollments_collection.update_one(
            {'_id': enrollment['_id']},
            {'$set': {'progress': new_progress}}
        )
        
        return jsonify({
            'success': True,
            'progress': new_progress
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/teacher/courses/<course_id>/content', methods=['GET', 'POST'])
@login_required
def manage_course_content(course_id):
    if current_user.user_type != 'teacher':
        return redirect(url_for('home'))
    
    try:
        course_id_obj = ObjectId(course_id)
    except:
        abort(404)
    
    course = courses_collection.find_one({
        '_id': course_id_obj,
        'teacher_id': current_user.user_id
    })
    if not course:
        abort(404)
    
    if request.method == 'POST':
        if 'reorder' in request.form:
            try:
                order = request.form.getlist('content_order[]')
                for idx, content_id in enumerate(order, start=1):
                    try:
                        content_id_obj = ObjectId(content_id)
                        course_content_collection.update_one(
                            {'_id': content_id_obj},
                            {'$set': {'position': idx}}
                        )
                    except:
                        continue
                flash('Content reordered successfully!', 'success')
            except Exception as e:
                flash('Failed to reorder content', 'danger')
        elif 'delete' in request.form:
            try:
                content_id = request.form.get('content_id')
                content_id_obj = ObjectId(content_id)
                course_content_collection.delete_one({
                    '_id': content_id_obj,
                    'course_id': course_id_obj
                })
                flash('Content deleted successfully!', 'success')
            except Exception as e:
                flash('Failed to delete content', 'danger')
        return redirect(url_for('manage_course_content', course_id=course_id))
    
    content_items = list(course_content_collection.find({
        'course_id': course_id_obj
    }).sort('position', 1))
    
    return render_template('dashboard/teacher/manage_content.html',
        course=course,
        content_items=content_items
    )

@app.route('/teacher/courses/<course_id>/content/add', methods=['GET', 'POST'])
@login_required
def add_course_content(course_id):
    if current_user.user_type != 'teacher':
        return redirect(url_for('home'))
    
    try:
        course_id_obj = ObjectId(course_id)
    except:
        abort(404)
    
    course = courses_collection.find_one({
        '_id': course_id_obj,
        'teacher_id': current_user.user_id
    })
    if not course:
        abort(404)
    
    if request.method == 'POST':
        try:
            title = request.form.get('title')
            content_type = request.form.get('content_type')
            url = request.form.get('url')
            description = request.form.get('description', '')
            
            if not all([title, content_type, url]):
                flash('Title, type, and URL are required', 'danger')
                return redirect(url_for('add_course_content', course_id=course_id))
            
            # Get max position
            last_content = course_content_collection.find_one(
                {'course_id': course_id_obj},
                sort=[('position', -1)]
            )
            max_position = last_content['position'] if last_content else 0
            
            course_content_collection.insert_one({
                'course_id': course_id_obj,
                'title': title,
                'description': description,
                'content_type': content_type,
                'url': url,
                'position': max_position + 1
            })
            flash('Content added successfully!', 'success')
            return redirect(url_for('manage_course_content', course_id=course_id))
        except Exception as e:
            flash('Failed to add content', 'danger')
            print(f"Error adding content: {str(e)}")
    
    return render_template('dashboard/teacher/add_content.html', course=course)

# Template filters
@app.template_filter('capitalize_first')
def capitalize_first_filter(text):
    return capitalize_first(text)

@app.template_filter('capitalize_name')
def capitalize_name_filter(text):
    return capitalize_name(text)

@app.template_filter('avg')
def avg_filter(lst):
    if not lst:
        return 0
    return sum(lst) / len(lst)

if __name__ == '__main__':
    app.run(debug=True)