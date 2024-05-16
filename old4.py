from flask import Flask, render_template, redirect, url_for, session, flash, request,send_file,Response
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, BooleanField, IntegerField,TextAreaField
from wtforms.validators import DataRequired, Email, ValidationError, Length, InputRequired, Regexp
import bcrypt
import random
from flask_mail import Mail, Message
from flask_mysqldb import MySQL
import cv2
import random
import os
import pandas as pd
from combinedcode import app,allowed_file,partial_mask_data,pseudonymize_data,generate_synthetic_data,swap_data
from werkzeug.utils import secure_filename
from anonypyx import Anonymizer
from appp import app ,get_file_size,allowedd_file
from PIL import Image
app = Flask(__name__)

COMPRESSED_FOLDER = 'compressed'
app.config['COMPRESSED_FOLDER'] = COMPRESSED_FOLDER
ALLOWED_EXTENSIONSs = {'png', 'jpg', 'jpeg'}
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'csv'}
USER_ROLE = 'user'
ADMIN_ROLE = 'admin'
# MySQL Configuration
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'mydatabase'
app.secret_key = 'your_secret_key_here'
app.config['MAIL_USERNAME'] = 'tessssst123456789@outlook.com'
app.config['MAIL_SERVER'] = 'smtp.office365.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_PASSWORD'] = 'Testkregeisse'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
mail = Mail(app)
mysql = MySQL(app)
import mysql.connector as sql_db
mysql = sql_db.connect(
    host=app.config['MYSQL_HOST'],
    user=app.config['MYSQL_USER'],
    password=app.config['MYSQL_PASSWORD'],
    database=app.config['MYSQL_DB']
)
def get_db_connection():
    conn = sql_db.connect(
         # Your database connection details here: host, user, password, database
         host="localhost",
         user="root",
         password="",
         database="mydatabase"
    )
    return conn
@app.route('/com')
def comindex():
    return render_template('comindex.html')

@app.route('/compress', methods=['POST'])
def compress():
    if 'file' not in request.files:
        return "No file part", 400

    file = request.files['file']
    compression_level = int(request.form['compression_level'])

    if file.filename == '':
        return "No selected file", 400

    if file and allowedd_file(file.filename):
        input_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        output_path = os.path.join(app.config['COMPRESSED_FOLDER'], file.filename)
        file.save(input_path)

        try:
            with Image.open(input_path) as img:
                img.save(output_path, quality=compression_level)

            original_size_kb = get_file_size(input_path)
            compressed_size_kb = get_file_size(output_path)

            return render_template('comresult.html', 
                                    original_size=original_size_kb, 
                                    compressed_size=compressed_size_kb,
                                    filename=file.filename)
        except Exception as e:
            return f"Error compressing image: {e}", 500
    else:
        return "Invalid file format", 400

@app.route('/dowwnload/<filename>')
def comdownload(filename):
    return send_file(os.path.join(app.config['COMPRESSED_FOLDER'], filename), as_attachment=True)

class FeedbackForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    message = TextAreaField("Feedback Message", validators=[DataRequired(), Length(min=10)]) 
    submit = SubmitField("Submit Feedback")
@app.route('/feedback', methods=['GET', 'POST'])
def feedback():
    form = FeedbackForm()

    if form.validate_on_submit():
        print("Form submitted successfully")  # Debugging statement

        try:
            conn = get_db_connection()

            if conn:
                cursor = conn.cursor()

                # Insert feedback into the database
                cursor.execute(
                    "INSERT INTO feedback (Name, Email, Message) VALUES (%s, %s, %s)",
                    (form.name.data, form.email.data, form.message.data)
                )
                conn.commit()
                print("Feedback inserted into the database")  # Debugging statement

                flash('Thank you for your feedback!', 'success')

            else:
                flash('Database connection error', 'error')

        except sql_db.Error as err:
            flash(f'An error occurred while submitting your feedback: {err}', 'error')

        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

    else:
        print("Form validation failed")  # Debugging statement

    # Fetch feedback data from the database
    conn = get_db_connection()

    if conn:
        cursor = conn.cursor()
        cursor.execute("SELECT Name, Message, reply FROM feedback")
        feedback_data = cursor.fetchall()
        print("Feedback data fetched from the database:", feedback_data)  # Debugging statement
        conn.close()
    else:
        flash('Database connection error', 'error')
        feedback_data = []

    return render_template('feedback.html', form=form, feedback_data=feedback_data)

@app.route('/admin/feedback', methods=['GET', 'POST'])
def admin_feedback():
    conn = None
    cursor = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        if request.method == 'POST':
            if 'delete_id' in request.form:
                feedback_id = request.form['delete_id']
                cursor.execute("DELETE FROM feedback WHERE id = %s", (feedback_id,))
                conn.commit()
                flash('Feedback deleted successfully!', 'success')

            elif 'reply_id' in request.form:
                feedback_id = request.form['reply_id']
                reply_message = request.form['reply_message']
                cursor.execute("UPDATE feedback SET reply = %s WHERE id = %s", (reply_message, feedback_id))
                conn.commit()
                flash('Reply sent successfully!', 'success')

        cursor.execute("SELECT * FROM feedback")
        feedback_data = cursor.fetchall()

    except sql_db.Error as err:
        flash(f'An error occurred while retrieving feedback: {err}', 'error')
        return redirect(url_for('indexx'))

    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

    return render_template('admin_feedback.html', feedback_data=feedback_data)


class ManageUsersForm(FlaskForm):
    # Define any form fields needed for managing users
    pass


    
class RegisterForm(FlaskForm):
    name_prefix = SelectField("Title", choices=[('', ''), ('Mr.', 'Mr.'), ('Mrs.', 'Mrs.'), ('Miss', 'Miss')], validators=[DataRequired()])
    first_name = StringField("First Name", validators=[DataRequired(), Length(max=50), Regexp('^[a-zA-Z]*$', message='First name must contain only letters')])
    last_name = StringField("Last Name", validators=[DataRequired(), Length(max=50), Regexp('^[a-zA-Z]*$', message='Last name must contain only letters')])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8)])  
    confirm_password = PasswordField("Confirm Password", validators=[DataRequired()]) 
    address = StringField("Address", validators=[DataRequired()])
    address_city = StringField("City", validators=[DataRequired()])
    address_state = StringField("State", validators=[DataRequired()])
    address_pincode = StringField("Pincode", validators=[DataRequired(), Length(min=6, max=6)])
    country = SelectField("Country", choices=[('', ''), ('India', 'India'), ('USA', 'USA'), ('Canada', 'Canada')], validators=[DataRequired()])
    security_question = SelectField("Security Question", choices=[('', ''), ('mother_maiden_name', 'What is your mother\'s maiden name?'),
                                                                  ('first_pet_name', 'What is the name of your first pet?')],
                                     validators=[DataRequired()])
    security_answer = StringField("Security Answer", validators=[DataRequired()])
    agree_terms = BooleanField("I agree to the terms and conditions", validators=[InputRequired()])
    captcha_answer = IntegerField('Solve:', validators=[DataRequired()])
    submit = SubmitField("Register")

    def validate_email(self, field):
        cursor = mysql.cursor()

        cursor.execute("SELECT * FROM user where email=%s", (field.data,))
        user = cursor.fetchone()
        cursor.close()
        if user:
            raise ValidationError('Email Already Taken')

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")

@app.route('/')
def indexx():
    return render_template('indexxx.html')

@app.route('/registerr', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        if form.agree_terms.data:
            captcha_result = session.pop('captcha_result', None)
            user_answer = form.captcha_answer.data

            if user_answer and captcha_result is not None:
                if int(user_answer) == captcha_result:
                    try:
                        hashed_password = bcrypt.hashpw(form.password.data.encode('utf-8'), bcrypt.gensalt())

                        conn = get_db_connection()
                        cursor = conn.cursor()
                        cursor.execute("INSERT INTO user (title, first_name, last_name, email, password, address, city, state, country, pincode, security_question, security_answer) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)", (form.name_prefix.data, form.first_name.data, form.last_name.data, form.email.data, hashed_password, form.address.data, form.address_city.data, form.address_state.data, form.country.data, form.address_pincode.data, form.security_question.data, form.security_answer.data))
                        conn.commit()
                        cursor.close()
                        conn.close()
                        global otp
                        otp = random.randint(100000, 999999)
                        session['email_verification_otp'] = otp  # Store OTP in session

                        msg = Message('Email verification', sender='tessssst123456789@outlook.com', recipients=[form.email.data])
                        msg.body = 'hi ' + form.first_name.data + "\n your email OTP is: " + str(otp)
                        mail.send(msg)

                        return render_template('email_verify.html', email=form.email.data)

                    except Exception as e:
                        flash("An error occurred while processing your request. Please try again.")
                        app.logger.error("Error during registration: %s", str(e))
                        return render_template('register.html', form=form)  # Return in case of failure
                else:
                    flash("Incorrect CAPTCHA. Please try again.")
                    return render_template('register.html', form=form)
            else:
                flash("CAPTCHA validation failed. Please try again.")
                return render_template('register.html', form=form)
        else:
            flash("Please agree to the terms and conditions.")
            return render_template('register.html', form=form)
    else:
        captcha = generate_captcha()
        return render_template('register.html', form=form, captcha=captcha)
    
def generate_captcha():
    # Generate random numbers and operator
    num1 = random.randint(1, 20)  
    num2 = random.randint(1, 20)
    operator = random.choice(['+', '-', '*', '/'])  

    while True:  
        expression = f"{num1} {operator} {num2}"
        result = eval(expression)  
        if operator != '/' or result != 0:
            break

    # Store the result in session
    session['captcha_result'] = result
    return expression



@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        conn = sql_db.connect( host="localhost",
            user="root",
            password="",
            database="mydatabase")
        cursor = conn.cursor()  
        cursor.execute("SELECT * FROM user WHERE email=%s", (email,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()  
        if user and bcrypt.checkpw(password.encode('utf-8'), user[5].encode('utf-8')):
            session['user_id'] = user[0]
            
            return redirect(url_for('dashboard'))
        else:
            flash("Login failed. Please check your email and password")
            return redirect(url_for('login'))

    return render_template('login.html', form=form)
@app.route('/admin_login', methods=['GET', 'POST'])
def logiin():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        conn = sql_db.connect(
            host="localhost",
            user="root",
            password="",
            database="mydatabase"
        )  # Establish connection inside the function

        cursor = conn.cursor()  
        cursor.execute("SELECT * FROM user WHERE email=%s", (email,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()  

        if user and bcrypt.checkpw(password.encode('utf-8'), user[5].encode('utf-8')):
            session['user_id'] = user[0]
            session['role'] = user[6] 
            return render_template('admin.html')   # Redirect to admin area
        else:
            flash("Login failed. Please check your email and password")
            return redirect(url_for('logiin'))

    return render_template('admin_login.html', form=form) 
@app.route('/verify_email', methods=['GET', 'POST'])
def verify_email():
    if request.method == 'POST':  # Added indentation
        user_otp = request.form.get('otp')  # Get OTP from form
        if user_otp and int(user_otp) == session.get('email_verification_otp'):
            # ... Update user as verified (from previous examples) ...
            flash("Your Email is Verified... You can login Now!!!!")
            return redirect(url_for('login'))
        else:
            flash("Your Email is failed.... Register with valid mail")
            return redirect(url_for('register'))

    return render_template('verify_email.html') # Add this line

def user_delete(self, email):
    db = self.connection()  # Assuming you have a function to get the DB connection
    mycursor = db.cursor()
    sq = "delete from user where email =%s"
    record = [email]
    mycursor.execute(sq, record)
    db.commit()
    mycursor.close()
    db.close()
    return True  # or False depending on whether the deletion was successful


@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        user_id = session['user_id']
        conn = sql_db.connect( 
            host="localhost",
            user="root",
            password="",
            database="mydatabase"
        )

        cursor = conn.cursor()  
        cursor.execute("SELECT * FROM anonymized_data WHERE user_id = %s", (user_id,))
        anonymized_data = cursor.fetchall()
        cursor.close()
        conn.close()
        return render_template('dashboard.html', anonymized_data=anonymized_data)
    else:
        return redirect(url_for('login'))

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session.pop('user_id', None)
    flash("You have been logged out successfully.")
    return redirect(url_for('login'))
db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': '',
    'database': 'mydatabase'
}

# Function to generate a 6-digit OTP
def generate_otp():
    return str(random.randint(100000, 999999))

# Function to send OTP email
def send_otp_email(email, otp):
    try:
        msg = Message('Password Reset OTP', sender='tessssst123456789@outlook.com', recipients=[email])
        msg.body = f'Your OTP is: {otp}'
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')

        # Check if the email exists in the database
        conn = sql_db.connect(**db_config)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM user WHERE email = %s", (email,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if user:
            # Generate OTP and store it in session
            otp = generate_otp()
            session['reset_password_otp'] = otp
            session['reset_password_email'] = email

            # Send OTP to user's email
            if send_otp_email(email, otp):
                flash('An OTP has been sent to your email.', 'success')
                return redirect(url_for('verify_otp'))
            else:
                flash('Failed to send OTP email. Please try again later.', 'error')
        else:
            flash('Email not found. Please enter a valid email.', 'error')

    return render_template('forgot_password.html')

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        user_otp = request.form.get('otp')
        if user_otp and user_otp == session.get('reset_password_otp'):
            flash("Your Email is Verified... You can reset your password  Now!!!!")
            return redirect(url_for('reset_password'))
        else:
            flash('Incorrect OTP. Please try again.', 'error')

    return render_template('verify_otp.html')

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        # Check if passwords match
        if new_password != confirm_password:
            flash('Passwords do not match. Please try again.', 'error')
            return redirect(url_for('reset_password'))

        # Retrieve email from session
        email = session.get('reset_password_email')

        # Update password in the database
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        conn = sql_db.connect(**db_config)
        cursor = conn.cursor()
        cursor.execute("UPDATE user SET password = %s WHERE email = %s", (hashed_password, email))
        conn.commit()
        cursor.close()
        conn.close()

        flash('Password reset successfully. You can now login with your new password.', 'success')
        # Clear session data after successful password reset
        session.pop('reset_password_otp', None)
        session.pop('reset_password_email', None)

        return redirect(url_for('login'))

    return render_template('reset_password.html')



def blur_image(image_path):
    image = cv2.imread(image_path)
    blurred_image = cv2.GaussianBlur(image, (25, 25), 0)
    cv2.imwrite(image_path, blurred_image)
def save_to_database(original_path, anonymized_path, user_id):
    with open(original_path, 'rb') as original_file, open(anonymized_path, 'rb') as anonymized_file:
        original_data = original_file.read()
        anonymized_data = anonymized_file.read()

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO anonymized_data (user_id, original_data_blob, anonymized_data_blob, data_type) VALUES (%s, %s, %s, 'image')", (user_id, original_data, anonymized_data))
        cursor.commit()
        cursor.close()
        conn.close()

        print("Data inserted into database successfully!")
    except Exception as e:
        print("Error inserting data into database:", e)



@app.route('/ii')
def indexxx():
    return render_template('indexx.html')
@app.route('/image', methods=['POST'])
def upload_image():
    if 'file' not in request.files:
        return "No file part"

    file = request.files['file']
    if file.filename == '':
        return "No selected file"

    filename = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    original_path = filename
    
    # Save the file to 'static/uploads' directory
    file.save(filename)

    # Blur the uploaded image
    blur_image(filename)

    # Store the file path in the database
    # Modify the INSERT query to include the file paths
    user_id = session.get('user_id')
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO anonymized_data (user_id, original_data, anonymized_data, data_type) VALUES (%s, %s, %s, 'image')", (user_id, filename, filename))

    conn.commit()
    cursor.close()
    conn.close()
    # Perform any other necessary operations
    return render_template('result.html', filename=filename)



@app.route('/download/<filename>')
def downloadd(filename):
    print("Attempting to download file:", filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    print("File path:", file_path)
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    else:
        return "File not found"
# Methods




@app.route('/previous_records')
def previous_records():
    try:
        user_id = session.get('user_id')
        print("User ID from session:", user_id)  # Check if user_id is retrieved correctly

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM anonymized_data WHERE user_id = %s", (user_id,))
        records = cursor.fetchall()
        cursor.close()
        conn.close()

        print("Fetched records:", records)  # Check if any records are fetched

        return render_template('previous_records.html', records=records)
    except Exception as e:
        print("An error occurred while fetching previous records:", str(e))
        return "An error occurred while fetching previous records"

@app.route('/download_records', methods=['POST'])
def download_records():
    try:
        user_id = session.get('user_id')
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM anonymized_data WHERE user_id = %s", (user_id,))
        records = cursor.fetchall()
        cursor.close()
        conn.close()

        # Prepare CSV data
        csv_data = "Record ID,User ID,Original Data,Anonymized Data,Data Type\n"
        for record in records:
            csv_data += f"{record[0]},{record[1]},{record[2]},{record[3]},{record[4]}\n"

        # Return as a downloadable CSV file
        return Response(
            csv_data,
            mimetype="text/csv",
            headers={"Content-disposition": "attachment; filename=previous_records.csv"}
        )
    except Exception as e:
        print("An error occurred while downloading records:", str(e))
        return "An error occurred while downloading records"

@app.route('/delete_record/<int:record_id>', methods=['POST'])
def delete_record(record_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM anonymized_data WHERE id = %s", (record_id,))
        conn.commit()
        cursor.close()
        conn.close()
        return "Record deleted successfully"
    except Exception as e:
        print("An error occurred while deleting record:", str(e))
        return "An error occurred while deleting record"

@app.route('/download_record/<filename>', methods=['GET'])
def download_record(filename):
    try:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if os.path.exists(file_path):
            return send_file(file_path, as_attachment=True)
        else:
            return "File not found"
    except Exception as e:
        print("An error occurred while downloading record:", str(e))
        return "An error occurred while downloading record"
@app.route('/contactForm', methods=['GET', 'POST'])
def contactForm():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        question = request.form['question']

        conn = sql_db.connect(
            host="localhost",
            user="root",
            password="",
            database="mydatabase"
        )

        cursor = conn.cursor()
        cursor.execute("INSERT INTO contact (Name, Email, Question) VALUES (%s, %s, %s)", (name, email, question))
        conn.commit()
        cursor.close()
        conn.close()

        flash('Thank you for contacting us!', 'success')
        return redirect(url_for('indexx'))
    return render_template('contactForm.html') 




@app.route('/aboutus')
def about_us():
    return render_template('aboutus.html')

@app.route('/search', methods=['POST'])
def search():
    query = request.form.get('query')
    # Implement search functionality here, for example, redirect to search results page
    return redirect(url_for('search_results', query=query))

@app.route('/searchresults/<query>')
def searchresults(query):
    # Implement search results rendering here
    return f'Search results for: {query}'


@app.route('/admin')
def admin_home():
    if 'role' in session and session['role'] == ADMIN_ROLE:
        return render_template('admin.html')
    else:
        return redirect(url_for('login'))
@app.route('/manage_users', methods=['GET', 'POST'])
def manage_users():
    conn = None
    cursor = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        if request.method == 'POST':
            if 'delete_id' in request.form:
                user_id = request.form['delete_id']
                cursor.execute("DELETE FROM user WHERE id = %s", (user_id,))
                conn.commit()
                flash('User deleted successfully!', 'success')

            # Add more conditions for other actions if needed

        cursor.execute("SELECT id, title, first_name, last_name, email, address, city, state, country, pincode FROM user")
        user_data = cursor.fetchall()

    except sql_db.Error as err:
        flash(f'An error occurred while retrieving user data: {err}', 'error')
        return render_template('admin.html')

    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

    return render_template('manage_users.html', user_data=user_data)
@app.route('/aa')
def index():
    return render_template('cindex.html')

@app.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        return "No file part", 400

    file = request.files['file']

    if file.filename == '':
        return "No selected file", 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        df = pd.read_csv(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        columns = df.columns.tolist()
        return render_template('canonymize.html', columns=columns, filename=filename)
    else:
        return "Invalid file format", 400

@app.route('/anonymize', methods=['POST'])
def anonymize():
    filename = request.form.get('filename')
    technique = request.form.get('technique')
    columns = request.form.getlist('columns')
    
    if not filename or not technique or not columns:
        return "Form data is missing", 400

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    df = pd.read_csv(file_path)
    
    # Ensure the column dtypes are appropriate
    for column in columns:
        df[column] = pd.to_numeric(df[column], errors='coerce')
    
    
    if technique == 'masking':
        for column in columns:
            df[column] = df[column].apply(partial_mask_data)
    elif technique == 'swapping':
        for column in columns:
            df[column] = swap_data(df[column])
    elif technique == 'pseudonymization':
        for column in columns:
            df[column] = df[column].apply(pseudonymize_data)
    elif technique == 'synthetic':
        for column in columns:
            df[column] = generate_synthetic_data(df[column])
    else:
        return "Invalid technique", 400
    
    # Save the anonymized DataFrame to a CSV file
    anonymized_file = 'anonymized_' + filename
    anonymized_file_path = os.path.join(app.config['UPLOAD_FOLDER'], anonymized_file)
    df.to_csv(anonymized_file_path, index=False)
    
    return render_template('cdownload.html', filename=anonymized_file)

@app.route('/download/<filename>')
def download(filename):
    return send_file(os.path.join(app.config['UPLOAD_FOLDER'], filename), as_attachment=True)

@app.route('/aaaa')
def inndex():
    return render_template('kindex.html')

@app.route('/uplload', methods=['POST'])
def uupload():
    if 'file' not in request.files:
        return "No file part", 400

    file = request.files['file']

    if file.filename == '':
        return "No selected file", 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        df = pd.read_csv(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        columns = df.columns.tolist()
        return render_template('kanonymize.html', columns=columns, filename=filename)
    else:
        return "Invalid file format", 400

@app.route('/annonymize', methods=['POST'])
def annonymize():
    columns = request.form.getlist('columns[]')  # Retrieve selected columns as a list
    filename = request.form.get('filename')
    
    if not columns or not filename:
        return "Form data is missing", 400

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    df = pd.read_csv(file_path)
    
    # Ensure the column dtypes are appropriate
    for column in columns:
        df[column] = pd.to_numeric(df[column], errors='coerce').dropna()
    
    # Calculate the value of k based on the number of records in the DataFrame
    k = min(len(df), 3)  # Set k to the minimum of 3 or the number of records
    
    # Anonymize data using the Mondrian algorithm
    anonymizer = Anonymizer(df, k=k, algorithm="Mondrian", feature_columns=columns)
    anonymized_df = anonymizer.anonymize()
    
    # Save the anonymized DataFrame to a CSV file
    anonymized_file = 'anonymized_' + filename
    anonymized_file_path = os.path.join(app.config['UPLOAD_FOLDER'], anonymized_file)
    anonymized_df.to_csv(anonymized_file_path, index=False)
    
    return render_template('kdownload.html', filename=anonymized_file)

@app.route('/downlload/<filename>')
def downlload(filename):
    return send_file(os.path.join(app.config['UPLOAD_FOLDER'], filename), as_attachment=True)



if __name__ == '__main__':
    app.run(debug=True)
