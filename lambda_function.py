from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_
from werkzeug.security import generate_password_hash, check_password_hash
from jwt import ExpiredSignatureError, InvalidTokenError, DecodeError
import jwt
import datetime
import awsgi
from functools import wraps
import boto3
# from config import SECRET_KEY
import os


app = Flask(__name__)
CORS(app, resources={
    r"/doctors/*": {"origins": ["https://www.unilate.be", "https://dev.unilate.be", "http://localhost:3000"], "supports_credentials": True},
    r"/delays/*": {"origins": ["https://www.unilate.be", "https://dev.unilate.be/", "http://localhost:3000"], "supports_credentials": True}
}, allow_headers=["Content-Type", "X-Amz-Date", "Authorization", "X-Api-Key", "x-access-tokens"])

# app.config['SECRET_KEY'] = SECRET_KEY
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
username = os.getenv('username')
password = os.getenv('password')
app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://{username}:{password}@unilate-test.cl020ce0qv5c.eu-north-1.rds.amazonaws.com/unilate'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

ses = boto3.client('ses')
HTML_EMAIL_CONTENT = """
<!DOCTYPE html>
<html>
<head>
    <style>
        body {
            font-family: Arial, sans-serif;
            color: #5383FF;
            background-color: #ffffff;
            margin: 0;
            padding: 0;
        }
        .container {
            max-width: 600px;
            margin: auto;
            background-color: #ffffff;
            padding: 20px;
        }
        .header {
            background-color: #5383FF;
            color: #ffffff;
            padding: 10px;
            text-align: center;
            font-size: 24px;
            font-weight: bold;
        }
        .content {
            color: #333333;
            line-height: 1.6;
            padding: 20px;
        }
        .footer {
            background-color: #f2f2f2;
            color: #333333;
            text-align: center;
            padding: 10px;
            font-size: 14px;
        }
        #blue {
            color: #5383FF;
        }
        a {
            color: #5383FF;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            Bienvenue à Unilate
        </div>
        <div class="content">
            <p>Bonjour,</p>
            <p>Nous sommes ravis de vous accueillir sur <strong id="blue">Unilate</strong>, la plateforme révolutionnaire qui transforme l'expérience des rendez-vous médicaux en Belgique.</p>
            <p>Si vous avez des questions ou besoin d'aide, n'hésitez pas à contacter notre équipe de support.</p>
            <p>Cordialement,</p>
            <p><strong id="blue">L'équipe Unilate</strong></p>
        </div>
        <div class="footer">
            Commencez votre aventure sur notre <a href="https://www.unilate.be">site web</a>.
        </div>
    </div>
</body>
</html>

"""

class Doctor(db.Model):
    __tablename__ = 'Doctors'
    
    DoctorID = db.Column(db.Integer, primary_key=True)  
    Name = db.Column(db.String(255), nullable=False) 
    Specialty = db.Column(db.String(255))  
    City = db.Column(db.String(255))  
    Email = db.Column(db.String(255), nullable=False, unique=True)  
    PhoneNumber = db.Column(db.String(20))  
    HospitalName = db.Column(db.String(255))  
    PasswordHash = db.Column(db.String(255))  
    Picture = db.Column(db.String(255), default='man-white-brown') 

    def set_password(self, password):
        self.PasswordHash = generate_password_hash(password)  

    def check_password(self, password):
        return check_password_hash(self.PasswordHash, password)  

class Delay(db.Model):
    __tablename__ = 'Delays'
    
    DelayID = db.Column(db.Integer, primary_key=True)  
    DoctorID = db.Column(db.Integer, db.ForeignKey('Doctors.DoctorID'), nullable=False)  
    DelayDuration = db.Column(db.Integer, nullable=False)  
    StartTimestamp = db.Column(db.Integer, nullable=False)  
    EndTimestamp = db.Column(db.Integer, nullable=False)  
    AnnouncementTimestamp = db.Column(db.DateTime, nullable=False) 

class PatientSubscription(db.Model):
    __tablename__ = 'PatientSubscriptions'
    
    SubscriptionID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    DoctorID = db.Column(db.Integer, db.ForeignKey('Doctors.DoctorID'), nullable=False)
    PatientPhoneNumber = db.Column(db.String(20), nullable=False)
    AppointmentTime = db.Column(db.Integer, nullable=False)


# Wrap db.create_all in an application context
with app.app_context():
    db.create_all()


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('token')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = Doctor.query.filter_by(DoctorID=data['doctor_id']).first()
            if current_user is None:
                raise InvalidTokenError("User not found.")
        except ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except (InvalidTokenError, DecodeError) as e:
            return jsonify({'message': 'Token is invalid!'}), 401
        except Exception as e:
            return jsonify({'message': 'Unable to validate token.'}), 500

        return f(current_user, *args, **kwargs)

    return decorated



# Registration endpoint
@app.route('/doctors/register', methods=['POST'])
def register_doctor():
    data = request.get_json()
    picture = data.get('picture', 'man-white-brown')  # Get the picture from the request, or use the default
    doctor = Doctor(
        Name=data['name'],
        Specialty=data['specialty'],
        City=data['city'],
        Email=data['email'],
        PhoneNumber=data['phone_number'],
        HospitalName=data['hospital_name'],
        Picture=picture
    )
    doctor.set_password(data['password'])
    db.session.add(doctor)
    try:
        db.session.commit()

        ses.send_email(
            Source='Unilate Team <harold.unilate@gmail.com>',
            Destination={'ToAddresses': [doctor.Email]},
            Message={
                'Subject': {'Data': 'Welcome to Unilate'},
                'Body': {
                    'Html': {'Data': HTML_EMAIL_CONTENT}
                }
            }
        )

        token = jwt.encode({
            'doctor_id': doctor.DoctorID,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        response = make_response(jsonify({'message': 'New doctor registered'}))
        # Set the cookie
        response.set_cookie('token', token, httponly=True, path='/', secure=True, samesite='None')
        return response, 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/doctors/login', methods=['POST'])
def login_doctor():
    auth = request.json
    if not auth or not auth.get('email') or not auth.get('password'):
        return jsonify({'message': 'Could not verify', 'WWW-Authenticate': 'Basic realm="Login required!"'}), 401

    doctor = Doctor.query.filter_by(Email=auth.get('email')).first()
    if doctor and doctor.check_password(auth.get('password')):
        token = jwt.encode({
            'doctor_id': doctor.DoctorID,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        response = make_response(jsonify({'message': 'Login successful'}))
        # Set the cookie
        response.set_cookie('token', token, httponly=True, path='/', secure=True, samesite='None')
        
        # Print the Set-Cookie header if it's been set
        print("Set-Cookie Header:", response.headers.get('Set-Cookie'))

        return response, 200
    else:
        return jsonify({'message': 'Doctor not found or password is wrong'}), 401

    
@app.route('/doctors/me', methods=['GET'])
@token_required
def get_current_doctor(current_user):
    # current_user is already populated by the @token_required decorator
    # Use current_user.DoctorID to get the doctor's information

    doctor = Doctor.query.filter_by(DoctorID=current_user.DoctorID).first()
    if not doctor:
        return jsonify({'message': 'Doctor not found'}), 404

    # Returning detailed information of the doctor
    doctor_data = {
        'doctor_id': doctor.DoctorID,
        'name': doctor.Name,
        'specialty': doctor.Specialty,
        'city': doctor.City,
        'email': doctor.Email,
        'phone_number': doctor.PhoneNumber,
        'hospital_name': doctor.HospitalName,
        'picture': doctor.Picture
    }

    return jsonify({'doctor': doctor_data}), 200

@app.route('/doctors/private/<int:doctor_id>', methods=['GET'])
@token_required
def get_doctor_private(current_user, doctor_id):
    # Ensure the current user is the doctor whose delay is being updated
    if current_user.DoctorID != doctor_id:
        return jsonify({'message': 'Permission denied'}), 403

    doctor = Doctor.query.filter_by(DoctorID=current_user.DoctorID).first()
    if not doctor:
        return jsonify({'message': 'Doctor not found'}), 404

    # Returning detailed information of the doctor
    doctor_data = {
        'doctor_id': doctor.DoctorID,
        'name': doctor.Name,
        'specialty': doctor.Specialty,
        'city': doctor.City,
        'email': doctor.Email,
        'phone_number': doctor.PhoneNumber,
        'hospital_name': doctor.HospitalName,
        'picture': doctor.Picture
    }

    return jsonify({'doctor': doctor_data}), 200

    
@app.route('/logout', methods=['POST'])
def logout():
    response = make_response(jsonify({'message': 'Logout successful'}))
    response.set_cookie(
        'token',
        value='',
        expires=0,
        path='/', # Ensure this matches the path set during login
        # Omit the 'Domain' if it was not set during login
        secure=True, 
        httponly=True,
        samesite='None' # Ensure your site is served over HTTPS
    )
    return response



# Retrieve doctor info
@app.route('/doctors/<int:doctor_id>', methods=['GET'])
def get_doctor(doctor_id):
    doctor = Doctor.query.filter_by(DoctorID=doctor_id).first()

    if not doctor:
        return jsonify({'message': 'Doctor not found'}), 404

    doctor_data = {
        'id': doctor.DoctorID,
        'name': doctor.Name,
        'specialty': doctor.Specialty,
        'city': doctor.City,
        'email': doctor.Email,
        'phone_number': doctor.PhoneNumber,
        'hospital_name': doctor.HospitalName,
        'picture': doctor.Picture
    }

    return jsonify({'doctor': doctor_data}), 200


@app.route('/doctors/<int:doctor_id>', methods=['PUT'])
@token_required
def update_doctor(current_user, doctor_id):
    if current_user.DoctorID != doctor_id:
        return jsonify({'message': 'Permission denied'}), 403
    
    data = request.get_json()
    doctor = Doctor.query.filter_by(DoctorID=doctor_id).first()

    if not doctor:
        return jsonify({'message': 'Doctor not found'}), 404

    doctor.Name = data.get('name', doctor.Name)
    doctor.Specialty = data.get('specialty', doctor.Specialty)
    doctor.City = data.get('city', doctor.City)
    doctor.Email = data.get('email', doctor.Email)
    doctor.PhoneNumber = data.get('phone_number', doctor.PhoneNumber)
    doctor.HospitalName = data.get('hospital_name', doctor.HospitalName)
    doctor.Picture = data.get('picture', doctor.Picture)

    db.session.commit()

    return jsonify({'message': 'Doctor profile updated successfully'}), 200

@app.route('/doctors/update_password/<int:doctor_id>', methods=['PUT'])
@token_required
def update_doctor_password(current_user, doctor_id):
    if current_user.DoctorID != doctor_id:
        return jsonify({'message': 'Permission denied'}), 403

    data = request.get_json()
    new_password = data.get('password')
    if not new_password:
        return jsonify({'message': 'No new password provided'}), 400

    doctor = Doctor.query.filter_by(DoctorID=doctor_id).first()
    if doctor:
        doctor.set_password(new_password)
        db.session.commit()
        return jsonify({'message': 'Password updated successfully'}), 200
    else:
        return jsonify({'message': 'Doctor not found'}), 404
    

@app.route('/doctors/delete/<int:doctor_id>', methods=['DELETE'])
@token_required
def delete_doctor(current_user, doctor_id):
    if current_user.DoctorID != doctor_id:
        return jsonify({'message': 'Permission denied'}), 403

    # First, find and delete the delay entry associated with the doctor
    delay = Delay.query.filter_by(DoctorID=doctor_id).first()
    if delay:
        db.session.delete(delay)

    # Then, find and delete the doctor
    doctor = Doctor.query.filter_by(DoctorID=doctor_id).first()
    if doctor:
        db.session.delete(doctor)
        try:
            db.session.commit()
            return jsonify({'message': 'Doctor account deleted successfully'}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500
    else:
        return jsonify({'message': 'Doctor not found'}), 404


@app.route('/subscribe', methods=['POST'])
def subscribe():
    data = request.get_json()
    new_subscription = PatientSubscription(
        DoctorID=data['doctor_id'],
        PatientPhoneNumber=data['phone_number'],
        AppointmentTime=data['appointment_time']
    )
    db.session.add(new_subscription)
    try:
        db.session.commit()
        return jsonify({'message': 'Subscription successful'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500



@app.route('/delays/<int:doctor_id>', methods=['PUT'])
@token_required
def update_delay(current_user, doctor_id):
    # Ensure the current user is the doctor whose delay is being updated
    if current_user.DoctorID != doctor_id:
        return jsonify({'message': 'Permission denied'}), 403

    data = request.get_json()
    delay = Delay.query.filter_by(DoctorID=doctor_id).first()

    if not delay:
        return jsonify({'message': 'Delay entry not found for the doctor'}), 404

    delay.DelayDuration = data.get('delay_duration', delay.DelayDuration)
    delay.StartTimestamp = data.get('start_timestamp', delay.StartTimestamp)
    delay.EndTimestamp = data.get('end_timestamp', delay.EndTimestamp)
    delay.AnnouncementTimestamp = data.get('announcement_timestamp', delay.AnnouncementTimestamp)

    db.session.commit()

    # Check for affected patients and send notifications
    notify_patients_of_delay(doctor_id, delay.StartTimeStamp, delay.EndTimeStamp)

    return jsonify({'message': 'Delay updated successfully'}), 200

@app.route('/testNotification', methods=['POST'])
def test_notification():

    notify_patients_of_delay(21, 1, 24)
    return jsonify({'message': 'Message sent!'}), 200

def notify_patients_of_delay(doctor_id, start_time, end_time):
    subscriptions = PatientSubscription.query.filter_by(DoctorID=doctor_id).all()
    sns_client = boto3.client('sns')
    for subscription in subscriptions:
        if is_time_affected(start_time, end_time, subscription.AppointmentTime):
            print("Let's try!")
            try:
                print("We are trying!")
                response = sns_client.publish(
                    PhoneNumber=subscription.PatientPhoneNumber,
                    Message=f"Votre docteur annonce du retard! Allez sur Unilate pour verifier!"
                )
                print(f"Message sent! ID: {response['MessageId']}")
            except Exception as e:
                print(f"Failed to send SMS: {e}")

def is_time_affected(doctor_start_time, doctor_end_time, patient_appointment_time):
    return doctor_start_time <= patient_appointment_time <= doctor_end_time 

@app.route('/delays/<int:doctor_id>', methods=['GET'])
def get_current_delay(doctor_id):
    delay = Delay.query.filter_by(DoctorID=doctor_id).first()
    if not delay:
        return jsonify({'message': 'No delay entry found for this doctor'}), 404

    current_delay = {
        'doctor_id': delay.DoctorID,
        'delay_duration': delay.DelayDuration,
        'start_timestamp': delay.StartTimestamp,
        'end_timestamp': delay.EndTimestamp,
        'announcement_timestamp': delay.AnnouncementTimestamp
    }
    return jsonify(current_delay), 200


# Search endpoint
@app.route('/doctors', methods=['GET'])
def search_doctors():
    search_term = request.args.get('search')

    if search_term:
        query = Doctor.query.filter(
            or_(
                Doctor.Name.ilike(f'%{search_term}%'),
                Doctor.City.ilike(f'%{search_term}%'),
                Doctor.Specialty.ilike(f'%{search_term}%')
            )
        )
    else:
        query = Doctor.query

    doctors = query.all()
    doctors_data = [{
        'id': doctor.DoctorID,
        'name': doctor.Name,
        'specialty': doctor.Specialty,
        'city': doctor.City,
        'email': doctor.Email,
        'phone_number': doctor.PhoneNumber,
        'hospital_name': doctor.HospitalName,
        'picture': doctor.Picture
    } for doctor in doctors]

    return jsonify({'doctors': doctors_data})

# Return all the doctors
@app.route('/doctors/all', methods=['GET'])
def get_all_doctors():
    doctors = Doctor.query.all()
    doctors_data = [{
        'id': doctor.DoctorID,
        'name': doctor.Name,
        'specialty': doctor.Specialty,
        'city': doctor.City,
        'email': doctor.Email,
        'phone_number': doctor.PhoneNumber,
        'hospital_name': doctor.HospitalName,
        'picture': doctor.Picture
    } for doctor in doctors]

    return jsonify({'doctors': doctors_data})


# Health Check endpoint
@app.route('/', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy'}), 200


# if __name__ == '__main__':
#     app.run(debug=True, host='0.0.0.0', port=8012, use_reloader=False)


def lambda_handler(event, context):
    response = awsgi.response(app, event, context)

    # Check if the headers exist in the event and set the origin accordingly
    headers = event.get('headers', {})
    origin = headers.get('origin') if headers else 'https://www.unilate.be'

    # Prepare the response headers
    response_headers = {
        "Content-Type": "application/json",
        "Access-Control-Allow-Credentials": "true",
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Headers": "Content-Type,Authorization",
        "Access-Control-Allow-Methods": "GET,PUT,POST,DELETE,OPTIONS"
    }

    # Construct the modified response
    modified_response = {
        "isBase64Encoded": False,
        "statusCode": response['statusCode'],
        "headers": response_headers,
        "multiValueHeaders": response.get('multiValueHeaders', {}),
        "body": response['body']
    }

    # Check if 'Set-Cookie' is in the Flask response headers and add it to the multiValueHeaders
    flask_response_headers = response.get('headers', {})
    if 'Set-Cookie' in flask_response_headers:
        # AWS API Gateway expects the 'Set-Cookie' header to be in multiValueHeaders
        modified_response['multiValueHeaders']['Set-Cookie'] = [flask_response_headers['Set-Cookie']]

    return modified_response

