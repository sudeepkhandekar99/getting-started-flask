from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_httpauth import HTTPTokenAuth
from passlib.apps import custom_app_context as pwd_context
from datetime import datetime
import secrets

# object of flask 
app = Flask(__name__)

# DB config data
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:root@localhost/mydb4'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# secret token for auth
app.config['SECRET_KEY'] = 'root@123'

# object of SQLAlchemy (ORM)
db = SQLAlchemy(app)

# object of HTTPTokenAuth
auth = HTTPTokenAuth(scheme='Bearer')


# users table
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    account_created = db.Column(db.DateTime, default=datetime.utcnow)
    account_updated = db.Column(db.DateTime, onupdate=datetime.utcnow, default=datetime.utcnow)
    token = db.Column(db.String(32), unique=True, nullable=False)

    def hash_password(self, password):
        self.password_hash = pwd_context.hash(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)
    
    def generate_auth_token(self):
        return secrets.token_hex(16)


@auth.verify_token
def verify_token(token):
    # Verify the token here, and return the corresponding user if valid
    user = User.query.filter_by(token=token).first()
    return user


@app.route('/')
def home():
    return "This is the root endpoint"

########################################################################
# [PUBLIC] Operations available to all users without authentication    #
########################################################################


@app.route('/health_checkup', methods=['GET'])
def health_check():
    # simple health checkup
    try:
        return {"message": 'health_checkup check is working'}
    except:
        return {"message": 'health_checkup check is NOT working'}


# [PUBLIC] create user
@app.route('/v1/user', methods=['POST'])
def create_user():
    # getting the payload
    data = request.get_json()

    # exception handling
    if ((not data) or ('email' not in data) or ('password' not in data)):
        return jsonify({'message': 'Missing required fields.'}), 400
    
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'message': 'Email already in use.'}), 400
    
    # creating SQLAlchemy object for insertion
    user = User(email=data['email'], first_name=data['first_name'], last_name=data['last_name'])

    # hashing the password
    user.hash_password(data['password'])

    # generate a unique token for the user
    user.token = user.generate_auth_token()

    # DB entry
    db.session.add(user)
    try:
        db.session.commit()
    except:
        db.session.rollback()
        return jsonify({"message": "User could not be created"}), 400

    return jsonify({"email": user.email, "first_name": user.first_name, "last_name": user.last_name, "token": user.token}), 201

# [PUBLIC] Extra API for debugging and token fetch
@app.route('/v1/get_all_users', methods=['GET'])
def get_users():
    auth_header = request.headers.get('Authorization')
    print(auth_header)

    users = User.query.all()

    # Creating a list of dictionaries with user information
    users_data = [
        {
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'account_created': user.account_created.isoformat(),
            'account_updated': user.account_updated.isoformat(),
            'token': user.token
        }
        for user in users
    ]

    return jsonify(users_data), 200


########################################################################
# [AUTHENTICATED] Operations available only to authenticated users     #
########################################################################


# [AUTHENTICATED] get details of a user based on their Bearer token passed in postman authorization
@app.route('/v1/user/self', methods=['GET'])
@auth.login_required
def get_user():
    user = auth.current_user()
    return jsonify({
        "email": user.email,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "account_created": user.account_created.isoformat(),
        "account_updated": user.account_updated.isoformat()
    }), 200


# [AUTHENTICATED] updated details of a user based on their Bearer token passed in postman authorization
@app.route('/v1/user/self', methods=['PUT'])
@auth.login_required
def update_user():
    user = auth.current_user()
    data = request.get_json()

    # Check if the data contains valid fields for updating
    if (not data) or (('first_name' not in data) and ('last_name' not in data) and ('email' not in data)):
        return jsonify({'message': 'Invalid data for updating user.'}), 400

    # Update the user data
    if 'first_name' in data:
        user.first_name = data['first_name']
    if 'last_name' in data:
        user.last_name = data['last_name']
    if 'email' in data:
        user.email = data['email']
        
    # Update the account_updated timestamp
    user.account_updated = datetime.utcnow()

    # Commit changes to the database
    try:
        db.session.commit()
        return jsonify({"message": "User data updated successfully."}), 200
    except:
        db.session.rollback()
        return jsonify({"message": "Failed to update user data."}), 500


# create tables using SQLAlchemy (table creation without RAW Queries. Using ORM.)
def create_tables():
    with app.app_context():
        db.create_all()

create_tables()

# Run flask app
if (__name__ == "__main__"):
    app.run(debug=True)