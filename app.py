from flask import Flask, request, jsonify, make_response
from pymongo import MongoClient
from bson.objectid import ObjectId
from flask_cors import CORS
#from flask_jwt_extended import JWTManager, create_access_token
#from flask_socketio import SocketIO
#from flask_talisman import Talisman
import jwt
from werkzeug.security import check_password_hash
from datetime import datetime, timedelta
from dotenv import load_dotenv
import os
import re
from functools import wraps

app = Flask(__name__)
app_url=os.environ.get('APP_REACT')
#CORS(app)
CORS(app, supports_credentials=True, resources={r"/*": {"origins": app_url}})

load_dotenv()

client = MongoClient(os.environ.get('MONGODB_URL'))
db = client[os.environ.get('MONGODB_DATABASE')]

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
wrong_attempts = {}
lockout_time = 60 * 30

"""
"username": "admin",
"password": "aDm!n2023"

"username": "steam01",
"password": "sTeAmo12023"

"username": "steam02",
"password": "sTE@m022023"
"""

def handle_invalid_login(uName):
    if uName in wrong_attempts:
        wrong_attempts[uName]['count'] += 1
        wrong_attempts[uName]['timestamp'] = datetime.now()
    else:
        wrong_attempts[uName] = {'count': 1, 'timestamp': datetime.now()}

def check_user_failed_attempt(uName):
    if uName in wrong_attempts and wrong_attempts[uName]['count'] >= 3:
        time_elapsed = datetime.now() - wrong_attempts[uName]['timestamp']
        time_left = timedelta(seconds=lockout_time) - time_elapsed
        minutes, seconds = divmod(time_left.seconds, 60)
        formatted_time_left = f"{minutes:02d}:{seconds:02d}"
        return True, formatted_time_left
    else:
        return False, None

@app.route('/login', methods=['POST'])
def login():
    username = request.json['username']
    password = request.json['password']

    isUserBlocked, timeRemaining = check_user_failed_attempt(username)

    if not username or not password:
        return jsonify({'error': 'Missing username or password'}), 400
    
    user = db['users'].find_one({'username': username})
    if isUserBlocked:
        return jsonify({
            'error': 'User blocked! Try after ' + timeRemaining + ' minutes'
        }), 401
    if not user:
        return jsonify({'error': 'User does not exist'}), 401
    if not check_password_hash(user['password'], password):
        handle_invalid_login(username)
        return jsonify({'error': 'Invalid username or password'}), 401
    
    token = jwt.encode({'username': username, 'role': user['role'], 'exp': datetime.utcnow() + timedelta(minutes=30)}, app.config['SECRET_KEY'])
    response = make_response(jsonify({'message': 'Successfully logged in!', 'username': username, 'role': user['role']}))
    response.set_cookie(key='token', value=token, httponly=True, secure=True, samesite="None")

    return response

def authenticate(role):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = request.cookies.get("token")
            if not token:
                return jsonify({'error': 'Missing token'}), 401

            try:
                header = jwt.get_unverified_header(token)
                algorithm = header['alg']
                payload = jwt.decode(token, app.config['SECRET_KEY'],algorithms=[algorithm])       # Decode the token to get the payload
            except Exception as ex:
                print(f"{ex}")
                return jsonify({'error': 'Invalid token'}), 401

            # Check if the user's role matches the required role
            if payload['role'] != role:
                return jsonify({'error': 'Unauthorized access'}), 403
            return f(*args, **kwargs)

        return wrapper
    return decorator

@app.route('/routes', methods = ['POST', 'GET'])
@authenticate('admin')
def delivery_route():
    if request.method == 'POST':
        fromL = request.json['fromL']
        toL = request.json['toL']
        regex = '^[A-Za-z]+$'

        if re.match(regex, fromL) and re.match(regex, toL):
            result = db['routes'].insert_one({
            "fromL": fromL,
            "toL" : toL,
            "route": fromL + ' to ' + toL
            })

            return jsonify({
                'id': str(result.inserted_id),
                'route': 'Route ' + fromL + ' to ' + toL + ' added'
            })
        else: 
            return jsonify({
                'error': 'pattern does not match'
            }), 400
    
    if request.method == 'GET':
        routes = db['routes'].find()
        routesJson = []

        for data in routes:
            id = str(data['_id'])
            route_name = data['route']

            routeDict = {
                'id': id,
                'route': route_name
            }
            routesJson.append(routeDict)

        return jsonify(routesJson)
    
@app.route('/routes/<string:id>', methods = ['DELETE'])
@authenticate('admin')
def route_delete(id):
    Id = ObjectId(id)
    db['routes'].delete_one({'_id': Id})
    return jsonify({
        'message': 'Route ' + id + ' removed'
    })

@app.route('/delivery', methods=['POST', 'GET'])
@authenticate('admin')
def delivery_assigned():
    if request.method == 'POST':
        routename = request.json['routename']
        vehicle = request.json['vehicle']
        team = request.json['team']
        status = request.json['stat']

        vehicles = os.environ.get('APP_VEHICLES')
        steam = os.environ.get('APP_STEAMS')
        routeinput = db['routes'].find_one({'route': routename})

        if vehicle in vehicles and team in steam and routeinput and status == 'not reached depot':
            result = db['delivery'].insert_one({
            'route': routename,
            'vehicle': vehicle,
            'team': team,
            'status': status
        })

            return jsonify({
                'id': str(result.inserted_id),
                'message': 'Vehicle ' + vehicle + ' assigned to team ' + team + ' on route ' + routename + '.'
            })
        else:
            return jsonify({
                'error': 'Input pattern does not match'
            }), 400
    
    if request.method == 'GET':
        deliveries = db['delivery'].find()
            
        deliveryJson = []

        for data in deliveries:
            id = str(data['_id'])
            routename = data['route']
            vehicle = data['vehicle']
            team = data['team']
            status = data['status']

            deliveryDict = {
                'id': id,
                'route': routename,
                'vehicle': vehicle,
                'team': team,
                'status': status
            }
            deliveryJson.append(deliveryDict)
        return jsonify(deliveryJson)
    
@app.route('/deliverystatus', methods = ['GET']) 
@authenticate('steam')
def delstatus():
    steam = request.args.get('team')
    deliveries = db['delivery'].find({'team': steam})
            
    deliveryJson = []

    for data in deliveries:
        id = str(data['_id'])
        routename = data['route']
        vehicle = data['vehicle']
        team = data['team']
        status = data['status']

        deliveryDict = {
            'id': id,
            'route': routename,
            'vehicle': vehicle,
            'team': team,
            'status': status
        }
        deliveryJson.append(deliveryDict)
    return jsonify(deliveryJson)

@app.route('/delivery/<string:id>', methods=['PUT','DELETE'])
@authenticate('admin')
def onedelivery(id):
    if request.method == 'PUT':
        team = request.json['team']

        teams = os.environ.get('PUT_TEAMS')

        if team in teams:
            db['delivery'].update_one(
            {'_id': ObjectId(id)},
            {
                '$set': {
                    'team': team
                    }
            }
            )
            
            return jsonify({
                'message': 'Delivery ' + id + ' is updated!'
            })
        else: 
            return jsonify({
                'error': 'Input pattern does not match'
            }), 400
    
    if request.method == 'DELETE':
        db['delivery'].delete_many({'_id': ObjectId(id)})
        return jsonify({
            'message': 'Delivery ' + id + ' is deleted!'
            })
    
@app.route('/deliverystatus/<string:id>', methods=['PUT'])
@authenticate('steam')
def statusupdate(id):
    stat = request.json['stat']
    stats = os.environ.get('PUT_STATS')
    
    if stat in stats:
        db['delivery'].update_one(
        {'_id': ObjectId(id)},
        {
            '$set': {
                'status': stat
                }
        }
        )
            
        return jsonify({
            'message': 'Delivery ' + id + ' is updated!'
            })
    else:
        return jsonify({
            'error': 'Input pattern does not match'
        }), 400

if __name__ == '__main__':
    app.debug = True
    app.run()    