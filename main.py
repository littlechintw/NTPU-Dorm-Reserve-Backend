#!/usr/bin/python
# -*- coding: utf-8 -*-

from func import *
from func_admin import *
import sqlite3
from flask import Flask, request, send_file, Blueprint, session, abort, redirect, url_for
from flask_cors import CORS

# Google Login
import json
import os
import pathlib
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests
# Google Login

app = Flask(__name__)
app.config['JSON_AS_ASCII'] = False
CORS(app)

# Google Login
google_settings_redirect_uri = "https://ntpudorm.littlechin.tw/api/google/callback"
# Get the json from client_secret.json
client_secret_json = {}
with open('client_secret.json') as f:
    client_secret_json = json.load(f)

app.config['SECRET_KEY'] = client_secret_json['web']['client_secret']
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

GOOGLE_CLIENT_ID = client_secret_json['web']['client_id']
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, 'client_secret.json')

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri=google_settings_redirect_uri
)

def google_login_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return redirect(url_for('login'))
        else:
            return function()

    return wrapper
# Google Login

# 建立 API Blueprint
api = Blueprint('api', __name__)

# To view this app is already run
@api.route('/monitor', methods=['GET'])
def check_active():
    try:
        events_id = create_id(5)
        write_log(request.remote_addr, request.url, events_id, "", "Alive check!")
        print('I think someone ask me whether I am alive, and hi, I still here!')
        return 'great!', 200
    except Exception as e:
        print(e)
        error_500('Server Error', '', request.remote_addr, request.url, events_id), 500

# To login with the student system
@api.route('/login', methods=['POST'])
def login():
    try:
        events_id = create_id(5)
        write_log(request.remote_addr, request.url, events_id, "/login first in", "")

        try:
            data = request.get_json()
            logs = {
                'url': '/account',
                'request': data
            }
            write_log(request.remote_addr, request.url, events_id, str(logs), "")
        except:
            return error_403('No given data', '', request.remote_addr, request.url, events_id), 403
        else:
            if 'stu_id' not in data:
                return error_403('No given data', '', request.remote_addr, request.url, events_id), 403
            write_log(request.remote_addr, request.url, events_id, str(data['stu_id']), "")
            if 'pwd' not in data:
                return error_403('No given data', '', request.remote_addr, request.url, events_id), 403
            if len(data['stu_id']) != 9:
                return error_403('學號輸入錯誤', '', request.remote_addr, request.url, events_id), 200
            if not check_is_num(data['stu_id']):
                return error_403('學號輸入錯誤', '', request.remote_addr, request.url, events_id), 200

        if not check_reserve_time():
            return error_403('非預約時間 / Not a valid time ({})'.format(get_nowtime_taipei_time()), '', request.remote_addr, request.url, events_id), 200

        # Check this account wheater exist in database
        user_dorm = get_user_dorm(data['stu_id'])
        if user_dorm == 'no':
            return error_403('這個帳號不在使用範圍內', '', request.remote_addr, request.url, events_id), 200

        # Check this user whether in accouts table
        conn = sqlite3.connect('main.db')
        c = conn.cursor()
        c.execute('''
                    SELECT * FROM accounts WHERE id = ?
                ''', (data['stu_id'],))
        record = c.fetchone()
        conn.close()

        token = generate_jwt(data['stu_id'], str(request.remote_addr))

        # If user not in account table, add this user to account table
        if not record:
            # Verify this account is correct
            login_flag = verify_account_from_stu_sys(data['stu_id'], data['pwd'])
            logs_green(login_flag)
            if login_flag['err'] != 200:
                print(login_flag)
                return error_403('帳號或密碼輸入錯誤', '', request.remote_addr, request.url, events_id), 200
            
            conn = sqlite3.connect('main.db')
            c = conn.cursor()
            c.execute('''
                        INSERT INTO accounts (id, passwd, created, status, session, session_time) VALUES (?, ?, ?, ?, ?, ?)
                    ''', (data['stu_id'], data['pwd'], get_nowtime_taipei_time(), 'normal', token, get_nowtime_taipei_time()))
            conn.commit()
            conn.close()
        
        # If user in account table, verify password. If it's correct, update this user's session, session_time. Or, goto check from stu_sys, and update this user's password, session, session_time.
        else:
            if record[1] != data['pwd']:
                # Verify this account is correct
                login_flag = verify_account_from_stu_sys(data['stu_id'], data['pwd'])
                logs_green(login_flag)
                if login_flag['err'] != 200:
                    print(login_flag)
                    return error_403('帳號或密碼輸入錯誤', '', request.remote_addr, request.url, events_id), 200
                else:
                    conn = sqlite3.connect('main.db')
                    c = conn.cursor()
                    c.execute('''
                                UPDATE accounts SET passwd = ?, session = ?, session_time = ? WHERE id = ?
                            ''', (data['pwd'], token, get_nowtime_taipei_time(), data['stu_id']))
                    conn.commit()
                    conn.close()
            else:
                conn = sqlite3.connect('main.db')
                c = conn.cursor()
                c.execute('''
                            UPDATE accounts SET session = ?, session_time = ? WHERE id = ?
                        ''', (token, get_nowtime_taipei_time(), data['stu_id']))
                conn.commit()
                conn.close()

        # sql_line = "SELECT * FROM account WHERE stu_id = '" + data['stu_id'] + "'"
        return ok_200('OK', 'Bearer ' + token, request.remote_addr, request.url, events_id), 200

        # curl -X POST -H "Content-Type: application/json" -d '{"stu_id": "A1234567", "pwd": "1234567"}' http://localhost:5000/login
    except Exception as e:
        print(e)
        return error_500('Server Error', '', request.remote_addr, request.url, events_id), 500

@api.route('/google/login')
def google_login():
    authorization_url, state = flow.authorization_url(prompt='select_account')
    session['state'] = state
    return redirect(authorization_url)

@api.route('/google/callback')
def google_callback():
    flow.fetch_token(authorization_response=request.url)

    if not session['state'] == request.args['state']:
        abort(500)

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )
    
    session['google_id'] = id_info.get('sub')
    session['name'] = id_info.get('name')
    print(id_info)
    hd = id_info['hd']
    email = id_info['email']
    email_verified = id_info['email_verified']
    
    try:
        events_id = create_id(5)
        write_log(request.remote_addr, request.url, events_id, "/google/login", "")

        if not check_reserve_time():
            return error_403('非預約時間 / Not a valid time ({})'.format(get_nowtime_taipei_time()), '', request.remote_addr, request.url, events_id), 200
        
        if hd != 'gm.ntpu.edu.tw':
            return redirect('/login?err=請使用學校信箱登入 / Please use school email to login')
        if not email_verified:
            return redirect('/login?err=請先驗證信箱 / Please verify your email')
        if not check_is_num(email[1:10]):
            return redirect('/login?err=請使用正確帳號登入 / Please use correct account to login')
        
        stu_id = email[1:10]

        # Check this account wheater exist in database
        user_dorm = get_user_dorm(stu_id)
        if user_dorm == 'no':
            return redirect('/login?err=這個帳號不在使用範圍內 / This account is not in the range of use')

        # Check this user whether in accouts table
        conn = sqlite3.connect('main.db')
        c = conn.cursor()
        c.execute('''
                    SELECT * FROM accounts WHERE id = ?
                ''', (stu_id,))
        record = c.fetchone()
        conn.close()

        token = generate_jwt(stu_id, str(request.remote_addr))

        # If user not in account table, add this user to account table
        if not record:
            conn = sqlite3.connect('main.db')
            c = conn.cursor()
            c.execute('''
                        INSERT INTO accounts (id, passwd, created, status, session, session_time) VALUES (?, ?, ?, ?, ?, ?)
                    ''', (stu_id, 'pwd', get_nowtime_taipei_time(), 'normal', token, get_nowtime_taipei_time()))
            conn.commit()
            conn.close()
        
        # If user in account table, verify password. If it's correct, update this user's session, session_time. Or, goto check from stu_sys, and update this user's password, session, session_time.
        else:
            conn = sqlite3.connect('main.db')
            c = conn.cursor()
            c.execute('''
                        UPDATE accounts SET session = ?, session_time = ? WHERE id = ?
                    ''', (token, get_nowtime_taipei_time(), stu_id))
            conn.commit()
            conn.close()

            
        return redirect('/login?token=Bearer ' + token)

    
    except Exception as e:
        print(e)
        return error_500('Server Error', '', request.remote_addr, request.url, events_id), 500

@api.route('/reserveTime', methods=['GET'])
def reserveTime():
    try:
        events_id = create_id(5)
        write_log(request.remote_addr, request.url, events_id, "", "reserveTime")
        reserveNow = check_reserve_time()
        RESERVE_START = get_config('RESERVE_START')
        RESERVE_END = get_config('RESERVE_END')
        return ok_200({
            'reserve': reserveNow,
            'time': RESERVE_START[:-3],
        }, '', request.remote_addr, request.url, events_id), 200
    except Exception as e:
        print(e)
        error_500('Server Error', '', request.remote_addr, request.url, events_id), 500


# To test whether this token is valid
@api.route('/verify', methods=['POST'])
def verify():
    try:
        events_id = create_id(5)

        # Take header and verify it
        token = request.headers.get('Authorization')
        if not token:
            return error_403('No given token', '', request.remote_addr, request.url, events_id), 403
        if token[:7] != 'Bearer ':
            return error_403('No given token', '', request.remote_addr, request.url, events_id), 403
        token = token[7:]
        if not verify_jwt(token, request.remote_addr):
            return error_403('Token is invalid', '', request.remote_addr, request.url, events_id), 403
        return ok_200('OK', '', request.remote_addr, request.url, events_id), 200
    except Exception as e:
        print(e)
        return error_500('Server Error', '', request.remote_addr, request.url, events_id), 500

# To get events list
@api.route('/get_events', methods=['POST'])
def get_events():
    try:
        events_id = create_id(5)

        # Take header and verify it
        token = request.headers.get('Authorization')
        if not token:
            return error_403('No given token', '', request.remote_addr, request.url, events_id), 403
        if token[:7] != 'Bearer ':
            return error_403('No given token', '', request.remote_addr, request.url, events_id), 403
        token = token[7:]
        if not verify_jwt(token, request.remote_addr):
            return error_403('Token is invalid', '', request.remote_addr, request.url, events_id), 403

        response_json = {
            'reserved': True,
            'events': [],
            'reserved_data': {}
        }

        user = get_user_id_from_token(token)
        user_dorm = get_user_dorm(user)
        if not (user_dorm == 'sun' or user_dorm == 'moon' or user_dorm == 'star' or user_dorm == 'morn'):
            return error_403('這個帳號不在使用範圍內', '', request.remote_addr, request.url, events_id), 200
        
        # Check this user whether reserved
        reserved = check_user_if_reserved(user)

        if reserved:
            checkIn = check_user_if_checkin(user)
            response_json['reserved_data']['id'], response_json['reserved_data']['event'], response_json['reserved_data']['parking'],  = get_user_reserve_record(user)
            response_json['reserved_data']['event'] = get_event_name_by_id(response_json['reserved_data']['event'])
            response_json['reserved_data']['qrcode'] = base64_encode(response_json['reserved_data']['id'])
            response_json['reserved_data']['dorm'] = get_user_dorm_and_room(user)
            response_json['reserved_data']['checkIn'] = checkIn
            return ok_200(response_json, '', request.remote_addr, request.url, events_id), 200
        response_json['reserved'] = False

        res = get_events_list_by_dorm(user_dorm)
        response_json['events'] = res

        return ok_200(response_json, '', request.remote_addr, request.url, events_id), 200
    except Exception as e:
        print(e)
        return error_500('Server Error', '', request.remote_addr, request.url, events_id), 500

@api.route('/reserve_event', methods=['POST'])
def reserve_event():
    try:
        events_id = create_id(5)

        try:
            data = request.get_json()
            logs = {
                'url': '/reserve_event',
                'request': data
            }
            write_log(request.remote_addr, request.url, events_id, str(logs), "")
        except:
            return error_403('Not valid request', '', request.remote_addr, request.url, events_id), 403
        else:
            if 'event' not in data:
                return error_403('Not valid request', '', request.remote_addr, request.url, events_id), 403
            if 'parking' not in data:
                return error_403('Not valid request', '', request.remote_addr, request.url, events_id), 403
            if 'health_form' not in data:
                return error_403('Not valid request', '', request.remote_addr, request.url, events_id), 403
            if 'phone' not in data['health_form']:
                return error_403('Not valid request', '', request.remote_addr, request.url, events_id), 403
            if 'check_1' not in data['health_form']:
                return error_403('Not valid request', '', request.remote_addr, request.url, events_id), 403
            if 'check_2' not in data['health_form']:
                return error_403('Not valid request', '', request.remote_addr, request.url, events_id), 403

        health_form = {
            'phone': data['health_form']['phone'],
            'check_1': data['health_form']['check_1'],
            'check_2': data['health_form']['check_2']
        }

        # Take header and verify it
        token = request.headers.get('Authorization')
        if not token:
            return error_403('No given token', '', request.remote_addr, request.url, events_id), 403
        if token[:7] != 'Bearer ':
            return error_403('No given token', '', request.remote_addr, request.url, events_id), 403
        token = token[7:]
        if not verify_jwt(token, request.remote_addr):
            return error_403('Token is invalid', '', request.remote_addr, request.url, events_id), 403
        
        # Check this user whether has reserved
        user = get_user_id_from_token(token)
        write_log(request.remote_addr, request.url, events_id, str(user), "")
        reserved = check_user_if_reserved(user)
        if reserved:
            return error_403('You cannot do that', '', request.remote_addr, request.url, events_id), 403
        
        # Check this event is valid for reserve
        user_dorm = get_user_dorm(user)
        dorm_events_list = get_events_list_by_dorm(user_dorm)
        events = {}
        for event in dorm_events_list:
            if event['event_id'] == data['event']:
                events = event
                break
        if events == {}:
            return error_403('What are you doing now', '', request.remote_addr, request.url, events_id), 403
        if events['remainReserve'] <= 0:
            return error_403('This event is full', '', request.remote_addr, request.url, events_id), 200

        # Reserve this event
        add_reserve_log(user, data['event'], data['parking'])
        edit_health_data(user, health_form)

        events['remainReserve'] -= 1

        return ok_200(events, '', request.remote_addr, request.url, events_id), 200
    except Exception as e:
        print(e)
        return error_500('Server Error', '', request.remote_addr, request.url, events_id), 500

@api.route('/cancel_reserve', methods=['POST'])
def cancel_reserve():
    try:
        events_id = create_id(5)

        # Take header and verify it
        token = request.headers.get('Authorization')
        if not token:
            return error_403('No given token', '', request.remote_addr, request.url, events_id), 403
        if token[:7] != 'Bearer ':
            return error_403('No given token', '', request.remote_addr, request.url, events_id), 403
        token = token[7:]
        if not verify_jwt(token, request.remote_addr):
            return error_403('Token is invalid', '', request.remote_addr, request.url, events_id), 403

        # Check this user whether has reserved
        user = get_user_id_from_token(token)
        reserved = check_user_if_reserved(user)
        if not reserved:
            return error_403('You cannot do that', '', request.remote_addr, request.url, events_id), 200

        # Cancel this event
        user = get_user_id_from_token(token)

        checkinStatus = check_user_if_checkin(user)
        if checkinStatus:
            return error_403('You cannot do that', '', request.remote_addr, request.url, events_id), 200

        user_dorm = get_user_dorm(user)
        delete_reserve_log(user)

        res = get_events_list_by_dorm(user_dorm)

        return ok_200(res, '', request.remote_addr, request.url, events_id), 200
    except Exception as e:
        print(e)
        return error_500('Server Error', '', request.remote_addr, request.url, events_id), 500

@api.route('/healthy_form_checker', methods=['POST'])
def healthy_form_checker():
    try:
        events_id = create_id(5)

        # Take header and verify it
        token = request.headers.get('Authorization')
        if not token:
            return error_403('No given token', '', request.remote_addr, request.url, events_id), 403
        if token[:7] != 'Bearer ':
            return error_403('No given token', '', request.remote_addr, request.url, events_id), 403
        token = token[7:]
        if not verify_jwt(token, request.remote_addr):
            return error_403('Token is invalid', '', request.remote_addr, request.url, events_id), 403

        user = get_user_id_from_token(token)
        health_form_already = healthy_form_check(user)

        if health_form_already:
            return ok_200('Y', '', request.remote_addr, request.url, events_id), 200
        else:
            return ok_200('N', '', request.remote_addr, request.url, events_id), 200
    except Exception as e:
        print(e)
        return error_500('Server Error', '', request.remote_addr, request.url, events_id), 500

@api.route('/admin/login', methods=['POST'])
def admin_login():
    try:
        events_id = create_id(5)
        write_log(request.remote_addr, request.url, events_id, "/admin/login first in", "")

        try:
            data = request.get_json()
            logs = {
                'url': '/account',
                'request': data
            }
            write_log(request.remote_addr, request.url, events_id, str(logs), "")
        except:
            return error_403('No given data', '', request.remote_addr, request.url, events_id), 403
        else:
            if 'id' not in data:
                return error_403('No given data', '', request.remote_addr, request.url, events_id), 403
            write_log(request.remote_addr, request.url, events_id, str(id), "")
            if 'pwd' not in data:
                return error_403('No given data', '', request.remote_addr, request.url, events_id), 403

        # Check this account wheater exist in database
        user_dorm = get_user_dorm(data['id'])
        if user_dorm != 'admin' and user_dorm != 'master':
            return error_403('這個帳號不在使用範圍內', '', request.remote_addr, request.url, events_id), 200

        # Check this user whether in accouts table
        conn = sqlite3.connect('main.db')
        c = conn.cursor()
        c.execute('''
                    SELECT * FROM accounts WHERE id = ?
                ''', (data['id'],))
        record = c.fetchone()
        conn.close()

        token = generate_jwt_one_day(data['id'], str(request.remote_addr))

        if record[1] != data['pwd']:
            return error_403('帳號或密碼輸入錯誤', '', request.remote_addr, request.url, events_id), 200
        else:
            conn = sqlite3.connect('main.db')
            c = conn.cursor()
            c.execute('''
                        UPDATE accounts SET session = ?, session_time = ? WHERE id = ?
                    ''', (token, get_nowtime_taipei_time(), data['id']))
            conn.commit()
            conn.close()

        # sql_line = "SELECT * FROM account WHERE stu_id = '" + data['stu_id'] + "'"
        return ok_200('OK', 'Bearer ' + token, request.remote_addr, request.url, events_id), 200

        # curl -X POST -H "Content-Type: application/json" -d '{"stu_id": "A1234567", "pwd": "1234567"}' http://localhost:5000/login
    except Exception as e:
        print(e)
        return error_500('Server Error', '', request.remote_addr, request.url, events_id), 500

@api.route('/admin/verify', methods=['POST'])
def admin_verify():
    try:
        events_id = create_id(5)

        # Take header and verify it
        token = request.headers.get('Authorization')
        if not token:
            return error_403('No given token', '', request.remote_addr, request.url, events_id), 403
        if token[:7] != 'Bearer ':
            return error_403('No given token', '', request.remote_addr, request.url, events_id), 403
        token = token[7:]
        if not verify_jwt_one_day(token, request.remote_addr):
            return error_403('Token is invalid', '', request.remote_addr, request.url, events_id), 403

        user = get_user_id_from_token(token)
        user_rule = get_user_dorm(user)

        if user_rule != 'admin' and user_rule != 'master':
            return error_403('You are not admin', '', request.remote_addr, request.url, events_id), 200

        res = {
            'rule': user_rule
        }
        return ok_200(res, '', request.remote_addr, request.url, events_id), 200
    except Exception as e:
        print(e)
        return error_500('Server Error', '', request.remote_addr, request.url, events_id), 500

@api.route('/admin/get_user_data', methods=['POST'])
def admin_get_user_data():
    # try:

    events_id = create_id(5)

    try:
        data = request.get_json()
        logs = {
            'url': '/admin/get_user_data',
            'request': data
        }
        write_log(request.remote_addr, request.url, events_id, str(logs), "")
    except:
        return error_403('No given data', '', request.remote_addr, request.url, events_id), 403
    else:
        if 'id' not in data:
            return error_403('No given data', '', request.remote_addr, request.url, events_id), 403

    # Take header and verify it
    token = request.headers.get('Authorization')
    if not token:
        return error_403('No given token', '', request.remote_addr, request.url, events_id), 403
    if token[:7] != 'Bearer ':
        return error_403('No given token', '', request.remote_addr, request.url, events_id), 403
    token = token[7:]
    if not verify_jwt_one_day(token, request.remote_addr):
        return error_403('Token is invalid', '', request.remote_addr, request.url, events_id), 403

    user = get_user_id_from_token(token)
    write_log(request.remote_addr, request.url, events_id, str(user), "")
    user_rule = get_user_dorm(user)

    if user_rule != 'admin' and user_rule != 'master':
        return error_403('You are not admin', '', request.remote_addr, request.url, events_id), 200

    if len(data['id']) == 12:
        data['id'] = base64_decode(data['id'])

    visitor_checkout = False
    if len(data['id']) == 10:
        checkoutFlag, userTmp = admin_visitor_checkout(data['id'])
        if checkoutFlag == False:
            return error_403('Visitor error', '', request.remote_addr, request.url, events_id), 200
        data['id'] = userTmp
        visitor_checkout = True
    
    print('check3')
    user_data = admin_take_user_data(data['id'])
    print('check4')
    if visitor_checkout:
        user_data['alert'] = '訪客已結束'
    if user_data['error']:
        return error_403('No such user', '', request.remote_addr, request.url, events_id), 200

    return ok_200(user_data, '', request.remote_addr, request.url, events_id), 200

    # except Exception as e:
    #     print(e)
    #     return error_500('Server Error', '', request.remote_addr, request.url, events_id), 500

@api.route('/admin/edit_user_data', methods=['POST'])
def admin_edit_user_data():
    try:
        events_id = create_id(5)

        try:
            data = request.get_json()
            logs = {
                'url': '/admin/edit_user_data',
                'request': data
            }
            write_log(request.remote_addr, request.url, events_id, str(logs), "")
        except:
            return error_403('No given data', '', request.remote_addr, request.url, events_id), 403
        else:
            if 'id' not in data:
                return error_403('No given data', '', request.remote_addr, request.url, events_id), 403
            if 'parking' not in data:
            #     return error_403('No given data', '', request.remote_addr, request.url, events_id), 403
            # if 'parking' != True and 'parking' != False:
                return error_403('No given data', '', request.remote_addr, request.url, events_id), 403
            if 'bill' not in data:
                return error_403('No given data', '', request.remote_addr, request.url, events_id), 403
            # if 'bill' != True and 'bill' != False:
            #     return error_403('No given data', '', request.remote_addr, request.url, events_id), 403
            if 'card' not in data:
                return error_403('No given data', '', request.remote_addr, request.url, events_id), 403
            if 'visitor' not in data:
                return error_403('No given data', '', request.remote_addr, request.url, events_id), 403
            # if 'visitor' != True and 'visitor' != False:
            #     return error_403('No given data', '', request.remote_addr, request.url, events_id), 403
            if 'visitorId' not in data:
                return error_403('No given data', '', request.remote_addr, request.url, events_id), 403
            if 'visitorPhone' not in data:
                return error_403('No given data', '', request.remote_addr, request.url, events_id), 403

        # Take header and verify it
        token = request.headers.get('Authorization')
        if not token:
            return error_403('No given token', '', request.remote_addr, request.url, events_id), 403
        if token[:7] != 'Bearer ':
            return error_403('No given token', '', request.remote_addr, request.url, events_id), 403
        token = token[7:]
        if not verify_jwt_one_day(token, request.remote_addr):
            return error_403('Token is invalid', '', request.remote_addr, request.url, events_id), 403

        user = get_user_id_from_token(token)
        write_log(request.remote_addr, request.url, events_id, str(user), "")
        user_rule = get_user_dorm(user)

        if user_rule != 'admin' and user_rule != 'master':
            return error_403('You are not admin', '', request.remote_addr, request.url, events_id), 200

        admin_edit_user_checkin(data['id'], data['parking'], data['bill'], data['card'])

        if data['visitor'] == 1:
            visitorFlag = admin_edit_user_visitor(data['id'], data['visitorId'], data['visitorPhone'])
            if visitorFlag == False:
                return error_403('Visitor error', '', request.remote_addr, request.url, events_id), 200
        
        user_data = admin_take_user_data(data['id'])
        if user_data['error']:
            return error_403('No such user', '', request.remote_addr, request.url, events_id), 200

        return ok_200(user_data, '', request.remote_addr, request.url, events_id), 200
    except Exception as e:
        print(e)
        return error_500('Server Error', '', request.remote_addr, request.url, events_id), 500

@api.route('/admin/visitor_checkout', methods=['POST'])
def admin_visitor_checkout_url():
    try:
        events_id = create_id(5)

        try:
            data = request.get_json()
            logs = {
                'url': '/admin/visitor_checkout',
                'request': data
            }
            write_log(request.remote_addr, request.url, events_id, str(logs), "")
        except:
            return error_403('No given data', '', request.remote_addr, request.url, events_id), 403
        else:
            if 'id' not in data:
                return error_403('No given data', '', request.remote_addr, request.url, events_id), 403

        # Take header and verify it
        token = request.headers.get('Authorization')
        if not token:
            return error_403('No given token', '', request.remote_addr, request.url, events_id), 403
        if token[:7] != 'Bearer ':
            return error_403('No given token', '', request.remote_addr, request.url, events_id), 403
        token = token[7:]
        if not verify_jwt_one_day(token, request.remote_addr):
            return error_403('Token is invalid', '', request.remote_addr, request.url, events_id), 403

        user = get_user_id_from_token(token)
        write_log(request.remote_addr, request.url, events_id, str(user), "")
        user_rule = get_user_dorm(user)

        if user_rule != 'admin' and user_rule != 'master':
            return error_403('You are not admin', '', request.remote_addr, request.url, events_id), 200

        checkoutFlag, userTmp = admin_visitor_checkout_by_stuid(data['id'])
        if checkoutFlag == False:
            return error_403('Visitor error', '', request.remote_addr, request.url, events_id), 200

        user_data = admin_take_user_data(userTmp)
        if user_data['error']:
            return error_403('No such user', '', request.remote_addr, request.url, events_id), 200

        return ok_200(user_data, '', request.remote_addr, request.url, events_id), 200
    except Exception as e:
        print(e)
        return error_500('Server Error', '', request.remote_addr, request.url, events_id), 500

@api.route('/admin/edit_user', methods=['POST'])
def admin_edit_user_api():
    try:
        events_id = create_id(5)

        try:
            data = request.get_json()
            logs = {
                'url': '/admin/edit_user',
                'request': data
            }
            write_log(request.remote_addr, request.url, events_id, str(logs), "")
        except:
            return error_403('No given data', '', request.remote_addr, request.url, events_id), 403
        else:
            if 'id' not in data:
                return error_403('No given data', '', request.remote_addr, request.url, events_id), 403
            if 'name' not in data:
                return error_403('No given data', '', request.remote_addr, request.url, events_id), 403
            if 'dorm' not in data:
                return error_403('No given data', '', request.remote_addr, request.url, events_id), 403
            if data['dorm'] != 'sun' and data['dorm'] != 'moon' and data['dorm'] != 'star' and data['dorm'] != 'morn':
                return error_403('No given data', '', request.remote_addr, request.url, events_id), 403
            if 'room' not in data:
                return error_403('No given data', '', request.remote_addr, request.url, events_id), 403
            if 'action' not in data:
                return error_403('No given data', '', request.remote_addr, request.url, events_id), 403
            if data['action'] != 'a' and data['action'] != 'e' and data['action'] != 'd' and data['action'] != 'dc':
                return error_403('No given data', '', request.remote_addr, request.url, events_id), 403

        # Take header and verify it
        token = request.headers.get('Authorization')
        if not token:
            return error_403('No given token', '', request.remote_addr, request.url, events_id), 403
        if token[:7] != 'Bearer ':
            return error_403('No given token', '', request.remote_addr, request.url, events_id), 403
        token = token[7:]
        if not verify_jwt_one_day(token, request.remote_addr):
            return error_403('Token is invalid', '', request.remote_addr, request.url, events_id), 403

        user = get_user_id_from_token(token)
        write_log(request.remote_addr, request.url, events_id, str(user), "")
        user_rule = get_user_dorm(user)

        if user_rule != 'admin' and user_rule != 'master':
            return error_403('You are not admin', '', request.remote_addr, request.url, events_id), 200

        actionFlag = False
        if data['action'] == 'a':
            actionFlag = admin_add_user(data['id'], data['name'], data['dorm'], data['room'])
        elif data['action'] == 'e':
            actionFlag = admin_edit_user(data['id'], data['name'], data['dorm'], data['room'])
        elif data['action'] == 'd':
            actionFlag = admin_delete_user(data['id'])
        elif data['action'] == 'dc':
            actionFlag = admin_delete_user_checkin(data['id'])

        if actionFlag == False:
            return error_403('Action error', '', request.remote_addr, request.url, events_id), 200
        user_data = admin_take_user_data(data['id'])

        return ok_200(user_data, '', request.remote_addr, request.url, events_id), 200
    except Exception as e:
        print(e)
        return error_500('Server Error', '', request.remote_addr, request.url, events_id), 500

@api.route('/admin/reserve_status', methods=['POST'])
def admin_reserve_status():
    try:
        events_id = create_id(5)
        # Take header and verify it
        token = request.headers.get('Authorization')
        if not token:
            return error_403('No given token', '', request.remote_addr, request.url, events_id), 403
        if token[:7] != 'Bearer ':
            return error_403('No given token', '', request.remote_addr, request.url, events_id), 403
        token = token[7:]
        if not verify_jwt_one_day(token, request.remote_addr):
            return error_403('Token is invalid', '', request.remote_addr, request.url, events_id), 403

        user = get_user_id_from_token(token)
        user_rule = get_user_dorm(user)

        if user_rule != 'admin' and user_rule != 'master':
            return error_403('You are not admin', '', request.remote_addr, request.url, events_id), 200

        res = admin_get_reserve_status()

        return ok_200(res, '', request.remote_addr, request.url, events_id), 200
    except Exception as e:
        print(e)
        return error_500('Server Error', '', request.remote_addr, request.url, events_id), 500

@api.route('/admin/reserve_delete', methods=['POST'])
def admin_reserve_delete():
    try:
        events_id = create_id(5)

        try:
            data = request.get_json()
            logs = {
                'url': '/admin/edit_user',
                'request': data
            }
            write_log(request.remote_addr, request.url, events_id, str(logs), "")
        except:
            return error_403('No given data', '', request.remote_addr, request.url, events_id), 403
        else:
            if 'id' not in data:
                return error_403('No given data', '', request.remote_addr, request.url, events_id), 403

        # Take header and verify it
        token = request.headers.get('Authorization')
        if not token:
            return error_403('No given token', '', request.remote_addr, request.url, events_id), 403
        if token[:7] != 'Bearer ':
            return error_403('No given token', '', request.remote_addr, request.url, events_id), 403
        token = token[7:]
        if not verify_jwt_one_day(token, request.remote_addr):
            return error_403('Token is invalid', '', request.remote_addr, request.url, events_id), 403

        user = get_user_id_from_token(token)
        write_log(request.remote_addr, request.url, events_id, str(user), "")
        user_rule = get_user_dorm(user)

        if user_rule != 'admin' and user_rule != 'master':
            return error_403('You are not admin', '', request.remote_addr, request.url, events_id), 200

        deleteFlag = admin_delete_reserve(data['id'])
        if deleteFlag == False:
            return error_403('Action error', '', request.remote_addr, request.url, events_id), 200

        res = admin_get_reserve_status()

        return ok_200(res, '', request.remote_addr, request.url, events_id), 200
    except Exception as e:
        print(e)
        return error_500('Server Error', '', request.remote_addr, request.url, events_id), 500

@api.route('/admin/read_events', methods=['GET'])
def admin_read_events():
    try:
        events_id = create_id(5)

        try:
            logs = {
                'url': '/admin/read_events'
            }
            write_log(request.remote_addr, request.url, events_id, str(logs), "")
        except:
            return error_403('No given data', '', request.remote_addr, request.url, events_id), 403

        # Take header and verify it
        token = request.headers.get('Authorization')
        if not token:
            return error_403('No given token', '', request.remote_addr, request.url, events_id), 403
        if token[:7] != 'Bearer ':
            return error_403('No given token', '', request.remote_addr, request.url, events_id), 403
        token = token[7:]
        if not verify_jwt_one_day(token, request.remote_addr):
            return error_403('Token is invalid', '', request.remote_addr, request.url, events_id), 403

        user = get_user_id_from_token(token)
        write_log(request.remote_addr, request.url, events_id, str(user), "")
        user_rule = get_user_dorm(user)

        if user_rule != 'admin':
            return error_403('You are not admin', '', request.remote_addr, request.url, events_id), 200

        events = admin_get_events()

        return ok_200(events, '', request.remote_addr, request.url, events_id), 200
    except Exception as e:
        print(e)
        return error_500('Server Error', '', request.remote_addr, request.url, events_id), 500

@api.route('/admin/write_events', methods=['POST'])
def admin_write_events():
    try:
        events_id = create_id(5)

        try:
            data = request.get_json()
            logs = {
                'url': '/admin/write_events',
                'request': data
            }
            write_log(request.remote_addr, request.url, events_id, str(logs), "")
        except:
            return error_403('No given data', '', request.remote_addr, request.url, events_id), 403
        else:
            if 'events' not in data:
                return error_403('No given data', '', request.remote_addr, request.url, events_id), 403

        # Take header and verify it
        token = request.headers.get('Authorization')
        if not token:
            return error_403('No given token', '', request.remote_addr, request.url, events_id), 403
        if token[:7] != 'Bearer ':
            return error_403('No given token', '', request.remote_addr, request.url, events_id), 403
        token = token[7:]
        if not verify_jwt_one_day(token, request.remote_addr):
            return error_403('Token is invalid', '', request.remote_addr, request.url, events_id), 403

        user = get_user_id_from_token(token)
        write_log(request.remote_addr, request.url, events_id, str(user), "")
        user_rule = get_user_dorm(user)

        if user_rule != 'admin':
            return error_403('You are not admin', '', request.remote_addr, request.url, events_id), 200

        admin_set_events(data['events'])

        events = admin_get_events()

        return ok_200(events, '', request.remote_addr, request.url, events_id), 200
    except Exception as e:
        print(e)
        return error_500('Server Error', '', request.remote_addr, request.url, events_id), 500

@api.route('/admin/read_config', methods=['GET'])
def admin_read_config():
    try:
        events_id = create_id(5)

        try:
            logs = {
                'url': '/admin/read_config'
            }
            write_log(request.remote_addr, request.url, events_id, str(logs), "")
        except:
            return error_403('No given data', '', request.remote_addr, request.url, events_id), 403

        # Take header and verify it
        token = request.headers.get('Authorization')
        if not token:
            return error_403('No given token', '', request.remote_addr, request.url, events_id), 403
        if token[:7] != 'Bearer ':
            return error_403('No given token', '', request.remote_addr, request.url, events_id), 403
        token = token[7:]
        if not verify_jwt_one_day(token, request.remote_addr):
            return error_403('Token is invalid', '', request.remote_addr, request.url, events_id), 403

        user = get_user_id_from_token(token)
        write_log(request.remote_addr, request.url, events_id, str(user), "")
        user_rule = get_user_dorm(user)

        if user_rule != 'admin':
            return error_403('You are not admin', '', request.remote_addr, request.url, events_id), 200

        res = admin_get_config()

        return ok_200(res, '', request.remote_addr, request.url, events_id), 200
    except Exception as e:
        print(e)
        return error_500('Server Error', '', request.remote_addr, request.url, events_id), 500

@api.route('/admin/write_config', methods=['POST'])
def admin_write_config():
    try:
        events_id = create_id(5)

        try:
            data = request.get_json()
            logs = {
                'url': '/admin/write_config',
                'request': data
            }
            write_log(request.remote_addr, request.url, events_id, str(logs), "")
        except:
            return error_403('No given data', '', request.remote_addr, request.url, events_id), 403
        else:
            if 'config' not in data:
                return error_403('No given data', '', request.remote_addr, request.url, events_id), 403

        # Take header and verify it
        token = request.headers.get('Authorization')
        if not token:
            return error_403('No given token', '', request.remote_addr, request.url, events_id), 403
        if token[:7] != 'Bearer ':
            return error_403('No given token', '', request.remote_addr, request.url, events_id), 403
        token = token[7:]
        if not verify_jwt_one_day(token, request.remote_addr):
            return error_403('Token is invalid', '', request.remote_addr, request.url, events_id), 403

        user = get_user_id_from_token(token)
        write_log(request.remote_addr, request.url, events_id, str(user), "")
        user_rule = get_user_dorm(user)

        if user_rule != 'admin':
            return error_403('You are not admin', '', request.remote_addr, request.url, events_id), 200

        writeFlag = admin_set_config(data['config'])
        if writeFlag == False:
            return error_403('Action error', '', request.remote_addr, request.url, events_id), 200

        res = admin_get_config()

        return ok_200(res, '', request.remote_addr, request.url, events_id), 200
    except Exception as e:
        print(e)
        return error_500('Server Error', '', request.remote_addr, request.url, events_id), 500

@api.route('/admin/read_admin_member', methods=['GET'])
def admin_read_admin_member():
    try:
        events_id = create_id(5)

        try:
            logs = {
                'url': '/admin/read_admin_member'
            }
            write_log(request.remote_addr, request.url, events_id, str(logs), "")
        except:
            return error_403('No given data', '', request.remote_addr, request.url, events_id), 403

        # Take header and verify it
        token = request.headers.get('Authorization')
        if not token:
            return error_403('No given token', '', request.remote_addr, request.url, events_id), 403
        if token[:7] != 'Bearer ':
            return error_403('No given token', '', request.remote_addr, request.url, events_id), 403
        token = token[7:]
        if not verify_jwt_one_day(token, request.remote_addr):
            return error_403('Token is invalid', '', request.remote_addr, request.url, events_id), 403

        user = get_user_id_from_token(token)
        write_log(request.remote_addr, request.url, events_id, str(user), "")
        user_rule = get_user_dorm(user)

        if user_rule != 'admin':
            return error_403('You are not admin', '', request.remote_addr, request.url, events_id), 200

        res = admin_get_admin_member()

        return ok_200(res, '', request.remote_addr, request.url, events_id), 200
    except Exception as e:
        print(e)
        return error_500('Server Error', '', request.remote_addr, request.url, events_id), 500

@api.route('/admin/edit_admin_member', methods=['POST'])
def admin_edit_admin_member():
    try:
        events_id = create_id(5)

        try:
            data = request.get_json()
            logs = {
                'url': '/admin/edit_admin_member',
                'request': data
            }
            write_log(request.remote_addr, request.url, events_id, str(logs), "")
        except:
            return error_403('No given data', '', request.remote_addr, request.url, events_id), 403
        else:
            if 'member' not in data:
                return error_403('No given data', '', request.remote_addr, request.url, events_id), 403
            if 'action' not in data:
                return error_403('No given data', '', request.remote_addr, request.url, events_id), 403

        # Take header and verify it
        token = request.headers.get('Authorization')
        if not token:
            return error_403('No given token', '', request.remote_addr, request.url, events_id), 403
        if token[:7] != 'Bearer ':
            return error_403('No given token', '', request.remote_addr, request.url, events_id), 403
        token = token[7:]
        if not verify_jwt_one_day(token, request.remote_addr):
            return error_403('Token is invalid', '', request.remote_addr, request.url, events_id), 403

        user = get_user_id_from_token(token)
        write_log(request.remote_addr, request.url, events_id, str(user), "")
        user_rule = get_user_dorm(user)

        if user_rule != 'admin':
            return error_403('You are not admin', '', request.remote_addr, request.url, events_id), 200

        if data['action'] == 'add':
            res = admin_set_admin_member(data['member'])
        elif data['action'] == 'delete':
            res = admin_delete_admin_member(data['member'])

        return ok_200(res, '', request.remote_addr, request.url, events_id), 200
    except Exception as e:
        print(e)
        return error_500('Server Error', '', request.remote_addr, request.url, events_id), 500

@api.route('/admin/upload_all_member', methods=['POST'])
def admin_upload_all_member():
    # try:
        events_id = create_id(5)

        try:
            data = request.get_json()
            logs = {
                'url': '/admin/upload_all_member',
                'request': data
            }
            write_log(request.remote_addr, request.url, events_id, str(logs), "")
        except:
            return error_403('No given data', '', request.remote_addr, request.url, events_id), 403
        else:
            if 'member' not in data:
                return error_403('No given data', '', request.remote_addr, request.url, events_id), 403

        # Take header and verify it
        token = request.headers.get('Authorization')
        if not token:
            return error_403('No given token', '', request.remote_addr, request.url, events_id), 403
        if token[:7] != 'Bearer ':
            return error_403('No given token', '', request.remote_addr, request.url, events_id), 403
        token = token[7:]
        if not verify_jwt_one_day(token, request.remote_addr):
            return error_403('Token is invalid', '', request.remote_addr, request.url, events_id), 403

        user = get_user_id_from_token(token)
        write_log(request.remote_addr, request.url, events_id, str(user), "")
        user_rule = get_user_dorm(user)

        if user_rule != 'admin':
            return error_403('You are not admin', '', request.remote_addr, request.url, events_id), 200

        res = upload_all_member(data['member'])

        return ok_200(res, '', request.remote_addr, request.url, events_id), 200
    # except Exception as e:
    #     print(e)
    #     return error_500('Server Error', '', request.remote_addr, request.url, events_id), 500

@api.route('/admin/delete_all_data', methods=['GET'])
def admin_delete_all_data():
    try:
        events_id = create_id(5)

        try:
            logs = {
                'url': '/admin/delete_all_data'
            }
            write_log(request.remote_addr, request.url, events_id, str(logs), "")
        except:
            return error_403('No given data', '', request.remote_addr, request.url, events_id), 403

        # Take header and verify it
        token = request.headers.get('Authorization')
        if not token:
            return error_403('No given token', '', request.remote_addr, request.url, events_id), 403
        if token[:7] != 'Bearer ':
            return error_403('No given token', '', request.remote_addr, request.url, events_id), 403

        token = token[7:]
        if not verify_jwt_one_day(token, request.remote_addr):
            return error_403('Token is invalid', '', request.remote_addr, request.url, events_id), 403
        
        user = get_user_id_from_token(token)
        write_log(request.remote_addr, request.url, events_id, str(user), "")
        user_rule = get_user_dorm(user)

        if user_rule != 'admin':
            return error_403('You are not admin', '', request.remote_addr, request.url, events_id), 200

        res = admin_delete_all_checkin_data()

        return ok_200(res, '', request.remote_addr, request.url, events_id), 200
    except Exception as e:
        print(e)
        return error_500('Server Error', '', request.remote_addr, request.url, events_id), 500

@api.route('/api/reserve_status', methods=['GET'])
def api_reserve_status():
    return {
        'sun': get_events_list_by_dorm('sun'),
        'moon': get_events_list_by_dorm('moon'),
        'star': get_events_list_by_dorm('star'),
        'morn': get_events_list_by_dorm('morn'),
    }

@api.route('/api/checkin_status', methods=['GET'])
def api_checkin_status():
    return get_checkin_status()

@api.route('/api/reserve_and_checkin_status', methods=['GET'])
def api_reserve_and_checkin_status():
    try:
        event_id = create_id(5)

        try:
            logs = {
                'url': '/api/reserve_and_checkin_status'
            }
            write_log(request.remote_addr, request.url, event_id, str(logs), "")
        except:
            return error_403('No given data', '', request.remote_addr, request.url, event_id), 403
            
        # Take header and verify it
        token = request.headers.get('Authorization')
        if not token:
            return error_403('No given token', '', request.remote_addr, request.url, event_id), 403
        if token[:7] != 'Bearer ':
            return error_403('No given token', '', request.remote_addr, request.url, event_id), 403
        token = token[7:]
        if not verify_jwt_one_day(token, request.remote_addr):
            return error_403('Token is invalid', '', request.remote_addr, request.url, event_id), 403

        user = get_user_id_from_token(token)
        write_log(request.remote_addr, request.url, event_id, str(user), "")
        user_rule = get_user_dorm(user)

        if user_rule != 'admin' and user_rule != 'master':
            return error_403('You are not admin', '', request.remote_addr, request.url, event_id), 200

        checkIn = get_checkin_status()
        reserve = {
            'sun': get_events_list_by_dorm('sun'),
            'moon': get_events_list_by_dorm('moon'),
            'star': get_events_list_by_dorm('star'),
            'morn': get_events_list_by_dorm('morn'),
        }

        for i in reserve['sun']:
            if 'sun' in checkIn:
                if i['event_name'] in checkIn['sun']:
                    i['checkin'] = checkIn['sun'][i['event_name']]
                else:
                    i['checkin'] = 0
            else:
                i['checkin'] = 0
        if 'other' in checkIn['sun']:
            reserve['sun'].append({
                'event_name': '其他',
                'checkin': checkIn['sun']['other']
            })
        totalReserve = 0
        totalCheckin = 0
        for i in reserve['sun']:
            if 'haveReserve' in i:
                totalReserve += i['haveReserve']
            totalCheckin += i['checkin']
        reserve['sun'].append({
            'event_name': '總計',
            'haveReserve': totalReserve,
            'checkin': totalCheckin
        })

        for i in reserve['moon']:
            if 'moon' in checkIn:
                if i['event_name'] in checkIn['moon']:
                    i['checkin'] = checkIn['moon'][i['event_name']]
                else:
                    i['checkin'] = 0
            else:
                i['checkin'] = 0
        if 'other' in checkIn['moon']:
            reserve['moon'].append({
                'event_name': '其他',
                'checkin': checkIn['moon']['other']
            })
        totalReserve = 0
        totalCheckin = 0
        for i in reserve['moon']:
            if 'haveReserve' in i:
                totalReserve += i['haveReserve']
            totalCheckin += i['checkin']
        reserve['moon'].append({
            'event_name': '總計',
            'haveReserve': totalReserve,
            'checkin': totalCheckin
        })

        for i in reserve['star']:
            if 'star' in checkIn:
                if i['event_name'] in checkIn['star']:
                    i['checkin'] = checkIn['star'][i['event_name']]
                else:
                    i['checkin'] = 0
            else:
                i['checkin'] = 0
        if 'other' in checkIn['star']:
            reserve['star'].append({
                'event_name': '其他',
                'checkin': checkIn['star']['other']
            })
        totalReserve = 0
        totalCheckin = 0
        for i in reserve['star']:
            if 'haveReserve' in i:
                totalReserve += i['haveReserve']
            totalCheckin += i['checkin']
        reserve['star'].append({
            'event_name': '總計',
            'haveReserve': totalReserve,
            'checkin': totalCheckin
        })

        for i in reserve['morn']:
            if 'morn' in checkIn:
                if i['event_name'] in checkIn['morn']:
                    i['checkin'] = checkIn['morn'][i['event_name']]
                else:
                    i['checkin'] = 0
            else:
                i['checkin'] = 0
        if 'other' in checkIn['morn']:
            reserve['morn'].append({
                'event_name': '其他',
                'checkin': checkIn['morn']['other']
            })
        totalReserve = 0
        totalCheckin = 0
        for i in reserve['morn']:
            if 'haveReserve' in i:
                totalReserve += i['haveReserve']
            totalCheckin += i['checkin']
        reserve['morn'].append({
            'event_name': '總計',
            'haveReserve': totalReserve,
            'checkin': totalCheckin
        })
        
        return ok_200(reserve, '', request.remote_addr, request.url, event_id), 200
    except Exception as e:
        print(e)
        return error_500('Server Error', '', request.remote_addr, request.url, event_id), 500

@api.route('/api/parking_couple', methods=['GET'])
def api_parking_couple():
    return get_parking_couple()

@api.route('/api/visitor_inside', methods=['GET'])
def api_visitor_inside():
    try:
        events_id = create_id(5)

        # Take header and verify it
        token = request.headers.get('Authorization')
        if not token:
            return error_403('No given token', '', request.remote_addr, request.url, events_id), 403
        if token[:7] != 'Bearer ':
            return error_403('No given token', '', request.remote_addr, request.url, events_id), 403
        token = token[7:]
        if not verify_jwt_one_day(token, request.remote_addr):
            return error_403('Token is invalid', '', request.remote_addr, request.url, events_id), 403

        user = get_user_id_from_token(token)
        write_log(request.remote_addr, request.url, events_id, str(user), "")
        user_rule = get_user_dorm(user)

        if user_rule != 'admin':
            return error_403('You are not admin', '', request.remote_addr, request.url, events_id), 200

        return ok_200(get_visitor_inside(), '', request.remote_addr, request.url, events_id), 200
    except Exception as e:
        print(e)
        return error_500('Server Error', '', request.remote_addr, request.url, events_id), 500

@api.route('/admin/access/csv/<random>/<sessionCode>', methods=['GET'])
def admin_access_csv(random, sessionCode):
    try:
        events_id = create_id(5)

        # Take header and verify it
        token = sessionCode
        if not token:
            return error_403('No given token', '', request.remote_addr, request.url, events_id), 403
        if token[:7] != 'Bearer ':
            return error_403('No given token', '', request.remote_addr, request.url, events_id), 403
        token = token[7:]
        if not verify_jwt_one_day(token, request.remote_addr):
            return error_403('Token is invalid', '', request.remote_addr, request.url, events_id), 403

        user = get_user_id_from_token(token)
        user_rule = get_user_dorm(user)

        if user_rule != 'admin' and user_rule != 'master':
            return error_403('You are not admin', '', request.remote_addr, request.url, events_id), 200

        csv_path = admin_download_csv()
        return send_file(csv_path, as_attachment=True)
    except Exception as e:
        print(e)
        return error_500('Server Error', '', request.remote_addr, request.url, events_id), 500

# 在主應用中註冊 Blueprint，並指定 url_prefix 為 '/api'
app.register_blueprint(api, url_prefix='/api')

if __name__ == '__main__':
    init_sqlite()
    app.run(host='0.0.0.0', port=4777, debug=True)

