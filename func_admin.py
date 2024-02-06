#!/usr/bin/python
# -*- coding: utf-8 -*-

import sqlite3
import requests
import jwt
import os
# from dotenv import load_dotenv
import time
import base64
import json
import csv
from func import *

def admin_get_events():
    conn = sqlite3.connect('main.db')
    c = conn.cursor()
    c.execute("SELECT * FROM events")
    events = c.fetchall()
    conn.close()

    res = {
        'data': []
    }
    for i in events:
        res['data'].append({
            'id': i[0],
            'name': i[1],
            'sun': i[5],
            'moon': i[6],
            'star': i[7],
            'morn': i[8],
        })

    return res['data']

def admin_set_events(data):
    conn = sqlite3.connect('main.db')
    c = conn.cursor()
    
    # Clear all events
    c.execute("DELETE FROM events")
    
    # Insert new events
    for i in data:
        c.execute("INSERT INTO events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", (i['id'], i['name'], '', '', '', i['sun'], i['moon'], i['star'], i['morn']))
    conn.commit()
    conn.close()

def admin_get_config():
    conn = sqlite3.connect('main.db')
    c = conn.cursor()
    c.execute("SELECT * FROM config")
    config = c.fetchall()
    conn.close()

    res = {
        'data': []
    }
    for i in config:
        res['data'].append({
            'title': i[0],
            'data': i[1]
        })

    return res['data']

def admin_set_config(data):
    conn = sqlite3.connect('main.db')
    c = conn.cursor()
    
    for i in data:
        # Check if config exists
        c.execute("SELECT * FROM config WHERE title = ?", (i['title'],))
        # If config exists, update it
        if c.fetchone():
            c.execute("UPDATE config SET data = ? WHERE title = ?", (i['data'], i['title']))
        # If config doesn't exist, create it
        else:
            c.execute("INSERT INTO config VALUES (?, ?)", (i['title'], i['data']))
    conn.commit()
    conn.close()

    return {
        'status': 'success'
    }

def admin_get_admin_member():
    conn = sqlite3.connect('main.db')
    c = conn.cursor()
    # Select all members with admin and master role
    c.execute("SELECT * FROM member WHERE dorm = 'admin' OR dorm = 'master'")
    members = c.fetchall()
    res = {
        'data': []
    }
    for i in members:
        res['data'].append({
            'id': i[0],
            'dorm': i[2],
            'passwd': '******'
        })

    return res['data']

def admin_set_admin_member(data):
    conn = sqlite3.connect('main.db')
    c = conn.cursor()
    
    # Check if member exists
    c.execute("SELECT * FROM member WHERE id = ?", (data['id'],))
    # If member doesn't exist, create it
    if not c.fetchone():
        if data['dorm'] == 'admin' or data['dorm'] == 'master':
            print('Add new admin member {}'.format(data['id']))
            c.execute("INSERT INTO member VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (data['id'], '管理帳號', data['dorm'], '', '', '', '', ''))
            
            # Check if account exists
            c.execute("SELECT * FROM accounts WHERE id = ?", (data['id'],))
            # If account exists, update it
            if c.fetchone():
                c.execute("UPDATE accounts SET passwd = ? WHERE id = ?", (data['passwd'], data['id']))
            # If account doesn't exist, create it
            else:
                c.execute("INSERT INTO accounts VALUES (?, ?, ?, ?, ?, ?, ?)", (data['id'], data['passwd'], get_nowtime_taipei_time(), 'normal', '', '', ''))
        
    conn.commit()
    conn.close()
    return admin_get_admin_member()

def admin_delete_admin_member(data):
    conn = sqlite3.connect('main.db')
    c = conn.cursor()
    
    # Check if member exists
    c.execute("SELECT * FROM member WHERE id = ?", (data['id'],))
    # If member exists, update status to disabled
    if c.fetchone():
        c.execute("DELETE FROM member WHERE id = ?", (data['id'],))
        c.execute("DELETE FROM accounts WHERE id = ?", (data['id'],))
            
    conn.commit()
    conn.close()

    return admin_get_admin_member()

def upload_all_member(jsonData):
    # [{
    #     'dorm': 'morn',
    #     'id': '410885045',
    #     'name': 'YC',
    #     'bed': '310',
    # }]

    errMsg = ""
    conn = sqlite3.connect('main.db')
    c = conn.cursor()

    # Clear all members not include admin and master
    c.execute("DELETE FROM member WHERE dorm != 'admin' AND dorm != 'master'")

    # Check if member exists
    for i in jsonData:
        c.execute("SELECT * FROM member WHERE id = ?", (i['id'],))
        # If member exists, update it
        if c.fetchone():
            errMsg += "學號 {} 重複，請檢查檔案後再次上傳，以確保資料完整\n".format(i['id'])
        # If member doesn't exist, create it
        else:
            c.execute("INSERT INTO member VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (i['id'], i['name'], i['dorm'], i['bed'], '', '', '', ''))

    conn.commit()
    conn.close()

    if errMsg == "":
        return {
            'status': 'success'
        }
    else:
        return {
            'status': 'error',
            'errMsg': errMsg
        }
    
def admin_delete_all_checkin_data():
    # Delete all data in checkin table
    conn = sqlite3.connect('main.db')
    c = conn.cursor()
    c.execute("DELETE FROM checkIn")
    conn.commit()
    conn.close()

    return {
        'status': 'success'
    }
