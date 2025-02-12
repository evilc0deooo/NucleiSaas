# -*- coding: utf-8 -*-

import re
import os
import random
import string
import hashlib
from flask import Flask, redirect, url_for, session, flash
from datetime import timedelta
from flask_httpauth import HTTPBasicAuth
from functools import wraps
from config import Config
from thirdparty import curr_date
from common.mongo import conn_db
from common.logger import logger


def check_email(email):
    """
    检查邮箱合规
    """
    if re.match(r'^\w[a-zA-Z1-9.]{1,19}@[a-zA-Z\d]{1,10}.[com]', email):
        return True
    return


def check_special_char(username):
    """
    检查用户名合规性
    """
    # 过滤特殊字符，用户名长度是否为 5-15
    if not re.search(r'\W', username) and 5 <= len(username) <= 15:
        return True


def check_password_content(string):
    """
    检查密码合规性
    """
    # 检查密码是否为数字和大小写字母的组合，长度范围是否为 8-15
    if re.search(r'^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).*$', string) and 8 <= len(string) <= 15:
        return True


def generate_secure_password(length=12):
    """
    生成强密码口令，确保密码包含至少一个大写字母、一个小写字母、一个数字和一个特殊字符
    """
    while True:
        password = ''.join(
            random.choice(string.ascii_letters + string.digits + string.punctuation) for i in range(length))
        if (any(c.isupper() for c in password) and
                any(c.islower() for c in password) and
                any(c.isdigit() for c in password) and
                any(c in string.punctuation for c in password)):
            break
    return password


def en_password(password):
    """
    密码哈希加密
    :param password: 明文密码
    """
    md5 = hashlib.md5()
    md5.update(password.encode('utf-8'))
    encrypted_text = md5.hexdigest()
    return encrypted_text


def check_password(encode_password, password):
    """
    对密码明文和哈希校验比对
    :param encode_password: 哈希密码
    :param password: 明文密码
    """
    return encode_password == en_password(password)


def init_admin(username='admin'):
    """
    初始化管理员用户
    """
    password = generate_secure_password()
    admin_user = {
        'username': username,
        'password': en_password(password),
        'purview': ['1', '2', '3', '4', '5', '6', '7', '8', '9'],
        'create_date': curr_date(),
        'email': 'admin@admin.com'
    }

    # 检查 username 是否已经存在
    existing_user = conn_db('users').find_one({'username': admin_user['username']})

    if not existing_user:
        conn_db('users').insert_one(admin_user)
        logger.info(f'管理员初始化成功 ——> 账号: {username}, 密码: {password}')


auth = HTTPBasicAuth()
"""
添加 Basic Authentication 认证
"""
users = {
    Config.AUTH_USERNAME: Config.AUTH_PASSWORD,
}


@auth.verify_password
def verify_password(username, password):
    """
    验证回调函数
    """
    if username in users and users[username] == password:
        return username


def login_check(f):
    """
    登录状态检查
    """

    @wraps(f)
    def wrapper(*args, **kwargs):

        if 'login' in session:
            if session['login'] == '1':
                return f(*args, **kwargs)
            else:
                flash('No permission to access')
                return redirect(url_for('login'))
        else:
            flash('No permission to access')
            return redirect(url_for('login'))

    return wrapper


app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') or os.urandom(64)  # secret key 密钥
app.permanent_session_lifetime = timedelta(hours=3)  # session 过期时间
app.debug = False  # 关闭 Debug
app.config['ALLOWED_EXTENSIONS'] = {'txt'}  # 文件上传白名单


def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


# 初始化管理员
init_admin()
