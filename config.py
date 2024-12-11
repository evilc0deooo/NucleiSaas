# -*- coding: utf-8 -*-

import os


class Config(object):
    # Basic Authentication 认证
    AUTH_USERNAME = os.getenv('AUTH_USERNAME', 'admin')
    AUTH_PASSWORD = os.getenv('AUTH_PASSWORD', 'admin')

    # redis 扫描队列
    REDIS_HOST = os.getenv('REDIS_HOST', '127.0.0.1')
    REDIS_PORT = os.getenv('REDIS_PORT', '6379')
    # nuclei 扫描队列
    REDIS_DB = 1
    # zombie 扫描队列
    REDIS_DB2 = 2
    REDIS_PWD = os.getenv('REDIS_PWD', 'redis_password')  # 避免特殊字符

    # mongo 数据集结果展示
    MONGO_HOST = os.getenv('MONGO_HOST', '127.0.0.1')
    MONGO_PORT = os.getenv('MONGO_PORT', '27017')
    MONGO_PWD = os.getenv('MONGO_PWD', 'mongo_password')  # 避免特殊字符
    MONGO_DB = 'teamwork'
    MONGO_USERNAME = 'admin'
    MONGO_AUTH_DB = 'admin'
    MONGO_URL = f'mongodb://{MONGO_USERNAME}:{MONGO_PWD}@{MONGO_HOST}:{MONGO_PORT}'

    # 节点数量，最小设置为 3 ,设置的越多切片就越多每个节点分配到的目标就少很多
    NODES_NUMBER = 5
    # 节点延时时间默认 1 分钟检查队列一次
    NODES_DELAY = 1
    # Nuclei 进程并发限制
    NUCLEI_MAX_WORKERS = os.getenv('NUCLEI_MAX_WORKERS', '10')

    # DetectConfiguration
    API_URL = os.getenv('ASSETS_API_URL', 'http://127.0.0.1:5020')
    API_TOKEN = os.getenv('ASSETS_TOKEN', '123456')
    API_MONGO_DB = 'assets'
