# -*- coding: utf-8 -*-

import hashlib
import os
import pathlib
import platform
import random
import shlex
import string
import subprocess
import time
from datetime import datetime

base_directory = pathlib.Path(__file__).parent.parent

NUCLEI_ARM_BIN = os.path.join(base_directory, 'thirdparty/nuclei_tools/nuclei_macos')
NUCLEI_UNIX_BIN = os.path.join(base_directory, 'thirdparty/nuclei_tools/nuclei_linux')
# 自定义 Nuclei Template Yaml 目录
NUCLEI_YAML = os.path.join(base_directory, 'thirdparty/nuclei_template')

ZOMBIE_ARM_BIN = os.path.join(base_directory, 'thirdparty/zombie_tools/zombie_darwin_amd64')
ZOMBIE_UNIX_BIN = os.path.join(base_directory, 'thirdparty/zombie_tools/zombie_linux_amd64')

# 导出数据集
MONGOEXPORT_ARM_BIN = os.path.join(base_directory,
                                   'thirdparty/mongo_tools/mongodb-database-tools-macos-arm64-100.9.5/bin/mongoexport')
MONGOEXPORT_UNIX_BIN = os.path.join(base_directory,
                                    'thirdparty/mongo_tools/mongodb-database-tools-ubuntu2204-x86_64-100.9.5/bin/mongoexport')

TMP_PATH = os.path.join(base_directory, 'thirdparty/tmp')
if not os.path.exists(TMP_PATH):
    os.mkdir(TMP_PATH)


def exists_file(path_list):
    """
    判断 POC Yaml 文件或路径是否存在
    """
    for path in set(path_list):
        if not os.path.exists(NUCLEI_YAML + '/' + path):
            return path

    return 'ALL_EXISTS'


def load_file(path):
    with open(path, 'r+', encoding='utf-8') as f:
        return f.readlines()


def random_choices(k=6):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=k))


def gen_md5(s):
    return hashlib.md5(s.encode()).hexdigest()


def curr_date():
    """
    获取当前时间
    """
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


# def curr_date(secs):
#     """
#     获取当前时间
#     """
#     return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(secs))


def exec_system(cmd, **kwargs):
    cmd = ' '.join(cmd)
    timeout = 4 * 60 * 60

    if kwargs.get('timeout'):
        timeout = kwargs['timeout']
        kwargs.pop('timeout')

    completed = subprocess.run(shlex.split(cmd), timeout=timeout, check=False, close_fds=True, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, **kwargs)

    # 判断命令执行是否失败
    if completed.returncode != 0:
        return 'error'

    return completed


def check_output(cmd, **kwargs):
    cmd = ' '.join(cmd)
    timeout = 4 * 60 * 60

    if kwargs.get('timeout'):
        timeout = kwargs.pop('timeout')

    if 'stdout' in kwargs:
        raise ValueError('stdout argument not allowed, it will be overridden.')

    output = subprocess.run(shlex.split(cmd), stdout=subprocess.PIPE, timeout=timeout, check=False, **kwargs).stdout
    return output


def get_architecture():
    """
    判断当前机器架构信息
    """
    machine = platform.machine()
    if 'arm' in machine.lower():
        return 'ARM'
    elif '64' in platform.architecture()[0]:
        return '64-bit Intel/AMD'
    else:
        return '32-bit Intel/AMD'
