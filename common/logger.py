# -*- coding: utf-8 -*-

import pathlib
from loguru import logger

# 路径设置
relative_directory = pathlib.Path(__file__).parent.parent  # 主项目代码相对路径
result_save_dir = relative_directory.joinpath('logs')  # 结果保存目录
log_path = result_save_dir.joinpath('debug.log')  # 日志保存路径

format_ = '{time} - {level} - {file} - {line} - {message}'
logger.remove()
logger.add(log_path, format=format_, enqueue=True, retention='12 hours', rotation="50 MB", encoding='utf-8')
