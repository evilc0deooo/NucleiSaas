# -*- coding: utf-8 -*-

import json
import time
import copy
import thirdparty
from thirdparty.getjsurlscan import getJsUrl
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
from common.mongo import conn_db
from common.logger import logger
from config import Config

"""
API安全检测自动化工具.
https://github.com/evilc0deooo/ChkApi_0x727
"""


class ChkAPIScan(object):
    def __init__(self, project_id, _sites, cookies=None, chrome='on', attack_type=0, no_api_scan=0):
        self.project_id = project_id
        self.sites = _sites
        self.cookies = cookies
        self.chrome = chrome
        self.attack_type = attack_type
        self.no_api_scan = no_api_scan

    @staticmethod
    def get_domain(url):
        """
        获取 url 中的域名和端口
        """
        try:
            parsed_url = urlparse(url)
            domain_with_port = parsed_url.netloc
            return domain_with_port
        except ValueError:
            print(f'无法解析 URL: {url}')
            return None

    def chk_api_scan(self, target):
        """
        执行 ChkAPI 扫描任务
        """
        hae_item = {
            'project_id': self.project_id,
            'name': '',
            'matches': '',
            'url': '',
            'date': thirdparty.curr_date(),
            'site': self.get_domain(target),
        }

        chk_api_res = getJsUrl.run_url(target, cookies=None, chrome='off', attackType=0, noApiScan=0)
        if not chk_api_res:
            return
        _data = json.loads(chk_api_res)
        diff_hash = _data['diff_hash']
        if diff_hash:
            print('存在 diff_hash')

        hae_data = _data['hae_data']
        if hae_data:
            for item in hae_data:
                hae_item = copy.deepcopy(hae_item)
                # 防御性编程, 移除可能存在的 _id 字段
                hae_item.pop('_id', None)
                hae_item['name'] = item[0]
                hae_item['matches'] = item[1]
                hae_item['url'] = item[2]
                try:
                    conn_db('chkapi_ret').insert_one(hae_item)
                except Exception as e:
                    logger.error(f'ChkAPI HAE 检测结果写入数据库发生异常自动跳过 -> {hae_item}')
                    logger.error(f'错误异常信息 -> {e}')

        sensitive_info = _data['sensitive_info']
        if sensitive_info:
            for item in hae_data:
                hae_item = copy.deepcopy(hae_item)
                hae_item.pop('_id', None)
                hae_item['name'] = item[0]
                hae_item['matches'] = item[1]
                hae_item['url'] = item[2]
                try:
                    conn_db('chkapi_ret').insert_one(hae_item)
                except Exception as e:
                    logger.error(f'ChkAPI 敏感信息检测结果写入数据库发生异常自动跳过 -> {hae_item}')
                    logger.error(f'错误异常信息 -> {e}')

    def run(self):
        max_workers = Config.CHKAPI_MAX_WORKERS
        try:
            with ThreadPoolExecutor(max_workers=int(max_workers)) as executor:
                executor.map(self.chk_api_scan, self.sites)
        except KeyboardInterrupt:
            executor.shutdown(wait=False)
            logger.error(f'ChkAPI 程序被中断，资源已清理完毕')
        except Exception as e:
            logger.error(f'ChkAPI 错误异常信息 -> {e}')

        chk_api_res = thirdparty.TMP_PATH + '/chk_api_res'
        del_chkapi_dir = thirdparty.delete_directory_contents(chk_api_res)
        if not del_chkapi_dir:
            logger.error(f'ChkAPI 删除 {chk_api_res} 目录失败')


def run(project_id, _sites, cookies=None, chrome='on', attack_type=0, no_api_scan=0):
    """
    类统一调用入口
    """
    t1 = time.time()
    s = ChkAPIScan(project_id, _sites, cookies=cookies, chrome=chrome, attack_type=attack_type, no_api_scan=no_api_scan)
    logger.info(f'start chkapi scan {len(_sites)} site')

    # 防御式编程
    if not _sites:
        return

    s.run()
    elapse = time.time() - t1
    logger.info(f'end chkapi scan elapse {elapse}')
