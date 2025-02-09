# -*- coding: utf-8 -*-

import json
import os
import thirdparty
from common.logger import logger

"""
Debian 10 / Ubuntu 20.04 (或更新版本): apt -y install curl whois bind9-host mtr-tiny jq ipcalc grepcidr nmap ncat aha
将 asn 脚本从 shell 安装到 /usr/bin: curl "https://raw.githubusercontent.com/nitefood/asn/master/asn" > /usr/bin/asn && chmod 0755 /usr/bin/asn
"""


class GenASN(object):
    def __init__(self, cy_tlds, tmp_dir):
        self.count = 0
        self.cy_tlds = cy_tlds
        self.tmp_dir = tmp_dir
        self.filename = f'asn_gen_{cy_tlds}_{thirdparty.random_choices()}.txt'
        self.asn_gen_output_path = os.path.join(tmp_dir, self.filename)
        self.ipv4_list = []
        self.asn_info = {}

    def gen_country_ipv4(self):
        """
        查询指定国家或地区的 CIDR IP 段
        """

        if not self.cy_tlds:
            return None

        country_tlds = [
            'af', 'al', 'dz', 'as', 'ad', 'ao', 'ai', 'aq', 'ag', 'ar', 'am', 'aw',
            'au', 'at', 'az', 'bs', 'bh', 'bd', 'bb', 'by', 'be', 'bz', 'bj', 'bm',
            'bt', 'bo', 'ba', 'bw', 'br', 'io', 'bn', 'bg', 'bf', 'bi', 'cv', 'kh',
            'cm', 'ca', 'ky', 'cf', 'td', 'cl', 'cn', 'cx', 'cc', 'co', 'km', 'cg',
            'cd', 'ck', 'cr', 'ci', 'hr', 'cu', 'cy', 'cz', 'dk', 'dj', 'dm', 'do',
            'ec', 'eg', 'sv', 'gq', 'er', 'ee', 'et', 'eu', 'fk', 'fo', 'fj', 'fi',
            'fr', 'gf', 'pf', 'ga', 'gm', 'ge', 'de', 'gh', 'gi', 'gr', 'gl', 'gd',
            'gp', 'gu', 'gt', 'gg', 'gn', 'gw', 'gy', 'ht', 'hn', 'hk', 'hu', 'is',
            'in', 'id', 'ir', 'iq', 'ie', 'im', 'il', 'it', 'jm', 'jp', 'je', 'jo',
            'kz', 'ke', 'ki', 'kp', 'kr', 'kw', 'kg', 'la', 'lv', 'lb', 'ls', 'lr',
            'ly', 'li', 'lt', 'lu', 'mo', 'mg', 'mw', 'my', 'mv', 'ml', 'mt', 'mh',
            'mq', 'mr', 'mu', 'yt', 'mx', 'fm', 'md', 'mc', 'mn', 'me', 'ms', 'ma',
            'mz', 'mm', 'na', 'nr', 'np', 'nl', 'nc', 'nz', 'ni', 'ne', 'ng', 'nu',
            'nf', 'mp', 'no', 'om', 'pk', 'pw', 'pa', 'pg', 'py', 'pe', 'ph', 'pn',
            'pl', 'pt', 'pr', 'qa', 're', 'ro', 'ru', 'rw', 'sh', 'kn', 'lc', 'pm',
            'vc', 'ws', 'sm', 'st', 'sa', 'sn', 'us', 'si', 'sk', 'sl', 'sg', 'sb',
            'so', 'za', 'ss', 'es', 'lk', 'sd', 'sr', 'sj', 'sz', 'se', 'ch', 'sy',
            'tw', 'tj', 'tz', 'th', 'tl', 'tg', 'tk', 'to', 'tt', 'tn', 'tr', 'tm',
            'tc', 'tv', 'ug', 'ua', 'ae', 'gb', 'tz', 'uy', 'uz', 'vu', 'va', 've',
            'vn', 'wf', 'eh', 'ye', 'zm', 'zw'
        ]

        # 禁止查询大陆 CIDR 段
        black_country_tlds = ['cn']
        if self.cy_tlds not in country_tlds:
            logger.error(f'{self.cy_tlds} 错误的国家和地区顶级域名（ccTLD）.')
            return

        if self.cy_tlds in black_country_tlds:
            logger.error(f'{self.cy_tlds} 在国家和地区顶级域名黑名单内.')
            return

        asn_command = ['asn', '-j', '-c', f'.{self.cy_tlds}']
        logger.info(' '.join(asn_command))
        result = thirdparty.exec_system(asn_command, timeout=96 * 60 * 60)
        if result.returncode == 0:
            # 提取 IPv4 地址列表
            data = json.loads(result.stdout.decode())
            ipv4_list = data['results'][0]['ipv4']
            self.ipv4_list = ipv4_list
        else:
            logger.error(f'error executing command: {result.stderr}.')
            return

    def cidr_write(self):
        """
        将 cidr 块写到文件
        """
        self.count = 0
        if not self.ipv4_list:
            logger.warning(f'本次 {self.cy_tlds} 生成 CDIR 块数量 -> {self.count}.')
            logger.error(f'检查代理网络连接.')
            return

        with open(self.asn_gen_output_path, 'w') as f:
            for ipv4 in self.ipv4_list:
                ipv4 = ipv4.strip()
                if not ipv4:
                    continue
                f.write(ipv4 + '\n')
                self.count += 1

        logger.info(f'本次 {self.cy_tlds} 生成 CDIR 块数量 -> {self.count}.')

    def run(self):
        self.gen_country_ipv4()
        self.cidr_write()
        curr_date = thirdparty.curr_date()
        self.asn_info['curr_date'] = curr_date
        if not self.ipv4_list:
            self.asn_info['filename'] = 'NULL'
        self.asn_info['filename'] = self.filename
        self.asn_info['cidr_count'] = self.count

        return self.asn_info


def run(cy_tlds, tmp=None):
    """
    类统一调用入口
    """
    if not tmp:
        tmp = thirdparty.TMP_PATH
    gen = GenASN(cy_tlds, tmp)
    asn_info = gen.run()
    return asn_info


if __name__ == '__main__':
    print(run('us'))
