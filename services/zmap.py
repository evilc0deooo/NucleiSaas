# -*- coding: utf-8 -*-

import os
import csv
import thirdparty
from services.logger import logger

"""
cd /root/
wget https://github.com/zmap/zmap/archive/refs/tags/v4.1.0-RC1.tar.gz

sudo apt-get -y install cmake make gcc
sudo apt-get -y install build-essential cmake libgmp3-dev gengetopt libpcap-dev flex byacc libjson-c-dev pkg-config libunistring-dev libjudy-dev

tar -xzf v4.1.0-RC1.tar.gz
cd zmap-4.1.0-RC1
cmake .
make -C ./src
sudo make -C ./src install

# 扫描的目标文件经过测试只支持 CIDR 格式网段，不支持单 IP。
zmap -p 3306 --output-module=csv --output-fields=saddr,sport --output-filter='success=1 && repeat=0' --no-header-row -o port_80_8090_7001_61616.csv -w /root/ip.txt -b /root/zmap-4.1.0-RC1/conf/blocklist.conf -B 500M

# 扫描结果标准输出。
cat /root/zmap-4.1.0-RC1/port_80_8090_7001_61616.csv | sed 's/,/:/g' | sort -u
"""


class ZmapScan(object):
    def __init__(self, target, port, tmp_dir):
        self.count = 0
        self.target = target
        self.port = port
        self.tmp_dir = tmp_dir
        self.filename = f'zmap_gen_{thirdparty.random_choices()}.txt'
        self.zmap_output_path = os.path.join(tmp_dir, self.filename)
        self.zmap_info = {}

    def zmap_scan(self):
        """
        服务端口扫描
        """
        if os.path.exists('/root/zmap-4.1.0-RC1/conf/blocklist.conf'):
            zmap_command = [
                'zmap',
                '-p', f'{self.port}',
                '--output-module=csv',
                '--output-fields=saddr,sport',
                '--output-filter="success=1 && repeat=0"',
                '--no-header-row',
                '-o', f'{self.zmap_output_path}',
                '-w', f'{self.target}',
                '-b', '/root/zmap-4.1.0-RC1/conf/blocklist.conf',
                '-B', '500M'
            ]

            logger.info(' '.join(zmap_command))
            thirdparty.exec_system(zmap_command, timeout=96 * 60 * 60)

        else:
            logger.warning('zmap 缺少文件 /root/zmap-4.1.0-RC1/conf/blocklist.conf')
            zmap_command = [
                'zmap',
                '-p', f'{self.port}',
                '--output-module=csv',
                '--output-fields=saddr,sport',
                '--output-filter="success=1 && repeat=0"',
                '--no-header-row',
                '-o', f'{self.zmap_output_path}',
                '-w', f'{self.target}',
                '-B', '500M'
            ]

            logger.info(' '.join(zmap_command))
            thirdparty.exec_system(zmap_command, timeout=96 * 60 * 60)

    def parse_zmap_output(self):
        """
        处理 zmap 扫描结果
        """
        self.count = 0
        with open(self.zmap_output_path, 'r') as csvfile:
            csv_reader = csv.reader(csvfile)
            if not csv_reader:
                logger.info(f'本次 zmap 扫描结果数量 -> {self.count}.')
                return

            for row in csv_reader:
                # 替换逗号为冒号并将结果添加到集合中
                modified_row = ':'.join(row)
                with open('ip_addresses.txt', 'w') as f:
                    f.write('\n'.join(modified_row) + '\n')
                self.count += 1

        logger.info(f'本次 zmap 扫描结果数量 -> {self.count}.')

    def run(self):
        self.zmap_scan()
        self.parse_zmap_output()
        curr_date = thirdparty.curr_date()
        self.zmap_info['curr_date'] = curr_date
        self.zmap_info['filename'] = self.filename
        self.zmap_info['count'] = self.count

        return self.zmap_info


def run(target, port, tmp=None):
    """
    类统一调用入口
    """
    if not tmp:
        tmp = thirdparty.TMP_PATH
    gen = ZmapScan(target, port, tmp)
    zmap_info = gen.run()
    return zmap_info


if __name__ == '__main__':
    zmap = ZmapScan('1.txt', '6379', thirdparty.TMP_PATH)
    zmap.run()
