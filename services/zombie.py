# -*- coding: utf-8 -*-

import os
import json
import time
import thirdparty
from services.logger import logger

"""
一个轻量级的服务口令爆破工具, 继承了hydra的命令行设计, hashcat的字典生成, 以及红队向的功能设计.
https://github.com/chainreactors/zombie

说明文档：
https://chainreactors.github.io/wiki/zombie/start/#_3
"""


class ZombieScan(object):
    def __init__(self, target, service, user_dict, pwd_dict, tmp_dir):
        # 目前支持的爆破服务
        self.service_list = ['ssh', 'smb', 'http', 'tomcat', 'kibana', 'mysql', 'mssql', 'oracle', 'mongo', 'mongodb',
                             'postgre', 'redis', 'ftp', 'smtp', 'pop3', 'ldap', 'telnet', 'vnc', 'rdp']

        self.target = target
        self.service = service

        # 根据服务内置一些账号
        if not user_dict or (len(user_dict) == 1 and not user_dict[0]):
            if service == 'mysql':
                user_dict = ['root', 'admin']
            elif service == 'ssh':
                user_dict = ['root', 'ubuntu', 'oracle']
            elif service == 'tomcat':
                user_dict = ['tomcat']
            elif service == 'mssql':
                user_dict = ['sa']
            elif service == 'oracle':
                user_dict = ['system', 'sys']
            elif service == 'mongo':
                user_dict = ['admin']
            elif service == 'rdp':
                user_dict = ['administrator']
            elif service == 'redis':
                user_dict = ['null']
            else:
                user_dict = ['']

        # 内置默认密码
        if not pwd_dict:
            pwd_dict = ['Aa123456', '!QAZ2wsx', 'P@ssw0rd', 'Passw0rd123', '!@#QWEasd', '1qaz@WSX', 'p@ssw0rd']

        self.user_dict = user_dict
        self.pwd_dict = pwd_dict

        if thirdparty.get_architecture() == 'ARM':
            self.zombie_bin = thirdparty.ZOMBIE_ARM_BIN
        else:
            self.zombie_bin = thirdparty.ZOMBIE_UNIX_BIN

        self.tmp_dir = tmp_dir
        self.zombie_user_dict = os.path.join(tmp_dir, f'zombie_{service}_user_{thirdparty.random_choices()}')
        self.zombie_pass_dict = os.path.join(tmp_dir, f'zombie_{service}_pass_{thirdparty.random_choices()}')
        self.zombie_gen_output_path = os.path.join(tmp_dir, f'zombie_gen_{thirdparty.random_choices()}')
        self.zombie_output_path = os.path.join(tmp_dir, f'zombie_scan_{thirdparty.random_choices()}.json')
        os.chmod(self.zombie_bin, 0o777)

    def gen_user_pwd_dict(self):
        """
        生成临时账号密码字典
        """
        with open(self.zombie_user_dict, 'w') as f:
            for user in self.user_dict:
                f.write(f'{user}\n')

        with open(self.zombie_pass_dict, 'w') as f:
            for pwd in self.pwd_dict:
                f.write(f'{pwd}\n')

        logger.info(f'zombie 生成 {self.service} 服务临时账号密码字典.')

    def target_write(self):
        """
        将需要爆破的目标写到文件
        """
        count = 0
        with open(self.zombie_gen_output_path, 'w') as f:
            for _t in self.target:
                target = _t.strip()
                if not target:
                    continue
                f.write(target + '\n')
                count += 1

        logger.info(f'本次 zombie 需要爆破目标计数 -> {count}.')

    def zombie(self):
        """
        服务爆破
        """
        zombie_command = [self.zombie_bin,
                          f'--IP={self.zombie_gen_output_path}',
                          f'--USER={self.zombie_user_dict}',
                          f'--PWD={self.zombie_pass_dict}',
                          f'--service={self.service}',
                          f'--file={self.zombie_output_path}',
                          f'--file-format=json',
                          '-t=700',
                          '--timeout=5',
                          '--no-unauth',
                          '--debug'
                          ]

        logger.info(' '.join(zombie_command))
        thirdparty.exec_system(zombie_command, timeout=96 * 60 * 60)

    def _delete_file(self):
        try:
            os.unlink(self.zombie_gen_output_path)
            os.unlink(self.zombie_user_dict)
            os.unlink(self.zombie_pass_dict)
            # 删除结果临时文件
            if os.path.exists(self.zombie_output_path):
                os.unlink(self.zombie_output_path)
        except Exception as e:
            logger.warning(e)

    def parse_zombie_output(self):
        """
        处理 zombie 扫描结果
        """
        results = []
        with open(self.zombie_output_path, 'r+', encoding='utf-8') as f:
            while True:
                line = f.readline()
                if not line:
                    break

                data = json.loads(line)
                results.append(data)
                logger.info(data)

        return results

    def run(self):
        if self.service not in self.service_list:
            logger.error(f'目前不支持该服务 {self.service} 扫描.')
            return []

        self.target_write()
        self.gen_user_pwd_dict()
        self.zombie()
        output = self.parse_zombie_output()

        # 删除临时文件
        self._delete_file()
        logger.info(f'end zombie scan output result -> {len(output)}.')
        return output


def run(_target, service, user_dict, pwd_dict, tmp=None):
    """
    类统一调用入口
    """
    if not tmp:
        tmp = thirdparty.TMP_PATH

    # 防御式编程
    if not _target:
        scan_results = []
        return scan_results

    t1 = time.time()
    s = ZombieScan(_target, service, user_dict, pwd_dict, tmp)
    logger.info(f'start zombie scan {len(_target)} target ip.')

    zombie_results = s.run()
    elapse = time.time() - t1
    logger.info(f'end zombie scan elapse {elapse}.')
    print(zombie_results)
    return zombie_results


if __name__ == '__main__':
    t = ['127.0.0.1']
    s = 'ssh'
    u = ['']
    p = ['']
    run(t, s, u, p)
