# -*- coding: utf-8 -*-

import os
import time
import json
import thirdparty
from concurrent.futures import ThreadPoolExecutor
from common.mongo import conn_db
from common.logger import logger
from config import Config


class NucleiScan(object):
    def __init__(self, project_id, _sites, nuclei_template_yaml, tags, severity, proxy, tmp_dir):
        self.project_id = project_id
        self.sites = _sites
        self.nuclei_template_yaml = nuclei_template_yaml
        self.tmp_dir = tmp_dir
        if thirdparty.get_architecture() == 'ARM':
            self.nuclei_bin = thirdparty.NUCLEI_ARM_BIN
        else:
            self.nuclei_bin = thirdparty.NUCLEI_UNIX_BIN

        self.poc_yaml_list = nuclei_template_yaml.split(',')
        self.tags_list = tags.split(',')
        self.severity_list = severity.split(',')
        self.nuclei_template = thirdparty.NUCLEI_YAML
        self.nuclei_tags = ','.join([item.strip() for item in self.tags_list])
        self.nuclei_severity = ','.join([item.strip() for item in self.severity_list])
        self.proxy = proxy.rstrip('/')  # Nuclei 扫描代理
        self.nuclei_rate = 500  # Nuclei 并发线程
        self.poc_template_list = []
        self.exclude_id = 'open-proxy-internal,open-proxy-portscan,CVE-2023-24044,CVE-2019-11248'  # 排除指定 id 的模板（逗号分隔，文件）
        os.chmod(self.nuclei_bin, 0o777)

    def find_file_recursively(self, poc_templates, search_dirs):
        """
        通过 YAML POC 文件名称获取绝对路径
        """
        if '.yaml' not in poc_templates or 'nuclei-templates' in poc_templates:
            return search_dirs + '/' + poc_templates
        for root, dirs, files in os.walk(self.nuclei_template):
            if poc_templates in files:
                return os.path.join(root, poc_templates)

        return None

    def nuclei_scan(self, target):

        for filename in self.poc_yaml_list:
            yaml_poc_name = self.find_file_recursively(filename.strip(), self.nuclei_template)
            # Yaml POC 文件存在则加入到列表
            if yaml_poc_name:
                self.poc_template_list.append(yaml_poc_name)

        scan_nuclei_template = ','.join(item for item in set(self.poc_template_list))
        # 判断是否通过 tags 来过滤 Yaml POC 文件
        if self.nuclei_tags:
            if self.proxy:
                cmd_parameters = [self.nuclei_bin, '-duc ',
                                  f'-u {target} ',
                                  f'-t {scan_nuclei_template} ',
                                  f'-severity {self.nuclei_severity} ',
                                  f'-tags {self.nuclei_tags} ',
                                  f'-exclude-id {self.exclude_id}',
                                  '-jsonl ',
                                  '-max-host-error 20 ',
                                  f'-rate-limit {self.nuclei_rate} ',
                                  '-timeout 10 ',
                                  '-no-color ',
                                  '-stats ',
                                  f'-proxy {self.proxy}'
                                  ]
            else:
                cmd_parameters = [self.nuclei_bin, '-duc ',
                                  f'-u {target} ',
                                  f'-t {scan_nuclei_template} ',
                                  f'-severity {self.nuclei_severity} ',
                                  f'-tags {self.nuclei_tags} ',
                                  f'-exclude-id {self.exclude_id}',
                                  '-jsonl ',
                                  '-max-host-error 20 ',
                                  f'-rate-limit {self.nuclei_rate} ',
                                  '-timeout 10 ',
                                  '-no-color ',
                                  '-stats ',
                                  ]
        else:
            if self.proxy:
                cmd_parameters = [self.nuclei_bin, '-duc ',
                                  f'-u {target} ',
                                  f'-t {scan_nuclei_template} ',
                                  f'-severity {self.nuclei_severity} ',
                                  f'-exclude-id {self.exclude_id}',
                                  '-jsonl ',
                                  '-max-host-error 20 ',
                                  f'-rate-limit {self.nuclei_rate} ',
                                  '-timeout 10 ',
                                  '-no-color ',
                                  '-stats ',
                                  f'-proxy {self.proxy}'
                                  ]
            else:
                cmd_parameters = [self.nuclei_bin, '-duc ',
                                  f'-u {target} ',
                                  f'-t {scan_nuclei_template} ',
                                  f'-severity {self.nuclei_severity} ',
                                  f'-exclude-id {self.exclude_id}',
                                  '-jsonl ',
                                  '-max-host-error 20 ',
                                  f'-rate-limit {self.nuclei_rate} ',
                                  '-timeout 10 ',
                                  '-no-color ',
                                  '-stats ',
                                  ]

        print(' '.join(cmd_parameters))
        result = thirdparty.exec_system(cmd_parameters, timeout=60 * 60)  # 超时设置为 1 小时
        outline = result.stdout.splitlines()
        print(outline)
        if outline:
            data_list = []
            for line in outline:
                try:
                    _data = json.loads(line.decode('utf-8'))
                    data_list.append(_data)

                except json.JSONDecodeError:
                    logger.error(f'无法解析该行 -> {line}')

            logger.info(f'目标 {target} 漏洞计数 -> {len(data_list)}')
            for data in data_list:
                item = {
                    'project_id': self.project_id,
                    'template_url': data.get('template-url', ''),
                    'template_id': data.get('template-id', ''),
                    'vuln_name': data.get('info', {}).get('name', ''),
                    'vuln_severity': data.get('info', {}).get('severity', ''),
                    'vuln_url': data.get('matched-at', ''),
                    'curl_command': data.get('curl-command', ''),
                    'target': data.get('host', ''),
                    'extracted-results': data.get('extracted-results', '-'),
                    'date': thirdparty.curr_date()
                }

                # 防御性编程
                if not item['template_id']:
                    continue

                try:
                    # print(item)
                    conn_db('nuclei_ret').insert_one(item)
                except Exception as e:
                    logger.error(f'Nuclei 漏洞结果写入数据库发生异常自动跳过 -> {item}')
                    logger.error(f'错误异常信息 -> {e}')

    def run(self):
        max_workers = Config.NUCLEI_MAX_WORKERS
        try:
            with ThreadPoolExecutor(max_workers=int(max_workers)) as executor:
                executor.map(self.nuclei_scan, self.sites)
        except KeyboardInterrupt:
            executor.shutdown(wait=False)
            logger.error(f'Nuclei 程序被中断，资源已清理完毕')
        except Exception as e:
            logger.error(f'Nuclei 错误异常信息 -> {e}')


def run(project_id, _sites, nuclei_template_yaml, tags, severity, proxy):
    """
    类统一调用入口
    """
    t1 = time.time()
    s = NucleiScan(project_id, _sites, nuclei_template_yaml, tags, severity, proxy, thirdparty.TMP_PATH)
    logger.info(f'start nuclei scan {len(_sites)} site')

    # 防御式编程
    if not _sites:
        return

    s.run()
    elapse = time.time() - t1
    logger.info(f'end nuclei scan elapse {elapse}')


if __name__ == '__main__':
    sites = ['127.0.0.21']

    run('172efc14296ae5f5be939af1', sites, 'ssl-dns-names.yaml', '', 'info,low,medium,high', 'socks5://127.0.0.1:7890')
    # run('172efc14296ae5f5be939af1', sites, 'nuclei-templates/http/miscellaneous/robots-txt-endpoint.yaml', '', 'info,low,medium,high', '')
