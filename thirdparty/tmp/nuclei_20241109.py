# -*- coding: utf-8 -*-

import os
import time
import json
import thirdparty
from services.logger import logger


class NucleiScan(object):
    def __init__(self, _sites, nuclei_template_yaml, tags, severity, proxy, tmp_dir):
        self.sites = _sites
        self.nuclei_template_yaml = nuclei_template_yaml
        self.tmp_dir = tmp_dir
        if thirdparty.get_architecture() == 'ARM':
            self.nuclei_bin = thirdparty.NUCLEI_ARM_BIN
        else:
            self.nuclei_bin = thirdparty.NUCLEI_UNIX_BIN

        self.sites_gen_output_path = os.path.join(tmp_dir, f'sites_gen_{thirdparty.random_choices()}')
        self.nuclei_output_path = os.path.join(tmp_dir, f'nuclei_{thirdparty.random_choices()}')
        self.poc_yaml_list = nuclei_template_yaml.split(',')
        self.tags_list = tags.split(',')
        self.severity_list = severity.split(',')
        self.nuclei_template = ','.join([thirdparty.NUCLEI_YAML + '/' + item.strip() for item in self.poc_yaml_list])
        self.nuclei_tags = ','.join([item.strip() for item in self.tags_list])
        self.nuclei_severity = ','.join([item.strip() for item in self.severity_list])
        self.proxy = proxy.rstrip('/')  # Nuclei 扫描代理
        self.nuclei_rate = 500  # Nuclei 并发线程
        os.chmod(self.nuclei_bin, 0o777)

    def sites_write(self):
        """
        将目标站点写到文件
        """
        count = 0
        with open(self.sites_gen_output_path, 'w') as f:
            for site in self.sites:
                site = site.strip()
                if not site:
                    continue
                f.write(site + '\n')
                count += 1

        logger.info(f'本次需要扫描目标站点计数 -> {count}.')

    def nuclei_scan(self):
        # 判断是否通过 tags 来过滤 Yaml POC 文件
        if self.nuclei_tags:
            if self.proxy:
                cmd_parameters = [self.nuclei_bin, '-duc ',
                                  '-type http ',
                                  f'-list {self.sites_gen_output_path} ',
                                  f'-t {self.nuclei_template} ',
                                  f'-severity {self.nuclei_severity} ',
                                  f'-tags {self.nuclei_tags} ',
                                  '-jsonl ',
                                  '-max-host-error 20 ',
                                  f'-rate-limit {self.nuclei_rate} ',
                                  '-timeout 10 ',
                                  '-no-color ',
                                  '-stats ',
                                  '-stats-interval 60 ',
                                  f'-o {self.nuclei_output_path} ',
                                  f'-proxy {self.proxy}'
                                  ]
            else:
                cmd_parameters = [self.nuclei_bin, '-duc ',
                                  '-type http ',
                                  f'-list {self.sites_gen_output_path} ',
                                  f'-t {self.nuclei_template} ',
                                  f'-severity {self.nuclei_severity} ',
                                  f'-tags {self.nuclei_tags} ',
                                  '-jsonl ',
                                  '-max-host-error 20 ',
                                  f'-rate-limit {self.nuclei_rate} ',
                                  '-timeout 10 ',
                                  '-no-color ',
                                  '-stats ',
                                  '-stats-interval 60 ',
                                  f'-o {self.nuclei_output_path} ',
                                  ]
        else:
            if self.proxy:
                cmd_parameters = [self.nuclei_bin, '-duc ',
                                  '-type http ',
                                  f'-list {self.sites_gen_output_path} ',
                                  f'-t {self.nuclei_template} ',
                                  f'-severity {self.nuclei_severity} ',
                                  '-jsonl ',
                                  '-max-host-error 20 ',
                                  f'-rate-limit {self.nuclei_rate} ',
                                  '-timeout 10 ',
                                  '-no-color ',
                                  '-stats ',
                                  '-stats-interval 60 ',
                                  f'-o {self.nuclei_output_path} ',
                                  f'-proxy {self.proxy}'
                                  ]
            else:
                cmd_parameters = [self.nuclei_bin, '-duc ',
                                  '-type http ',
                                  f'-list {self.sites_gen_output_path} ',
                                  f'-t {self.nuclei_template} ',
                                  f'-severity {self.nuclei_severity} ',
                                  '-jsonl ',
                                  '-max-host-error 20 ',
                                  f'-rate-limit {self.nuclei_rate} ',
                                  '-timeout 10 ',
                                  '-no-color ',
                                  '-stats ',
                                  '-stats-interval 60 ',
                                  f'-o {self.nuclei_output_path} ',
                                  ]

        # logger.info(' '.join(cmd_parameters))
        thirdparty.exec_system(cmd_parameters, timeout=96 * 60 * 60)

    def _delete_file(self):
        try:
            os.unlink(self.sites_gen_output_path)
            # 删除结果临时文件
            if os.path.exists(self.nuclei_output_path):
                os.unlink(self.nuclei_output_path)
        except Exception as e:
            logger.warning(e)

    def parse_nuclei_output(self) -> list:
        results = []
        with open(self.nuclei_output_path, 'r+', encoding='utf-8') as f:
            while True:
                line = f.readline()
                if not line:
                    break

                data = json.loads(line)
                item = {
                    'template_url': data.get('template-url', ''),
                    'template_id': data.get('template-id', ''),
                    'vuln_name': data.get('info', {}).get('name', ''),
                    'vuln_severity': data.get('info', {}).get('severity', ''),
                    'vuln_url': data.get('matched-at', ''),
                    'curl_command': data.get('curl-command', ''),
                    'target': data.get('host', '')
                }

                logger.info(item)
                results.append(item)

        return results

    def run(self):
        self.sites_write()
        self.nuclei_scan()
        output = self.parse_nuclei_output()

        # 删除临时文件
        self._delete_file()
        logger.info(f'end nuclei_scan output result -> {len(output)}.')
        return output


def run(_sites, nuclei_template_yaml, tags, severity, proxy):
    """
    类统一调用入口
    """
    t1 = time.time()
    s = NucleiScan(_sites, nuclei_template_yaml, tags, severity, proxy, thirdparty.TMP_PATH)
    logger.info(f'start nuclei scan {len(_sites)} site.')

    # 防御式编程
    if not _sites:
        scan_results = []
        return scan_results

    scan_results = s.run()
    elapse = time.time() - t1
    logger.info(f'end nuclei scan elapse {elapse}.')

    # 防御式编程
    if not scan_results:
        scan_results = []
        return scan_results

    print(scan_results)
    return scan_results


if __name__ == '__main__':
    sites = ['https://www.baidu.com/']

    run(sites, 'nuclei-templates/http/miscellaneous/robots-txt.yaml', '', 'info', '')