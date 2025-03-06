# -*- coding: utf-8 -*-

import time
import platform
import thirdparty
from services.chkapi import run as ChkAPIScan
from services.nuclei import run as NucleiScan
from services.zombie import run as ZombieScan
from common.redis_queue import NucleiRedisQueue, ZombieRedisQueue, ChkAPIRedisQueue
from common.mongo import conn_db
from common.mongo import get_nuclei_project
from common.mongo import get_zombie_project
from common.mongo import get_chkapi_project
from common.mongo import update_node_info
from config import Config
from common.logger import logger


def target_split(sites_count):
    """
    假设始终有五个节点处理任务，每个节点处理 1/5 的任务
    """
    sites_count = int(sites_count)
    # 目标数量少于 10 个则不进行分发处理
    if sites_count < 10:
        return sites_count
    quotient = sites_count // int(Config.NODES_NUMBER)
    # 限制一个节点处理目标的数量最多 1000 条，为了更快的给用户响应
    if quotient > 1000:
        return 1000
    remainder = sites_count % int(Config.NODES_NUMBER)
    if remainder == 0:
        return quotient
    elif remainder == 1:
        return quotient + 1
    else:
        return quotient + 2


def agent_monitor():
    """
    监听队列内目标数量并分发 Agent 做扫描
    """
    node_name = platform.node()  # 节点名称为当前主机名
    print(f'{node_name} 开启 Scan Agent BATE 正在监听成功')
    logger.info(f'{node_name} 开启 Scan Agent BATE 正在监听成功')
    update_node_info(node_name)  # 实时更新节点状态
    while True:
        nuclei_collection_data = NucleiRedisQueue.get_collection()

        # 优先扫描 Nuclei 队列,如果 redis 队列内没有 nuclei 待扫描目标
        if len(nuclei_collection_data) != 0:
            # 获取 redis 所有集合判断如果为空则跳过过去下一个集合
            for nuclei_queue_name in nuclei_collection_data:
                print(f'实时监控 {nuclei_queue_name} -> Nuclei 队列内目前目标站点 -> {NucleiRedisQueue.queue_length(nuclei_queue_name)}')
                queue_elements = len(NucleiRedisQueue.queue_data(nuclei_queue_name))

                nuclei_project_data = get_nuclei_project(nuclei_queue_name)
                nuclei_template_yaml = nuclei_project_data['nuclei_template_yaml']
                nuclei_template_tags = nuclei_project_data['nuclei_template_tags']
                nuclei_severity = nuclei_project_data['nuclei_severity']
                nuclei_proxy = nuclei_project_data['nuclei_proxy']

                update_node_info(node_name)  # 实时更新节点状态
                nuclei_sites_list = []
                site_splits = target_split(queue_elements)
                for i in range(site_splits):
                    element = NucleiRedisQueue.dequeue(nuclei_queue_name)
                    if element is None:
                        continue

                    _site = element.decode('utf-8')
                    if _site not in nuclei_sites_list:
                        nuclei_sites_list.append(_site)

                # print(nuclei_template_yaml)
                NucleiScan(nuclei_queue_name, nuclei_sites_list, nuclei_template_yaml, nuclei_template_tags, nuclei_severity, nuclei_proxy)

                # 防御性编程, 防止列表元素过大造成内存溢出等问题
                nuclei_sites_list.clear()

        else:
            # 如果 nuclei 扫描队列处于空闲状态则扫描 zombie 目标队列
            print(f'实时监控 Nuclei 当前无待扫描队列')
            update_node_info(node_name)  # 实时更新节点状态

            # 查询 zombie 待扫描目标
            zombie_collection_data = ZombieRedisQueue.get_collection()  # 获取 zombie 的扫描队列
            if len(zombie_collection_data) != 0:
                # 获取 redis 所有集合判断如果 zombie 扫描队列为空则跳过去下一个集合
                for zombie_queue_name in zombie_collection_data:
                    print(f'实时监控 {zombie_queue_name} -> zombie 队列内目前目标 IP -> {ZombieRedisQueue.queue_length(zombie_queue_name)}')
                    zombie_queue_elements = len(ZombieRedisQueue.queue_data(zombie_queue_name))

                    zombie_project_data = get_zombie_project(zombie_queue_name)
                    service = zombie_project_data['service']
                    user_dict = zombie_project_data['user_dict']
                    pwd_dict = zombie_project_data['pwd_dict']
                    zombie_ips_list = []
                    ip_splits = target_split(zombie_queue_elements)
                    for i in range(ip_splits):
                        zombie_element = ZombieRedisQueue.dequeue(zombie_queue_name)
                        if zombie_element is None:
                            continue

                        ip_adder = zombie_element.decode('utf-8')
                        if ip_adder not in zombie_ips_list:
                            zombie_ips_list.append(ip_adder)

                    zombie_results = ZombieScan(zombie_ips_list, service, user_dict, pwd_dict)
                    if not zombie_results:
                        continue

                    for item in zombie_results:
                        item['project_id'] = zombie_queue_name
                        item['date'] = thirdparty.curr_date()
                        try:
                            conn_db('zombie_ret').insert_one(item)
                        except Exception as e:
                            logger.error(f'zombie 爆破结果写入数据库发生异常自动跳过 -> {item}')
                            logger.error(f'错误异常信息 -> {e}')
                            continue

                    # 防御性编程, 防止列表元素过大造成内存溢出等问题
                    zombie_ips_list.clear()

            else:
                # 如果 nuclei 和 zombie 扫描队列处于空闲状态则进入 chkapi 安全扫描
                print(f'实时监控 zombie 当前无待扫描队列')
                update_node_info(node_name)  # 实时更新节点状态

                # 查询 chkapi 待扫描目标
                chkapi_collection_data = ChkAPIRedisQueue.get_collection()  # 获取 chkapi 的扫描队列
                if len(chkapi_collection_data) != 0:
                    # 获取 redis 所有集合判断如果 chkapi 扫描队列为空则跳过去下一个集合
                    for chkapi_queue_name in chkapi_collection_data:
                        print(f'实时监控 {chkapi_queue_name} -> ChkAPI 队列内目前目标 -> {ChkAPIRedisQueue.queue_length(chkapi_queue_name)}')
                        chkapi_queue_elements = len(ChkAPIRedisQueue.queue_data(chkapi_queue_name))

                        chkapi_project_data = get_chkapi_project(chkapi_queue_name)
                        cookies = chkapi_project_data['cookies']
                        chrome = chkapi_project_data['chrome']
                        attack_type = chkapi_project_data['attack_type']
                        no_api_scan = chkapi_project_data['no_api_scan']
                        chkapi_sites_list = []
                        chkapi_splits = target_split(chkapi_queue_elements)
                        for i in range(chkapi_splits):
                            chkapi_element = ChkAPIRedisQueue.dequeue(chkapi_queue_name)
                            if chkapi_element is None:
                                continue

                            chkapi_target = chkapi_element.decode('utf-8')
                            if chkapi_target not in chkapi_sites_list:
                                chkapi_sites_list.append(chkapi_target)

                        chkapi_results = ChkAPIScan(chkapi_queue_name, chkapi_sites_list, cookies, chrome, attack_type, no_api_scan)
                        if not chkapi_results:
                            continue

                        for item in chkapi_results:
                            item['project_id'] = chkapi_queue_name
                            item['date'] = thirdparty.curr_date()
                            try:
                                conn_db('chkapi_ret').insert_one(item)
                            except Exception as e:
                                logger.error(f'ChkAPI 敏感信息检测结果写入数据库发生异常自动跳过 -> {item}')
                                logger.error(f'错误异常信息 -> {e}')
                                continue

                        # 防御性编程, 防止列表元素过大造成内存溢出等问题
                        chkapi_sites_list.clear()


                else:
                    # nuclei, zombie, chkapi 都没有需要扫描的队列等待继续扫描
                    # time.sleep(3)
                    time.sleep(int(Config.NODES_DELAY) * 60)
                    continue


if __name__ == '__main__':
    try:
        agent_monitor()
    except KeyboardInterrupt:
        print('Scan Agent 程序被中断')
        logger.error('Scan Agent 程序被中断')
