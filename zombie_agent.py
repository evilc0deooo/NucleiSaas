# -*- coding: utf-8 -*-

import re
import time
import platform
from datetime import datetime
from services.zombie import run as ZombieScan
from services.redis_queue import RedisClient
from services.mongo import conn_db, get_project_zombie
from config import Config
from services.logger import logger

redisQueue = RedisClient(Config.REDIS_DB2)


def curr_date():
    """
    Get the current time
    """
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def target2list(target):
    target = target.strip().lower()
    target_lists = re.split(r',|\s', target)
    # 清除空白符
    target_lists = list(filter(None, target_lists))
    target_lists = list(set(target_lists))

    return target_lists


def dict2list(target):
    target = target.strip()
    target_lists = re.split(r',|\s', target)
    # 清除空白符
    target_lists = list(filter(None, target_lists))
    target_lists = list(set(target_lists))

    return target_lists


def add_data(queue_name, sites):
    """
    添加 IP 目标到队列
    """
    logger.info(f'新建任务 -> 队列已有内IP目标数量 -> {redisQueue.queue_length(queue_name)}.')
    queue_elements = redisQueue.queue_data(queue_name)
    all_queue_list = []
    for element in queue_elements:
        utf8_string = element.decode('utf-8')
        all_queue_list.append(utf8_string)

    for site in sites:
        if site in all_queue_list:
            continue
        redisQueue.enqueue(queue_name, site)
    logger.info(f'新建任务成功 -> 队列内存在 IP 目标总数量 -> {redisQueue.queue_length(queue_name)}.')


def read_file_in_batches(file_path, batch_size=10000):
    """
    针对大量数据使用文件上传方式
    batch_size 默认每次批量处理 10000 条数据
    """
    with open(file_path, 'r') as file:
        batch = []
        for line in file:
            url = line.strip()
            if url:
                batch.append(url)
                if len(batch) >= batch_size:
                    yield batch
                    batch = []
        if batch:
            yield batch


def batch_add_data(queue_name, file_name):
    """
    使用上传文件添加IP到队列
    """
    logger.info(f'新建任务 -> 队列已有内 IP 目标数量 -> {redisQueue.queue_length(queue_name)}')

    # 批量读取文件并写入 Redis
    for site in read_file_in_batches(file_name):
        try:
            redisQueue.enqueue_batch(queue_name, site)
        except Exception as e:
            logger.error(f'新建任务失败 -> Exception -> {e}')
            break
    logger.info(f'新建任务成功 -> 队列内存在 IP 目标总数量 -> {redisQueue.queue_length(queue_name)}.')


def create_project(name, target, description, service, user_dict, pwd_dict, batch=0):
    """
    创建新服务爆破项目
    """
    project_data = {
        'project_name': name,
        'project_description': description,
        'service': service,
        'user_dict': user_dict,
        'pwd_dict': pwd_dict,
        'date': curr_date()
    }
    project_id = conn_db('zombie_project').insert_one(project_data).inserted_id
    logger.info(f'新建 zombie 爆破服务项目 -> {name} -> {project_id}.')
    if batch == 0:
        try:
            add_data(str(project_id), target)
        except Exception as e:
            logger.error(f'新建项目失败 -> {name} -> Exception -> {e}.')
        return project_id
    else:
        try:
            batch_add_data(str(project_id), target)
        except Exception as e:
            logger.error(f'新建项目失败 -> {name} -> Exception -> {e}.')
        return project_id


def get_zombie_queue(project_id='ALL'):
    """
    获取 zombie 服务爆破项目队列长度
    """
    if project_id == 'ALL':
        count = 0
        collection_data = redisQueue.get_collection()
        for queue_name in collection_data:
            count += len(redisQueue.queue_data(queue_name))
        return count
    else:
        queue_elements = len(redisQueue.queue_data(project_id))
        return queue_elements


def del_target(project_id):
    """
    删除指定项目队列集合
    """
    redis_key = redisQueue.exists_collection(project_id)
    # 删除之前先判断该集合存不存在
    if redis_key:
        del_sts = redisQueue.del_collection(project_id)
        if del_sts:
            logger.info(f'{project_id}集合队列删除成功.')
        else:
            logger.error(f'{project_id}集合队列删除失败.')

        return del_sts
    else:
        # 不存在该集合默认就已删除
        return True


def del_all_targets():
    """
    删除所有 zombie 待扫描队列目标集合
    """
    collection_data = redisQueue.get_collection()
    for project_id in collection_data:
        del_tars = del_target(project_id)
        if del_tars:
            logger.info(f'{project_id} 集合队列删除成功.')
        else:
            logger.error(f'{project_id} 集合队列删除失败.')

    collection_data = redisQueue.get_collection()
    if len(collection_data) == 0:
        logger.info(f'已删除所有 zombie 待扫描队列目标集合.')

    return len(collection_data)


def target_split(targets_count):
    """
    假设始终有五个节点处理任务，每个节点处理 1/5 的任务
    """
    targets_count = int(targets_count)
    # 目标数量少于 10 个则不进行分发处理
    if targets_count < 10:
        return targets_count
    quotient = targets_count // int(Config.NODES_NUMBER)
    # 限制一个节点处理目标的数量最多 10000 条
    if quotient > 1000:
        return 1000
    remainder = targets_count % int(Config.NODES_NUMBER)
    if remainder == 0:
        return quotient
    elif remainder == 1:
        return quotient + 1
    else:
        return quotient + 2


def update_node(node_name):
    """
    更新 zombie Agent 节点回连时间戳，方便查看节点状态
    """
    nodes_data = conn_db('nodes').find_one({'node_name': f'{node_name}'})
    if nodes_data:
        update_data = {'$set': {
            'date': curr_date()  # 更新为当前日期时间
        }}

        conn_db('nodes').update_one({'node_name': node_name}, update_data)
    else:
        nodes = {'node_name': f'{node_name}', 'date': curr_date()}
        conn_db('nodes').insert_one(nodes)


def agent2_monitor():
    """
    监听队列内目标数量并分发 Agent zombie 做扫描
    """
    node_name = platform.node()  # 节点名称为当前主机名
    zombie_node_name = f'zombie-{node_name}'  # 节点名称为当前主机名
    print(f'{zombie_node_name} 开启 zombie Agent 正在监听成功')
    logger.info(f'{zombie_node_name} 开启 zombie Agent 正在监听成功')
    update_node(f'{zombie_node_name}')  # 实时更新节点状态
    while True:
        collection_data = redisQueue.get_collection()

        # 如果 redis 队列内没有扫描目标，则三分钟监听一次
        if len(collection_data) == 0:
            logger.info(f'实时监控 zombie 当前无待扫描队列')
            # time.sleep(3)
            time.sleep(int(Config.NODES_DELAY) * 60)

            update_node(node_name)  # 实时更新节点状态
            continue

        # 获取 redis 所有集合判断如果为空则跳过过去下一个集合
        for queue_name in collection_data:
            logger.info(f'实时监控 {queue_name} -> zombie 队列内目前目标 IP -> {redisQueue.queue_length(queue_name)}')
            queue_elements = len(redisQueue.queue_data(queue_name))

            project_data = get_project_zombie(queue_name)
            service = project_data['service']
            user_dict = project_data['user_dict']
            pwd_dict = project_data['pwd_dict']

            update_node(node_name)  # 实时更新节点状态
            ips_list = []
            ip_splits = target_split(queue_elements)
            for i in range(ip_splits):
                element = redisQueue.dequeue(queue_name)
                if element is None:
                    continue

                ip_adder = element.decode('utf-8')
                if ip_adder not in ips_list:
                    ips_list.append(ip_adder)

            zombie_results = ZombieScan(ips_list, service, user_dict, pwd_dict)
            if not zombie_results:
                continue
            for item in zombie_results:
                item['project_id'] = queue_name
                try:
                    conn_db('zombie_ret').insert_one(item)
                except Exception as e:
                    logger.error(f'zombie 爆破结果写入数据库发生异常自动跳过 -> {item}')
                    logger.error(f'错误异常信息 -> {e}')
                    continue

            # 防御性编程, 防止列表元素过大造成内存溢出等问题
            ips_list.clear()


if __name__ == '__main__':
    agent2_monitor()
