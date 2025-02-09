# -*- coding: utf-8 -*-

import redis
import thirdparty
from config import Config
from common.logger import logger


class RedisClient(object):
    def __init__(self, db_name):
        """
        连接到 Redis 服务器
        """
        self.host = Config.REDIS_HOST
        self.port = Config.REDIS_PORT
        self.db = db_name
        self.password = Config.REDIS_PWD
        self.redis_client = redis.StrictRedis(host=self.host, port=int(self.port), db=self.db, password=self.password)

    def enqueue(self, queue_name, element):
        """
        将元素添加到队列尾部
        """
        self.redis_client.rpush(queue_name, element)

    def enqueue_batch(self, queue_name, elements):
        """
        批量将元素添加到队列尾部
        """
        with self.redis_client.pipeline() as pipe:
            for element in elements:
                pipe.rpush(queue_name, element)
            pipe.execute()

    def dequeue(self, queue_name):
        """
        从队列头部获取元素
        """
        return self.redis_client.lpop(queue_name)

    def queue_length(self, queue_name):
        """
        获取队列长度
        """
        return self.redis_client.llen(queue_name)

    def queue_data(self, queue_name):
        """
        获取队列中的所有元素
        """
        queue_elements = self.redis_client.lrange(queue_name, 0, -1)
        return queue_elements

    # 获取所有键
    def get_collection(self):
        """
        获取所有符合 list 类型的集合
        """
        all_keys = self.redis_client.keys('*')
        set_keys = [key.decode('utf-8') for key in all_keys if b'list' == self.redis_client.type(key)]
        return set_keys

    def del_collection(self, queue_name):
        """
        删除集合
        """
        return self.redis_client.delete(queue_name)

    def exists_collection(self, queue_name):
        """
        判断 queue_name 是否存在
        """
        return self.redis_client.exists(queue_name) and b'list' == self.redis_client.type(queue_name)


# nuclei 扫描队列
NucleiRedisQueue = RedisClient(Config.REDIS_DB)

# zombie 扫描队列
ZombieRedisQueue = RedisClient(Config.REDIS_DB2)


def add_nuclei_target(queue_name, sites):
    """
    添加目标站点到队列
    """
    logger.info(f'新建任务 -> 队列已有内目标站点数量 -> {NucleiRedisQueue.queue_length(queue_name)}')
    queue_elements = NucleiRedisQueue.queue_data(queue_name)
    all_queue_list = []
    for element in queue_elements:
        utf8_string = element.decode('utf-8')
        all_queue_list.append(utf8_string)

    for site in sites:
        if site in all_queue_list:
            continue
        NucleiRedisQueue.enqueue(queue_name, site)
    logger.info(f'新建任务成功 -> 队列内存在目标站点总数量 -> {NucleiRedisQueue.queue_length(queue_name)}')


def batch_add_data(queue_name, file_name):
    """
    使用上传文件添加站点到队列
    """
    logger.info(f'新建任务 -> 队列已有内目标数量 -> {NucleiRedisQueue.queue_length(queue_name)}')

    # 批量读取文件并写入 Redis
    for site in thirdparty.read_file_in_batches(file_name):
        try:
            NucleiRedisQueue.enqueue_batch(queue_name, site)
        except Exception as e:
            logger.error(f'新建任务失败 -> Exception -> {e}')
            break
    logger.info(f'新建任务成功 -> 队列内存在目标总数量 -> {NucleiRedisQueue.queue_length(queue_name)}')


def get_nuclei_queue(project_id='ALL'):
    """
    获取 Nuclei 项目队列长度
    """
    if project_id == 'ALL':
        count = 0
        collection_data = NucleiRedisQueue.get_collection()
        for queue_name in collection_data:
            count += len(NucleiRedisQueue.queue_data(queue_name))
        return count
    else:
        queue_elements = len(NucleiRedisQueue.queue_data(project_id))
        return queue_elements


def del_nuclei_sites(project_id):
    """
    删除指定项目队列集合
    """
    redis_key = NucleiRedisQueue.exists_collection(project_id)
    # 删除之前先判断该集合存不存在
    if redis_key:
        del_sts = NucleiRedisQueue.del_collection(project_id)
        if del_sts:
            logger.info(f'{project_id} 集合队列删除成功')
        else:
            logger.error(f'{project_id} 集合队列删除失败')

        return del_sts
    else:
        # 不存在该集合默认就已删除
        return True


def del_nuclei_all_sites():
    """
    删除所有待扫描队列目标集合
    """
    collection_data = NucleiRedisQueue.get_collection()
    for project_id in collection_data:
        del_sts = del_nuclei_sites(project_id)
        if del_sts:
            logger.info(f'{project_id} Nuclei 集合队列删除成功')
        else:
            logger.error(f'{project_id} Nuclei 集合队列删除失败')

    collection_data = NucleiRedisQueue.get_collection()
    if len(collection_data) == 0:
        logger.info(f'已删除所有 Nuclei 待扫描队列目标集合')

    return len(collection_data)


# zombie agent service

def add_zombie_target(queue_name, sites):
    """
    添加 IP 目标到队列
    """
    logger.info(f'新建任务 -> 队列已有内IP目标数量 -> {ZombieRedisQueue.queue_length(queue_name)}')
    queue_elements = ZombieRedisQueue.queue_data(queue_name)
    all_queue_list = []
    for element in queue_elements:
        utf8_string = element.decode('utf-8')
        all_queue_list.append(utf8_string)

    for site in sites:
        if site in all_queue_list:
            continue
        ZombieRedisQueue.enqueue(queue_name, site)
    logger.info(f'新建任务成功 -> 队列内存在 IP 目标总数量 -> {ZombieRedisQueue.queue_length(queue_name)}')


def get_zombie_queue(project_id='ALL'):
    """
    获取 zombie 服务爆破项目队列长度
    """
    if project_id == 'ALL':
        count = 0
        collection_data = ZombieRedisQueue.get_collection()
        for queue_name in collection_data:
            count += len(ZombieRedisQueue.queue_data(queue_name))
        return count
    else:
        queue_elements = len(ZombieRedisQueue.queue_data(project_id))
        return queue_elements


def del_zombie_target(project_id):
    """
    删除 zombie 指定项目队列集合
    """
    redis_key = ZombieRedisQueue.exists_collection(project_id)
    # 删除之前先判断该集合存不存在
    if redis_key:
        del_sts = ZombieRedisQueue.del_collection(project_id)
        if del_sts:
            logger.info(f'{project_id}集合队列删除成功')
        else:
            logger.error(f'{project_id}集合队列删除失败')

        return del_sts
    else:
        # 不存在该集合默认就已删除
        return True


def del_zombie_all_targets():
    """
    删除所有 zombie 待扫描队列目标集合
    """
    collection_data = ZombieRedisQueue.get_collection()
    for project_id in collection_data:
        del_tars = del_zombie_target(project_id)
        if del_tars:
            logger.info(f'{project_id} 集合队列删除成功')
        else:
            logger.error(f'{project_id} 集合队列删除失败')

    collection_data = ZombieRedisQueue.get_collection()
    if len(collection_data) == 0:
        logger.info(f'已删除所有 zombie 待扫描队列目标集合')

    return len(collection_data)
