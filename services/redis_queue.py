# -*- coding: utf-8 -*-

import redis
from config import Config


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
