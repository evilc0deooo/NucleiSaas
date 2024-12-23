# NucleiPlatform

## nuclei-scan 分布式扫描系统

此框架适用于任何基于命令行的扫描器。

### 功能逻辑设计

NucleiPlatform 扫描模块
—> 逻辑设计简单，随时添加目标资产，针对大量资产进行无脑扫描。
—> 支持对资产进行项目分组。
—> 至少两至三台机器去做 Nuclei 分布式扫描。
—> 支持对节点状态，扫描队列的查询。

AssetsDetectAPI 资产收集模块
—> 支持 celery 分布式任务调度。
—> 支持对资产进行项目分组，主要功能流程域名收集（域名爆破和网络测绘）、端口扫描、站点查询、指纹识别、服务识别、证书信息、站点截图、目录扫描。

### 项目部署

__修改控制文件描述符限制__
```bash
#!/bin/bash

# 系统
echo 'fs.file-max = 65535' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# 用户 cat /etc/security/limits.conf
sudo tee -a /etc/security/limits.conf << EOF
*               hard    nofile          65535
*               soft    nofile          65535
root            hard    nofile          65535
root            soft    nofile          65535
*               soft    nproc           65535
*               hard    nproc           65535
root            soft    nproc           65535
root            hard    nproc           65535
*               soft    core            unlimited
*               hard    core            unlimited
root            soft    core            unlimited
root            hard    core            unlimited
EOF

# Systemd  
# cd /etc/systemd/
# grep -rn -F "DefaultLimitNOFILE"
sudo sed -i '/DefaultLimitNOFILE/c DefaultLimitNOFILE=65535' /etc/systemd/*.conf
sudo systemctl daemon-reexec
```

__创建启动 Redis 容器__
```bash
docker pull redis:latest
docker run -d --name redis -p 6379:6379 redis:latest --requirepass "redis_password"
```

__创建启动 Mongo 容器__
```bash
docker pull mongo
docker run -d \
  --name mongodb \
  -p 27017:27017 \
  -e MONGO_INITDB_ROOT_USERNAME=admin \
  -e MONGO_INITDB_ROOT_PASSWORD=mongo_password \
  mongo
```

__启动 Web__
```bash
screen python3 app.py
```

__运行 Scan Agent__
```bash
screen python3 nuclei_agent.py
screen python3 zombie_agent.py
```

## 界面

![img.png](images/img.png)

![img.png](images/img_3.png)

![img.png](images/img2.png)

![img.png](images/img_1.png)

![img.png](images/img_2.png)

