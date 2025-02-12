#!/bin/bash

apt-get install -y tzdata
ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime

# ----------------------------------------------------------

# 安装数据库容器 (控制端需要执行, 客户端不需要执行 docker 相关命令)
# sudo apt -y install docker.io
# sudo docker pull mongo
# docker pull redis:latest
# docker run -d --name mongodb -p 27018:27017 -e MONGO_INITDB_ROOT_USERNAME=admin -e MONGO_INITDB_ROOT_PASSWORD=mongodb_password mongo
# docker run -d --name redis -p 6380:6379 redis:latest --requirepass redis_password
# docker ps

# ----------------------------------------------------------

# 终端永久修改系统控制文件描述符限制
echo 'fs.file-max = 65535' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
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

sudo sed -i '/DefaultLimitNOFILE/c DefaultLimitNOFILE=65535' /etc/systemd/*.conf
sudo systemctl daemon-reexec
ulimit -n 65535

# ----------------------------------------------------------

# 修改内核分配策略允许内存过度分配
echo 1 > /proc/sys/vm/overcommit_memory
sudo apt-get -y update

# 安装相关依赖
sudo apt -y install python3-pip python3.12-venv gcc nmap
sudo apt -y --fix-broken install
sudo apt -y install libappindicator3-1 libasound2t64 libatk-bridge2.0-0 libatk1.0-0 libc6 libcairo2 libcups2 libdbus-1-3 libexpat1 libfontconfig1 libgbm1 libgcc1 libgdk-pixbuf2.0-0 libglib2.0-0 libgtk-3-0 libnspr4 libnss3 libpango-1.0-0 libpangocairo-1.0-0 libstdc++6 libx11-6 libx11-xcb1 libxcb1 libxcomposite1 libxcursor1 libxdamage1 libxext6 libxfixes3 libxi6 libxrandr2 libxrender1 libxss1 libxtst6 lsb-release wget xdg-utils
sudo apt-get -y install fonts-liberation libu2f-udev
wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb && sudo dpkg -i google-chrome-stable_current_amd64.deb

sudo apt -y --fix-broken install
apt -y install chromium-chromedriver

google-chrome --version
sudo mkdir -p /root/snap/chromium/common/.cache
sudo chmod -R 755 /root/snap/chromium/common/.cache
sudo chmod 1777 /run/user
sudo mkdir -p /run/user/0
sudo chmod 700 /run/user/0
sudo chown root:root /run/user/0
chromedriver --version

python3 -m venv /opt/py_env

# source /opt/py_env/bin/activate
/opt/py_env/bin/python -m pip uninstall urllib3 chardet
/opt/py_env/bin/python -m pip install urllib3 chardet
/opt/py_env/bin/python -m pip install urllib3 chardet beautifulsoup4 tldextract selenium pyyaml openpyxl

# ----------------------------------------------------------

# ~/NucleiSaas
git clone https://github.com/evilc0deooo/NucleiPlatform.git /root/NucleiPlatform
if [ $? -ne 0 ]; then
    exit 1
fi

/opt/py_env/bin/python -m pip install -r /root/NucleiPlatform/requirements.txt
/opt/py_env/bin/python -m pip uninstall pymongo
/opt/py_env/bin/python -m pip install pymongo==4.7.3

# python -m pip install -r requirements.txt
# python -m pip uninstall pymongo
# python -m pip install pymongo==4.7.3
# python agent.py

# ----------------------------------------------------------

# ~/AssetsDetectAPI
git clone https://github.com/evilc0deooo/AssetsDetectAPI.git /root/AssetsDetectAPI
if [ $? -ne 0 ]; then
    exit 1
fi

/opt/py_env/bin/python -m pip install -r /root/AssetsDetectAPI/requirements.txt

# python -m pip install -r requirements.txt
# celery -A celerytask.celery worker -l debug -Q assets_task -n celery_task -c 2 -O fair
