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
# 当前终端修改控制文件描述符限制
sudo ulimit -n 65535