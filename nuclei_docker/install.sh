#!/bin/bash

apt install -y docker.io

# 安装 mongo 容器
docker pull mongo
docker run -d \
  --name mongodb \
  -p 27018:27017 \
  -e MONGO_INITDB_ROOT_USERNAME=admin \
  -e MONGO_INITDB_ROOT_PASSWORD=mongo_password \
  mongo

# 安装 redis 容器
docker pull redis:latest
docker run -d --name redis -p 6380:6379 redis:latest --requirepass "redis_password"

# 查看 Docker 容器 IP
docker ps -q | xargs -I {} docker inspect -f '{{.Name}} {{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' {}
