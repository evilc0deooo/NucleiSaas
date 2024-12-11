FROM ubuntu:22.04

# docker ps -q | xargs -I {} docker inspect -f '{{.Name}} {{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' {}
# docker build --no-cache -t nuclei-flask .
# docker run --env-file .NucleiEnv -itd -p 63335:63335 nuclei-flask
# docker run --env-file .NucleiEnv -itd nuclei-flask

# 设置工作目录
WORKDIR /root

ARG FILE_NAME=nuclei-scan.zip
ENV FILE_NAME=${FILE_NAME}

# 安装相关依赖
RUN apt -y update
RUN apt -y install --no-install-recommends python3 unzip vim python3-pip
RUN apt-get install -y tzdata && ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime

# 添加文件
ADD $FILE_NAME /root

# 解压文件
RUN unzip /root/$FILE_NAME -d /root

# 安装 Python 依赖
RUN pip3 install -r /root/nuclei-scan/requirements.txt

# 删除非项目文件
RUN rm -rf /root/$FILE_NAME
RUN rm -rf /root/__MACOSX
RUN cd /root/nuclei-scan && rm -rf .DS_Store .git* .idea README.md Dockerfile venv

# Expose port
EXPOSE 63335

ENTRYPOINT ["python3", "/root/nuclei-scan/nuclei_agent.py"]
# ENTRYPOINT ["python3", "/root/nuclei-scan/app.py"]
