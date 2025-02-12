# NucleiPlatform

Nuclei SaaS 化服务并集成了资产扫描系统。

## nuclei-scan 分布式扫描系统

此框架适用于任何基于命令行的扫描器。

## 免责声明

本工具仅限授权安全测试使用，禁止非法攻击未授权站点。
请使用者遵守《中华人民共和国网络安全法》，勿将本项目用于未授权的测试，参与本项目的开发成员不负任何连带法律责任。

### 功能逻辑设计

NucleiPlatform 扫描模块
—> 逻辑设计简单，随时添加目标资产, 针对大量资产进行扫描。
—> 支持对资产收集 (魔改的 ARL 灯塔) 进行项目分组。
—> 建议三台机器去做 Nuclei Agent 节点扫描。
—> 支持对节点状态，扫描队列的查询。

AssetsDetectAPI 资产收集模块
—> 支持 celery 分布式任务调度。
—> 支持对资产进行项目分组，主要功能流程域名收集（域名爆破和网络测绘）、端口扫描、站点查询、指纹识别、服务识别、证书信息、站点截图、目录扫描。

__主控端服务器建议最低使用 4h8g VPS 服务器，客户端服务器最低使用 4h4g，画的图有偏差因为中途修改了扫描逻辑。__

### 项目部署

测试环境
```
Python 3.12.3
```

```
PRETTY_NAME="Ubuntu 24.04.1 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04.1 LTS (Noble Numbat)"
VERSION_CODENAME=noble
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
UBUNTU_CODENAME=noble
LOGO=ubuntu-logo
```

正常来说会上下兼容，其他操作系统未进行测试（暂且不支持 Windows 系统部署）。

