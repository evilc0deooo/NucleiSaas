# -*- coding: utf-8 -*-

import os
import thirdparty
import requests
from werkzeug.utils import secure_filename
from flask import send_file, jsonify, after_this_request, redirect, url_for, flash, request, render_template, session
from common.mongo import get_nodes_data, del_nodes
from common.mongo import create_nuclei_project, get_project_data, get_nuclei_data, download_nuclei_data, delete_nuclei_project
from common.mongo import create_zombie_project, get_zombie_project_data, get_zombie_data, download_zombie_data, delete_zombie_project
from common.mongo import create_chkapi_project, get_chkapi_project_data, get_chkapi_data, download_chkapi_hae_data, delete_chkapi_project
from common.mongo import download_domain_data, download_site_data, download_file_leak_data, assets_site_link_nuclei
from common.mongo import conn_db, query_account, query_account_data, add_user, del_user
from common.redis_queue import get_nuclei_queue, del_nuclei_sites, del_nuclei_all_sites
from common.redis_queue import get_zombie_queue, del_zombie_target, del_zombie_all_targets
from common.redis_queue import get_chkapi_queue, del_chkapi_target, del_chkapi_all_targets
from views.__init__ import app, auth, login_check, check_password, allowed_file
from views.__init__ import check_email, check_special_char, check_password_content, en_password
from config import Config
from loguru import logger


@app.route('/Login', methods=['GET', 'POST'])
@auth.login_required
def login():
    """
    登录逻辑
    """
    if request.method == 'GET':
        return render_template('login.html')

    if request.method == 'POST':
        account = request.form.get('username')
        password = request.form.get('password')
        try:
            user_data = query_account(account)
            if check_password(user_data['password'], password):
                session['login'] = '1'
                session['account'] = user_data['username']
                session['email'] = user_data['email']
                session['purview'] = user_data['purview']
                # 配置资产搜集 API 及认证 Token
                session['assets_api_url'] = Config.API_URL
                session['assets_api_token'] = Config.API_TOKEN
                flash('登录成功')
                return redirect(url_for('project_view'))
            else:
                flash('用户名或密码错误')
                return render_template('login.html')
        except Exception as e:
            print(e)
            flash(f'登陆发生异常错误 {e}')
            return render_template('login.html')


@app.route('/Logout', methods=['GET'])
@login_check
def logout():
    """
    用户登出
    """
    session['login'] = ''
    session['account'] = ''
    session['user_email'] = ''
    session['user_purview'] = ''
    flash('登出成功')
    return redirect(url_for('login'))


@app.route('/', methods=['GET'])
@app.route('/Dashboard', methods=['GET'])
@app.route('/ProjectView/<int:page_index>', methods=['GET'])
@app.route('/ProjectView', methods=['GET'])
@auth.login_required
@login_check
def project_view(page_size=10, page_index=1):
    """
    项目视图
    """
    if request.method == 'GET':
        entries = get_project_data(page_size, page_index)
        return render_template('project-view.html', page_size=page_size, page=page_index, entries=entries, session=session)


@app.route('/NewTask', methods=['GET', 'POST'])
@auth.login_required
@login_check
def new_nuclei_task():
    """
    添加任务
    """
    if request.method == 'GET':
        return render_template('new-task.html')

    if request.method == 'POST':
        project_name = request.form.get('project_name')
        project_description = request.form.get('project_description')
        nuclei_template_yaml = request.form.get('nuclei_template_yaml').rstrip(',')
        nuclei_template_tags = request.form.get('nuclei_template_tags', '').rstrip(',')
        nuclei_proxy = request.form.get('nuclei_proxy', '').rstrip(',')
        severity_critical = request.form.get('severity_critical', '')
        severity_high = request.form.get('severity_high', '')
        severity_medium = request.form.get('severity_medium', '')
        severity_low = request.form.get('severity_low', '')
        severity_info = request.form.get("severity_info", '')
        sites = request.form.get('sites')
        if not project_name:
            flash('请输入项目名称')
            return redirect(url_for('new_nuclei_task'))

        # 禁止目录穿越
        if not nuclei_template_yaml or './' in nuclei_template_yaml or '..' in nuclei_template_yaml:
            flash('请输入指定要运行的YAML模板名称或者模板目录（以逗号分隔或目录形式）')
            return redirect(url_for('new_nuclei_task'))

        if not severity_critical and not severity_high and not severity_medium and not severity_low and not severity_info:
            flash('根据漏洞严重程度来过滤运行的模板不能为空')
            return redirect(url_for('new_nuclei_task'))

        # 使用列表推导式过滤掉空字符串
        nuclei_severity_list = [s for s in [severity_critical, severity_high, severity_medium, severity_low, severity_info] if s.strip()]
        # 将过滤后的字符串列表用逗号分隔拼接成一个字符串
        nuclei_severity = ','.join(nuclei_severity_list)
        if not sites:
            flash('请输入扫描目标')
            return redirect(url_for('new_nuclei_task'))

        sites_list = thirdparty.target2list(sites)
        create_nuclei_project(project_name, sites_list, project_description, nuclei_template_yaml, nuclei_template_tags, nuclei_severity, nuclei_proxy, account=session['account'], batch=0)
        flash('成功创建项目')
        return redirect(url_for('project_view'))


@app.route('/BatchTask', methods=['GET', 'POST'])
@auth.login_required
@login_check
def batch_nuclei_task():
    if request.method == 'GET':
        return render_template('new-batch-task.html')

    if request.method == 'POST':
        project_name = request.form.get('project_name')
        project_description = request.form.get('project_description')
        nuclei_template_yaml = request.form.get('nuclei_template_yaml').rstrip(',')
        nuclei_template_tags = request.form.get('nuclei_template_tags', '').rstrip(',')
        nuclei_proxy = request.form.get('nuclei_proxy', '').rstrip(',')
        severity_critical = request.form.get('severity_critical', '')
        severity_high = request.form.get('severity_high', '')
        severity_medium = request.form.get('severity_medium', '')
        severity_low = request.form.get('severity_low', '')
        severity_info = request.form.get('severity_info', '')

        if not project_name:
            flash('请输入项目名称')
            return redirect(url_for('batch_nuclei_task'))

        if not nuclei_template_yaml or './' in nuclei_template_yaml or '..' in nuclei_template_yaml:
            flash('请输入指定要运行的YAML模板名称或者模板目录（以逗号分隔或目录形式）')
            return redirect(url_for('batch_nuclei_task'))

        if not severity_critical and not severity_high and not severity_medium and not severity_low and not severity_info:
            flash('根据漏洞严重程度来过滤运行的模板不能为空')
            return redirect(url_for('batch_nuclei_task'))

        # 使用列表推导式过滤掉空字符串
        nuclei_severity_list = [s for s in [severity_critical, severity_high, severity_medium, severity_low, severity_info] if s.strip()]
        # 将过滤后的字符串列表用逗号分隔拼接成一个字符串
        nuclei_severity = ','.join(nuclei_severity_list)

        if 'file' not in request.files:
            flash('请上传目标文件（仅支持 txt 文件）')
            return redirect(url_for('batch_nuclei_task'))

        file = request.files['file']
        if file.filename == '':
            flash('请上传目标文件（仅支持 txt 文件）')
            return redirect(url_for('batch_nuclei_task'))

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            new_filename = f'{thirdparty.TMP_PATH}/{thirdparty.random_choices()}_{filename}'
            file.save(new_filename)
            create_nuclei_project(project_name, new_filename, project_description, nuclei_template_yaml, nuclei_template_tags, nuclei_severity, nuclei_proxy, account=session['account'], batch=1)
            flash('成功创建项目')
            return redirect(url_for('project_view'))

        else:
            flash('请上传目标文件（仅支持 txt 文件）')
            return redirect(url_for('batch_nuclei_task'))


@app.route('/VulRet/<project_id>', methods=['GET'])
@auth.login_required
@login_check
def nuclei_ret(project_id):
    """
    查看扫描结果
    """
    if request.method == 'GET':
        return render_template('nuclei-ret.html', project_id=project_id)


@app.route('/Ajax/VulRet/<project_id>', methods=['GET'])
@auth.login_required
@login_check
def get_vul_data(project_id):
    """
    漏洞扫描结果 Ajax 接口
    """
    draw = int(request.args.get('draw', 0))
    start = int(request.args.get('start', 0))
    length = int(request.args.get('length', 10))
    return get_nuclei_data(draw, start, length, project_id)


@app.route('/ZombieProjectView/<int:page_index>', methods=['GET'])
@app.route('/ZombieProjectView', methods=['GET'])
@auth.login_required
@login_check
def zombie_project_view(page_size=10, page_index=1):
    """
    弱口令服务项目视图
    """
    if request.method == 'GET':
        entries = get_zombie_project_data(page_size, page_index)
        return render_template('zombie-project-view.html', page_size=page_size, page=page_index, entries=entries)


@app.route('/NewZombieTask', methods=['GET', 'POST'])
@auth.login_required
@login_check
def new_zombie_task():
    """
    添加服务爆破任务
    """
    if request.method == 'GET':
        return render_template('new-zombie-task.html')

    if request.method == 'POST':
        project_name = request.form.get('project_name')
        project_description = request.form.get('project_description')
        service_name = request.form.get('service_name')
        user_dict = request.form.get('user_dict')
        pass_dict = request.form.get('pass_dict')
        ips_list = request.form.get('ips_list')
        if not project_name:
            flash('请输入项目名称')
            return redirect(url_for('new_zombie_task'))

        if not ips_list:
            flash('请输入扫描目标')
            return redirect(url_for('new_zombie_task'))

        ips_list = thirdparty.target2list(ips_list)
        user_dict = thirdparty.dict2list(user_dict)
        pass_dict = thirdparty.dict2list(pass_dict)

        create_zombie_project(project_name, ips_list, project_description, service_name, user_dict, pass_dict, account=session['account'], batch=0)
        flash('成功创建项目')
        return redirect(url_for('zombie_project_view'))


@app.route('/BatchZombieTask', methods=['GET', 'POST'])
@auth.login_required
@login_check
def batch_zombie_task():
    if request.method == 'GET':
        return render_template('new-zombie-batch-task.html')

    if request.method == 'POST':
        project_name = request.form.get('project_name')
        project_description = request.form.get('project_description')
        service_name = request.form.get('service_name')
        user_dict = request.form.get('user_dict')
        pass_dict = request.form.get('pass_dict')
        if not project_name:
            flash('请输入项目名称')
            return redirect(url_for('batch_zombie_task'))

        if not service_name:
            flash('请选择爆破的服务名称')
            return redirect(url_for('batch_zombie_task'))

        if 'file' not in request.files:
            flash('请上传 IP 目标文件（仅支持 txt 文件）')
            return redirect(url_for('batch_zombie_task'))

        file = request.files['file']
        if file.filename == '':
            flash('请上传 IP 目标文件（仅支持 txt 文件）')
            return redirect(url_for('batch_zombie_task'))

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            new_filename = f'{thirdparty.TMP_PATH}/{thirdparty.random_choices()}_{filename}'
            file.save(new_filename)

            user_dict = thirdparty.dict2list(user_dict)
            pass_dict = thirdparty.dict2list(pass_dict)

            create_zombie_project(project_name, new_filename, project_description, service_name, user_dict, pass_dict, account=session['account'], batch=1)
            flash('成功创建项目')
            return redirect(url_for('zombie_project_view'))

        else:
            flash('请上传 IP 目标文件（仅支持 txt 文件）')
            return redirect(url_for('batch_zombie_task'))


@app.route('/ZombieRet/<project_id>', methods=['GET'])
@auth.login_required
@login_check
def zombie_ret(project_id):
    """
    查看 zombie 扫描结果
    """
    if request.method == 'GET':
        return render_template('zombie-ret.html', project_id=project_id, session=session)


@app.route('/Ajax/ZombieRet/<project_id>', methods=['GET'])
@auth.login_required
@login_check
def get_zombie_ret(project_id):
    """
    弱口令服务扫描结果 Ajax 接口
    """
    draw = int(request.args.get('draw', 0))
    start = int(request.args.get('start', 0))
    length = int(request.args.get('length', 10))
    return get_zombie_data(draw, start, length, project_id)


@app.route('/ChkAPIProjectView/<int:page_index>', methods=['GET'])
@app.route('/ChkAPIProjectView', methods=['GET'])
@auth.login_required
@login_check
def chkapi_project_view(page_size=10, page_index=1):
    """
    API 安全检测项目视图
    """
    if request.method == 'GET':
        entries = get_chkapi_project_data(page_size, page_index)
        return render_template('chkapi-project-view.html', page_size=page_size, page=page_index, entries=entries)


@app.route('/NewChkAPITask', methods=['GET', 'POST'])
@auth.login_required
@login_check
def new_chkapi_task():
    """
    添加 API 安全检测任务
    """
    if request.method == 'GET':
        return render_template('new-chkapi-task.html')

    if request.method == 'POST':
        project_name = request.form.get('project_name')
        project_description = request.form.get('project_description')
        cookies = request.form.get('cookies')
        chrome = request.form.get('chrome')
        attack_type = request.form.get('attack_type')
        no_api_scan = request.form.get('no_api_scan')
        sites = request.form.get('sites')
        if not project_name:
            flash('请输入项目名称')
            return redirect(url_for('new_chkapi_task'))

        if not sites:
            flash('请输入扫描目标')
            return redirect(url_for('new_chkapi_task'))

        if not cookies:
            cookies = ''

        if not chrome:
            flash('请选择是否开启 chromedriver 扫描')
            return redirect(url_for('new_chkapi_task'))

        if not attack_type:
            flash('请选择是否 ATTACK TYPE 选项扫描')

        if not no_api_scan:
            flash('请选择是否扫描 API 接口漏洞')

        url_list = thirdparty.target2list(sites)

        create_chkapi_project(project_name, url_list, project_description, cookies=cookies, chrome=chrome, attack_type=attack_type, no_api_scan=no_api_scan, account=session['account'], batch=0)
        flash('成功创建项目')
        return redirect(url_for('chkapi_project_view'))


@app.route('/BatchChkAPITask', methods=['GET', 'POST'])
@auth.login_required
@login_check
def batch_chkapi_task():
    if request.method == 'GET':
        return render_template('new-chkapi-batch-task.html')

    if request.method == 'POST':
        project_name = request.form.get('project_name')
        project_description = request.form.get('project_description')
        cookies = request.form.get('cookies')
        chrome = request.form.get('chrome')
        attack_type = request.form.get('attack_type')
        no_api_scan = request.form.get('no_api_scan')
        if not project_name:
            flash('请输入项目名称')
            return redirect(url_for('batch_chkapi_task'))

        if not cookies:
            cookies = ''

        if not chrome:
            flash('请选择是否开启 chromedriver 扫描')
            return redirect(url_for('batch_chkapi_task'))

        if not attack_type:
            flash('请选择是否 ATTACK TYPE 选项扫描')

        if not no_api_scan:
            flash('请选择是否扫描 API 接口漏洞')

        if 'file' not in request.files:
            flash('请上传目标文件（仅支持 txt 文件）')
            return redirect(url_for('batch_chkapi_task'))

        file = request.files['file']
        if file.filename == '':
            flash('请上传目标文件（仅支持 txt 文件）')
            return redirect(url_for('batch_chkapi_task'))

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            new_filename = f'{thirdparty.TMP_PATH}/{thirdparty.random_choices()}_{filename}'
            file.save(new_filename)

            create_chkapi_project(project_name, new_filename, project_description, cookies=cookies, chrome=chrome, attack_type=attack_type, no_api_scan=no_api_scan, account=session['account'], batch=1)
            flash('成功创建项目')
            return redirect(url_for('chkapi_project_view'))

        else:
            flash('请上传IP目标文件（仅支持 txt 文件）')
            return redirect(url_for('batch_chkapi_task'))


@app.route('/ChkAPIRet/<project_id>', methods=['GET'])
@auth.login_required
@login_check
def chkapi_ret(project_id):
    """
    查看 ChkAPI 扫描结果
    """
    if request.method == 'GET':
        return render_template('chkapi-hae-ret.html', project_id=project_id, session=session)


@app.route('/Ajax/ChkAPIRet/<project_id>', methods=['GET'])
@auth.login_required
@login_check
def get_chkapi_ret(project_id):
    """
    ChkAPI 敏感信息扫描结果 Ajax 接口
    """
    draw = int(request.args.get('draw', 0))
    start = int(request.args.get('start', 0))
    length = int(request.args.get('length', 10))
    return get_chkapi_data(draw, start, length, project_id)


@app.route('/CheckQueue/<project_id>', methods=['GET'])
@auth.login_required
@login_check
def query_queue(project_id):
    """
    查询 nuclei 指定队列数量
    """
    if request.method == 'GET':
        count = get_nuclei_queue(project_id)
        flash(f'{project_id} 队列待扫描目标：{count}')
        return render_template('nuclei-ret.html', project_id=project_id)


@app.route('/CheckZombieQueue/<project_id>', methods=['GET'])
@auth.login_required
@login_check
def query_zombie_queue(project_id):
    """
    查询 zombie 指定队列数量
    """
    if request.method == 'GET':
        count = get_zombie_queue(project_id)
        flash(f'{project_id} 队列待扫描目标：{count}')
        return render_template('zombie-ret.html', project_id=project_id)


@app.route('/CheckChkAPIQueue/<project_id>', methods=['GET'])
@auth.login_required
@login_check
def query_chkapi_queue(project_id):
    """
    查询 zombie 指定队列数量
    """
    if request.method == 'GET':
        count = get_chkapi_queue(project_id)
        flash(f'{project_id} 队列待扫描目标：{count}')
        return render_template('chkapi-hae-ret.html', project_id=project_id)


@app.route('/Download/VulRet/<project_id>', methods=['GET'])
@auth.login_required
@login_check
def download_vul_file(project_id):
    """
    下载 Nuclei 扫描结果
    """
    file_path = download_nuclei_data(project_id)
    if file_path:
        @after_this_request
        def _delete_file(response):
            try:
                os.unlink(file_path)
                # 下载完成后删除临时文件
                if os.path.exists(file_path):
                    os.unlink(file_path)
            except Exception as e:
                logger.warning(e)

            return response

        return send_file(file_path, as_attachment=True)
    else:
        flash('导出 Nuclei 扫描结果失败')
        return render_template('nuclei-ret.html', project_id=project_id)


@app.route('/Download/ZombieRet/<project_id>', methods=['GET'])
@auth.login_required
@login_check
def download_zombie_file(project_id):
    """
    下载 zombie 扫描结果
    """
    file_path = download_zombie_data(project_id)
    if file_path:
        @after_this_request
        def _delete_file(response):
            try:
                os.unlink(file_path)
                # 下载完成后删除临时文件
                if os.path.exists(file_path):
                    os.unlink(file_path)
            except Exception as e:
                logger.warning(e)

            return response

        return send_file(file_path, as_attachment=True)
    else:
        flash('导出 zombie 扫描结果失败')
        return render_template('zombie-ret.html', project_id=project_id)


@app.route('/Download/ChkAPIRet/<project_id>', methods=['GET'])
@auth.login_required
@login_check
def download_chkapi_hae_file(project_id):
    """
    下载 ChkAPI 敏感信息检测结果
    """
    file_path = download_chkapi_hae_data(project_id)
    if file_path:
        @after_this_request
        def _delete_file(response):
            try:
                os.unlink(file_path)
                if os.path.exists(file_path):
                    os.unlink(file_path)
            except Exception as e:
                logger.warning(e)

            return response

        return send_file(file_path, as_attachment=True)
    else:
        flash('导出 ChkAPI 扫描结果失败')
        return render_template('chkapi-hae-ret.html', project_id=project_id)


@app.route('/Download/Domain/<task_id>', methods=['GET'])
@auth.login_required
@login_check
def download_domain_file(task_id):
    """
    下载域名信息
    """
    file_path = download_domain_data(task_id)
    if file_path:
        @after_this_request
        def _delete_file(response):
            try:
                os.unlink(file_path)
                if os.path.exists(file_path):
                    os.unlink(file_path)
            except Exception as e:
                logger.warning(e)

            return response

        return send_file(file_path, as_attachment=True)
    else:
        flash(f'导出域名信息失败')
        return redirect(url_for('get_domain'))


@app.route('/Download/Project/Domain/<project_id>', methods=['GET'])
@auth.login_required
@login_check
def download_project_domain_file(project_id):
    """
    下载指定项目下所有任务的域名信息
    """
    file_path = download_domain_data(project_id=project_id)
    if file_path:
        @after_this_request
        def _delete_file(response):
            try:
                os.unlink(file_path)
                if os.path.exists(file_path):
                    os.unlink(file_path)
            except Exception as e:
                logger.warning(e)

            return response

        return send_file(file_path, as_attachment=True)
    else:
        flash(f'导出域名信息失败')
        return redirect(url_for('get_assets_project'))


@app.route('/Download/Site/<task_id>', methods=['GET'])
@auth.login_required
@login_check
def download_site_file(task_id):
    """
    下载站点集合
    """
    file_path = download_site_data(task_id)
    if file_path:
        @after_this_request
        def _delete_file(response):
            try:
                os.unlink(file_path)
                if os.path.exists(file_path):
                    os.unlink(file_path)
            except Exception as e:
                logger.warning(e)

            return response

        return send_file(file_path, as_attachment=True)
    else:
        flash(f'导出站点信息失败')
        return redirect(url_for('get_sites'))


@app.route('/Download/Project/Site/<project_id>', methods=['GET'])
@auth.login_required
@login_check
def download_project_site_file(project_id):
    """
    下载指定项目下所有任务的站点集合
    """
    file_path = download_site_data(project_id=project_id)
    if file_path:
        @after_this_request
        def _delete_file(response):
            try:
                os.unlink(file_path)
                if os.path.exists(file_path):
                    os.unlink(file_path)
            except Exception as e:
                logger.warning(e)

            return response

        return send_file(file_path, as_attachment=True)
    else:
        flash(f'导出站点信息失败')
        return redirect(url_for('get_assets_project'))


@app.route('/Download/FileLeak/<task_id>', methods=['GET'])
@auth.login_required
@login_check
def download_file_leak_assets(task_id):
    """
    下载文件泄露资产
    """
    file_path = download_file_leak_data(task_id)
    if file_path:
        @after_this_request
        def _delete_file(response):
            try:
                os.unlink(file_path)
                if os.path.exists(file_path):
                    os.unlink(file_path)
            except Exception as e:
                logger.warning(e)

            return response

        return send_file(file_path, as_attachment=True)
    else:
        flash(f'导出文件泄露信息失败')
        return redirect(url_for('get_file_leak'))


@app.route('/Download/Project/FileLeak/<project_id>', methods=['GET'])
@auth.login_required
@login_check
def download_project_file_leak_assets(project_id):
    """
    下载指定项目下所有任务的文件泄露资产
    """
    file_path = download_file_leak_data(project_id=project_id)
    if file_path:
        @after_this_request
        def _delete_file(response):
            try:
                os.unlink(file_path)
                if os.path.exists(file_path):
                    os.unlink(file_path)
            except Exception as e:
                logger.warning(e)

            return response

        return send_file(file_path, as_attachment=True)
    else:
        flash(f'导出文件泄露信息失败')
        return redirect(url_for('get_assets_project'))


@app.route('/AssetsProject/LinkNucleiTask/<project_id>', methods=['GET'])
@auth.login_required
@login_check
def assets_sites_link_nuclei(project_id):
    """
    将资产收集后的站点推送至 Nuclei 项目
    """
    file_path = assets_site_link_nuclei(project_id=project_id)
    if file_path:
        project_name = '资产收集自动推送'
        new_filename = file_path
        project_description = f'{project_id}'
        nuclei_template_yaml = 'nuclei-templates/http'
        nuclei_severity = 'critical,high,medium'
        nuclei_template_tags = ''
        nuclei_proxy = ''
        create_nuclei_project(project_name, new_filename, project_description, nuclei_template_yaml, nuclei_template_tags, nuclei_severity, nuclei_proxy, account=session['account'], batch=1)
        flash('成功推送至 Nuclei 扫描')
        thirdparty.delete_file(file_path)
        return redirect(url_for('project_view'))

    else:
        flash(f'没有找到存活站点, 无法推送至 Nuclei 扫描')
        return redirect(url_for('get_assets_project'))


@app.route('/DelProject/<project_id>', methods=['GET'])
@auth.login_required
@login_check
def del_nuclei_project(project_id):
    """
    删除 nuclei 项目
    """
    if request.method == 'GET':
        del_s = delete_nuclei_project(project_id)
        if del_s:
            flash(f'{project_id} Nuclei 项目已删除')
            del_sts = del_nuclei_sites(project_id)
            if del_sts:
                flash(f'{project_id} Nuclei 扫描队列已删除')
            else:
                flash(f'{project_id} Nuclei 扫描队列删除失败')
        else:
            flash(f'{project_id} Nuclei 项目删除失败')

        return redirect(url_for('project_view'))


@app.route('/DelQueue/<project_id>', methods=['GET'])
@auth.login_required
@login_check
def del_nuclei_queue(project_id):
    """
    删除指定 nuclei 项目队列
    """
    if request.method == 'GET':
        del_sts = del_nuclei_sites(project_id)
        if del_sts:
            flash(f'{project_id} Nuclei 扫描队列已删除')
        else:
            flash(f'{project_id} Nuclei 扫描队列删除失败')

        return redirect(url_for('project_view'))


@app.route('/ClearNucleiSites', methods=['GET'])
@auth.login_required
@login_check
def clear_nuclei_sites():
    """
    删除所有 nuclei 待扫描队列
    """
    if request.method == 'GET':
        try:
            count = del_nuclei_all_sites()
            if count == 0:
                flash('已删除 Nuclei 所有待扫描队列')
            else:
                flash(f'{count} 个集合 Nuclei 待扫描队列删除失败')
        except Exception as e:
            flash(f'删除 Nuclei 项目所有待扫描队列异常 {e}')
        return redirect(url_for('project_view'))


@app.route('/DelZombieProject/<project_id>', methods=['GET'])
@auth.login_required
@login_check
def del_zombie_project(project_id):
    """
    删除 zombie 项目
    """
    if request.method == 'GET':
        del_s = delete_zombie_project(project_id)
        if del_s:
            flash(f'{project_id} Zombie 项目已删除')
            del_sts = del_zombie_target(project_id)
            if del_sts:
                flash(f'{project_id} Zombie 扫描队列已删除')
            else:
                flash(f'{project_id} Zombie 扫描队列删除失败')
        else:
            flash(f'{project_id} Zombie 项目删除失败')

        return redirect(url_for('zombie_project_view'))


@app.route('/DelZombieQueue/<project_id>', methods=['GET'])
@auth.login_required
@login_check
def del_zombie_queue(project_id):
    """
    删除指定 zombie 项目队列
    """
    if request.method == 'GET':
        del_sts = del_zombie_target(project_id)
        if del_sts:
            flash(f'{project_id} Zombie 扫描队列已删除')
        else:
            flash(f'{project_id} Zombie 扫描队列删除失败')

        return redirect(url_for('zombie_project_view'))


@app.route('/ClearZombieIPs', methods=['GET'])
@auth.login_required
@login_check
def clear_zombie_ips():
    """
    删除所有 zombie 待扫描队列
    """
    if request.method == 'GET':
        try:
            count = del_zombie_all_targets()
            if count == 0:
                flash('已删除 Zombie 所有待扫描队列')
            else:
                flash(f'{count} 个集合 Zombie 待扫描队列删除失败')
        except Exception as e:
            flash(f'删除 Zombie 项目所有待扫描队列异常 {e}')
        return redirect(url_for('zombie_project_view'))


@app.route('/DelChkAPIProject/<project_id>', methods=['GET'])
@auth.login_required
@login_check
def del_chkapi_project(project_id):
    """
    删除 ChkAPI 项目
    """
    if request.method == 'GET':
        del_s = delete_chkapi_project(project_id)
        if del_s:
            flash(f'{project_id} ChkAPI 项目已删除')
            del_sts = del_zombie_target(project_id)
            if del_sts:
                flash(f'{project_id} ChkAPI 扫描队列已删除')
            else:
                flash(f'{project_id} ChkAPI 扫描队列删除失败')
        else:
            flash(f'{project_id} ChkAPI 项目删除失败')

        return redirect(url_for('chkapi_project_view'))


@app.route('/DelChkAPIQueue/<project_id>', methods=['GET'])
@auth.login_required
@login_check
def del_chkapi_queue(project_id):
    """
    删除指定 ChkAPI 项目队列
    """
    if request.method == 'GET':
        del_sts = del_chkapi_target(project_id)
        if del_sts:
            flash(f'{project_id} ChkAPI 扫描队列已删除')
        else:
            flash(f'{project_id} ChkAPI 扫描队列删除失败')

        return redirect(url_for('chkapi_project_view'))


@app.route('/ClearChkAPISites', methods=['GET'])
@auth.login_required
@login_check
def clear_chkapi_sites():
    """
    删除所有 ChkAPI 待扫描队列
    """
    if request.method == 'GET':
        try:
            count = del_chkapi_all_targets()
            if count == 0:
                flash('已删除 ChkAPI 所有待扫描队列')
            else:
                flash(f'{count} 个集合 ChkAPI 待扫描队列删除失败')
        except Exception as e:
            flash(f'删除 ChkAPI 项目所有待扫描队列异常 {e}')
        return redirect(url_for('chkapi_project_view'))


@app.route('/NewDomainTask', methods=['GET', 'POST'])
@auth.login_required
@login_check
def api_newtask():
    """
    添加资产扫描任务
    """
    if request.method == 'GET':
        return render_template('api-new-task.html')

    if request.method == 'POST':
        project_name = request.form.get('project_name')
        project_description = request.form.get('project_description')
        target = request.form.get('target')
        domain_brute = request.form.get('domain_brute')
        domain_brute_type = request.form.get('domain_brute_type')
        alt_dns = request.form.get('alt_dns')
        dns_query_plugin = request.form.get('dns_query_plugin')
        skip_not_found_domain = request.form.get('skip_not_found_domain')
        port_scan = request.form.get('port_scan')
        skip_scan_cdn_ip = request.form.get('skip_scan_cdn_ip')
        port_scan_type = request.form.get('port_scan_type')
        port_custom = request.form.get('port_custom')
        service_detection = request.form.get('service_detection')
        os_detection = request.form.get('os_detection')
        ssl_cert = request.form.get('ssl_cert')
        site_identify = request.form.get('site_identify')
        site_capture = request.form.get('site_capture')
        file_leak = request.form.get('file_leak')
        only_file_leak = request.form.get('only_file_leak')
        if not project_name:
            flash('请输入项目名称')
            return redirect(url_for('api_newtask'))

        if not target:
            flash('请输入扫描目标')
            return redirect(url_for('api_newtask'))

        params = {
            'project_name': project_name,
            'project_description': project_description,
            'target': target,
            'domain_brute': domain_brute,
            'domain_brute_type': domain_brute_type,
            'alt_dns': alt_dns,
            'dns_query_plugin': dns_query_plugin,
            'skip_not_found_domain': skip_not_found_domain,
            'port_scan': port_scan,
            'skip_scan_cdn_ip': skip_scan_cdn_ip,
            'port_scan_type': port_scan_type,
            'port_custom': port_custom,
            'service_detection': service_detection,
            'os_detection': os_detection,
            'ssl_cert': ssl_cert,
            'site_identify': site_identify,
            'site_capture': site_capture,
            'file_leak': file_leak,
            'only_file_leak': only_file_leak,
            'account': session['account']
        }

        headers = {'token': session['assets_api_token'], 'accept': 'application/json'}
        req = requests.post(session['assets_api_url'] + '/api/task', json=params, headers=headers)
        data = req.json()
        message = data['message']
        if req.status_code == 200 and data['code'] == 300:
            flash(f'{message}')
        elif req.status_code == 200 and data['code'] == 200:
            flash(f'{message}')
        else:
            flash(f'资产收集 API 接口错误 {message}')
        return redirect(url_for('get_assets_project'))


@app.route('/AssetsProject', methods=['GET', 'POST'])
@auth.login_required
@login_check
def get_assets_project():
    """
    域名资产 -> 项目视图
    """
    if request.method == 'GET':
        return render_template('api-project-view.html')


@app.route('/Ajax/AssetsProjectView', methods=['GET'])
@auth.login_required
@login_check
def ajax_assets_project_view():
    """
    项目数据 Ajax 接口
    """
    if request.method == 'GET':
        draw = int(request.args.get('draw', 0))
        start = int(request.args.get('start', 0))
        length = int(request.args.get('length', 20))
        # 搜索框的值
        project_name = request.args.get('project_name')
        project_description = request.args.get('project_description')
        project_id = request.args.get('project_id')
        account = session['account']

        # 如果是管理员权限将 account 查询条件置空, 这样可以查看所有项目
        if '1' in session['purview']:
            account = None

        # 构建外部 API 请求的查询参数
        params = {
            'project_id': project_id,
            'project_name': project_name,
            'project_description': project_description,
            'account': account,
            'page': start // length + 1,  # 计算页码
            'size': length,  # 每页大小
            'order': None  # 排序顺序, 默认为降序
        }

        headers = {'token': session['assets_api_token'], 'accept': 'application/json'}
        req = requests.get(session['assets_api_url'] + '/api/project', params=params, headers=headers)
        data = req.json()
        items = data.get('items', [])
        total = data.get('total', 0)

        result = {
            'draw': draw,
            'recordsTotal': total,
            'recordsFiltered': total,
            'data': [{
                'id': item.get('_id'),
                'project_id': item.get('project_id'),
                'project_name': item.get('project_name'),
                'project_description': item.get('project_description'),
                'account': item.get('account'),
                'create_time': item.get('create_time')
            } for item in items]
        }

        return jsonify(result)


@app.route('/DelAssetsProject/<project_id>', methods=['GET'])
@auth.login_required
@login_check
def delete_assets_project(project_id, option=True):
    """
    删除项目（会删除所有项目下所有任务数据）
    """
    if request.method == 'GET':
        if not project_id:
            flash(f'请输入项目 ID')
            return redirect(url_for('get_assets_project'))

        params = {
            'del_task_data': option,
            'project_id': [project_id]
        }

        headers = {'token': session['assets_api_token'], 'accept': 'application/json'}
        req = requests.post(session['assets_api_url'] + '/api/project/delete', json=params, headers=headers)
        data = req.json()
        message = data['message']
        if req.status_code == 200 and data['code'] == 300:
            flash(f'{project_id} {message}')
        elif req.status_code == 200 and data['code'] == 200:
            flash(f'{project_id} {message}')
        else:
            flash(f'资产收集 API 接口错误 {message}')

        return redirect(url_for('get_assets_project'))


@app.route('/TaskManage', methods=['GET'])
@app.route('/TaskManage/<project_id>', methods=['GET'])
@auth.login_required
@login_check
def get_task(project_id=None):
    """
    资产收集 -> 任务管理
    """
    if request.method == 'GET':
        if '1' not in session['purview'] and not project_id:
            flash('权限不足, 请联系超级管理员操作')
            return redirect(url_for('get_assets_project'))

        return render_template('api-task.html', project_id=project_id)


@app.route('/Ajax/GetTask', methods=['GET'])
@auth.login_required
@login_check
def ajax_get_task():
    """
    获取任务数据 Ajax 接口
    """
    if request.method == 'GET':
        draw = int(request.args.get('draw', 0))
        start = int(request.args.get('start', 0))
        length = int(request.args.get('length', 10))
        project_id = request.args.get('project_id')
        task_id = request.args.get('task_id')
        target = request.args.get('target')
        task_status = request.args.get('task_status')

        if '1' not in session['purview'] and not project_id:
            flash('权限不足, 请联系超级管理员操作')
            return redirect(url_for('get_assets_project'))

        params = {
            'project_id': project_id,
            '_id': task_id,
            'target': target,
            'status': task_status,
            'page': start // length + 1,
            'size': length,
            'order': None
        }

        headers = {'token': session['assets_api_token'], 'accept': 'application/json'}
        req = requests.get(session['assets_api_url'] + '/api/task', params=params, headers=headers)
        data = req.json()
        items = data.get('items', [])
        total = data.get('total', 0)

        result = {
            'draw': draw,
            'recordsTotal': total,
            'recordsFiltered': total,
            'data': [{
                'task_id': item.get('_id'),
                'target': item.get('target'),
                'start_time': item.get('start_time'),
                'task_status': item.get('status'),
                'type': item.get('type'),
                'task_tag': item.get('task_tag'),
                'end_time': item.get('end_time'),
                'service': item.get('service'),
                'celery_id': item.get('celery_id'),
                'project_name': item.get('project_name'),
                'project_id': item.get('project_id'),
                'options': item.get('options'),
                'statistic': item.get('statistic'),
            } for item in items]
        }

        return jsonify(result)


@app.route('/StopTask/<task_id>', methods=['GET'])
@auth.login_required
@login_check
def stop_task(task_id):
    """
    停止指定任务接口
    """
    if request.method == 'GET':
        if '1' not in session['purview'] and not task_id:
            flash('权限不足, 请联系超级管理员操作')
            return redirect(url_for('get_assets_project'))

        params = {
            'task_id': [
                task_id
            ]
        }

        headers = {'token': session['assets_api_token'], 'accept': 'application/json'}
        req = requests.post(session['assets_api_url'] + '/api/task/batch_stop', json=params, headers=headers)
        data = req.json()
        message = data['message']
        if req.status_code == 200 and data['code'] == 300:
            flash(f'{task_id} {message}')
        elif req.status_code == 200 and data['code'] == 200:
            flash(f'{task_id} {message}')
        else:
            flash(f'资产收集 API 接口错误 {message}')
        return redirect(url_for('get_task'))


@app.route('/DelTask/<task_id>', methods=['GET'])
@auth.login_required
@login_check
def del_task(task_id):
    """
    删除指定任务接口
    """
    if request.method == 'GET':
        if '1' not in session['purview'] and not task_id:
            flash('权限不足, 请联系超级管理员操作')
            return redirect(url_for('get_assets_project'))

        params = {
            'del_task_data': True,  # 默认删除指定任务的所有数据
            'task_id': [
                task_id
            ]
        }

        headers = {'token': session['assets_api_token'], 'accept': 'application/json'}
        req = requests.post(session['assets_api_url'] + '/api/task/delete', json=params, headers=headers)
        data = req.json()
        message = data['message']
        if req.status_code == 200 and data['code'] == 300:
            flash(f'{task_id} {message}')
        elif req.status_code == 200 and data['code'] == 200:
            flash(f'{task_id} {message}')
        else:
            flash(f'资产收集 API 接口错误 {message}')
        return redirect(url_for('get_task'))


@app.route('/DelTask/ErrorStatus', methods=['GET'])
@auth.login_required
@login_check
def del_error_task():
    """
    删除所有失败任务接口
    """
    if request.method == 'GET':
        if '1' not in session['purview']:
            flash('权限不足, 请联系超级管理员操作')
            return redirect(url_for('get_assets_project'))

        # 获取所有 error 状态的任务列表
        _task_data = conn_db('task', db_name=Config.API_MONGO_DB).find({'status': 'error'})
        _task_id_list = [str(doc['_id']) for doc in _task_data]
        if not _task_id_list:
            flash(f'没有失败的任务')
            return redirect(url_for('get_assets_project'))

        params = {
            'del_task_data': True,
            'task_id': _task_id_list
        }

        headers = {'token': session['assets_api_token'], 'accept': 'application/json'}
        req = requests.post(session['assets_api_url'] + '/api/task/delete', json=params, headers=headers)
        data = req.json()
        message = data['message']
        if req.status_code == 200 and data['code'] == 300:
            flash(message)
        elif req.status_code == 200 and data['code'] == 200:
            flash(message)
        else:
            flash(f'资产收集 API 接口错误 {message}')
        return redirect(url_for('get_task'))


@app.route('/Sites', methods=['GET'])
@app.route('/Sites/<task_id>', methods=['GET'])
@auth.login_required
@login_check
def get_sites(task_id=None):
    """
    资产收集 -> 站点资产
    """
    if request.method == 'GET':
        if '1' not in session['purview'] and not task_id:
            flash('权限不足, 请联系超级管理员操作')
            return redirect(url_for('get_assets_project'))

        return render_template('api-sites.html', task_id=task_id)


@app.route('/Ajax/GetSites', methods=['GET'])
@auth.login_required
@login_check
def ajax_get_sites():
    """
    站点数据 Ajax 请求
    """
    if request.method == 'GET':
        draw = int(request.args.get('draw', 0))
        start = int(request.args.get('start', 0))
        length = int(request.args.get('length', 10))
        task_id = request.args.get('task_id')
        site = request.args.get('site')
        hostname = request.args.get('hostname')
        ip = request.args.get('ip')
        title = request.args.get('title')
        http_server = request.args.get('http_server')
        headers = request.args.get('headers')
        finger_name = request.args.get('finger_name')
        status_code = request.args.get('status_code')
        favicon_hash = request.args.get('favicon_hash')
        site_tag = request.args.get('site_tag')

        if '1' not in session['purview'] and not task_id:
            flash('权限不足, 请联系超级管理员操作')
            return redirect(url_for('get_assets_project'))

        params = {
            'task_id': task_id,
            'site': site,
            'hostname': hostname,
            'ip': ip,
            'title': title,
            'http_server': http_server,
            'headers': headers,
            'finger.name': finger_name,
            'status': status_code,
            'favicon.hash': favicon_hash,
            'tag': site_tag,
            'page': start // length + 1,
            'size': length,
            'order': None
        }
        # 检测是合法长度的 task_id
        if not task_id or len(task_id) != 24:
            del params['task_id']
        if not site:
            del params['site']
        if not hostname:
            del params['hostname']
        if not ip:
            del params['ip']
        if not title:
            del params['title']
        if not http_server:
            del params['http_server']
        if not headers:
            del params['headers']
        if not finger_name:
            del params['finger.name']
        if not status_code:
            del params['status']
        if not favicon_hash:
            del params['favicon.hash']
        if not site_tag:
            del params['tag']

        headers = {'token': session['assets_api_token'], 'accept': 'application/json'}
        req = requests.get(session['assets_api_url'] + '/api/site', params=params, headers=headers)
        data = req.json()
        items = data.get('items', [])
        total = data.get('total', 0)
        result = {
            'draw': draw,
            'recordsTotal': total,
            'recordsFiltered': total,
            'data': [{
                'task_id': item.get('task_id'),
                'site': item.get('site'),
                'hostname': item.get('hostname'),
                'ip': item.get('ip'),
                'title': item.get('title'),
                'status': item.get('status'),
                'headers': item.get('headers'),
                'http_server': item.get('http_server'),
                'body_length': item.get('body_length'),
                'finger': item.get('finger'),
                'favicon': item.get('favicon'),
                'screenshot': item.get('screenshot'),
                'fld': item.get('fld'),
                'tag': item.get('tag')
            } for item in items]
        }

        return jsonify(result)


@app.route('/Domain', methods=['GET'])
@app.route('/Domain/<task_id>', methods=['GET'])
@auth.login_required
@login_check
def get_domain(task_id=None):
    if request.method == 'GET':
        if '1' not in session['purview'] and not task_id:
            flash('权限不足, 请联系超级管理员操作')
            return redirect(url_for('get_assets_project'))

        return render_template('api-domain.html', task_id=task_id)


@app.route('/Ajax/GetDomains', methods=['GET'])
@auth.login_required
@login_check
def ajax_get_domains():
    """
    域名数据 Ajax 请求
    """
    if request.method == 'GET':
        draw = int(request.args.get('draw', 0))
        start = int(request.args.get('start', 0))
        length = int(request.args.get('length', 10))
        task_id = request.args.get('task_id')
        domain = request.args.get('domain')
        record = request.args.get('record')
        record_type = request.args.get('record_type')
        ips = request.args.get('ips')
        source = request.args.get('source')

        if '1' not in session['purview'] and not task_id:
            flash('权限不足, 请联系超级管理员操作')
            return redirect(url_for('get_assets_project'))

        params = {
            'task_id': task_id,
            'domain': domain,
            'record': record,
            'type': record_type,
            'ips': ips,
            'source': source,
            'page': start // length + 1,
            'size': length,
            'order': None
        }

        if not task_id or len(task_id) != 24:
            del params['task_id']

        if not domain:
            del params['domain']

        if not record:
            del params['record']

        if not record_type:
            del params['type']

        if not ips:
            del params['ips']

        if not source:
            del params['source']

        headers = {'token': session['assets_api_token'], 'accept': 'application/json'}
        req = requests.get(session['assets_api_url'] + '/api/domain', params=params, headers=headers)
        data = req.json()
        items = data.get('items', [])
        total = data.get('total', 0)
        result = {
            'draw': draw,
            'recordsTotal': total,
            'recordsFiltered': total,
            'data': [{
                'task_id': item.get('task_id'),
                'domain': item.get('domain'),
                'record': item.get('record'),
                'type': item.get('type'),
                'ips': item.get('ips'),
                'source': item.get('source'),
                'fld': item.get('fld')
            } for item in items]
        }

        return jsonify(result)


@app.route('/IPs', methods=['GET'])
@app.route('/IPs/<task_id>', methods=['GET'])
@auth.login_required
@login_check
def get_ips(task_id=None):
    if request.method == 'GET':
        if '1' not in session['purview'] and not task_id:
            flash('权限不足, 请联系超级管理员操作')
            return redirect(url_for('get_assets_project'))

        return render_template('api-ips.html', task_id=task_id)


@app.route('/Ajax/GetIPs', methods=['GET'])
@auth.login_required
@login_check
def ajax_get_ips():
    """
    IP 信息 Ajax 请求
    """
    if request.method == 'GET':
        draw = int(request.args.get('draw', 0))
        start = int(request.args.get('start', 0))
        length = int(request.args.get('length', 10))
        task_id = request.args.get('task_id')
        ip = request.args.get('ip')
        domain = request.args.get('domain')
        port = request.args.get('port')
        service_name = request.args.get('service_name')
        service_version = request.args.get('service_version')
        service_product = request.args.get('service_product')
        os_name = request.args.get('os_name')
        ip_type = request.args.get('ip_type')
        cdn_name = request.args.get('cdn_name')
        asn_number = request.args.get('asn_number')
        asn_organization = request.args.get('asn_organization')

        if '1' not in session['purview'] and not task_id:
            flash('权限不足, 请联系超级管理员操作')
            return redirect(url_for('get_assets_project'))

        params = {
            'task_id': task_id,
            'ip': ip,
            'domain': domain,
            'port_info.port_id': port,
            'port_info.service_name': service_name,
            'port_info.version': service_version,
            'port_info.product': service_product,
            'os_info.name': os_name,
            'ip_type': ip_type,
            'cdn_name': cdn_name,
            'geo_asn.number': asn_number,
            'geo_asn.organization': asn_organization,
            'page': start // length + 1,
            'size': length,
            'order': None
        }

        if not task_id or len(task_id) != 24:
            del params['task_id']

        if not ip:
            del params['ip']

        if not domain:
            del params['domain']

        if not port:
            del params['port_info.port_id']

        if not service_name:
            del params['port_info.service_name']

        if not service_version:
            del params['port_info.version']

        if not service_product:
            del params['port_info.product']

        if not os_name:
            del params['os_info.name']

        if not ip_type:
            del params['ip_type']

        if not cdn_name:
            del params['cdn_name']

        if not asn_number:
            del params['geo_asn.number']

        if not asn_organization:
            del params['geo_asn.organization']

        headers = {'token': session['assets_api_token'], 'accept': 'application/json'}
        req = requests.get(session['assets_api_url'] + '/api/ip', params=params, headers=headers)
        data = req.json()
        items = data.get('items', [])
        total = data.get('total', 0)

        result = {
            'draw': draw,
            'recordsTotal': total,
            'recordsFiltered': total,
            'data': [{
                'task_id': item.get('task_id'),
                'ip': item.get('ip'),
                'domain': item.get('domain'),
                'port_info': item.get('port_info'),
                'os_info': item.get('os_info'),
                'ip_type': item.get('ip_type'),
                'cdn_name': item.get('cdn_name'),
                'geo_asn': item.get('geo_asn'),
                'geo_city': item.get('geo_city')
            } for item in items]
        }

        return jsonify(result)


@app.route('/Service', methods=['GET'])
@app.route('/Service/<task_id>', methods=['GET'])
@auth.login_required
@login_check
def get_service(task_id=None):
    if request.method == 'GET':
        if '1' not in session['purview'] and not task_id:
            flash('权限不足, 请联系超级管理员操作')
            return redirect(url_for('get_assets_project'))

        return render_template('api-service.html', task_id=task_id)


@app.route('/Ajax/GetService', methods=['GET'])
@auth.login_required
@login_check
def ajax_get_service():
    """
    服务信息 Ajax 请求
    """
    if request.method == 'GET':
        draw = int(request.args.get('draw', 0))
        start = int(request.args.get('start', 0))
        length = int(request.args.get('length', 10))
        task_id = request.args.get('task_id')
        ip = request.args.get('ip')
        port = request.args.get('port')
        service_name = request.args.get('service_name')
        service_version = request.args.get('service_version')
        service_product = request.args.get('service_product')

        if '1' not in session['purview'] and not task_id:
            flash('权限不足, 请联系超级管理员操作')
            return redirect(url_for('get_assets_project'))

        params = {
            'task_id': task_id,
            'service_info.ip': ip,
            'service_info.port_id': port,
            'service_name': service_name,
            'service_info.version': service_version,
            'service_info.product': service_product,
            'page': start // length + 1,
            'size': length,
            'order': None
        }

        if not task_id or len(task_id) != 24:
            del params['task_id']

        if not ip:
            del params['service_info.ip']

        if not port:
            del params['service_info.port_id']

        if not service_name:
            del params['service_name']

        if not service_version:
            del params['service_info.version']

        if not service_product:
            del params['service_info.product']

        headers = {'token': session['assets_api_token'], 'accept': 'application/json'}
        req = requests.get(session['assets_api_url'] + '/api/service', params=params, headers=headers)
        data = req.json()
        items = data.get('items', [])
        total = data.get('total', 0)

        result = {
            'draw': draw,
            'recordsTotal': total,
            'recordsFiltered': total,
            'data': [{
                'task_id': item.get('task_id'),
                'service_name': item.get('service_name'),
                'service_info': item.get('service_info')
            } for item in items]
        }

        return jsonify(result)


@app.route('/Cert', methods=['GET'])
@app.route('/Cert/<task_id>', methods=['GET'])
@auth.login_required
@login_check
def get_cert(task_id=None):
    if request.method == 'GET':
        if '1' not in session['purview'] and not task_id:
            flash('权限不足, 请联系超级管理员操作')
            return redirect(url_for('get_assets_project'))

        return render_template('api-cert.html', task_id=task_id)


@app.route('/Ajax/GetCert', methods=['GET'])
@auth.login_required
@login_check
def ajax_get_cert():
    """
    SSL 证书 Ajax 请求
    """
    if request.method == 'GET':
        draw = int(request.args.get('draw', 0))
        start = int(request.args.get('start', 0))
        length = int(request.args.get('length', 10))
        task_id = request.args.get('task_id')
        ip = request.args.get('ip')
        port = request.args.get('port')
        subject_dn = request.args.get('subject_dn')
        issuer_dn = request.args.get('issuer_dn')
        serial_number = request.args.get('serial_number')
        start_time = request.args.get('start_time')
        end_time = request.args.get('end_time')
        fingerprint_sha256 = request.args.get('fingerprint_sha256')
        fingerprint_sha1 = request.args.get('fingerprint_sha1')
        fingerprint_md5 = request.args.get('fingerprint_md5')
        alt_name = request.args.get('alt_name')

        if '1' not in session['purview'] and not task_id:
            flash('权限不足, 请联系超级管理员操作')
            return redirect(url_for('get_assets_project'))

        params = {
            'task_id': task_id,
            'ip': ip,
            'port': port,
            'cert.subject_dn': subject_dn,
            'cert.issuer_dn': issuer_dn,
            'cert.serial_number': serial_number,
            'cert.validity.start': start_time,
            'cert.validity.end': end_time,
            'cert.fingerprint.sha256': fingerprint_sha256,
            'cert.fingerprint.sha1': fingerprint_sha1,
            'cert.fingerprint.md5': fingerprint_md5,
            'cert.extensions.subjectAltName': alt_name,
            'page': start // length + 1,
            'size': length,
            'order': None
        }

        if not task_id or len(task_id) != 24:
            del params['task_id']

        if not ip:
            del params['ip']

        if not port:
            del params['port']

        if not subject_dn:
            del params['cert.subject_dn']

        if not serial_number:
            del params['cert.serial_number']

        if not start_time:
            del params['cert.validity.start']

        if not end_time:
            del params['cert.validity.end']

        if not fingerprint_sha256:
            del params['cert.fingerprint.sha256']

        if not fingerprint_sha1:
            del params['cert.fingerprint.sha1']

        if not fingerprint_md5:
            del params['cert.fingerprint.md5']

        if not alt_name:
            del params['cert.extensions.subjectAltName']

        headers = {'token': session['assets_api_token'], 'accept': 'application/json'}
        req = requests.get(session['assets_api_url'] + '/api/cert', params=params, headers=headers)
        data = req.json()
        items = data.get('items', [])
        total = data.get('total', 0)

        result = {
            'draw': draw,
            'recordsTotal': total,
            'recordsFiltered': total,
            'data': [{
                'task_id': item.get('task_id'),
                'ip': item.get('ip'),
                'port': item.get('port'),
                'cert': item.get('cert')
            } for item in items]
        }

        return jsonify(result)


@app.route('/FileLeak', methods=['GET'])
@app.route('/FileLeak/<task_id>', methods=['GET'])
@auth.login_required
@login_check
def get_file_leak(task_id=None):
    if request.method == 'GET':
        if '1' not in session['purview'] and not task_id:
            flash('权限不足, 请联系超级管理员操作')
            return redirect(url_for('get_assets_project'))

        return render_template('api-file-leak.html', task_id=task_id)


@app.route('/Ajax/GetFileLeak', methods=['GET'])
@auth.login_required
@login_check
def ajax_get_file_leak():
    """
    目录文件泄露 Ajax 请求
    """
    if request.method == 'GET':
        draw = int(request.args.get('draw', 0))
        start = int(request.args.get('start', 0))
        length = int(request.args.get('length', 10))
        task_id = request.args.get('task_id')
        url = request.args.get('url')
        site = request.args.get('site')
        content_length = request.args.get('content_length')
        status_code = request.args.get('status_code')
        title = request.args.get('title')

        if '1' not in session['purview'] and not task_id:
            flash('权限不足, 请联系超级管理员操作')
            return redirect(url_for('get_assets_project'))

        params = {
            'task_id': task_id,
            'url': url,
            'site': site,
            'content_length': content_length,
            'status_code': status_code,
            'title': title,
            'page': start // length + 1,
            'size': length,
            'order': None
        }

        if not task_id or len(task_id) != 24:
            del params['task_id']

        if not url:
            del params['url']

        if not site:
            del params['site']

        if not content_length:
            del params['content_length']

        if not status_code:
            del params['status_code']

        if not title:
            del params['title']

        headers = {'token': session['assets_api_token'], 'accept': 'application/json'}
        req = requests.get(session['assets_api_url'] + '/api/file_leak', params=params, headers=headers)
        data = req.json()
        items = data.get('items', [])
        total = data.get('total', 0)

        result = {
            'draw': draw,
            'recordsTotal': total,
            'recordsFiltered': total,
            'data': [{
                'task_id': item.get('task_id'),
                'title': item.get('title'),
                'url': item.get('url'),
                'status_code': item.get('status_code'),
                'site': item.get('site'),
                'content_length': item.get('content_length')
            } for item in items]
        }

        return jsonify(result)


@app.route('/CIDR', methods=['GET'])
@app.route('/CIDR/<task_id>', methods=['GET'])
@auth.login_required
@login_check
def get_cidr(task_id=None):
    if request.method == 'GET':
        if '1' not in session['purview'] and not task_id:
            flash('权限不足, 请联系超级管理员操作')
            return redirect(url_for('get_assets_project'))

        return render_template('api-cidr.html', task_id=task_id)


@app.route('/Ajax/GetCIDR', methods=['GET'])
@auth.login_required
@login_check
def ajax_get_cidr():
    """
    C 段统计数据 Ajax 请求
    """
    if request.method == 'GET':
        draw = int(request.args.get('draw', 0))
        start = int(request.args.get('start', 0))
        length = int(request.args.get('length', 10))
        task_id = request.args.get('task_id')
        cidr_ip = request.args.get('cidr_ip')
        ip_count = request.args.get('ip_count')
        domain_count = request.args.get('domain_count')

        if '1' not in session['purview'] and not task_id:
            flash('权限不足, 请联系超级管理员操作')
            return redirect(url_for('get_assets_project'))

        params = {
            'task_id': task_id,
            'cidr_ip': cidr_ip,
            'ip_count': ip_count,
            'domain_count': domain_count,
            'page': start // length + 1,
            'size': length,
            'order': 'ip_count'
        }

        if not task_id or len(task_id) != 24:
            del params['task_id']

        if not cidr_ip:
            del params['cidr_ip']

        if not ip_count:
            del params['ip_count']

        if not domain_count:
            del params['domain_count']

        headers = {'token': session['assets_api_token'], 'accept': 'application/json'}
        req = requests.get(session['assets_api_url'] + '/api/cip', params=params, headers=headers)
        data = req.json()
        items = data.get('items', [])
        total = data.get('total', 0)

        result = {
            'draw': draw,
            'recordsTotal': total,
            'recordsFiltered': total,
            'data': [{
                'task_id': item.get('task_id'),
                'cidr_ip': item.get('cidr_ip'),
                'ip_count': item.get('ip_count'),
                'ip_list': item.get('ip_list'),
                'domain_count': item.get('domain_count'),
                'domain_list': item.get('domain_list')
            } for item in items]
        }

        return jsonify(result)


@app.route('/CheckNodes', methods=['GET'])
@auth.login_required
@login_check
def check_nodes():
    """
    查看 Agent 节点状态
    """
    if request.method == 'GET':
        return render_template('nodes-status.html')


@app.route('/ClearNodes', methods=['GET'])
@auth.login_required
@login_check
def clear_nodes():
    """
    清空节点缓存
    """
    if request.method == 'GET':
        try:
            nodes_data = del_nodes()
            if nodes_data:
                flash('成功删除所有 Agent 节点缓存, 请耐心等待回连')
            else:
                flash(f'删除 Agent 节点缓存失败')
        except Exception as e:
            flash(f'删除 Agent 节点缓存异常 {e}')
        return redirect(url_for('project_view'))


@app.route('/Ajax/CheckNodes', methods=['GET'])
@auth.login_required
@login_check
def check_nodes_status():
    """
    检查节点状态接口
    """
    draw = int(request.args.get('draw', 0))
    start = int(request.args.get('start', 0))
    length = int(request.args.get('length', 20))
    return get_nodes_data(draw, start, length)


@app.route('/Users', methods=['GET'])
@auth.login_required
@login_check
def users_view():
    """
    用户管理视图
    """
    if '1' not in session['purview']:
        flash('权限不足, 请联系超级管理员操作')
        return redirect(url_for('project_view'))

    if request.method == 'GET':
        return render_template('member.html')


@app.route('/Ajax/GetUsers', methods=['GET'])
@auth.login_required
@login_check
def get_users_data():
    """
    Ajax 请求获取用户数据
    """
    if '1' not in session['purview']:
        flash('权限不足, 请联系超级管理员操作')
        return redirect(url_for('project_view'))

    if request.method == 'GET':
        draw = int(request.args.get('draw', 0))
        start = int(request.args.get('start', 0))
        length = int(request.args.get('length', 10))
        return query_account_data(draw, start, length)


@app.route('/DelUser/<user_id>', methods=['GET'])
@auth.login_required
@login_check
def del_user_data(user_id):
    """
    删除指定用户
    """
    if '1' not in session['purview']:
        flash('权限不足, 请联系超级管理员操作')
        return redirect(url_for('project_view'))

    if request.method == 'GET':
        username = del_user(user_id)
        if username:
            flash(f'{username} 用户删除成功')
            return redirect(url_for('users_view'))
        else:
            flash(f'初始化管理员用户禁止删除')
            return redirect(url_for('users_view'))


@app.route('/Register', methods=['GET', 'POST'])
@auth.login_required
@login_check
def register():
    """
    注册用户
    """
    if '1' not in session['purview']:
        flash('权限不足, 请联系超级管理员操作')
        return redirect(url_for('project_view'))

    if request.method == 'GET':
        return render_template('register.html')

    if request.method == 'POST':
        username = request.form.get('username')
        user_email = request.form.get('email')
        password = request.form.get('password')
        rpassword = request.form.get('rpassword')
        purview = ['2']  # 默认注册权限为普通用户

        if not check_email(user_email):
            flash('邮箱地址不正确')
            return render_template('login.html')

        if not check_special_char(username):
            flash('用户名不能包含特殊字符, 长度范围应遵循5到15')
            return render_template('login.html')

        if not check_password_content(password):
            flash('检查密码是否为数字和大小写字母的组合, 长度范围应遵循8-15')
            return render_template('login.html')

        # 判断是否已经存在该用户或邮箱.
        user = query_account(username)
        if user:
            flash('注册的邮箱或用户名已存在')
            return render_template('login.html')
        else:
            if password == rpassword:
                password = en_password(password)
                try:
                    add_user(username, password, purview, user_email)
                    flash('成功注册用户')
                    return redirect(url_for('users_view'))

                except Exception as e:
                    flash(f'用户注册异常 {e}')
                    return render_template('login.html')
            else:
                flash('两次密码输入不一致')
                return render_template('login.html')


@app.errorhandler(500)
@app.errorhandler(404)
@auth.login_required
def page_error(error):
    return render_template('error.html', error=error)
