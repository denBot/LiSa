"""
    Flask routes.
"""

import os
import re
import glob
import requests
import validators
import logging.config

from flask import jsonify, request, send_file
from celery import uuid
from celery.backends.database.models import Task
from sqlalchemy import exc
from lisa.web_api import tasks
from lisa.web_api.app import app, celery_app, Session, engine
from lisa.web_api.responses import ErrorAPIResponse
from lisa.config import logging_config, storage_path, dynamic_config

logging.config.dictConfig(logging_config)
log = logging.getLogger()


@app.errorhandler(404)
def page_not_found(e):
    """Page 404."""
    res = ErrorAPIResponse(1000).to_dict()
    return jsonify(res), 404


@app.errorhandler(500)
def internal_server_error(e):
    """Page 500."""
    res = ErrorAPIResponse(1001).to_dict()
    return jsonify(res), 500


def list_tasks(request_args, status=None):
    """General listing tasks function.

    :param request_args: Arguments passed to request.
    :param status: Status filter (e.g. 'SUCCESS').
    """
    limit = 1000

    if 'limit' in request_args:
        try:
            limit = int(request_args['limit'])
        except ValueError:
            res = ErrorAPIResponse(3000).to_dict()
            return jsonify(res), 400

        if limit < 1:
            res = ErrorAPIResponse(3000).to_dict()
            return jsonify(res), 400

    # unitialized db - no tasks
    if not engine.dialect.has_table(engine, 'celery_taskmeta'):
        return jsonify([])

    try:
        session = Session()

        if status:
            tasks = session.query(Task).filter(Task.status == status).order_by(
                Task.date_done.desc()).limit(limit)
        else:
            tasks = session.query(Task).order_by(
                Task.date_done.desc()).limit(limit)

    except (exc.SQLAlchemyError, exc.OperationalError):
        session.rollback()
    finally:
        session.close()

    res = []
    for task in tasks:
        res.append(task.to_dict())

    return jsonify(res)


@app.route('/api/tasks', methods=['GET'])
def list_all_tasks():
    """Lists all tasks."""
    return list_tasks(request.args)


@app.route('/api/tasks/finished', methods=['GET'])
def list_finished_tasks():
    """List tasks with status 'SUCCESS'"""
    return list_tasks(request.args, 'SUCCESS')


@app.route('/api/tasks/failed', methods=['GET'])
def list_failed():
    """Lists tasks with status 'FAILURE'"""
    return list_tasks(request.args, 'FAILURE')


@app.route('/api/tasks/pending', methods=['GET'])
def list_pending_tasks():
    """Lists tasks with status 'PENDING'"""
    limit = 100

    if 'limit' in request.args:
        try:
            limit = int(request.args['limit'])
        except ValueError:
            res = ErrorAPIResponse(3000).to_dict()
            return jsonify(res), 400

        if limit < 1:
            res = ErrorAPIResponse(3000).to_dict()
            return jsonify(res), 400

    i = celery_app.control.inspect()
    pending = i.reserved()

    return jsonify(pending)


@app.route('/api/tasks/view/<id>', methods=['GET'])
def task_view(id):
    """View task status endpoint."""
    task = celery_app.AsyncResult(id)

    res = {
        'status': task.state
    }

    return jsonify(res)


@app.route('/api/tasks/create/pcap', methods=['POST'])
def task_pcap_create():
    """Endpoint for network/pcap analysis task."""
    if 'pcap' not in request.files:
        # no pcap file
        res = ErrorAPIResponse(2010).to_dict()
        return jsonify(res), 400

    pcap_file = request.files['pcap']

    if pcap_file.filename == '':
        # noname file
        res = ErrorAPIResponse(2011).to_dict()
        return jsonify(res), 400

    # get pretty print parameter
    pretty = False
    if 'pretty' in request.form:
        pretty = request.form['pretty']
        if pretty not in ('true', 'false'):
            res = ErrorAPIResponse(2000).to_dict()
            return jsonify(res), 400

    task_id = uuid()

    # prepare directory and save pcap
    os.mkdir(f'{storage_path}/{task_id}')
    pcap_path = f'{storage_path}/{task_id}/{pcap_file.filename}'
    pcap_file.save(pcap_path)

    # run pcap analysis
    args = (pcap_path,)
    kwargs = {'pretty': pretty}
    tasks.pcap_analysis.apply_async(args, kwargs, task_id=task_id)

    res = {
        'task_id': task_id
    }
    return jsonify(res)


def validate_file_url(url):
    """Validates a given file URL
    Checks if:
    - url is invalid
    - response code is invalid
    - response content-disposition has no filename
    :param url: The file URL to be validated
    """
    if not validators.url(url):
        res = ErrorAPIResponse(2025).to_dict()
        return jsonify(res), 400
    
    try:
        r = requests.head(url, allow_redirects=True, timeout=10)

        if r.status_code != 200:
            res = ErrorAPIResponse(2024).to_dict()
            return jsonify(res), 400
        
    except Exception as e:
        print(e)
        res = ErrorAPIResponse(2024).to_dict()
        return jsonify(res), 400


def file_from_url(url):
    """Downloads a file from a given URL
    :param url: The URL to grab the file from.
    """
    try:
        res = requests.get(url, allow_redirects=True, timeout=10)
        filename = get_response_filename(res)

        if not filename:
            fname = os.path.basename(url)
            filename = fname if fname else "unknown_filename"

        file = res.content
        return filename, file
    except Exception as e:
        print(e)
        res = ErrorAPIResponse(2024).to_dict()
        return jsonify(res), 400


def get_response_filename(res):
    content_disposition = res.headers.get('content-disposition', '')
    filename = re.findall('filename=(.+)', content_disposition)
    return filename[0] if len(filename) > 0 else None


@app.route('/api/tasks/create/file', methods=['POST'])
def task_file_create():
    """Endpoint for full analysis task."""

    is_file_request = 'file' in request.files
    is_url_request = 'url' in request.form

    if not is_file_request and not is_url_request:
        # no file or url provided
        res = ErrorAPIResponse(2020).to_dict()
        return jsonify(res), 400

    if is_file_request and is_url_request:
        # both file and url provided
        res = ErrorAPIResponse(2023).to_dict()
        return jsonify(res), 400

    if is_url_request:
        url = request.form['url']
        error_response = validate_file_url(url)

        if error_response:
            return error_response

        filename, file = file_from_url(url)
    else:
        file = request.files['file']
        filename = file.filename

        if file.filename == '':
            # noname file
            res = ErrorAPIResponse(2021).to_dict()
            return jsonify(res), 400

    # get pretty print parameter
    pretty = False
    if 'pretty' in request.form:
        pretty = request.form['pretty']
        if pretty not in ('true', 'false'):
            res = ErrorAPIResponse(2000).to_dict()
            return jsonify(res), 400

    # ger exec time parameter
    exec_time = 20

    if 'exec_time' in request.form:
        try:
            exec_time = int(request.form['exec_time'])
        except ValueError:
            res = ErrorAPIResponse(2022).to_dict()
            return jsonify(res), 400

        if (
            exec_time < dynamic_config['min_exectime']
            or exec_time > dynamic_config['max_exectime']
        ):
            res = ErrorAPIResponse(2022).to_dict()
            return jsonify(res), 400

    task_id = uuid()

    # prepare directory and save file
    os.mkdir(f'{storage_path}/{task_id}')
    file_path = f'{storage_path}/{task_id}/{filename}'

    if is_url_request:
        open(file_path, 'wb').write(file)
    else:
        file.save(file_path)

    # run analysis
    args = (file_path,)
    kwargs = {
        'pretty': pretty,
        'exec_time': exec_time,
    }
    tasks.full_analysis.apply_async(args, kwargs, task_id=task_id)

    res = {
        'task_id': task_id
    }
    return jsonify(res)


@app.route('/api/report/<id>', methods=['GET'])
def get_report(id):
    """Get task report endpoint."""
    task = celery_app.AsyncResult(id)

    if task.state != 'SUCCESS':
        res = ErrorAPIResponse(1000).to_dict()
        return jsonify(res), 404

    return send_file(f'{storage_path}/{id}/report.json')


@app.route('/api/pcap/<id>', methods=['GET'])
def download_pcap(id):
    """Get analysis pcap."""
    pcaps = glob.glob(f'{storage_path}/{id}/*.pcap')

    if len(pcaps) == 0:
        res = ErrorAPIResponse(1003).to_dict()
        return jsonify(res), 404

    return send_file(pcaps[0], as_attachment=True)


@app.route('/api/json/<id>', methods=['GET'])
def download_json(id):
    """Download json report (serve file)."""
    json_file = f'{storage_path}/{id}/report.json'

    if not os.path.isfile(json_file):
        res = ErrorAPIResponse(1004).to_dict()
        return jsonify(res), 404

    return send_file(json_file, as_attachment=True)


@app.route('/api/machinelog/<id>', methods=['GET'])
def download_machine_log(id):
    """Download machine log."""
    log_file = f'{storage_path}/{id}/machine.log'

    if not os.path.isfile(log_file):
        res = ErrorAPIResponse(1005).to_dict()
        return jsonify(res), 404

    return send_file(log_file, as_attachment=True)


@app.route('/api/output/<id>', methods=['GET'])
def download_console_output(id):
    """Download binary's console output."""
    log_file = f'{storage_path}/{id}/prog.log'

    if not os.path.isfile(log_file):
        res = ErrorAPIResponse(1006).to_dict()
        return jsonify(res), 404

    return send_file(log_file, as_attachment=True)
