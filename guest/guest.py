from flask import Flask, request
import os
import sys
from os import path
import json
from multiprocessing import Process
import time
import subprocess as sub
import ctypes


BASE_PATH = 'C:'
PROCMON_PATH = BASE_PATH + '\\Procmon64.exe'
SAMPLES_PATH = BASE_PATH + '\\Samples'
LOGS_PATH = BASE_PATH + '\\Logs'

if not path.exists(SAMPLES_PATH):
    os.mkdir(SAMPLES_PATH)
if not path.exists(LOGS_PATH):
    os.mkdir(LOGS_PATH)

FATAL_ERROR = None

if not path.exists(PROCMON_PATH):
    FATAL_ERROR = f'Procmon executable not found in {PROCMON_PATH}'
elif ctypes.windll.shell32.IsUserAnAdmin() == 0:
    FATAL_ERROR = f'{sys.argv[0]} must be run as admin'
elif not path.isdir(SAMPLES_PATH):
    FATAL_ERROR = f'{SAMPLES_PATH} is not a folder'
elif not path.isdir(LOGS_PATH):
    FATAL_ERROR = f'{LOGS_PATH} is not a folder'

app = Flask(__name__)


def json_reply_ok(reply = {}):
    reply['status'] = 'ok'
    return json.dumps(reply)


def json_reply_error(err, reply = {}):
    reply['status'] = 'error'
    reply['error'] = err
    return json.dumps(reply)


def trace(sample_path, log_path, timeout):
    # NOTE: Weird code below works around the fact that Procmon
    # is a stupid, buggy, inconsistent piece of crap utility maintained
    # by the world's largest, richest software company.
    lockfile = log_path + '.lock'
    with open(lockfile, 'wt') as f:
        f.write('LOCKED')

    sub.Popen([PROCMON_PATH, '/AcceptEula', '/Terminate'])
    time.sleep(1)
    sub.Popen([PROCMON_PATH, '/AcceptEula', '/Minimized', '/Quiet', '/BackingFile', log_path])
    sample_proc = sub.Popen([sample_path])
    pid = sample_proc.pid
    time.sleep(timeout)
    sample_proc.kill()
    time.sleep(1)
    sub.Popen([PROCMON_PATH, '/AcceptEula', '/Terminate'])
    time.sleep(1)

    with open(log_path + '.pid', 'wt') as f:
        f.write(str(pid))
    os.remove(lockfile)


@app.route('/status')
def status():
    if FATAL_ERROR is None:
        return json_reply_ok()
    return json_reply_error(FATAL_ERROR)


@app.route('/submit', methods=['POST'])
def submit():
    if FATAL_ERROR is not None:
        return json_reply_error(FATAL_ERROR)

    req = request.get_json()
    sha256 = req['sha256']
    timeout = req['timeout']
    sample_path = path.join(SAMPLES_PATH, sha256)
    if not path.exists(sample_path):
        sample = bytes(req['sample'])
        with open(sample_path, 'wb') as f:
            f.write(sample)

    log_path = path.join(LOGS_PATH, sha256)
    log_gen = Process(target=trace, args=(sample_path, log_path, timeout))
    log_gen.run()

    return json_reply_ok()


@app.route('/get_log')
def get_log():
    if FATAL_ERROR is not None:
        return json_reply_error(FATAL_ERROR)

    req = request.get_json()
    sha256 = req['sha256']
    log_path = path.join(LOGS_PATH, sha256 + '.PML')
    log_lock = path.join(LOGS_PATH, sha256) + '.lock'
    sample_path = path.join(SAMPLES_PATH, sha256)
    pid_file = path.join(LOGS_PATH, sha256 + '.pid')

    if not path.exists(sample_path):
        return json_reply_error('no such sample!')
    elif path.exists(log_lock):
        return json_reply_error('log is not ready yet!')

    with open(log_path, 'rb') as f:
        log_bytes = list(f.read())
    with open(pid_file, 'rt') as f:
        pid = int(f.read())

    return json_reply_ok({'log': log_bytes, 'pid': pid})


if __name__ == '__main__':
    port = os.environ.get('FLASK_PORT', 5000)
    app.run(host='0.0.0.0', port=port)