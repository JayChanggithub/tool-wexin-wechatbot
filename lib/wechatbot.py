#!flask/bin/python
# -*- coding: utf-8 -*-

import logging
from urllib.parse import quote
from textwrap import dedent
from json import dumps, loads
from time import strftime, mktime
from sys import version_info, argv
from re import sub, search, findall
from requests import get, post, delete
from time import time, localtime, strftime
from os import (
    chdir,
    listdir,
    remove,
    getcwd,
    popen,
    makedirs,
    system
)
from os.path import (
    join,
    isdir,
    isfile,
    splitext,
    dirname,
    basename,
    getmtime,
    abspath
)

# wechat moudles
from wxpy import *
from wxpy import get_wechat_logger
from wxpy import WeChatLoggingHandler

# flask gevent server
import werkzeug
from werkzeug.serving import run_with_reloader
from werkzeug.debug import DebuggedApplication
from gevent import pywsgi, monkey
from geventwebsocket.handler import WebSocketHandler

# flask modules
from werkzeug.utils import secure_filename
from werkzeug.datastructures import FileStorage
from flask_restful import Resource, Api, reqparse
from flask import (
    Flask,
    jsonify,
    url_for,
    redirect,
    abort,
    request,
    current_app,
    make_response,
    send_file,
    render_template
)

app = Flask(__name__)
api = Api(app)
cwd = getcwd()
bot = Bot(console_qr=True, cache_path=True, logout_callback=True)
bot.enable_puid(path='wxpy_puid.pkl')

data = {
    'api_key': 'fdbca34300ab4aeb9a238d9fc6c91d2a',
    'warn_group': 'WeChat-Bot',
    'active_group': 'WeChat-Bot'
}

group_members = [
    'c105e423',
    '922ab01c'
]

key_word = [
    'a',
    'b',
    'c'
]

# app.debug = True
# @run_with_reloader
# def run_server():
#    if app.debug:
#        application = DebuggedApplication(app)
#    else:
#        application = app
#    server = pywsgi.WSGIServer(
#       ('0.0.0.0', 1990),
#       application,
#       handler_class=WebSocketHandler
#    )
#    server.serve_forever()

def wechatbot():
    tuling = Tuling(api_key=data['api_key'])
    groups = bot.groups().search(data['active_group'])[0]
    return tuling, groups

puids = { friend: friend.puid  for friend in bot.friends() if friend }
print('friends puids is {0}'.format(puids))
wechat = wechatbot()
tuling = wechat[0]
group = wechat[1]

# logging wechat
group_receiver = ensure_one(bot.groups().search(data['warn_group']))
logger = get_wechat_logger(group_receiver)
logger.error('wechat bot warning...')

@bot.register(chats=group, except_self=False, run_async=True)
def ai_reply(msg):
    tuling_url = 'http://www.tuling123.com/openapi/api'
    api_key = data['api_key']
    payload = {
        'key': api_key,
        'info': msg.text
    }

    if (msg.raw['Text'].lower() not in key_word or
        msg.member.puid not in group_members):
        return
    
    res = post(tuling_url, data=dumps(payload))
    result = res.json()
    r = get('http://10.99.104.219:5566/api/v1/project/readme/get?name=Baidu-BIOS-SetupVerify')
    ret = r.json()['info']
    print(
        'sender user {0}, msg: {1}, http GET status {2}'.format(
            msg.member, msg.text, res.status_code
        )
    )
    result.update({'text': ret})
    return '[SIT Notification]  ' + result['text']

@app.route('/api/v1/wechat-bot/healthy',
           methods=['GET'],
           strict_slashes=False)
def healthy():
    group.send('Wechat bot alived !')
    return make_response(jsonify({'ok': 'alived'}), 200)

@app.route('/api/v1/wechat-bot/release',
           methods=['GET'],
           strict_slashes=False)
def publish():

    args = request.args.to_dict()

    if ('script_name' not in args.keys() or
        'script_version' not in args.keys() or
        'script_commit' not in args.keys()):
        return make_response(jsonify(
            {'error': 'arguments not Found'}
        ), 404)

    script_name = args['script_name']
    script_version = args['script_version']
    commit_msgs = args['script_commit'].replace('.__', '..__').split('.__')
    commit_msg = [
        sub(r'^\d+\.', '', e)
        for e in commit_msgs
        if e.strip()
    ]

    script_commit = commit_msg
    info = dedent("""\
                 Gitlab release
                 ※ Project:《 {0} 》
                 ※ Revision:《 {1} 》
                 ※ Change list:
                   《 {2} 》
                 """).format(
                  script_name,
               script_version,
                script_commit)
    group.send(info)
    return make_response(jsonify({'ok': info}), 200)

@app.errorhandler(404)
def page_not_found(fail):
    return make_response(jsonify(
                {'fail': 'api not found.'}
            ), 404)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=1990, debug=True, threaded=True)
    embed()
