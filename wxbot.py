#!flask/bin/python
# -*- coding: utf-8 -*-
import logging
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

import xml.etree.cElementTree as ET
import sys
sys.path.append('./lib')
from WXBizMsgCrypt import (
    WXBizMsgCrypt,
    ResponseMessage,
    generateNonce
)

from gevent import monkey
from gevent.pywsgi import WSGIServer

monkey.patch_all()
app = Flask(__name__)
api = Api(app)
cwd = getcwd()

wx_data = {
    'agentid': 'xxxxxx',
    'corpsecret': 'xxxxxx',
    'corpid': 'xxxxxx',
    'bot_key': 'xxxxxx',
    'Token': '5gq5U7GBSOSIxxxx',
    'EncodingAESKey': 'AiT1IIIrORt41FyHIGKnUoXPzFHAp8DmlpbAjDzdr4Mxxx',
    'headers': {
        'Content-Type': 'application/json'
    }
}

wxcpt = WXBizMsgCrypt(
    wx_data['Token'],
    wx_data['EncodingAESKey'],
    wx_data['corpid']
)

template = {
    'script-mgt': dedent(
        """
        `GitLab release` **【 {0} 】** `Ver`. **{1}**
        > <font color="comment">Time:</font> **{3}**
        > <font color=\"info\">※ Project:</font> 【 {0} 】
        > <font color=\"info\">※</font> `Revision:` {1}
        > <font color=\"info\">※ Change list:</font>
        {2}
        """
    ),
    'alert-mgt': dedent(
        """
        `Alert name` **【 {0} 】**
        > <font color="comment">Host:</font> **{1}**
        > <font color=\"info\">※ Container:</font> 【 {2} 】
        > <font color=\"info\">※ Description:</font>
        {3}
        """
    ),
    'ares-report': 'comming soon!'
}

url_data = {
    'get_token_url': 'https://qyapi.weixin.qq.com/cgi-bin/gettoken',
    'get_application_url': 'https://qyapi.weixin.qq.com/cgi-bin/agent/get',
    'send_msg': 'https://qyapi.weixin.qq.com/cgi-bin/message/send',
    'devops_tool': 'http://ares-script-mgmt.cloudnative.ies.inventec/' + \
                   'api/v1/gitlab/groups?group={0}'
}

devops_users = [
    'IEC070781',
    'IEC070168',
    'IEC080332',
    'IEC050137',
    'IES182737'
]

type_fields = {
    'text': [
        'ToUserName',
        'FromUserName',
        'CreateTime',
        'MsgType',
        'Content',
        'MsgId',
        'AgentID'
    ],

    'image': [
        'ToUserName',
        'FromUserName',
        'CreateTime',
        'MsgType',
        'PicUrl',
        'MediaId',
        'MsgId',
        'AgentID'
    ],

    'voice': [
        'ToUserName',
        'FromUserName',
        'CreateTime',
        'MsgType',
        'Format',
        'MediaId',
        'MsgId',
        'AgentID'
    ],

    'video': [
        'ToUserName',
        'FromUserName',
        'CreateTime',
        'MsgType',
        'ThumbMediaId',
        'MediaId',
        'MsgId',
        'AgentID'
    ],

    'location': [
        'ToUserName',
        'FromUserName',
        'CreateTime',
        'MsgType',
        'Location_X',
        'Location_Y',
        'Scale',
        'Label',
        'MsgId',
        'AgentID'
    ],

    'link': [
        'ToUserName',
        'FromUserName',
        'CreateTime',
        'MsgType',
        'Title',
        'Description',
        'PicUrl',
        'MsgId',
        'AgentID'
    ]
}

def get_access_token():

    url = url_data['get_token_url']
    payload = {
        'corpsecret': wx_data['corpsecret'],
        'corpid': wx_data['corpid']
    }
    res = get(url, params=payload).json()
    return res['access_token']

def get_users():

    url = url_data['get_application_url']
    payload = {
        'access_token': get_access_token(),
        'agentid': wx_data['agentid']
    }
    res = post(url, params=payload).json()
    users = [
        user['userid']
        for user in res['allow_userinfos']['user']
        if user
    ]
    return users


def wechatbot():
    url = 'https://qyapi.weixin.qq.com/' + \
          'cgi-bin/webhook/send?key={0}'.format(wx_data['bot_key'])

    data = {
        'msgtype': 'text',
        'text': {
            'content': 'Lee.DavidCE you know?'
        }
    }

    respon = post(url=url, headers=wx_data['headers'], json=data)
    return respon.json()

@app.route('/wexin', methods=['GET', 'POST'], strict_slashes=False)
def weixin():

    msg = {}
    args = request.args.to_dict()

    # verify the URL
    if request.method == 'GET':
        try:
            sVerifyMsgSig = request.args.get('msg_signature')
            sVerifyTimeStamp = request.args.get('timestamp')
            sVerifyNonce = request.args.get('nonce')
            sVerifyEchoStr = request.args.get('echostr')
            ret, sEchoStr = wxcpt.VerifyURL(
                                sVerifyMsgSig,
                                sVerifyTimeStamp,
                                sVerifyNonce,
                                sVerifyEchoStr
                            )
            if ret != 0:
                return make_response(
                    jsonify(
                        {
                            'error verify url =>': str(ret)
                        }
                    ), 404
                )
            return make_response(jsonify({'success': sEchoStr}, 200))
        except ValueError as e:
            return make_response(
                jsonify(
                    {'value error': 'NULL'}
                ), 404
            )

    # receive custmers messages
    if request.method == 'POST':
        data = request.data
        encrypted_xml = data
        sVerifyMsgSig = request.args.get('msg_signature')
        sVerifyNonce = request.args.get('nonce')
        sVerifyTimeStamp = request.args.get('timestamp')
        ret, xml_content = wxcpt.DecryptMsg(
                               encrypted_xml,
                               sVerifyMsgSig,
                               sVerifyTimeStamp,
                               sVerifyNonce
                           )
        if ret != 0:
            return make_response(
                jsonify(
                    {
                        'error: decryptmsg response =>': str(ret)
                    }
                ), 404
            )

        xml_tree = ET.fromstring(xml_content)
        type_name = xml_tree.find('MsgType').text

        try:
            for nodename in type_fields[type_name]:
                msg[nodename] = xml_tree.find(nodename).text
        except:
            pass

        if not msg:
            return make_response('')

        message = msg

        try:
            replystr = message['Content']
        except:
            pass

        resp_dict = {
            'to_user': message['ToUserName'],
            'from_user': message['FromUserName'],
            'type': 'text',
            'content': replystr,
        }
        xml_message = ResponseMessage(resp_dict).xml
        nonce = generateNonce()
        ret, returnMsg = wxcpt.EncryptMsg(xml_message, nonce)
        res = returnMsg
        return make_response(jsonify({'ok': res}), 200)

@app.route('/api/v1/wechat-bot/release',
           methods=['GET'],
           strict_slashes=False)
def release_msg():

    url = url_data['send_msg'] + \
          '?access_token={0}'.format(get_access_token())
    tools_url = url_data['devops_tool'].format('Sit-develop-tool')
    forms = request.form.to_dict()

    if ('name' not in forms or
        'version' not in forms or
        'commit' not in forms or
        'service' not in forms):
        return make_response(jsonify(
            {'error': 'arguments not Found'}
        ), 404)

    name = forms['name']
    version = forms['version']
    service = forms['service']

    if service == 'script-mgt':

        commit_msgs = forms['commit'].replace('.__', '..__').split('.__')
        commit_msg = [
            sub(r'^\d+\.', '', e)
            for e in commit_msgs
            if e.strip()
        ]

        script_commit = '\n'.join(
            '> {0}.{1}'.format(i + 1, v)
            for i, v in enumerate(commit_msg)
        )
        content = template[service].format(
                      name,
                      version,
                      script_commit,
                      strftime("%Y-%m-%d %H:%M:%S", localtime())
                  )
    elif service == 'ares-report':
        return make_response(
            jsonify(
            {
                'ok': 'feature coming soon'
            }
        ), 200)
    else:
        return make_response(jsonify(
            {
                'error': 'arguments not Found'
            }
        ), 404)

    devops_tools = eval(get(tools_url).text)
    if name in devops_tools:
         users = '|'.join([user for user in devops_users])
    else:
         users = '@all'

    payload = {
        'touser': users,
        'msgtype': 'markdown',
        'agentid': wx_data['agentid'],
        'safe': 0,
        'markdown': {
            'content': content
        }
    }

    res = post(url, data=dumps(payload)).json()
    return make_response(jsonify({'ok': res}), 200)

@app.route('/api/v1/wechat-bot/alert-manager',
           methods=['POST'],
           strict_slashes=False)
def alerting():

    if request.method == 'POST':
        try:
            logging.basicConfig(
                level=logging.INFO,
                format='[%(asctime)s %(levelname)-8s] %(message)s',
                datefmt='%Y%m%d %H:%M:%S',
            )
            url = url_data['send_msg'] + \
                  '?access_token={0}'.format(get_access_token())
            data = loads(request.data)
            alerts =  data['alerts']
            users = '|'.join([user for user in devops_users])
            for idx, value in enumerate(alerts):
                title = alerts[idx]['labels']['alertname']
                host = alerts[idx]['labels']['instance']
                instance_name = alerts[idx]['labels']['name']
                descript = alerts[idx]['annotations']['description'].split('\n')[0]
                content = template['alert-mgt'].format(
                    title,
                    host,
                    instance_name,
                    descript
                )

                payload = {
                    'touser': users,
                    'msgtype': 'markdown',
                    'agentid': wx_data['agentid'],
                    'safe': 0,
                    'markdown': {
                        'content': content
                    }
                }

                res = post(url, data=dumps(payload)).json()
        except Exception as messages:
            logging.warning('=>, {0}'.format(messages))
    return make_response(jsonify({'ok': 'success'}), 200)

@app.errorhandler(404)
def page_not_found(fail):
    return make_response(
        jsonify(
            {'fail': 'api not found.'}
        ), 404
    )

if __name__ == '__main__':
    WSGIServer(('0.0.0.0', 1990), app).serve_forever()
