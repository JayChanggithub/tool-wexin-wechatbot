#!/usr/bin/env python
#-*- encoding:utf-8 -*-

import sys
sys.path.append('.')

import base64
import string
import random
import hashlib
import time
from Crypto.Cipher import AES
import xml.etree.cElementTree as ET
import ierror

class FormatException(Exception):
    pass

def throw_exception(message, exception_class=FormatException):

    raise exception_class(message)

def generateNonce(digits = 16):

    rule = string.ascii_lowercase + string.digits
    str = random.sample(rule, digits)
    return "".join(str)
class SHA1:

    def getSHA1(self, token, timestamp, nonce, encrypt):

        try:
            sortlist = [token, timestamp, nonce, encrypt]
            sortlist.sort()
            sha = hashlib.sha1()
            sha.update("".join(sortlist).encode('utf-8'))
            return  ierror.WXBizMsgCrypt_OK, sha.hexdigest()
        except Exception as e:
            print(e)
            return  ierror.WXBizMsgCrypt_ComputeSignature_Error, None
class XMLParse:

    AES_TEXT_RESPONSE_TEMPLATE = '<xml>'+\
        '<Encrypt><![CDATA[%(msg_encrypt)s]]></Encrypt>'+\
        '<MsgSignature><![CDATA[%(msg_signaturet)s]]></MsgSignature>'+\
        '<TimeStamp>%(timestamp)s</TimeStamp>'+\
        '<Nonce><![CDATA[%(nonce)s]]></Nonce>'+\
    '</xml>'

    def extract(self, xmltext):

        try:
            xml_tree = ET.fromstring(xmltext)
            encrypt  = xml_tree.find("Encrypt")
            return  ierror.WXBizMsgCrypt_OK, encrypt.text
        except Exception as e:
            print(e)
            return  ierror.WXBizMsgCrypt_ParseXml_Error,None,None

    def generate(self, encrypt, signature, timestamp, nonce):

        resp_dict = {
                    'msg_encrypt' : encrypt,
                    'msg_signaturet': signature,
                    'timestamp'    : timestamp,
                    'nonce'        : nonce,
                     }
        resp_xml = self.AES_TEXT_RESPONSE_TEMPLATE % resp_dict
        return resp_xml

class ResponseMessage():

    """
        text_response = {
            'to_user':'',
            'from_user':'',
            'timestamp':'',
            'type':'text',
            'content':'',
        }
        voice_response= {
            'to_user':'',
            'from_user':'',
            'timestamp':'',
            'type':'voice',
            'media_id':''
        }
        image_response= {
            'to_user':'',
            'from_user':'',
            'timestamp':'',
            'type':'image',
            'data':[
                {'media_id':''}
            ]
        }
        video_response= {
            'to_user':'',
            'from_user':'',
            'timestamp':'',
            'type':'video',
            'media_id':'',
            'title':'',
            'description':'',
        }
        article_response= {
            'to_user':'',
            'from_user':'',
            'timestamp':'',
            'type':'news',
            'data':[
                {'title':'',
                 'description':'',
                 'pic_url':'',
                 'url':'',
                }
            ]
        }

    """
    BASIC_RESPONSE_FIELDS = '<ToUserName><![CDATA[%(to_user)s]]></ToUserName>'+\
       '<FromUserName><![CDATA[%(from_user)s]]></FromUserName>'+\
       '<CreateTime>%(timestamp)s</CreateTime>'+\
       '<MsgType><![CDATA[%(type)s]]></MsgType>'

    TEXT_RESPONSE_FIELD = "<Content><![CDATA[%(content)s]]></Content>"
    VOICE_RESPONSE_FIELD = "<Voice><![CDATA[%(media_id)s]]></Voice>"
    IMAGE_RESPONSE_FIELD = "<MediaId><![CDATA[%(media_id)s]]></MediaId>"
    VIDEO_RESPONSE_FIELD = '<Video>'+\
                       '<MediaId><![CDATA[%(media_id)s]]></MediaId>' +\
                       '<Title><![CDATA[%(title)s]]></Title>'+\
                       '<Description><![CDATA[%(description)s]]></Description>'+\
                   '</Video>'
    ARTICLE_RESPONSE_FIELD = '<items>'+\
                       '<Title><![CDATA[%(title)s]]></Title>'+\
                       '<Description><![CDATA[%(description)s]]></Description>'+\
                       '<PicUrl><![CDATA[%(pic_url)s]]></PicUrl>' +\
                       '<Url><![CDATA[%(url)s]]></Url>'+\
                   '</items>'

    def __init__(self,data_dict):

        if 'timestamp' not in data_dict:
            data_dict['timestamp'] = str(int(time.time()))
        self.data = data_dict

    @property
    def xml(self):
        basic = self.BASIC_RESPONSE_FIELDS % self.data

        if self.data['type'] == 'text':
            return '<xml>' + basic + self.TEXT_RESPONSE_FIELD % self.data + '</xml>'

        elif self.data['type'] == 'image':
            tmp = ''
            for d in self.data['data']:
                tmp = tmp + self.IMAGE_RESPONSE_FIELD % d
            return '<xml>' + basic + '<Image>' +tmp+ '</Image></xml>'

        elif self.data['type'] == 'voice':
            return '<xml>' + basic + self.VOICE_RESPONSE_FIELD % self.data + '</xml>'

        elif self.data['type'] == 'video':
            return '<xml>' + basic + self.VIDEO_RESPONSE_FIELD % self.data + '</xml>'

        elif self.data['type'] == 'news':
            tmp = ''
            for d in self.data['data']:
                tmp = tmp + self.ARTICLE_RESPONSE_FIELD % d
            count = "<ArticleCount>"+str(len(self.data['data']))+"</ArticleCount>"
            return '<xml>' + basic + count + '<Articles>' +tmp+ '</Articles></xml>'
        else:
            return None

class PKCS7Encoder():

    block_size = 32
    def encode(self, text):
        text_length = len(text)
        amount_to_pad = self.block_size - (text_length % self.block_size)
        if amount_to_pad == 0:
            amount_to_pad = self.block_size
        pad = chr(amount_to_pad)
        if type(text) == bytes:
            return text + amount_to_pad * amount_to_pad.to_bytes(1,'big')
        return text + pad * amount_to_pad

    def decode(self, decrypted):
        pad = decrypted[-1]
        if pad<1 or pad >32:
            pad = 0
        return decrypted[:-pad]


class Prpcrypt(object):

    def __init__(self,key):

        self.key = key
        self.mode = AES.MODE_CBC

    def encrypt(self,text,receiveid):
        text_bytes = text.encode('utf8')
        text = generateNonce().encode('utf8') + int.to_bytes(len(text_bytes),4,byteorder='big') + text_bytes + receiveid.encode('utf8')
        pkcs7 = PKCS7Encoder()
        text = pkcs7.encode(text)
        cryptor = AES.new(self.key,self.mode,self.key[:16])
        try:
            ciphertext = cryptor.encrypt(text)
            return ierror.WXBizMsgCrypt_OK, base64.b64encode(ciphertext).decode('utf8')
        except Exception as e:
            print(e)
            return  ierror.WXBizMsgCrypt_EncryptAES_Error,None

    def decrypt(self,text,receiveid):

        try:
            cryptor = AES.new(self.key,self.mode,self.key[:16])
            plain_text  = cryptor.decrypt(base64.b64decode(text))

        except Exception as e:
            print(e)
            return  ierror.WXBizMsgCrypt_DecryptAES_Error,None
        try:
            pkcs7 = PKCS7Encoder()
            plain_text = pkcs7.decode(plain_text)

            xml_len = int.from_bytes(plain_text[16:20],byteorder='big')
            xml_content = plain_text[20 : 20 + xml_len].decode('utf-8')
            from_receiveid = plain_text[20 + xml_len:].decode('utf-8')
        except Exception as e:
            print(e)
            return  ierror.WXBizMsgCrypt_IllegalBuffer,None
        if  from_receiveid != receiveid:
            return ierror.WXBizMsgCrypt_ValidateCorpid_Error,None
        return 0,xml_content

class WXBizMsgCrypt(object):

    def __init__(self,sToken,sEncodingAESKey,sReceiveId):
        try:
            self.key = base64.b64decode(sEncodingAESKey+"=")
            assert len(self.key) == 32
        except:
            throw_exception("[error]: EncodingAESKey unvalid !", FormatException)
        self.m_sToken = sToken
        self.m_sReceiveId = sReceiveId

    def VerifyURL(self, sMsgSignature, sTimeStamp, sNonce, sEchoStr):
        sha1 = SHA1()
        ret,signature = sha1.getSHA1(self.m_sToken, sTimeStamp, sNonce, sEchoStr)
        if ret  != 0:
            return ret, None
        if not signature == sMsgSignature:
            return ierror.WXBizMsgCrypt_ValidateSignature_Error, None

        pc = Prpcrypt(self.key)
        ret,sReplyEchoStr = pc.decrypt(sEchoStr,self.m_sReceiveId)
        return ret,sReplyEchoStr

    def EncryptMsg(self, sReplyMsg, sNonce, timestamp = None):

        pc = Prpcrypt(self.key)
        ret,encrypt = pc.encrypt(sReplyMsg, self.m_sReceiveId)
        if ret != 0:
            return ret,None
        if timestamp is None:
            timestamp = str(int(time.time()))

        sha1 = SHA1()
        ret,signature = sha1.getSHA1(self.m_sToken, timestamp, sNonce, encrypt)
        if ret != 0:
            return ret,None
        xmlParse = XMLParse()
        return ret,xmlParse.generate(encrypt, signature, timestamp, sNonce)

    def DecryptMsg(self, sPostData, sMsgSignature, sTimeStamp, sNonce):

        xmlParse = XMLParse()
        ret,encrypt = xmlParse.extract(sPostData)
        if ret != 0:
            return ret, None
        sha1 = SHA1()
        ret,signature = sha1.getSHA1(self.m_sToken, sTimeStamp, sNonce, encrypt)
        if ret != 0:
            return ret, None
        if not signature == sMsgSignature:
            return ierror.WXBizMsgCrypt_ValidateSignature_Error, None
        pc = Prpcrypt(self.key)
        ret,xml_content = pc.decrypt(encrypt,self.m_sReceiveId)
        return ret,xml_content
