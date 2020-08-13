Tool-Wechat-Bot
===========================

[![](http://ipt-gitlab.ies.inventec:8000/images/wechat-bot.png)](#Tool-Wechat-Bot)

---

## Version

`Rev: 1.0.7`

---

## Suitable Project
  
  
  - [ ] Baidu
  - [ ] Ali
  - [ ] Tencent
  - [ ] JD
  - [ ] ByteDance
  - [x] None

---

## Status

[![pipeline status](http://ipt-gitlab.ies.inventec:8081/SIT-develop-tool/tool-wechat-bot/badges/master/pipeline.svg)](http://ipt-gitlab.ies.inventec:8081/SIT-develop-tool/tool-wechat-bot/commits/master)


---

## Description

 - Use python wechat libary to implement automatic announce release messages.
 
---

## prerequisites

 - Wechat bot account require to use web wechat permission.

---

## Usage

  - Docker container service

    - Step 1: Install service

      ```bash
      docker run -tid -p 1990:1990 \
                 --privileged=true \
                 --restart=always \
                 --name ipt-wechat \
                 -e "TZ=Asia/Shanghai" \
                 -v /srv/wechat:/var/log/gunicorn/ \
                 $CI_REGISTRY_IMAGE:$VERSION
      ```

    - Step 2: Scan QRcode from terminal

      ```bash
      $ docker logs ipt-wechat
      ```

## Contact

##### Author: Jay.Chang

##### Email: cqe5914678@gmail.com
