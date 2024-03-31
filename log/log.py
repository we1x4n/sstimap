import logging
from colorlog import ColoredFormatter

formatter = ColoredFormatter(
    # log_color设置颜色，如果使用reset，则后续颜色不改变，可使用第八行配置运行下看下效果
    "%(log_color)s%(asctime)s - %(levelname)s - %(message)s",
    # "%(log_color)s%(levelname)-8s%(reset)s %(log_color)s%(message)s",
    datefmt='%Y-%m-%d %H:%M:%S',
    reset=True,
    # 设置不同等级颜色
    log_colors={
        'DEBUG': 'fg_thin_cyan',
        'INFO': 'thin_green',
        'WARNING': 'yellow',
        'ERROR': 'red',
        'CRITICAL': 'red',
    },
    secondary_log_colors={},
    style='%'
)

handler = logging.StreamHandler()
handler.setFormatter(formatter)

logger = logging.getLogger('test')
logger.setLevel(logging.DEBUG)
logger.addHandler(handler)