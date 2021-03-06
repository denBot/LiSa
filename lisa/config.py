import os
"""
    Configuration.
"""

lisa_path = '/home/lisa'
storage_path = f'{lisa_path}/data/storage'

analyzers_config = [
    'lisa.analysis.static_analysis.StaticAnalyzer',
    'lisa.analysis.dynamic_analysis.DynamicAnalyzer',
    'lisa.analysis.network_analysis.NetworkAnalyzer',
    # custom modules
]

rabbit_mq_pass = os.getenv("RABBITMQ_PASS", "lisa")
mysql_pass = os.getenv("MYSQL_PASS", "lisa")
virus_total_key = os.getenv("VIRUSTOTAL_API_KEY", "")

if virus_total_key:
     analyzers_config.append('lisa.analysis.virustotal.VirusTotalAnalyzer')

dynamic_config = {
    'min_exectime': 10,
    'max_exectime': 1000
}

images = {
    'x86_64': {
        'run': f'{lisa_path}/images/x86_64/run.sh',
        'prompt': '# ',
        'rootfs': f'{lisa_path}/images/x86_64/images/rootfs.ext2'
    },
    'i386': {
        'run': f'{lisa_path}/images/i386/run.sh',
        'prompt': '# ',
        'rootfs': f'{lisa_path}/images/i386/images/rootfs.ext2'
    },
    'aarch64': {
        'run': f'{lisa_path}/images/aarch64/run.sh',
        'prompt': '# ',
        'rootfs': f'{lisa_path}/images/aarch64/images/rootfs.ext2'
    },
    'arm': {
        'run': f'{lisa_path}/images/arm/run.sh',
        'prompt': '# ',
        'rootfs': f'{lisa_path}/images/arm/images/rootfs.ext2'
    },
    'mips': {
        'run': f'{lisa_path}/images/mips/run.sh',
        'prompt': '# ',
        'rootfs': f'{lisa_path}/images/mips/images/rootfs.ext2'
    }
}

logging_config = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'default': {
            'format': ('%(asctime)s %(process)s:%(module)s '
                       '[%(levelname)s] - %(message)s'),
            'datefmt': '%Y-%m-%d %H:%M:%S'
        }
    },
    'handlers': {
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'default',
            'stream': 'ext://sys.stdout'
        }
    },
    'loggers': {
        '': {
            'level': 'DEBUG',
            'handlers': ['console']
        }
    }
}

celery_broker = f'pyamqp://lisa:{rabbit_mq_pass}@172.42.0.13//'
celery_backend = f'db+mysql+pymysql://lisa:{mysql_pass}@172.42.0.14/lisadb'
sql_backend = f'mysql+pymysql://lisa:{mysql_pass}@172.42.0.14/lisadb'
