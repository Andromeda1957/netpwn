import os

__path__ = ['modules']
__all__ = [filename.rsplit('.')[0] for filename in os.listdir(__path__[0])
           if not filename.startswith('_')
           and (filename.endswith('.py') or os.path.isdir("{}/{}".format(__path__[0], filename)))]