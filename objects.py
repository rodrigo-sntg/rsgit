import collections
import enum

# index object
IndexEntry = collections.namedtuple('IndexEntry', [
    'ctime_s', 'ctime_n', 'mtime_s', 'mtime_n', 'dev', 'ino', 'mode', 'uid',
    'gid', 'size', 'sha1', 'flags', 'path',
])

class ObjectType(enum.Enum):
    """    
    Object tipo enum para os tipos de objetos retirado da lista de object_type git/cache.h
    """
    commit = 1
    tree = 2
    blob = 3