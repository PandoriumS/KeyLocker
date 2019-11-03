from .base import *

try:
    from .local import *
except ImportError:
    print("Make file 'settings.local'! Make it from 'settings.local.py.skeleton'")


