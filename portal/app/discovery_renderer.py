"""Compatibility import for the shared offline action runtime."""
import sys
from . import rendering

sys.modules[__name__] = rendering
