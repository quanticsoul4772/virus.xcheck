import sys
import os
import pytest

# Add project root to path so tests can import virusxcheck
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
