#!/usr/bin/env python3

import sys
import os

sys.dont_write_bytecode = True

# Add the project root to the Python path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from src.app import CryptonApp

if __name__ == "__main__":
    app = CryptonApp()
    app.run()
