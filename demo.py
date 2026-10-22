"""端到端演示：python demo.py（等价于 python -m secassess demo）。"""
import sys

from secassess.demo import run_demo

if __name__ == "__main__":
    sys.exit(run_demo())
