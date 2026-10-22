"""命令行入口：python -m secassess serve|demo"""
from __future__ import annotations

import argparse
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="secassess", description="SecAssess 安全评估工具箱")
    sub = parser.add_subparsers(dest="command", required=True)
    serve = sub.add_parser("serve", help="启动 REST/SSE API 服务")
    serve.add_argument("--config", default="examples/platform.json", help="平台配置 JSON")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    demo = sub.add_parser("demo", help="运行端到端演示")
    demo.add_argument("--out", default="reports_out", help="报告输出目录")
    args = parser.parse_args(argv)

    if args.command == "serve":
        try:
            import uvicorn

            from .api.app import create_app
        except ImportError:
            print("需要安装 API 依赖：pip install 'secassess[api]'", file=sys.stderr)
            return 2
        from .platform import Platform

        uvicorn.run(create_app(Platform.from_file(args.config)), host=args.host, port=args.port)
        return 0

    from .demo import run_demo

    return run_demo(args.out)


if __name__ == "__main__":
    sys.exit(main())
