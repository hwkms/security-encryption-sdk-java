#!/bin/bash
SDK_HOME=$(cd $(dirname $0)/../..; pwd)
PYTHON_HOME_PATH="${SDK_HOME}/python"
function build() {
  cd $PYTHON_HOME_PATH
  if [ ! -d "dist" ]; then
     mkdir dist
  fi
  pip install setuptools==82.0.1
  pip install build
  # .so 以 base64 文本(.txt)入库，构建前解码还原
  python scripts/decode_openssl_so.py
  python -m build --wheel
  # 构建完成，删除临时 .so，保持源码目录干净
  python scripts/decode_openssl_so.py --clean
}
build