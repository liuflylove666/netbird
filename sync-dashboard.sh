#!/bin/bash

SOURCE="./dashboard/"
DEST="../netbird-dashboard/"

echo ">>> 正在同步 Dashboard 文件..."

# 使用 rsync 同步，排除 node_modules 和 .git 文件夹（通常不需要同步这些）
rsync -av --exclude='node_modules' --exclude='.git' "$SOURCE" "$DEST"

echo ">>> 同步完成！"
