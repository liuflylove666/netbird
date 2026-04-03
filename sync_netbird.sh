#!/bin/bash

# ==========================================
# NetBird Fork 同步助手 (完整版)
# ==========================================

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' 

echo -e "${BLUE}>>> 正在启动 NetBird 仓库同步程序...${NC}"

# 1. 检查是否在 Git 仓库中
if [ ! -d .git ]; then
    echo -e "${RED}[错误] 当前目录不是 Git 仓库！请在 netbird 项目根目录运行。${NC}"
    exit 1
fi

# 2. 检查并配置 upstream
UPSTREAM_URL="https://github.com/netbirdio/netbird.git"
if ! git remote | grep -q "upstream"; then
    echo -e "${YELLOW}[提示] 未检测到 upstream，正在自动关联官方仓库...${NC}"
    git remote add upstream "$UPSTREAM_URL"
fi

# 3. 检查当前是否存在未解决的冲突
if git status | grep -q "unmerged paths"; then
    echo -e "${RED}[警告] 检测到你还有未解决的合并冲突！${NC}"
    echo -e "${YELLOW}请先手动编辑冲突文件，执行 git add <文件> 并 git commit 提交后再运行此脚本。${NC}"
    exit 1
fi

# 4. 获取官方最新代码
echo -e "${BLUE}>>> 正在从官方拉取最新变动 (git fetch upstream)...${NC}"
git fetch upstream

# 5. 获取当前分支名
CURRENT_BRANCH=$(git symbolic-ref --short HEAD)
echo -e "${BLUE}>>> 当前本地分支: ${YELLOW}$CURRENT_BRANCH${NC}"

# 6. 尝试合并
echo -e "${BLUE}>>> 正在尝试合并 upstream/main 到 $CURRENT_BRANCH...${NC}"
if git merge upstream/main; then
    echo -e "${GREEN}[成功] 代码已自动合并，无冲突。${NC}"
    
    # 7. 自动推送到你的 GitHub (origin)
    echo -e "${BLUE}>>> 正在将更新推送到你的 GitHub 远程库 (origin)...${NC}"
    if git push origin "$CURRENT_BRANCH"; then
        echo -e "${GREEN}[完成] 你的 Fork 现在已经与官方同步！${NC}"
    else
        echo -e "${RED}[错误] 推送失败，请检查网络连接或权限。${NC}"
    fi
else
    echo -e "------------------------------------------------"
    echo -e "${RED}[停止] 检测到代码冲突 (Merge Conflict)！${NC}"
    echo -e "${YELLOW}由于你进行了二次开发，请按以下步骤手动解决:${NC}"
    echo -e "  1. 打开编辑器查找 <<<<<<< HEAD 标记"
    echo -e "  2. 决定保留你的代码还是官方代码"
    echo -e "  3. 解决后运行: ${BLUE}git add .${NC}"
    echo -e "  4. 接着运行: ${BLUE}git commit -m \"fix: sync with upstream and fix conflicts\"${NC}"
    echo -e "  5. 最后运行: ${BLUE}git push origin $CURRENT_BRANCH${NC}"
    echo -e "------------------------------------------------"
fi
