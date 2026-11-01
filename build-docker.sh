#!/bin/zsh
# docker 镜像构建：./build-docker.sh [tag]
set -e
TAG="${1:-latest}"
IMAGE="zcode-proxy"
docker build -t "$IMAGE:$TAG" .
echo "✅ $IMAGE:$TAG"
echo "   运行: docker run -d -p 8787:8787 -v ./state:/data/state $IMAGE:$TAG"
