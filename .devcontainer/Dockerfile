# Use the official Go image as base
FROM golang:1.23-bullseye

# Install system dependencies
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends \
        git \
        curl \
        wget \
        unzip \
        build-essential \
        gcc \
        g++ \
        libsqlite3-dev \
        sqlite3 \
        redis-tools \
        vim \
        nano \
        htop \
        jq \
        ca-certificates \
    && apt-get autoremove -y && apt-get clean -y && rm -rf /var/lib/apt/lists/*

# Install Go tools
RUN go install -v golang.org/x/tools/gopls@latest \
    && go install -v github.com/ramya-rao-a/go-outline@latest \
    && go install -v github.com/cweill/gotests/gotests@latest \
    && go install -v github.com/fatih/gomodifytags@latest \
    && go install -v github.com/josharian/impl@latest \
    && go install -v github.com/haya14busa/goplay/cmd/goplay@latest \
    && go install -v github.com/go-delve/delve/cmd/dlv@latest \
    && go install -v honnef.co/go/tools/cmd/staticcheck@latest \
    && go install -v golang.org/x/tools/cmd/goimports@latest \
    && go install -v github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Create a non-root user
ARG USERNAME=vscode
ARG USER_UID=1000
ARG USER_GID=$USER_UID

RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME \
    && apt-get update \
    && apt-get install -y sudo \
    && echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME \
    && chmod 0440 /etc/sudoers.d/$USERNAME

# Set up Go workspace
RUN mkdir -p /go/src /go/bin /go/pkg && chmod -R 777 /go
ENV GOPATH=/go
ENV PATH=$GOPATH/bin:$PATH

# Switch to non-root user
USER $USERNAME

# Set working directory
WORKDIR /workspace

# Default command
CMD ["sleep", "infinity"]
