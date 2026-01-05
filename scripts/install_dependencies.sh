#!/bin/bash
#
# Heap Mastery Course - Dependency Installation Script
# Automatically checks for and installs missing dependencies
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "==================================="
echo "  Heap Mastery Course Setup"
echo "  Dependency Installation"
echo "==================================="
echo ""

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to install package
install_package() {
    if [ -z "$SKIP_PROMPT" ]; then
        read -p "Install $1? (y/n) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo -e "${YELLOW}[!] Skipped $1${NC}"
            return 1
        fi
    fi

    echo -e "${BLUE}[*] Installing $1...${NC}"
    apt-get update -qq
    apt-get install -y "$1" >/dev/null 2>&1
    echo -e "${GREEN}[✓] $1 installed${NC}"
    return 0
}

# Check Python
echo -e "${BLUE}[1/7] Checking Python...${NC}"
if command_exists python3; then
    PYTHON_VERSION=$(python3 --version)
    echo -e "${GREEN}[✓] Python found: $PYTHON_VERSION${NC}"
else
    echo -e "${RED}[✗] Python3 not found${NC}"
    install_package python3
fi

# Check pip
echo ""
echo -e "${BLUE}[2/7] Checking pip...${NC}"
if command_exists pip3; then
    PIP_VERSION=$(pip3 --version)
    echo -e "${GREEN}[✓] pip found: $PIP_VERSION${NC}"
else
    echo -e "${RED}[✗] pip3 not found${NC}"
    apt-get update -qq
    apt-get install -y python3-pip >/dev/null 2>&1
    echo -e "${GREEN}[✓] pip3 installed${NC}"
fi

# Check and install Python packages
echo ""
echo -e "${BLUE}[3/7] Checking Python packages...${NC}"

PYTHON_PACKAGES=("pwntools" "capstone" "unicorn")

for pkg in "${PYTHON_PACKAGES[@]}"; do
    if python3 -c "import $pkg" 2>/dev/null; then
        VERSION=$(python3 -c "import $pkg; print($pkg.__version__)" 2>/dev/null || echo "installed")
        echo -e "${GREEN}[✓] $pkg: $VERSION${NC}"
    else
        echo -e "${YELLOW}[!] $pkg not found, installing...${NC}"
        pip3 install "$pkg" -q >/dev/null 2>&1
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}[✓] $pkg installed${NC}"
        else
            echo -e "${RED}[✗] Failed to install $pkg${NC}"
        fi
    fi
done

# Check GCC
echo ""
echo -e "${BLUE}[4/7] Checking GCC...${NC}"
if command_exists gcc; then
    GCC_VERSION=$(gcc --version | head -n1)
    echo -e "${GREEN}[✓] GCC found: $GCC_VERSION${NC}"
else
    echo -e "${RED}[✗] GCC not found${NC}"
    install_package gcc
fi

# Check GDB
echo ""
echo -e "${BLUE}[5/7] Checking GDB...${NC}"
if command_exists gdb; then
    GDB_VERSION=$(gdb --version | head -n1)
    echo -e "${GREEN}[✓] GDB found: $GDB_VERSION${NC}"
else
    echo -e "${RED}[✗] GDB not found${NC}"
    install_package gdb
fi

# Check Pwndbg
echo ""
echo -e "${BLUE}[6/7] Checking Pwndbg...${NC}"
if gdb -q -ex "python import pwndbg; quit" 2>/dev/null; then
    echo -e "${GREEN}[✓] Pwndbg installed${NC}"
else
    echo -e "${YELLOW}[!] Pwndbg not found${NC}"
    echo -e "${YELLOW}    Pwndbg is optional but recommended for heap debugging${NC}"

    if [ -z "$SKIP_PROMPT" ]; then
        read -p "Install Pwndbg? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            echo -e "${BLUE}[*] Installing Pwndbg...${NC}"
            cd /tmp
            git clone --depth=1 https://github.com/pwndbg/pwndbg >/dev/null 2>&1
            cd pwndbg
            ./setup.sh >/dev/null 2>&1
            echo -e "${GREEN}[✓] Pwndbg installed${NC}"
        fi
    fi
fi

# Check build tools
echo ""
echo -e "${BLUE}[7/7] Checking build tools...${NC}"
BUILD_TOOLS=("make" "cmake")

for tool in "${BUILD_TOOLS[@]}"; do
    if command_exists "$tool"; then
        echo -e "${GREEN}[✓] $tool found${NC}"
    else
        echo -e "${YELLOW}[!] $tool not found, installing...${NC}"
        apt-get update -qq
        apt-get install -y "$tool" >/dev/null 2>&1
        echo -e "${GREEN}[✓] $tool installed${NC}"
    fi
done

# Summary
echo ""
echo "==================================="
echo -e "${GREEN}  Installation Complete!${NC}"
echo "==================================="
echo ""
echo "All dependencies are installed. You can now:"
echo "  - Run tests: ./tests/test_all_levels.sh"
echo "  - Build all: mkdir build && cd build && cmake .. && make"
echo ""
