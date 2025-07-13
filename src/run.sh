#!/bin/bash

# Script to set up the development environment
set -e  # Exit on any error

# Define virtual environment directory
VENV_DIR="venv"

echo "Starting build process..."

# Check if virtual environment already exists
if [ -d "$VENV_DIR" ]; then
    echo "Virtual environment already exists in '$VENV_DIR'"
    echo "Checking if virtual environment is valid..."
    
    # Check if the virtual environment is valid by testing Python
    if [ -f "$VENV_DIR/bin/python" ]; then
        echo "Virtual environment appears to be valid"
    else
        echo "Virtual environment seems corrupted, recreating..."
        rm -rf "$VENV_DIR"
        python3 -m venv "$VENV_DIR"
        echo "New virtual environment created in '$VENV_DIR'"
    fi
else
    echo "Creating new virtual environment in '$VENV_DIR'..."
    python3 -m venv "$VENV_DIR"
    echo "Virtual environment created successfully"
fi

# Activate virtual environment
echo "Activating virtual environment..."
source "$VENV_DIR/bin/activate"

# Upgrade pip to latest version
echo "Upgrading pip..."
pip install --upgrade pip

# Install dependencies from requirements.txt
if [ -f "src/requirements.txt" ]; then
    echo "Installing dependencies from requirements.txt..."
    pip install -r src/requirements.txt
    echo "Dependencies installed successfully"
else
    echo "Warning: requirements.txt not found"
fi

# Run main.py
if [ -f "src/main.py" ]; then
    echo "Running src/main.py..."
    python src/main.py
else
    echo "main.py not found. Skipping execution."
fi

