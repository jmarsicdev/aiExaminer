#!/bin/bash
# aiExaminer Launch Script

PROJECT_DIR="/home/jmarsic/Documents/Code/projects/aiExaminer"
VENV_DIR="$PROJECT_DIR/.venv"

echo "--- Launching aiExaminer ---"

# Navigate to project directory
cd "$PROJECT_DIR" || { echo "Error: Could not change directory to $PROJECT_DIR"; exit 1; }

# Check if virtual environment exists
if [ ! -d "$VENV_DIR" ]; then
    echo "Error: Virtual environment not found at $VENV_DIR"
    exit 1
fi

# Activate virtual environment
source "$VENV_DIR/bin/activate"

# Set PYTHONPATH to include the project root
export PYTHONPATH="$PYTHONPATH:$PROJECT_DIR"

# Launch the application
python3 src/main.py

echo "--- aiExaminer closed ---"
