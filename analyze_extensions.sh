#!/bin/bash

# Function to display help message
show_help() {
    echo "Usage: $0 -s SOURCE_DIR [-r RESULTS_DIR] [-b| -w]"
    echo
    echo "Options:"
    echo "  -s    SOURCE_DIR    Directory containing the unpacked extensions"
    echo "  -r    RESULTS_DIR   Output directory for analysis results (default is parent dir of extension)"
    echo "  -b                  analysis of content-script and background-page only (optional)"
    echo "  -w                  analysis of content-script and wars only (optional)"
    echo "  -h                  Show this help message"
}

BP_ONLY=false
WAR_ONLY=false

# Parse command-line arguments
while getopts "s:r:bwh" opt; do
    case $opt in
        s)
            SOURCE_DIR="$OPTARG"
            ;;
        r)
            RESULTS_DIR="$OPTARG"
            ;;
        b)
            BP_ONLY=true
            ;;
        w)
            WAR_ONLY=true
            ;;
        h)
            show_help
            exit 0
            ;;
        *)
            show_help
            exit 1
            ;;
    esac
done

# Check if required arguments are provided
if [ -z "$SOURCE_DIR" ]; then
    echo "Error: SOURCE_DIR is required."
    show_help
    exit 1
fi

# Create results directory if it doesn't exist
if [[ ! -z "$RESULTS_DIR" ]]; then
    mkdir -p "$RESULTS_DIR"
fi

# TODO: allow single dirs to be analyzed
# Loop through all source extensions in the sources directory
for SOURCE in "$SOURCE_DIR"/*; do
    if [[ -d "$SOURCE" ]]; then
        echo "Testing source: $SOURCE"

        # Define content script and background page paths (update according to source structure)
        CONTENT_SCRIPT="$SOURCE/contentscript.js"
        BACKGROUND_PAGE="$SOURCE/background.js"
        WARS="$SOURCE/wars.js"

        # Check if necessary files exist
        if [[ -f "$CONTENT_SCRIPT" ]]; then
            if [[ $WAR_ONLY = false && -f "$BACKGROUND_PAGE" ]]; then
              echo "Analyzing content-script and background-page"
              python "./src/doublex.py" -cs "$CONTENT_SCRIPT" -bp "$BACKGROUND_PAGE" --analysis "$SOURCE/analysis-cs-bp.json"
            fi
            if [[ $BP_ONLY = false && -f "$WARS" ]]; then
              echo "Analyzing content-script and wars"
              python "./src/doublex.py" -cs "$CONTENT_SCRIPT" -bp "$WARS" --war --analysis "$SOURCE/analysis-cs-war.json"
            fi
            
            echo "Analysis completed for $SOURCE"
        else
            echo "Skipping $SOURCE: Required files not found (contentscript.js, background.js, manifest.json)"
        fi
    fi
done

echo "All sources tested. Results stored in $RESULTS_DIR."