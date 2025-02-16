#!/bin/bash

# Exit on error
set -e

# Define example directories and files (adjust these paths as needed)
EXAMPLES_DIR="./examples"  # Directory containing the example extensions
RESULTS_DIR="./results"    # Output directory for analysis results
SRC_DIR="./src"            # Directory containing the source code of DoubleX

# Create results directory if it doesn't exist
mkdir -p "$RESULTS_DIR"

# Loop through all example extensions in the examples directory
for EXAMPLE in "$EXAMPLES_DIR"/*; do
    if [[ -d "$EXAMPLE" ]]; then
        echo "Testing example: $EXAMPLE"

        # Define content script and background page paths (update according to example structure)
        CONTENT_SCRIPT="$EXAMPLE/contentscript.js"
        BACKGROUND_PAGE="$EXAMPLE/background.js"

        # Check if necessary files exist
        if [[ -f "$CONTENT_SCRIPT" && -f "$BACKGROUND_PAGE" ]]; then
            
            # Run DoubleX analysis
            # python ./src/doublex.py -cs ./examples/alias/contentscript.js -bp ./examples/alias/background.js
            python "$SRC_DIR/doublex.py" -cs "$CONTENT_SCRIPT" -bp "$BACKGROUND_PAGE" --analysis "$RESULTS_DIR/$(basename "$EXAMPLE")_analysis.json"
            
            echo "Analysis completed for $EXAMPLE"
        else
            echo "Skipping $EXAMPLE: Required files not found (contentscript.js, background.js, manifest.json)"
        fi
    fi
done

echo "All examples tested. Results stored in $RESULTS_DIR."