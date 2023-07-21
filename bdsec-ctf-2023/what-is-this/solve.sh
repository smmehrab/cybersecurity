#!/bin/bash

# Loop through each file in the current directory
for file in *; do
    if [ -f "$file" ] && [ "$file" != "solve.sh" ]; then  # Check if it's a regular file and not "script.sh"
        echo "---- $file ----"
        cat "$file" | grep "bdsec"
    fi
done
