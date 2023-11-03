#!/bin/bash

# Specify the directory where your image files are located
image_directory="./"

# Iterate over all files in the specified directory
for image_file in "$image_directory"/*; do
    if [ -f "$image_file" ]; then
        # Run the exiftool command on each image file
        exiftool "$image_file"
    fi
done
