#!/bin/bash

# Check if at least two arguments were provided
if [ $# -ne 5 ]; then
    echo "Usage: $0 <year> <test> <fileid> <place> <command>"
    echo "command is one of root, proof, root_proof"
    exit 1
fi

# Get the first two command-line arguments
year="$1"
test="$2"
name="$3"
cmd="$5"
ind="$4"

python3 providers/proof_gen.py "$year" "$test" "$name" "$ind" "$cmd"