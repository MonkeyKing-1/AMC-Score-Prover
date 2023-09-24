#!/bin/bash

# Check if at least two arguments were provided
if [ $# -ne 4 ]; then
    if [$4 != "keygen"] && [$4 != "verify-score"] && [$4 != "mock"] && [$4 != "prove"] && [$4 != "proverify"]; then
        echo "Usage: $0 <year> <test> <fileid> <command>"
        echo "command is one of keygen, verify-score, mock, prove, verify, proverify"
        echo "<year> and <test> are ignored for keygen"
        exit 1
    fi
fi

# Get the first two command-line arguments
year="$1"
test="$2"
name="$3"
cmd="$4"

if [ "$cmd" = "keygen" ]; then
    LOOKUP_BITS=17 cargo run --example amc -- --input "$name"_"$year""_AMC"$test"_proof.json" --name "merkle_proof" -k 18 "$cmd"
    exit 0
fi
if [ "$cmd" = "proverify" ]; then
    LOOKUP_BITS=17 cargo run --example amc -- --input "$name"_"$year""_AMC"$test"_proof.json" --name "$name"_"$year""_AMC"$test -k 18 "prove"
    LOOKUP_BITS=17 cargo run --example amc -- --input "$name"_"$year""_AMC"$test"_proof.json" --name "$name"_"$year""_AMC"$test -k 18 "verify-score"
    exit 0
fi



LOOKUP_BITS=17 cargo run --example amc -- --input "$name"_"$year""_AMC"$test"_proof.json" --name "$name"_"$year""_AMC"$test -k 18 "$cmd"
