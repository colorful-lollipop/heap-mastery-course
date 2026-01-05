#!/bin/bash
# Test compilation of all vulnerable programs

set -e

echo "Testing compilation of all levels..."

LEVELS=("level00_setup" "level01_overflow" "level02_uaf" "level03_fastbin_dup" "level04_tcache" "level05_heap_spray" "level06_feng_shui" "level07_advanced")

for level in "${LEVELS[@]}"; do
    echo "Compiling $level..."
    cd "$level/challenge"
    make clean
    make
    cd ../../
done

echo "All levels compiled successfully!"
