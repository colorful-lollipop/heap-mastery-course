#!/bin/bash
# Test all levels

set -e

echo "=========================================="
echo "  Heap Mastery Course - Test All Levels"
echo "=========================================="
echo ""

LEVELS=("level00_setup" "level01_overflow" "level02_uaf" "level03_fastbin_dup" "level04_tcache" "level05_heap_spray" "level06_feng_shui" "level07_advanced")

# Test compilation
echo "### Testing compilation ###"
for level in "${LEVELS[@]}"; do
    echo ""
    echo "Compiling $level..."
    cd "$level/challenge"
    make clean > /dev/null 2>&1 || true
    make
    cd ../../
done

echo ""
echo "✓ All levels compiled successfully!"

# Test Level 0
echo ""
echo "### Testing Level 0: Environment Check ###"
cd level00_setup
if [ -f "check_env" ]; then
    ./check_env
else
    echo "Level 0 not built yet"
fi
cd ..

echo ""
echo "=========================================="
echo "  All tests completed!"
echo "=========================================="
