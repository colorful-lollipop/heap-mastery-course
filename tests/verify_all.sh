#!/bin/bash
# verify_all.sh - Test all levels with provided exploits
#
# This script runs the solution exploit for each level and verifies
# that the exploit works correctly.

set -e

BUILD_DIR="./build"
LEVELS=(
    "level01_overflow:l1_vuln"
    "level02_uaf:l2_vuln"
    "level03_fastbin_dup:l3_vuln"
    "level04_tcache:l4_vuln"
    "level05_heap_spray:l5_vuln"
    "level06_feng_shui:l6_vuln"
    "level07_advanced:l7_vuln"
)

PASSED=0
FAILED=0
TOTAL=0

echo "═════════════════════════════════════════════════════"
echo "   Heap Mastery Course - Automated Verification"
echo "═════════════════════════════════════════════════════"
echo ""

# Function to create flag file
create_flag() {
    local level_dir=$1
    echo "FLAG{level_${level_dir}_passed}" > "${BUILD_DIR}/${level_dir}/flag.txt"
}

# Test each level
for level_config in "${LEVELS[@]}"; do
    IFS=':' read -r level_name binary_name <<< "$level_config"

    TOTAL=$((TOTAL + 1))
    LEVEL_NUM=$(echo $level_name | grep -oP '\d+')

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Testing Level ${LEVEL_NUM}: ${level_name}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    # Check if binary exists
    if [ ! -f "${BUILD_DIR}/${level_name}/${binary_name}" ]; then
        echo "❌ Binary not found: ${BUILD_DIR}/${level_name}/${binary_name}"
        FAILED=$((FAILED + 1))
        echo ""
        continue
    fi

    # Check if exploit exists
    if [ ! -f "${level_name}/answer/exploit_solution.py" ]; then
        echo "❌ Exploit not found: ${level_name}/answer/exploit_solution.py"
        echo "   Skipping automated test"
        FAILED=$((FAILED + 1))
        echo ""
        continue
    fi

    # Create flag file
    create_flag "${level_name}"

    # Run exploit
    echo "Running exploit..."
    if timeout 10 python3 "${level_name}/answer/exploit_solution.py" 2>&1 | tee /tmp/level_${LEVEL_NUM}_output.txt | grep -q "Flag:"; then
        echo "✅ Level ${LEVEL_NUM} PASSED"
        PASSED=$((PASSED + 1))
    else
        echo "❌ Level ${LEVEL_NUM} FAILED"
        echo "   Output saved to /tmp/level_${LEVEL_NUM}_output.txt"
        FAILED=$((FAILED + 1))
    fi

    echo ""
done

# Summary
echo "═════════════════════════════════════════════════════"
echo "   Summary"
echo "═════════════════════════════════════════════════════"
echo "  Total Levels:  ${TOTAL}"
echo "  Passed:        ${PASSED}"
echo "  Failed:        ${FAILED}"
echo ""

if [ ${FAILED} -eq 0 ]; then
    echo "🎉 All levels passed!"
    exit 0
else
    echo "⚠️  Some levels failed. Check the output above."
    exit 1
fi
