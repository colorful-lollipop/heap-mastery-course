# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an educational heap exploitation course ("Heap Mastery Course") with 8 progressive levels (0-7) teaching security researchers how to exploit heap vulnerabilities. Each level contains:
- **Vulnerable programs** (`challenge/vuln.c`) - C programs with intentional heap vulnerabilities for educational exploitation
- **Documentation** (theory.md, walkthrough.md, hints.md) - Comprehensive guides explaining exploitation techniques
- **Solution code** (exploit.py, exploit.c) - Reference implementations demonstrating successful exploitation

**Educational Purpose Only**: All code is for authorized security training, CTF competitions, and educational environments.

## Build System

### Root Build (CMake)
The project uses CMake for orchestration:

```bash
# Build all levels from clean
mkdir build && cd build
cmake ..
make

# Build with binary protections enabled
cmake -DENABLE_PROTECTIONS=ON ..
make

# Build solution/exploit code (not default)
cmake -DBUILD_SOLUTIONS=ON ..
make
```

**CMake Options**:
- `BUILD_SOLUTIONS=OFF` (default) - Only builds vulnerable programs, not exploit code
- `ENABLE_PROTECTIONS=OFF` (default) - Builds without PIE/canaries for easier learning

### Per-Level Builds (Makefile)
Each level has its own Makefile in `levelXX_*/challenge/`:

```bash
cd levelXX_*/challenge
make              # Build vulnerable program (no protections)
make pie          # Build with PIE enabled
make protections  # Build with full protections (stack canary, RELRO, PIE)
make flag         # Create flag.txt file for testing
make clean        # Remove build artifacts
```

**Build Output**: Binary named `vuln` in each `challenge/` directory

## Architecture

### Common Utilities Library
The `common/` directory contains a shared library (`libheap_utils.a`) providing:
- **heap_utils.c** - Chunk structure visualization, heap layout analysis, heap printing functions
- **debug_utils.c** - Hexdump, backtrace printing, colored debug macros

Used by Level 0's `check_env` program for environment verification.

### Vulnerable Program Structure
All vulnerable programs follow this pattern:
1. **Vulnerability** - Intentional heap bug (overflow, UAF, double free, etc.)
2. **Challenge goal** - Specific condition to trigger (e.g., make chunk2 equal "pwned!")
3. **Winner function** - Reads and displays flag.txt when challenge is solved
4. **Compilation flags** - Default: `-g -O0 -Wall -Wextra -fno-stack-protector -no-pie`

### Level Progression
- **Level 0**: Environment checker, validates gcc/gdb/pwndbg/pwntools installation
- **Level 1-2**: Basic vulnerabilities (heap overflow, UAF)
- **Level 3-4**: Core exploitation (fastbin double free, tcache poisoning)
- **Level 5-6**: Advanced layout (heap spraying, heap feng shui)
- **Level 7**: Modern mitigations bypass (Safe Linking, House techniques)

## Testing

### Full Test Suite
```bash
# From project root
./tests/test_all_levels.sh

# Test specific level (from build/)
./tests/test_all_levels.sh  # Compiles all levels and runs Level 0 check
```

### Manual Testing
```bash
# Test individual challenge
cd level01_overflow/challenge
make flag  # Create flag.txt
./vuln     # Run vulnerable program
# Then provide exploit input
```

### Exploit Testing
```bash
# Using provided exploit (Level 1 example)
cd level01_overflow/solution
python3 exploit.py  # Runs exploit against local vuln binary

# With GDB attached
python3 exploit.py DEBUG  # Attaches pwndbg automatically
```

## Development Workflow

### Adding New Levels
1. Create `levelXX_NAME/` directory
2. Add `challenge/vuln.c` with vulnerability
3. Create `CMakeLists.txt` following Level 0 pattern
4. Add to root `CMakeLists.txt` with `add_subdirectory(levelXX_NAME)`
5. Write README.md explaining the challenge
6. Add documentation in `docs/` subdirectory
7. Update root README.md level overview table

### Modifying Existing Levels
- **Vulnerability logic**: Edit `challenge/vuln.c`
- **Build flags**: Edit `challenge/Makefile`
- **Documentation**: Edit `docs/theory.md`, `docs/walkthrough.md`, `docs/hints.md`
- **Solution code**: Edit `solution/exploit.py`, `solution/exploit.c`

### Common Pitfalls

1. **Chunk metadata understanding**: glibc chunks have headers (prev_size, size, fd, bk) that affect heap layout
2. **glibc version differences**: Techniques vary significantly between glibc 2.27, 2.31, 2.32+ (Safe Linking)
3. **Protection interactions**: Even disabled protections (via `-no-pie`) can affect behavior; always test with both enabled and disabled
4. **ASLR effects**: Heap addresses randomize; exploits must use relative offsets or leak addresses

## Docker Environment

```bash
# Build and start container
docker-compose up -d

# Enter container
docker-compose exec course bash

# Inside container: already built, environment ready
./level00_setup/check_env  # Verify environment
cd level01_overflow/challenge && ./vuln  # Test challenge
```

**Container includes**:
- gcc, gdb, python3, pwntools (pre-installed)
- pwndbg and GEF (GDB plugins loaded via .gdbinit)
- Project pre-built in `/home/student/heap-course`

## Documentation Standards

Each level's README must include:
- Learning objectives
- Vulnerability description
- Challenge goal (exact condition to trigger winner())
- Difficulty rating and estimated time
- Prerequisites (previous levels)
- Hints reference to docs/hints.md

Theory/walkthrough/hints documents follow HTML `<details>` tags for collapsible progressive hint system.

## Key Technical Concepts

### glibc Heap Structure
```
Chunk layout (allocated):
+-----------+-------+------------------+
| prev_size | size  | user data        |
+-----------+-------+------------------+

Chunk layout (free):
+-----------+-------+-------+-------+------------------+
| prev_size | size  | fd    | bk    | (unused)         |
+-----------+-------+-------+-------+------------------+
```

### Exploit Primitives
- **Arbitrary write** - Control what address gets written to
- **Arbitrary read** - Read from controlled address
- **Heap overlap** - Multiple pointers to same chunk
- **Address leak** - Expose heap/libc addresses via puts/printf

### Modern Protections (Level 7)
- **Safe Linking** (glibc 2.32+) - XOR-obfuscated pointers in fastbin/tcache
- **Pointer encryption** - Mitigates fd/bk pointer corruption
- Requires new techniques (partial overwrite, House of Einherjar/Force)
