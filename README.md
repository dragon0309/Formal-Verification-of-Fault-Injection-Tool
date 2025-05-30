# Fault Injection Verification Tool

A formal verification framework for analyzing cryptographic circuits' resistance against fault injection attacks using SAT solvers.

## Overview

This tool evaluates the security of cryptographic implementations by modeling fault injection attacks as SAT problems. It can verify whether a circuit with countermeasures can effectively resist specific types of fault attacks.

## Supported Circuits

- **XOR Cipher**
- **S-Box**

## Features

### Fault Models
- **bit-flip**: Inverts the output (ite(control, !output, output))
- **set**: Forces output to constant 1 (ite(control, true, output))
- **reset**: Forces output to constant 0 (ite(control, false, output))

### Countermeasure Types
- **Detection**: Verifies if the circuit can detect injected faults

### Analysis Options
- Configurable fault quantity constraints (n_e)
- Multiple solver options (PySAT or external MiniSAT)

## Installation

### Requirements
- Python 3.8+
- Dependencies:
  ```
  python-sat>=0.1.7.dev6
  z3-solver>=4.12.0.0
  loguru>=0.7.0
  ```

### Setup

1. **Clone the repository**
   ```bash
   git clone [https://github.com/dragon0309/Formal-Verification-of-Fault-Injection-Tool.git fault_verification]
   cd fault_verification
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Basic Command

```bash
python src/main.py [circuit_name]
```

### Circuit Options
- `xor_cipher`
- `sbox`

### Examples

**Basic verification:**
```bash
python src/main.py xor_cipher
```

**Specify fault type:**
```bash
python src/main.py xor_cipher --fault-type set
```

**Choose n_e:**
```bash
python src/main.py xor_cipher -n_e 2
```

**Combined parameters:**
```bash
python src/main.py xor_cipher --fault-type set -n_e 2
```

## Project Structure

```
├── src/
│   ├── cnf_encoder.py    # Handles circuit-to-CNF conversion
│   ├── sat_solver.py     # Interfaces with SAT solvers
│   └── main.py           # Command-line interface
├── inputs/               # Circuit JSON definitions
├── outputs/              # Generated CNF files
├── requirements.txt      # Dependencies
└── README.md             # Documentation
```

## Core Components

### CNF Encoder

The `cnf_encoder.py` module converts circuit descriptions to CNF formulas:
- Translates gate logic to clauses
- Implements fault injection models
- Encodes countermeasure constraints


### SAT Solver Interface

The `sat_solver.py` module provides:
- Integration with PySAT and external MiniSAT
- Result interpretation based on countermeasure type
- Model parsing and fault vector extraction
- Robust error handling

### Main Program

The `main.py` script offers:
- Command-line argument processing
- JSON configuration handling
- Execution flow coordination
- Comprehensive logging

## Notes

- Input circuit definitions must be in the `inputs/` directory as JSON files
- The tool creates CNF files in the `outputs/` directory