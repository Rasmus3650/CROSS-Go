# CROSS-Go

**CROSS-Go** is a Go implementation of the **CROSS** post-quantum digital signature scheme. The implementation adheres closely to the official specification and is designed to be efficient and constant-time. Both theoretical analysis and practical evaluation (e.g., via DUDECT) support the claim of constant-time execution.

This implementation is **interoperable** with the official C reference implementation — signatures generated with the C reference can be verified using this Go implementation, and vice versa.

---

## 📦 Installation

To use CROSS-Go in your Go project:

1. **Initialize a Go module** (if you haven't already):

```bash
go mod init <your_project_name>
```

2. **Import the CROSS-Go library:**
```bash
go get github.com/Rasmus3650/CROSS-Go@v1.0.0
```

## 🗂️ Project Structure
```bash
CROSS-Go/
├── bench_profile.go
├── common/                  # Core arithmetic and utility functions
│   ├── cross.go
│   ├── fp_arith.go
│   ├── merkle.go
│   ├── pack_unpack.go
│   ├── params.go
│   ├── restr_arith.go
│   ├── seed.go
│   ├── shake.go
│   ├── tree_aux.go
│   └── utils.go
├── cpu.prof
├── debug_CROSS_submission/ # Official submission structure with additional materials
│   ├── Additional_Implementations/
│   ├── KAT/
│   ├── Optimized_Implementation/
│   ├── README
│   ├── Reference_Implementation/
│   └── Supporting_Documentation/
├── docs/
│   ├── literature/
│   └── template/
├── dudect/                 # DUDECT-based timing analysis for constant-time validation
│   ├── dudect_funcs.go
│   ├── dudect_funcs_different_key.go
│   ├── dudect.go
│   ├── makefile
│   └── utils.go
├── go.mod
├── go.sum
├── graphs/                 # Scripts and output visualizations
│   ├── balanced_tree.png
│   ├── fast_tree.png
│   ├── fast_tree.py
│   ├── memory_graph.py
│   ├── memory_graph_2.py
│   ├── runtime_graph.py
│   └── tree_graphs.py
├── KAT/                    # Known Answer Test framework
│   ├── interpreter.go
│   ├── KAT_DATA
│   └── sha_KAT.sh
├── LICENSE
├── main.go
├── pkg/
│   └── vanilla/
├── README.md
└── test/                   # Unit and integration tests
    ├── bench_test.go
    ├── compatibility_test.go
    ├── data/
    ├── keygen_test.go
    ├── merkle_test.go
    ├── negative_test.go
    ├── seed_test.go
    ├── shake_test.go
    ├── sign_rsdp_test.go
    └── sign_rsdpg_test.go
CROSS-Go/
├── bench_profile.go
├── common/                  # Core arithmetic and utility functions
│   ├── cross.go
│   ├── fp_arith.go
│   ├── merkle.go
│   ├── pack_unpack.go
│   ├── params.go
│   ├── restr_arith.go
│   ├── seed.go
│   ├── shake.go
│   ├── tree_aux.go
│   └── utils.go
├── cpu.prof
├── debug_CROSS_submission/ # Official submission structure with additional materials
│   ├── Additional_Implementations/
│   ├── KAT/
│   ├── Optimized_Implementation/
│   ├── README
│   ├── Reference_Implementation/
│   └── Supporting_Documentation/
├── docs/
│   ├── literature/
│   └── template/
├── dudect/                 # DUDECT-based timing analysis for constant-time validation
│   ├── dudect_funcs.go
│   ├── dudect_funcs_different_key.go
│   ├── dudect.go
│   ├── makefile
│   └── utils.go
├── go.mod
├── go.sum
├── graphs/                 # Scripts and output visualizations
│   ├── balanced_tree.png
│   ├── fast_tree.png
│   ├── fast_tree.py
│   ├── memory_graph.py
│   ├── memory_graph_2.py
│   ├── runtime_graph.py
│   └── tree_graphs.py
├── KAT/                    # Known Answer Test framework
│   ├── interpreter.go
│   ├── KAT_DATA
│   └── sha_KAT.sh
├── LICENSE
├── main.go
├── pkg/
│   └── vanilla/
├── README.md
└── test/                   # Unit and integration tests
    ├── bench_test.go
    ├── compatibility_test.go
    ├── data/
    ├── keygen_test.go
    ├── merkle_test.go
    ├── negative_test.go
    ├── seed_test.go
    ├── shake_test.go
    ├── sign_rsdp_test.go
    └── sign_rsdpg_test.go
```
## 📄 Supporting Documentation
A PDF of the Master’s thesis detailing the CROSS implementation and its design decisions will be linked here in the future.

## 📝 License
This project is released into the public domain. See LICENSE for details.
