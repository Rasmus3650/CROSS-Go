# PQC-Master-Thesis
```
├── README.md               # Project documentation, setup instructions
├── go.mod                 # Go module definition
├── go.sum                 # Go module checksums
├── cmd/                   # Command-line applications
│   ├── benchmark/         # Benchmarking tools
│   │   └── main.go
│   └── demo/             # Demo applications
│       └── main.go
├── internal/             # Private application and library code
│   ├── common/          # Shared utilities and constants
│   │   ├── params.go    # System parameters
│   │   └── utils.go     # Utility functions
│   ├── field/           # Finite field arithmetic (Example folder setup)
│   │   ├── field.go
│   │   └── operations.go
│   └── matrix/          # Matrix operations (Example folder setup)
│       ├── matrix.go
│       └── operations.go
├── pkg/                # Library code that can be used by external applications
│   ├── vanilla/        # Vanilla implementation
│   │   ├── signing.go
│   │   ├── verify.go
│   │   └── keygen.go
│   ├── optimized/      # Optimized implementation
│   │   ├── signing.go
│   │   ├── verify.go
│   │   ├── keygen.go
│   │   └── parallel.go
│   ├── constant_time/  # Constant-time implementation (stretch goal)
│   │   ├── signing.go
│   │   ├── verify.go
│   │   └── keygen.go
│   └── protocols/      # Protocol implementations
│       ├── basic/      # Pre Fiat-Shamir protocol
│       │   └── protocol.go
│       └── fiat_shamir/ # Fiat-Shamir protocols (Example folder setup)
│           ├── protocol_v1.go 
│           └── protocol_v2.go
├── test/              # Test data and test utilities
│   ├── testdata/      # Test data
│   └── helpers/       # Test helper functions
├── docs/              # Documentation
│   └── litterature/   # Reference Litterature
└── benchmarks/        # Benchmark results and analysis
    └── results/       # Benchmark data
```