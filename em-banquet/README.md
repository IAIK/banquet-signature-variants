# EM-Banquet
Banquet implementation using AES-128 in a single-key Evan-Mansour construction.


## Requirements

C++17 Compatible Toolchain

## Setup

```bash
mkdir build
cd build
cmake ..
make 
# benchmarks
./bench_free -i <iterations> <kappa> <N> <tau> <m1> <m2> #benchmark parameters freely
python3 ../tools/bench_all.py # benchmarks some of the selected parameters
```

The benchmark script contains a `SCALING_FACTOR` variable that is used to scale the measured cycles to ms. Configure it according to your specific machine.