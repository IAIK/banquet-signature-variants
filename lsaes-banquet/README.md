# LS-AES-Banquet
Banquet implementation using LS-AES as a block cipher.


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