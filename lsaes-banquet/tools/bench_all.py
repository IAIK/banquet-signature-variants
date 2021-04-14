#!/usr/bin/env python3
import sys
import os

executable = "./bench_free"
parser = "./"
logfile = "bench_output.txt"
iterations = 100

# kappa, N, Tau, m1, m2
parameters = [
    (128, 16, 41, 5, 10),
    (128, 31, 35, 5, 10),
    (128, 64, 31, 5, 10),
    (128, 128, 28, 5, 10),
    (128, 256, 25, 5, 10),
    (128, 512, 24, 5, 10),
    (128, 1024, 22, 5, 10),
]


SCALING_FACTOR = 1000 * 3600


def parse_bench(filename):
    with open(filename, "r") as f:
        content = f.read()

    testruns = content.split("Instance: ")
    if len(testruns) > 1:
        testruns.pop(0)

    for test in testruns:
        lines = test.splitlines()
        # first line is instance:
        # print(lines[0])
        lines.pop(0)
        # second line is header:
        # print(lines[0])
        lines.pop(0)

        count = 0
        keygen, sign, ver, size, ser, deser = 0, 0, 0, 0, 0, 0

        for line in lines:
            if len(line.strip()) == 0:
                continue
            vals = line.strip().split(",")
            keygen += int(vals[0])
            sign += int(vals[1])
            ver += int(vals[2])
            size += int(vals[3])
            ser += int(vals[4])
            deser += int(vals[5])
            count += 1

        keygen = (keygen / SCALING_FACTOR) / count
        sign = (sign / SCALING_FACTOR) / count
        ver = (ver / SCALING_FACTOR) / count
        size = float(size) / count
        ser = (ser / SCALING_FACTOR) / count
        deser = (deser / SCALING_FACTOR) / count
        print("{:.2f} & {:.2f} & {:.0f} \\\\".format(
            sign, ver, size))


for kappa, N, tau, m1, m2 in parameters:
    os.system("{executable} -i {iter} {kappa} {N} {tau} {m1} {m2} > {logfile}".format(
        executable=executable, iter=iterations, kappa=kappa/8, N=N, tau=tau, logfile=logfile, m1=m1,m2=m2))
    print("{kappa} & {N} & {tau} & ".format(kappa=kappa, N=N, tau=tau), end="")
    parse_bench(logfile)
