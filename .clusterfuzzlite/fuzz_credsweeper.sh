#!/bin/sh
# LLVMFuzzerTestOneInput for fuzzer detection.
set -x
pwd
ls -al
this_dir=$(dirname "$0")
LD_PRELOAD=$this_dir/sanitizer_with_fuzzer.so \
ASAN_OPTIONS=$ASAN_OPTIONS:symbolize=1:external_symbolizer_path=$this_dir/llvm-symbolizer:detect_leaks=0 \
$this_dir/fuzz_credsweeper.pkg $@
