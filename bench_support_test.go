package main

import "time"

// Benchmark sinks. Pure functions benchmarked in a loop can be eliminated
// entirely once inlined if their results are discarded; writing the result to
// a package-level variable forces the compiler to keep the work.
var (
	sinkBool     bool
	sinkString   string
	sinkStrings  []string
	sinkDuration time.Duration
)
