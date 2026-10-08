# Generated engine benchmarks

Measured locally on 2026-10-08T21:58:30.035Z. These are development measurements, not latency guarantees.

Hardware: Apple M3 Max, 14 logical CPUs, 36 GiB RAM; darwin/arm64; Node v24.19.0.

Synthetic fan-out: one owner, N independently owned identities, N application grants to one resource. Default query bounds; 100 repeated direct-grant cache reads. Wall times are local measurements, not service-level claims.

| Nodes | Edges | Compile (ms) | Query (ms) | Cached query mean (ms) | Paths returned | Limited | RSS (MiB) |
|---|---|---|---|---|---|---|---|
| 102 | 200 | 3.63 | 1.73 | 0.050 | 100 | False | 65.9 |
| 1002 | 2000 | 18.16 | 3.66 | 0.214 | 128 | True | 81.9 |
| 5002 | 10000 | 89.42 | 19.63 | 1.019 | 128 | True | 152.3 |

Larger fan-outs deliberately stop at 128 paths and report a limited result. The benchmark does not silently claim complete enumeration. Compile and query numbers include one cold sample; repeated cached queries use 100 iterations. RSS is process memory at the sample point, not isolated allocation. Reproduce with `pnpm engine:benchmark`; distributions and hardware are included in its JSON output.
