# MemDedup

C++17 protocol implementation for **MemDedup: Privacy-Preserving Memory Deduplication for Cross-Domain Multi-Agent Systems**.

## Build

Target platform: Linux/POSIX. Dependencies: a C++17 compiler, CMake 3.16+, Boost headers and OpenSSL 1.1.1+. BLAKE3 C is included.

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j 2
```

The build produces `libmemdedup.a` and `libblake3_portable.a`. An application can add this directory using `add_subdirectory` and link `MemDedup::memdedup`; public headers use `#include <memdedup/...>`.

## Layout

```text
include/memdedup/
  field.h                  512-bit prime-field arithmetic
  types.h, record.h        Triple encoding and record types
  bucket.h, hash_util.h    Weighted IBLT buckets and PRFs
  dedup_protocol.h         Encoding, masks, verified peeling, auxiliary recovery
  key_exchange.h           Pairwise X25519 mask setup
  network.h                TCP sockets and framed messages
  envelope.h               Protected envelopes and message permutation
  update_state.h           Scheduling, replay handling and state commit
  update_protocol.h        Provider/aggregator update interfaces and Shuffle forwarding
src/                       Implementations
third_party/blake3/        BLAKE3 C and license files
```

## Protocol interfaces

### Initial aggregation

Each provider constructs `DedupProtocol` with common public parameters, the agreed record key, its own coefficient secret and pairwise mask seeds. `encodePrimary` produces the masked weighted IBLT. The aggregator calls `aggregateTables` and `decode` using `primaryHashSeed()`.

If primary recovery leaves a residual core, providers call `encodeAuxiliary` with the common residual bitmap and auxiliary dimensions. The aggregator decodes the auxiliary table using `auxiliaryHashSeed()` and unions both decoded outputs. All agreed providers, including those with empty input, supply their mask contributions in each active round.

### Incremental updates

`UpdateOperation` represents one insertion or global deletion. `UpdateProvider` fixes its operation set at construction; `primary()` and `auxiliary()` encode the same set and reuse its coefficient secret across rounds. Duplicate operations are removed locally. An empty operation set produces a mask-only cover contribution.

`UpdateAggregator::primary` aggregates and decodes the agreed provider tables. If needed, `unresolvedPrimaryMap()` supplies the residual map, and `auxiliary()` completes recovery. `commit()` modifies the supplied `State` only after complete recovery:

```text
K_next = (K union insertions) minus deletions
```

Deletion takes precedence within one batch; a later batch can reinsert the record. Batch and request identifiers prevent replay. `State::save/load` stores the record set and replay metadata in one snapshot. The batch ID supplied to `commit()` must match `ProtocolParams::seed`.

### Scheduling and protected transport

`Scheduler::submit`, `trigger` and `acknowledge` implement distinct-provider threshold/earliest-deadline triggering, merged requests, cover selection and failed-batch requeueing. Time values are supplied by the caller in a consistent monotonic time unit.

`BatchDescriptor` encodes the batch ID, ordered private roster and public table parameters with a SHA-256 digest. Use protected controls to deliver it to providers; `validateBatchDescriptor` checks the local parameters. Local provider ranks and pairwise-seed indices follow the descriptor's roster order. The aggregator need only know the participant count.

`sendProtectedTable` and `receiveProtectedTable` serialize canonical field elements and wrap tables in ephemeral X25519/SHA-256/AES-256-GCM envelopes. `forwardShuffledTables` receives opaque provider envelopes and forwards a random permutation; `receiveShuffledTables` opens the agreed number of tables at the aggregator. Protected controls use separate phase values. The batch ID and phase are authenticated envelope data.

The application establishes connections, provisions authenticated keys and supplies consistent parameters. A protocol execution consists of these per-role calls; applications can invoke them in separate processes.

After a successful `commit()`, the aggregator persists the state if required and sends a protected acknowledgment. Providers release the corresponding pending operations only after that acknowledgment. Failed recovery or a missing participant retains the pending requests; the application creates a new batch/session for retry.

## Parameters and encoding

- Both aggregation and updates use `q = 2^512 - 569`; a field element occupies 64 wire bytes and a bucket 192 bytes. Modular arithmetic uses wider intermediate values before reduction.
- `encodeTriple` serializes three already canonicalized UTF-8 strings as compact JSON and pads the complete record to 64 bytes. It rejects overlength input. It performs JSON escaping, but semantic canonicalization and UTF-8 validity are the caller's responsibility. `decodeTripleRecord` recovers the JSON bytes.
- A canonical triple begins with `[` (`0x5b`), so its integer encoding lies below `L=(q-1)/2`. Update record encryption cycle-walks the reversible cipher within `[0,L)`; `v=2*C+deletion` then fits injectively in the same field. Record bytes are preserved. Arbitrary binary strings outside that record domain are rejected.
- The caller chooses the participant count, hash degree, table capacities, session seed/batch ID, record key and provider secrets. Record encryption keys must be explicitly supplied; no public-seed fallback is used.

## Implementation scope

This is a research prototype. The record cipher retains the existing four-round BLAKE3-based Feistel construction with restricted-domain cycle walking. Protected transport uses OpenSSL primitives, while authenticated enrollment, network anonymity and automatic failure recovery belong to the application. Snapshot replacement uses rename and does not promise power-loss durability. Global deletion changes the aggregator's result rather than providers' local storage.

## Third-party dependencies

See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for dependency licenses.
