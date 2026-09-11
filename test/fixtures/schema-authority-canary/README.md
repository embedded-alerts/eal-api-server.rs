# Independent schema-authority canary

`main.tsp` and `authored.schema.json` are independently maintained peer authorities. Neither file is generated from, ranked below, or allowed to overwrite the other.

CI (`.github/workflows/typespec-json-schema-peer-authority.yml`) runs [ORESoftware/typespec-json-schema-validator](https://github.com/ORESoftware/typespec-json-schema-validator) pinned to an exact commit: it generates JSON Schema B from TypeSpec into `.typespec-json-schema-validator/generated/`, validates both JSON Schema lanes as Draft 2020-12, compares top-level declarations and normalized semantics, executes bidirectional instance probes, and then proves the consumer-admission refusals. The generated schema and the deterministic receipt are evidence only.

Any unexplained mismatch returns `stopped_for_evaluation` and blocks promotion; execution failure returns `failed`. A passing canary proves this repository runs the gate. It does not certify unrelated domain contracts: those declarations must be independently authored in both lanes and admitted separately before downstream generation or release.
