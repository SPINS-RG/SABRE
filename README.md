# SABRE Prototype Repository

This repository is for SABRE: Security Analysis and Binary Repair Engine. The corresponding research manuscript titled _Run-time Attestation and Auditing: the Verifier’s Perspective_ accepted to WiSec 2025. ([WiSec version](https://dl.acm.org/doi/abs/10.1145/3734477.3734710), [Author Version](https://arxiv.org/abs/2411.10855))

## Repository Layout

- `verifier/` — main source code (SABRE core + `run.sh` test runner)
- `ACFA/` — MSP430 binaries for the BEEBs applications and CFLogs from hardware-based CFA architecture ACFA
- `TRACES/` — ARM Cortex-M33 binaries for the BEEBs applications from instrumentation-based CFA architecture TRACES

Within `ACFA` and `TRACES`, applications live under a per-attack-class benchmark set:
- `beebs/` — OVF test cases. For MSP430 (`ACFA/beebs/<app>/attack/`), for ARM (`TRACES/beebs/<app>/`).
- `beebs-uaf/` — UAF test cases.

The OVF and UAF cases are derived from the two open-source CFA architectures described in the SABRE paper.

## Requirements

These instructions are for running on Ubuntu.

- For MSP430: `msp430-elf-gcc`, `msp430-objdump`, and the SABRE MSP430 toolchain
- For ARM: `arm-none-eabi-objdump` (Cortex-M33 target)
- Python 3 (system) for the `verifier` Python sources

## How to run

Run from the `verifier` directory:

```
cd verifier
./run.sh <ARCH> <APP> <ovf|uaf>
```

- `<ARCH>` — `msp430` or `arm`
- `<APP>` — a BEEBs application: `aha-compress`, `cover`, `crc_32`, `fibcall`, `jfdctint`, `lcdnum`, or `libbs`
- `<ovf|uaf>` — attack class to detect/patch; selects the benchmark set automatically (`ovf` → `beebs`, `uaf` → `beebs-uaf`)

Examples:

```
./run.sh msp430 crc_32 ovf
./run.sh arm    fibcall uaf
```

While running, SABRE will first verify the CF-Log, then perform backward tracing and symbolic data-flow analysis to identify the memory corruption that caused the eventual control flow violation. It then patches the vulnerability and re-verifies with the patched binary.

Expected output:

- OVF: `[!] BUFFER OVERFLOW DETECTED: <INSTR>` (or `ATTACK DETECTED`), then `[!] NO ATTACK DETECTED [!] Concluded at <INSTR>` once patched
- UAF: `[!] USE-AFTER-FREE DETECTED: <INSTR>`, then `[!] NO ATTACK DETECTED [!] Concluded at <INSTR>` once patched

Afterwards the patched binary is written back to the application's benchmark-set subdirectory:
- MSP430 OVF -> `ACFA/beebs/<app>/attack/patched.elf` and `patched.lst`
- MSP430 UAF -> `ACFA/beebs-uaf/<app>/patched.elf` and `patched.lst`
- ARM OVF -> `TRACES/beebs/<app>/patched.elf` and `patched.lst`
- ARM UAF -> `TRACES/beebs-uaf/<app>/patched.elf` and `patched.lst`

## Notes

- The `verifier` run shares a working directory, so runs must be sequential (the scripts overwrite `patched.elf`, `objs`, and `logs`).
- This codebase is a research prototype accompanying the paper mentioned above, and it is intended to reflect the approach described there. The paper is the authoritative description of the approach, including its scope, assumptions, and guarantees.

## BibTex Entries

Paper: 
```
@inproceedings{caulfield2025run,
  title={Run-time Attestation and Auditing: The Verifier's Perspective},
  author={Caulfield, Adam Ilyas and Rattanavipanon, Norrathep and Nunes, Ivan De Oliveira},
  booktitle={18th ACM Conference on Security and Privacy in Wireless and Mobile Networks},
  pages={16--27},
  year={2025}
}
```

This repository:
```
@misc{sabre_repo,
  title={{Github Repository for SABRE}},
  author={Caulfield, Adam Ilyas and Rattanavipanon, Norrathep and Nunes, Ivan De Oliveira},
  howpublished={\url{https://github.com/SPINS-RG/SABRE}}
  year={2025}
}
```
