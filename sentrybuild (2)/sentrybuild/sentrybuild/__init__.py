"""SentryBuild — supply chain integrity and dynamic-linking anomaly scanner.

SentryBuild inspects ELF binaries and shared libraries for signs of
supply-chain tampering: unexpected IFUNC resolvers, modified GOT/PLT
entries, unauthorized dynamic symbol hooks, and drift against a known-good
baseline. It is intended for build-provenance verification, CI/CD gating,
and forensic triage — not for modifying or exploiting binaries.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
