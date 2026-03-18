"""gips runtime package."""

__version__ = "1.0.0"

FEATURES = (
    "lookup",
    "batch",
    "probe",
    "status",
    "doctor",
    "shell",
    "version",
    "json",
    "jsonl",
    "csv",
    "rdns",
    "asn",
    "whois",
    "latency",
)

__all__ = ["FEATURES", "__version__", "cli"]
