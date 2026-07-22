# Evidence: a protected clinical EHR medication-administration service

A runnable, self-verifying demonstration in a safety-critical domain. A clinical medication-administration service is protected with Actenon's shipped FastAPI adapter; the one authorized administration runs, and every adversarial variant — wrong patient, overdose, wrong drug, wrong route, double dose, stale order, missing/malformed proof — is refused before any side effect.

> No valid proof, no execution.
