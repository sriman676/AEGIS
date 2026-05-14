# AEGIS AI - Semantic Analyzer (Tier 1)

This package implements the Tier 1 **AI-assisted semantic security** component for AEGIS. 

## Purpose

As defined in `02_Functional_Requirements.md` (FR-004), the semantic analyzer provides:
* Classifications
* Annotations
* Risk Enrichment
* Explanations

It is an **advisory** service. It does not enforce trust, bypass policy, or mutate invariants.

## Architecture

This service exposes a REST API via FastAPI that the Rust deterministic core (`aegis-core`) can call to enrich its risk reports and graphs.

## Running Locally

```bash
# Create a virtual environment
python -m venv .venv
# Activate it (Windows)
.venv\Scripts\activate
# Install dependencies
pip install -e .
# Run the server
uvicorn src.main:app --reload
```
