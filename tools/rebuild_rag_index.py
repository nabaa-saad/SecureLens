"""Rebuild the local FAISS index for the bundled threat knowledge base."""

from __future__ import annotations

import json
from pathlib import Path

import faiss
import numpy as np
from sentence_transformers import SentenceTransformer


ROOT = Path(__file__).resolve().parents[1]
RAG_DIR = ROOT / "app" / "data" / "rag"
JSON_PATH = RAG_DIR / "knowledge_base.json"
INDEX_PATH = RAG_DIR / "index.faiss"
METADATA_PATH = RAG_DIR / "metadata.json"
MODEL_NAME = "all-MiniLM-L6-v2"


def build_document(entry: dict) -> str:
    return "\n".join(
        [
            f"Threat: {entry.get('threat_name', '')}",
            f"Category: {entry.get('category', '')}",
            f"Definition: {entry.get('definition', '')}",
            f"Attack Mechanism: {entry.get('attack_mechanism', '')}",
            "Technical Indicators: " + ", ".join(entry.get("technical_indicators", [])[:6]),
            "Detection Methods: " + ", ".join(entry.get("detection_methods", [])[:6]),
            "Keywords: " + ", ".join(entry.get("keywords", [])[:8]),
        ]
    )


def main() -> None:
    print(f"Loading threat knowledge from {JSON_PATH} ...")
    threats = json.loads(JSON_PATH.read_text(encoding="utf-8"))
    documents = [build_document(entry) for entry in threats]

    print(f"Encoding {len(documents)} threat documents with {MODEL_NAME} ...")
    model = SentenceTransformer(MODEL_NAME)
    embeddings = model.encode(documents, show_progress_bar=True)
    embeddings = np.asarray(embeddings, dtype="float32")

    dimension = embeddings.shape[1]
    index = faiss.IndexFlatL2(dimension)
    index.add(embeddings)

    print(f"Writing index to {INDEX_PATH} ...")
    faiss.write_index(index, str(INDEX_PATH))

    print(f"Writing metadata to {METADATA_PATH} ...")
    METADATA_PATH.write_text(
        json.dumps(threats, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print("RAG index rebuild complete.")


if __name__ == "__main__":
    main()
