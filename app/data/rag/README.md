# Threat RAG Assets

This directory stores the bundled threat-knowledge assets used by the app's RAG pipeline.

Files:
- `knowledge_base.json`: primary threat knowledge corpus
- `index.faiss`: local vector index for retrieval
- `metadata.json`: exported metadata aligned with the index
- `cyber_threat_knowledge_base.txt`: source reference text used during curation

If `knowledge_base.json` changes, rebuild the index with:

```bash
python tools/rebuild_rag_index.py
```
