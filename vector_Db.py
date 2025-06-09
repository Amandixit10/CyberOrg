#!/usr/bin/env python3
"""
Build an optimized FAISS vector database for vulnerability descriptions and metrics.
Uses Sentence Transformers for semantic embeddings and FAISS for similarity search.
"""

import json
import logging
from pathlib import Path
import numpy as np
from sentence_transformers import SentenceTransformer
import faiss
import argparse
import pickle
from typing import List, Dict

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

class VulnerabilityVectorDB:
    """Builds and manages an optimized FAISS vector database for vulnerability data."""
    
    def __init__(self, json_file: str = "./output/siemens_vulns.json", index_dir: str = "./vector_db", model_name: str = "all-MiniLM-L6-v2") -> None:
        self.json_file = Path(json_file)
        self.index_dir = Path(index_dir)
        self.index_dir.mkdir(parents=True, exist_ok=True)
        self.index_path = self.index_dir / "vuln_index.faiss"
        self.metadata_path = self.index_dir / "vuln_metadata.json"
        self.model_path = self.index_dir / "embedding_model.pkl"
        
        # Initialize Sentence Transformer model
        self.model_name = model_name
        self.model = SentenceTransformer(model_name)
        self.dimension = self.model.get_sentence_embedding_dimension()
        logger.info(f"Initialized SentenceTransformer model: {model_name} with dimension {self.dimension}")
        
        self.index = None
        self.metadata = []

    def load_data(self) -> List[Dict]:
        """Load vulnerability data from the JSON file."""
        try:
            with open(self.json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            if not isinstance(data, list):
                logger.error(f"Expected JSON array in {self.json_file}, got {type(data)}")
                return []
            
            valid_data = []
            for entry in data:
                if not isinstance(entry, dict) or "description" not in entry or not entry["description"].strip():
                    logger.warning(f"Skipping invalid entry: {entry.get('notification_id', 'unknown')}")
                    continue
                valid_data.append(entry)
            
            logger.info(f"Loaded {len(valid_data)} valid vulnerability entries from {self.json_file}")
            return valid_data
        except Exception as e:
            logger.error(f"Failed to load JSON file {self.json_file}: {e}")
            return []

    def build_index(self) -> None:
        """Build the FAISS index from the vulnerability data."""
        vuln_data = self.load_data()
        if not vuln_data:
            logger.warning("No data to process, exiting")
            return

        # Prepare text for embedding and metadata
        texts = []
        self.metadata = []
        for entry in vuln_data:
            description = entry["description"]
            texts.append(description)
            # Include all relevant fields in metadata
            self.metadata.append({
                "notification_id": entry.get("notification_id"),
                "title": entry.get("title", ""),
                "solution": entry.get("solution", ""),
                "impact": entry.get("impact", ""),
                "description": description,
                "synopsis": entry.get("synopsis", ""),
                "cvss_base_score": entry.get("cvss_base_score"),
                "cvss_temporal_score": entry.get("cvss_temporal_score"),
                "cvss_overall_score": entry.get("cvss_overall_score"),
                "vector": entry.get("vector", {
                    "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "N", "I": "N", "A": "N",
                    "E": "X", "RL": "X", "RC": "X"
                })
            })

        if not texts:
            logger.warning("No valid text data to index, exiting")
            return

        # Generate embeddings
        logger.info("Generating embeddings with SentenceTransformer...")
        embeddings = self.model.encode(texts, show_progress_bar=True, normalize_embeddings=True).astype('float32')

        # Build FAISS index with IndexIVFFlat
        logger.info("Building FAISS index with IndexIVFFlat...")
        nlist = max(100, int(np.sqrt(len(embeddings))))
        quantizer = faiss.IndexFlatL2(self.dimension)
        self.index = faiss.IndexIVFFlat(quantizer, self.dimension, nlist, faiss.METRIC_L2)
        
        self.index.train(embeddings)
        self.index.add(embeddings)
        self.index.nprobe = 10  # Adjust for speed vs. accuracy

        # Save the index and metadata
        faiss.write_index(self.index, str(self.index_path))
        with open(self.metadata_path, 'w', encoding='utf-8') as f:
            json.dump(self.metadata, f, indent=2)
        with open(self.model_path, 'wb') as f:
            pickle.dump({"model_name": self.model_name}, f)
        logger.info(f"Saved FAISS index to {self.index_path}, metadata to {self.metadata_path}, and model config to {self.model_path}")

    def query(self, query_texts: List[str], k: int = 5) -> List[List[Dict]]:
        """Query the vector database for similar vulnerabilities."""
        if self.index is None:
            logger.error("FAISS index not built, call build_index() first")
            return []

        query_embeddings = self.model.encode(query_texts, show_progress_bar=True, normalize_embeddings=True).astype('float32')
        distances, indices = self.index.search(query_embeddings, k)
        batch_results = []

        for query_idx in range(len(query_texts)):
            results = []
            for idx, distance in zip(indices[query_idx], distances[query_idx]):
                if idx >= 0 and idx < len(self.metadata):
                    result = self.metadata[idx].copy()
                    result["distance"] = float(distance)
                    results.append(result)
            batch_results.append(results)

        return batch_results

def main() -> None:
    parser = argparse.ArgumentParser(description='Build a FAISS vector database for vulnerability data')
    parser.add_argument('--json-file', '-j', default='./output/siemens_vulns.json', help='Path to the JSON file with vulnerability data')
    parser.add_argument('--index-dir', '-i', default='./vector_db', help='Directory to save the FAISS index and metadata')
    parser.add_argument('--model-name', '-m', default='all-MiniLM-L6-v2', help='SentenceTransformer model to use for embeddings')
    
    args = parser.parse_args()
    
    vector_db = VulnerabilityVectorDB(json_file=args.json_file, index_dir=args.index_dir, model_name=args.model_name)
    vector_db.build_index()

if __name__ == "__main__":
    main()