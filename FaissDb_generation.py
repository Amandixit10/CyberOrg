#!/usr/bin/env python3
"""
Build an optimized FAISS vector database from vulnerability JSON data.
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
from typing import List, Dict, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

class VulnerabilityVectorDB:
    """Builds and manages an optimized FAISS vector database for vulnerability data."""
    
    def __init__(self, json_file: str = "./output/siemens_vulns.json", index_dir: str = "./index", model_name: str = "all-MiniLM-L6-v2") -> None:
        self.json_file = Path(json_file)
        self.index_dir = Path(index_dir)
        self.index_dir.mkdir(parents=True, exist_ok=True)
        self.index_path = self.index_dir / "vuln_index.faiss"
        self.metadata_path = self.index_dir / "vuln_metadata.json"
        self.model_path = self.index_dir / "embedding_model.pkl"
        
        # Initialize Sentence Transformer model
        self.model_name = model_name
        self.model = SentenceTransformer(model_name)
        self.dimension = self.model.get_sentence_embedding_dimension()  # Dynamically get dimension
        logger.info(f"Initialized SentenceTransformer model: {model_name} with dimension {self.dimension}")
        
        self.index = None
        self.metadata = []
        self.id_to_index = {}

    def load_data(self) -> List[Dict]:
        """Load vulnerability data from the JSON file."""
        try:
            with open(self.json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            if not isinstance(data, list):
                logger.error(f"Expected JSON array in {self.json_file}, got {type(data)}")
                return []
            
            # Validate and filter entries
            valid_data = []
            invalid_count = 0
            for entry in data:
                if not isinstance(entry, dict):
                    logger.warning(f"Skipping invalid entry (not a dict): {entry}")
                    invalid_count += 1
                    continue
                if "description" not in entry or not entry["description"].strip():
                    logger.warning(f"Skipping entry with missing/empty description: {entry.get('notification_id', 'unknown')}")
                    invalid_count += 1
                    continue
                valid_data.append(entry)
            
            logger.info(f"Loaded {len(valid_data)} valid vulnerability entries from {self.json_file}. Skipped {invalid_count} invalid entries.")
            return valid_data
        except Exception as e:
            logger.error(f"Failed to load JSON file {self.json_file}: {e}")
            return []

    def build_index(self) -> None:
        """Build the FAISS index from the vulnerability data."""
        # Load data
        vuln_data = self.load_data()
        if not vuln_data:
            logger.warning("No data to process, exiting")
            return

        # Prepare text for embedding and metadata
        texts = []
        self.metadata = []
        for idx, entry in enumerate(vuln_data):
            notification_id = entry.get("notification_id", f"vuln_{idx}")  # Fallback ID if missing
            description = entry.get("description", "")
            text = f"{entry.get('synopsis', '')} {description}".strip()
            texts.append(text)
            
            # Include CVSS vector if available, otherwise use a placeholder
            cvss_vector = entry.get("cvss_vector", {
                "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "N", "I": "N", "A": "N"
            })
            
            self.metadata.append({
                "notification_id": notification_id,
                "title": entry.get("title", ""),
                "synopsis": entry.get("synopsis", ""),
                "description": description,
                "cvss_vector": cvss_vector
            })

        if not texts:
            logger.warning("No valid text data to index, exiting")
            return

        # Generate embeddings using Sentence Transformers
        logger.info("Generating embeddings with SentenceTransformer...")
        embeddings = self.model.encode(texts, show_progress_bar=True, normalize_embeddings=True).astype('float32')

        # Build FAISS index with IndexIVFFlat for scalability
        logger.info("Building FAISS index with IndexIVFFlat...")
        num_embeddings = len(embeddings)
        # Dynamically set nlist to be at most the number of embeddings, but at least 1
        nlist = max(1, min(int(np.sqrt(num_embeddings)), num_embeddings))
        logger.info(f"Number of embeddings: {num_embeddings}, setting nlist to {nlist}")
        quantizer = faiss.IndexFlatL2(self.dimension)
        self.index = faiss.IndexIVFFlat(quantizer, self.dimension, nlist, faiss.METRIC_L2)
        
        # Train the index
        self.index.train(embeddings)
        self.index.add(embeddings)
        self.index.nprobe = min(10, nlist)  # Number of clusters to search (trade-off between speed and accuracy)

        # Create ID to index mapping, handling duplicates
        self.id_to_index = {}
        for idx, meta in enumerate(self.metadata):
            nid = meta["notification_id"]
            if nid in self.id_to_index:
                logger.warning(f"Duplicate notification_id found: {nid}, keeping last entry")
            self.id_to_index[nid] = idx

        # Save the index, metadata, and model configuration
        faiss.write_index(self.index, str(self.index_path))
        with open(self.metadata_path, 'w', encoding='utf-8') as f:
            json.dump(self.metadata, f, indent=2)
        with open(self.model_path, 'wb') as f:
            pickle.dump({"model_name": self.model_name}, f)
        logger.info(f"Saved FAISS index to {self.index_path}, metadata to {self.metadata_path}, and model config to {self.model_path}")

    def query(self, query_texts: List[str], k: int = 5) -> List[List[Dict]]:
        """Batch query the vector database for similar vulnerabilities."""
        if self.index is None:
            logger.error("FAISS index not built, call build_index() first")
            return []

        # Generate embeddings for the queries
        query_embeddings = self.model.encode(query_texts, show_progress_bar=True, normalize_embeddings=True).astype('float32')

        # Search the index
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
    parser = argparse.ArgumentParser(description='Build an optimized FAISS vector database from vulnerability data')
    parser.add_argument('--json-file', '-j', default='./output/siemens_vulns.json', help='Path to the JSON file with vulnerability data')
    parser.add_argument('--index-dir', '-i', default='./index', help='Directory to save the FAISS index and metadata')
    parser.add_argument('--model-name', '-m', default='all-MiniLM-L6-v2', help='SentenceTransformer model to use for embeddings')
    parser.add_argument('--query', '-q', type=str, help='Query text to search for similar vulnerabilities after building the index')
    parser.add_argument('--top-k', '-k', type=int, default=5, help='Number of similar vulnerabilities to return (default: 5)')
    
    args = parser.parse_args()
    
    vector_db = VulnerabilityVectorDB(json_file=args.json_file, index_dir=args.index_dir, model_name=args.model_name)
    vector_db.build_index()
    
    if args.query:
        logger.info(f"Querying vector database with: {args.query}")
        results = vector_db.query([args.query], k=args.top_k)[0]  # Batch query with a single query
        if results:
            print("\nTop Similar Vulnerabilities:")
            for result in results:
                print(f"\nNotification ID: {result['notification_id']}")
                print(f"Title: {result['title']}")
                print(f"Synopsis: {result['synopsis']}")
                print(f"Description: {result['description']}")
                print(f"CVSS Vector: {result['cvss_vector']}")
                print(f"Distance: {result['distance']:.4f}")
        else:
            print("No similar vulnerabilities found.")

if __name__ == "__main__":
    main()