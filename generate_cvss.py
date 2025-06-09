#!/usr/bin/env python3
"""
Calculate CVSS Base, Temporal, and Overall scores for vulnerabilities using a vector DB.
Fixes three random metric parameters and retrieves the rest from vector DB matches.
"""

import json
import logging
import os
from pathlib import Path
from cvss import CVSS3
from decimal import Decimal
import numpy as np
from sentence_transformers import SentenceTransformer
import faiss
import pickle
from typing import List, Dict, Tuple
import os

print(os.getcwd())
# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Valid CVSS v3.1 metric values
CVSS_METRICS = {
    "AV": ["N", "A", "L", "P"],  # Attack Vector
    "AC": ["L", "H"],            # Attack Complexity
    "PR": ["N", "L", "H"],       # Privileges Required
    "UI": ["N", "R"],            # User Interaction
    "S": ["U", "C"],             # Scope
    "C": ["N", "L", "H"],        # Confidentiality Impact
    "I": ["N", "L", "H"],        # Integrity Impact
    "A": ["N", "L", "H"],        # Availability Impact
    "E": ["X", "U", "P", "F", "H"],  # Exploit Code Maturity
    "RL": ["X", "O", "T", "W", "U"], # Remediation Level
    "RC": ["X", "U", "R", "C"]   # Report Confidence
}

class VulnerabilityVectorDB:
    """Load and query an existing FAISS vector database for vulnerability data."""
    
    def __init__(self, index_dir: str = "./vector_db") -> None:
        self.index_dir = Path(index_dir)
        self.index_path = self.index_dir / "vuln_index.faiss"
        self.metadata_path = self.index_dir / "vuln_metadata.json"
        self.model_path = self.index_dir / "embedding_model.pkl"
        
        # Load FAISS index
        self.index = faiss.read_index(str(self.index_path))
        self.index.nprobe = 10
        
        # Load metadata
        with open(self.metadata_path, 'r', encoding='utf-8') as f:
            self.metadata = json.load(f)
        
        # Load model config and initialize SentenceTransformer
        with open(self.model_path, 'rb') as f:
            model_config = pickle.load(f)
        self.model = SentenceTransformer(model_config["model_name"])
        self.dimension = self.model.get_sentence_embedding_dimension()
        logger.info(f"Loaded vector DB from {index_dir} with {len(self.metadata)} entries")

    def query(self, query_texts: List[str], k: int = 1) -> List[Dict]:
        """Query the vector database for the closest match."""
        query_embeddings = self.model.encode(query_texts, show_progress_bar=True, normalize_embeddings=True).astype('float32')
        distances, indices = self.index.search(query_embeddings, k)
        results = []

        for query_idx in range(len(query_texts)):
            idx = indices[query_idx][0]
            if idx >= 0 and idx < len(self.metadata):
                result = self.metadata[idx].copy()
                result["distance"] = float(distances[query_idx][0])
                results.append(result)
            else:
                results.append({"description": query_texts[query_idx], "vector": {}, "distance": float('inf')})
                logger.warning(f"No match found for '{query_texts[query_idx][:50]}...'")
        
        return results

import os
from pathlib import Path
import logging

# Assuming logger is already configured
logger = logging.getLogger(__name__)

def load_vulnerabilities(data_dir: str) -> List[Dict]:
    """Load vulnerability data from all JSON files in the directory."""
    data_dir_path = Path(data_dir).resolve()  # Convert to absolute path
    logger.debug(f"Checking directory: {data_dir_path}")
    if not data_dir_path.exists():
        logger.error(f"Directory {data_dir_path} does not exist")
        return []
    if not data_dir_path.is_dir():
        logger.error(f"Path {data_dir_path} is not a directory")
        return []

    vulnerabilities = []
    json_files = list(data_dir_path.glob("*.json"))
    logger.debug(f"Found {len(json_files)} JSON files in {data_dir_path}")
    for json_file in json_files:
        try:
            logger.debug(f"Processing file: {json_file}")
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if isinstance(data, list):
                    for entry in data:
                        if isinstance(entry, dict) and "description" in entry:
                            vulnerabilities.append(entry)
                else:
                    logger.warning(f"Skipping {json_file}: Expected JSON array")
        except Exception as e:
            logger.error(f"Failed to load {json_file}: {e}")
    
    logger.info(f"Loaded {len(vulnerabilities)} vulnerabilities from {len(json_files)} JSON files")
    return vulnerabilities

def calculate_cvss_score(description: str, fixed_metrics: Dict[str, str], matched_vector: Dict[str, str]) -> Dict:
    """Calculate CVSS Base, Temporal, and Overall scores."""
    # Combine metrics: prioritize fixed metrics, then matched vector, then defaults
    metrics = {}
    all_metric_keys = list(CVSS_METRICS.keys())

    # Apply fixed metrics
    metrics.update(fixed_metrics)

    # Merge with matched vector, overriding only unfixed metrics
    for key in all_metric_keys:
        if key not in metrics:
            metrics[key] = matched_vector.get(key, CVSS_METRICS[key][0])  # Default to first value if missing

    # Construct CVSS vector string
    vector_parts = [f"{k}:{v}" for k, v in metrics.items()]
    vector_string = "/".join(["CVSS:3.1"] + vector_parts)
    logger.debug(f"CVSS vector for '{description[:50]}...': {vector_string}")

    try:
        cvss = CVSS3(vector_string)
        base_score = float(cvss.base_score) if cvss.base_score is not None else None
        temporal_score = float(cvss.temporal_score) if cvss.temporal_score is not None else None
        overall_score = float(cvss.environmental_score) if cvss.environmental_score is not None else None  # Using environmental as overall

        if base_score == 0.0:
            logger.warning(f"Base Score is 0.0 for '{description[:50]}...'. Check impact metrics (C, I, A).")

        return {
            "description": description,
            "cvss_vector": vector_string,
            "base_score": base_score,
            "temporal_score": temporal_score,
            "overall_score": overall_score
        }
    except ValueError as e:
        logger.error(f"Invalid CVSS vector for {description[:50]}...: {e}")
        return {"description": description, "cvss_vector": vector_string, "base_score": None, "temporal_score": None, "overall_score": None}

def process_vulnerabilities(data_dir: str, vector_db: VulnerabilityVectorDB, output_dir: str) -> None:
    """Process vulnerabilities and calculate CVSS scores."""
    vulnerabilities = load_vulnerabilities(data_dir)
    if not vulnerabilities:
        logger.warning("No vulnerabilities to process")
        return

    output_dir_path = Path(output_dir)
    output_dir_path.mkdir(parents=True, exist_ok=True)
    output_file = output_dir_path / "cvss_scores_with_vector_db.json"

    results = []
    for vuln in vulnerabilities:
        description = vuln.get("description", "")
        if not description:
            logger.warning("Skipping vulnerability with no description")
            continue

        # Query vector DB for the closest match
        matches = vector_db.query([description])
        matched_vector = matches[0].get("vector", {})

        # Randomly select 3 metrics to fix
        metric_keys = list(CVSS_METRICS.keys())
        np.random.shuffle(metric_keys)
        fixed_metrics = {}
        for key in metric_keys[:3]:  # Fix first 3 random metrics
            fixed_metrics[key] = np.random.choice(CVSS_METRICS[key])

        logger.debug(f"Fixed metrics for '{description[:50]}...': {fixed_metrics}")
        logger.debug(f"Matched vector: {matched_vector}")

        # Calculate CVSS scores
        result = calculate_cvss_score(description, fixed_metrics, matched_vector)
        results.append(result)

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)
    logger.info(f"Saved CVSS scores to {output_file} with {len(results)} entries")

def main() -> None:
    data_dir = "./output"
    vector_db_dir = "./vector_db"
    output_dir = "./output/cvss_scores"

    # Load vector DB
    vector_db = VulnerabilityVectorDB(index_dir=vector_db_dir)
    process_vulnerabilities(data_dir, vector_db, output_dir)

if __name__ == "__main__":
    main()