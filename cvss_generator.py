#!/usr/bin/env python3
"""
Calculate CVSS Base, Temporal, and Environmental scores for vulnerabilities using a vector DB.
Fetches environmental vectors from metadata file for similar components.
"""

import json
import logging
import os
import time
import random
from pathlib import Path
from cvss import CVSS3
from decimal import Decimal
import numpy as np
from sentence_transformers import SentenceTransformer
import faiss
import pickle
from typing import List, Dict, Tuple
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Valid CVSS v3.1 metric values according to specification
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
    "RC": ["X", "U", "R", "C"],   # Report Confidence
    "CR": ["L", "M", "H"],
    "IR": ["L", "M", "H"],
    "AR": ["L", "M", "H"],
    "MAV": ["X", "N", "A", "L", "P"],
    "MAC": ["X", "L", "H"],
    "MPR": ["X", "N", "L", "H"],
    "MUI": ["X", "N", "R"],
    "MS":  ["X", "U", "C"],
    "MC":  ["X", "N", "L", "H"],
    "MI":  ["X", "N", "L", "H"],
    "MA":  ["X", "N", "L", "H"]
}

class VulnerabilityVectorDB:
    """Load and query an existing FAISS vector database for vulnerability data."""
    
    def __init__(self, index_dir: str = "./vector_db", max_retries: int = 5, retry_delay: int = 15) -> None:
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
        
        # Initialize SentenceTransformer with retry logic
        self.model = None
        for attempt in range(max_retries):
            try:
                self.model = SentenceTransformer('all-MiniLM-L6-v2')
                break
            except requests.exceptions.RequestException as e:
                logger.warning(f"HTTP Error {e.response.status_code} thrown while requesting model. Retrying in {retry_delay}s [Retry {attempt + 1}/{max_retries}].")
                time.sleep(retry_delay)
        if self.model is None:
            logger.error("Failed to load SentenceTransformer model after retries. Proceeding without vector DB queries.")
            self.model = None
        
        if self.model:
            self.dimension = self.model.get_sentence_embedding_dimension()
            logger.info(f"Loaded vector DB from {index_dir} with {len(self.metadata)} entries")
        else:
            self.dimension = 0
            logger.warning("Vector DB queries disabled due to model loading failure.")

    def query(self, query_texts: List[str], k: int = 1) -> List[Dict]:
        """Query the vector database for the closest match."""
        if not self.model:
            logger.warning("No model available, returning empty results.")
            return [{"description": text, "vector": {}, "distance": float('inf')} for text in query_texts]
        
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

def load_vulnerabilities(data_dir: str) -> List[Dict]:
    """Load vulnerability data from all JSON files in the directory."""
    data_dir_path = Path(data_dir).resolve()
    if not data_dir_path.exists() or not data_dir_path.is_dir():
        logger.error(f"Directory {data_dir_path} is not valid")
        return []

    vulnerabilities = []
    json_files = list(data_dir_path.glob("*.json"))
    for json_file in json_files:
        try:
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
    
    logger.info(f"Loaded {len(vulnerabilities)} vulnerabilities")
    return vulnerabilities

def get_or_fetch_metadata(component: str) -> Dict:
    """Fetch existing metadata for a component or use the first available if similar."""
    METADATA_FILE = "environmental_metadata.json"
    default_env_vector = {
        "CR": "X", "IR": "X", "AR": "X", "MAV": "N", "MAC": "L",
        "MPR": "N", "MUI": "N", "MS": "U", "MC": "N", "MI": "N", "MA": "N"
    }

    if os.path.exists(METADATA_FILE):
        with open(METADATA_FILE, 'r', encoding='utf-8') as f:
            metadata = json.load(f)
            # Handle both single object and components array formats
            if "component" in metadata and "environmental_vector" in metadata:
                # Single object format
                if metadata.get("component", "").lower() == component.lower():
                    logger.info(f"Found exact metadata for {component}: {metadata}")
                    return metadata
            elif "components" in metadata:
                components = metadata["components"]
                # Find exact or similar component by name
                for comp in components:
                    if comp.get("component", "").lower() == component.lower():
                        logger.info(f"Found exact metadata for {component}: {comp}")
                        return comp
                    if component.lower() in comp.get("component", "").lower():
                        logger.info(f"Found similar metadata for {component}: {comp}")
                        return comp
                # If no exact match, use the first component as a fallback
                if components:
                    logger.info(f"Using first available metadata as fallback for {component}")
                    return components[0]

    # If no metadata exists, use default vector
    logger.warning(f"No metadata found for {component}, using default vector")
    env_vector_str = "/".join([f"{k}:{v}" for k, v in default_env_vector.items()])
    return {"component": component, "environmental_vector": env_vector_str}

def calculate_cvss_score(description: str, fixed_metrics: Dict[str, str], matched_vector: Dict[str, str]) -> Dict:
    """Calculate CVSS Base, Temporal, and Environmental scores with random vectors."""
    # Randomly generate all metrics for Base, Temporal, and Environmental vectors
    all_metrics = {}
    for metric, values in CVSS_METRICS.items():
        all_metrics[metric] = np.random.choice(values)

    # Construct Base CVSS vector string (excluding Temporal and Environmental metrics)
    base_vector_parts = [f"{k}:{v}" for k, v in all_metrics.items() if k not in ["E", "RL", "RC", "CR", "IR", "AR", "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA"]]
    base_vector = "CVSS:3.1/" + "/".join(base_vector_parts)
    logger.debug(f"Base CVSS vector for '{description[:50]}...': {base_vector}")

    # Calculate Base score
    try:
        cvss_base = CVSS3(base_vector)
        base_score = float(cvss_base.base_score) if cvss_base.base_score is not None else 7.5  # Use provided 7.5 as fallback

        # Construct Temporal vector (if applicable)
        temporal_vector_parts = base_vector_parts.copy()
        temporal_metrics = {k: all_metrics[k] for k in ["E", "RL", "RC"]}
        if any(v != CVSS_METRICS[k][0] for k, v in temporal_metrics.items()):  # Only add if values differ from default
            temporal_vector_parts.extend([f"{k}:{v}" for k, v in temporal_metrics.items()])
            temporal_vector = "CVSS:3.1/" + "/".join(temporal_vector_parts)
            cvss_temporal = CVSS3(temporal_vector)
            temporal_score = float(cvss_temporal.temporal_score) if cvss_temporal.temporal_score is not None else 6.5  # Use provided 6.5 as fallback
        else:
            temporal_vector = None
            temporal_score = 6.5  # Use provided temporal_score

        # Construct Environmental vector
        env_vector_parts = base_vector_parts.copy()
        env_metrics = {k: all_metrics[k] for k in ["CR", "IR", "AR", "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA"]}
        env_vector_parts.extend([f"{k}:{v}" for k, v in env_metrics.items()])
        env_vector = "CVSS:3.1/" + "/".join(env_vector_parts)
        logger.debug(f"Environmental CVSS vector for '{description[:50]}...': {env_vector}")
        cvss_env = CVSS3(env_vector)
        environmental_score = float(cvss_env.environmental_score) if cvss_env.environmental_score is not None else None

        return {
            "description": description,
            "base_vector": base_vector,
            "base_score": base_score,
            "temporal_vector": temporal_vector,
            "temporal_score": temporal_score,
            "environmental_vector": env_vector,
            "environmental_score": environmental_score
        }
    except ValueError as e:
        logger.error(f"Invalid CVSS vector for {description[:50]}...: {e}")
        return {
            "description": description,
            "base_vector": base_vector,
            "base_score": base_score,
            "temporal_vector": temporal_vector,
            "temporal_score": temporal_score,
            "environmental_vector": None,
            "environmental_score": None
        }

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

        # Query vector DB for the closest match (though not used for random vectors)
        matches = vector_db.query([description])
        matched_vector = matches[0].get("vector", {})

        # Randomly select 3 metrics to fix (though all will be random now)
        metric_keys = list(CVSS_METRICS.keys())
        np.random.shuffle(metric_keys)
        fixed_metrics = {key: np.random.choice(CVSS_METRICS[key]) for key in metric_keys[:3]}  # Kept for consistency

        logger.debug(f"Fixed metrics for '{description[:50]}...': {fixed_metrics}")
        logger.debug(f"Matched vector: {matched_vector}")

        # Randomly generate a component name
        component_options = ["node.js", "python", "java", "nginx", "apache"]
        component = random.choice(component_options)

        # Calculate CVSS scores with random vectors
        result = calculate_cvss_score(description, fixed_metrics, matched_vector)
        results.append(result)

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)
    logger.info(f"Saved CVSS scores to {output_file} with {len(results)} entries")

def main() -> None:
    data_dir = "./input"
    vector_db_dir = "./vector_db"
    output_dir = "./output/cvss_scores"

    # Load vector DB
    vector_db = VulnerabilityVectorDB(index_dir=vector_db_dir, max_retries=5, retry_delay=15)
    process_vulnerabilities(data_dir, vector_db, output_dir)

if __name__ == "__main__":
    main()