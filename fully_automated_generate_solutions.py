#!/usr/bin/env python3
"""
Fully automated script to process CVSS data, generate solutions using Ollama's tinyllma-1B model,
and store enriched data with severity in a new folder.
"""

import json
import logging
import os
from pathlib import Path
import requests
from cvss import CVSS3
from decimal import Decimal
import numpy as np
from sentence_transformers import SentenceTransformer
import faiss
import pickle
from typing import List, Dict

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Hardcoded paths
INPUT_FILE = "./output/cvss_scores/cvss_scores_with_vector_db.json"
VECTOR_DB_DIR = "./vector_db"
OUTPUT_DIR = "./output/solutions"
OLLAMA_API_URL = "http://localhost:11434/api/generate"

# Valid CVSS v3.1 metric values (for reference)
CVSS_METRICS = {
    "AV": ["N", "A", "L", "P"],
    "AC": ["L", "H"],
    "PR": ["N", "L", "H"],
    "UI": ["N", "R"],
    "S": ["U", "C"],
    "C": ["N", "L", "H"],
    "I": ["N", "L", "H"],
    "A": ["N", "L", "H"],
    "E": ["X", "U", "P", "F", "H"],
    "RL": ["X", "O", "T", "W", "U"],
    "RC": ["X", "U", "R", "C"]
}

class VulnerabilityVectorDB:
    """Load and query an existing FAISS vector database for vulnerability data."""
    
    def __init__(self):
        self.index_dir = Path(VECTOR_DB_DIR)
        self.index_path = self.index_dir / "vuln_index.faiss"
        self.metadata_path = self.index_dir / "vuln_metadata.json"
        self.model_path = self.index_dir / "embedding_model.pkl"
        
        # Load FAISS index
        self.index = faiss.read_index(str(self.index_path))
        self.index.nprobe = 10
        
        # Load metadata
        with open(self.metadata_path, 'r', encoding='utf-8') as f:
            self.metadata = json.load(f)
        
        # Load SentenceTransformer
        logger.info("Loading sentence transformer model...")
        self.model = SentenceTransformer('all-MiniLM-L6-v2')
        self.dimension = self.model.get_sentence_embedding_dimension()
        logger.info(f"Loaded vector DB from {VECTOR_DB_DIR} with {len(self.metadata)} entries")

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

class OllamaTinyLLM:
    """Wrapper for Ollama's tinyllma-1B model to generate solutions via API."""
    
    def __init__(self, api_url: str = OLLAMA_API_URL, model_name: str = "tinyllama"):
        self.api_url = api_url
        self.model_name = model_name
        logger.info(f"Initialized OllamaTinyLLM with model {model_name} at {api_url}")

    def generate_solution(self, description: str, cvss_context: str, matched_solution: str) -> str:
        """Generate a solution using Ollama's tinyllma-1B model."""
        prompt = f"""
You are a friendly security expert. Based on the following vulnerability description, CVSS context, and any existing solution, provide a practical solution with a human touch. If no existing solution fits or is available, propose a similar one based on best practices.

**Description**: {description}
**CVSS Context**: {cvss_context}
**Existing Solution (if any)**: {matched_solution or 'None'}

Please suggest a solution that is easy to understand, actionable, and written in a warm, supportive tone. Keep it concise but helpful!

### Solution:
"""
        payload = {
            "model": self.model_name,
            "prompt": prompt,
            "stream": False,
            "temperature": 0.7,
            "max_tokens": 150
        }
        
        try:
            response = requests.post(self.api_url, json=payload, timeout=120
                                     )
            response.raise_for_status()
            result = response.json()
            solution = result.get("response", "").strip()
            return solution if solution else "Oops! No solution generated—please check with your security team!"
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to generate solution: {e}")
            return "Error generating solution—please consult your security team!"

def load_cvss_data() -> List[Dict]:
    """Load CVSS data from the input JSON file."""
    try:
        with open(INPUT_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Failed to load {INPUT_FILE}: {e}")
        return []

def determine_severity(base_score: float) -> str:
    """Determine severity based on CVSS Base Score."""
    if base_score is None:
        return "Unknown"
    elif base_score >= 9.0:
        return "Critical"
    elif base_score >= 7.0:
        return "High"
    elif base_score >= 4.0:
        return "Medium"
    else:
        return "Low"

def process_and_generate_solutions():
    """Automatically process CVSS data, generate solutions, and save enriched data."""
    # Initialize components
    vector_db = VulnerabilityVectorDB()
    llm = OllamaTinyLLM()

    # Load CVSS data
    cvss_data = load_cvss_data()
    if not cvss_data:
        logger.warning("No CVSS data to process")
        return

    output_dir_path = Path(OUTPUT_DIR)
    output_dir_path.mkdir(parents=True, exist_ok=True)
    output_file = output_dir_path / "enriched_vulnerability_solutions.json"

    results = []
    for entry in cvss_data:
        description = entry.get("description", "")
        cvss_vector = entry.get("cvss_vector", "")
        base_score = entry.get("base_score", None)
        temporal_score = entry.get("temporal_score", None)
        overall_score = entry.get("overall_score", None)

        if not description or base_score is None:
            logger.warning(f"Skipping entry with incomplete data: {description[:50]}...")
            continue

        # Query vector DB for matching description
        matches = vector_db.query([description])
        matched_entry = matches[0]
        matched_solution = matched_entry.get("solution", "No pre-existing solution available")

        # Prepare CVSS context for LLM
        cvss_context = (
            f"Base Score: {base_score}, Temporal Score: {temporal_score}, "
            f"Overall Score: {overall_score}, Vector: {cvss_vector}"
        )

        # Generate solution with Ollama's tinyllma-1B
        solution = llm.generate_solution(description, cvss_context, matched_solution)
        logger.debug(f"Generated solution for '{description[:50]}...': {solution[:100]}...")

        # Determine severity
        severity = determine_severity(base_score)

        # Store enriched data
        results.append({
            "description": description,
            "cvss_vector": cvss_vector,
            "base_score": base_score,
            "temporal_score": temporal_score,
            "overall_score": overall_score,
            "severity": severity,
            "solution": solution
        })

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)
    logger.info(f"Saved enriched data to {output_file} with {len(results)} entries")

def main():
    process_and_generate_solutions()

if __name__ == "__main__":
    main()