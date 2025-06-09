
"""
Siemens Vulnerability Fetcher
Fetches vulnerability data from the Siemens ProductCERT API with sequential notification IDs,
storing all data in a single JSON file as an array.
"""

import json
import logging
import requests
from pathlib import Path
import argparse
from typing import Dict, List, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

class SiemensVulnFetcher:
    """Fetches and processes vulnerability data from the Siemens ProductCERT API."""
    
    def __init__(self, output_dir: str = "./output", output_file: str = "siemens_vulns.json") -> None:
        self.base_url = "https://svm.cert.siemens.com/portal/api/v1/public/notifications/"
        self.output_dir = Path(output_dir)
        self.output_file = self.output_dir / output_file
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._load_existing_data()
        logger.info("Siemens Vulnerability Fetcher initialized")

    def _load_existing_data(self) -> None:
        """Load existing data from the output JSON file if it exists."""
        if self.output_file.exists():
            try:
                with open(self.output_file, 'r', encoding='utf-8') as f:
                    self.existing_data = json.load(f)
                if not isinstance(self.existing_data, list):
                    self.existing_data = []
            except json.JSONDecodeError:
                self.existing_data = []
        else:
            self.existing_data = []

    def parse_vector(self, vector_string: Optional[str]) -> Dict[str, str]:
        """
        Parse a CVSS vector string into a nested dictionary.

        Args:
            vector_string (Optional[str]): The CVSS vector string (e.g., "CVSS:3.0/AV:N/AC:L/...").

        Returns:
            Dict[str, str]: A dictionary with CVSS parameters (e.g., {"AV": "N", "AC": "L", ...}).
        """
        if not vector_string or not isinstance(vector_string, str):
            return {
                "AV": "", "AC": "", "PR": "", "UI": "", "S": "",
                "C": "", "I": "", "A": "", "E": "", "RL": "", "RC": ""
            }

        # Initialize the result dictionary
        result = {
            "AV": "", "AC": "", "PR": "", "UI": "", "S": "",
            "C": "", "I": "", "A": "", "E": "", "RL": "", "RC": ""
        }

        # Parse the vector string (e.g., "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N/E:U/RL:O/RC:C")
        try:
            components = vector_string.split('/')
            for component in components:
                if ':' in component:
                    key, value = component.split(':')
                    if key in result:
                        result[key] = value
                    elif key == 'I':
                        result['H'] = value  # Map 'I' from vector to 'H' in output
        except Exception as e:
            logger.error(f"Failed to parse vector string {vector_string}: {e}")

        return result

    def fetch_vulnerability(self, notification_id: int) -> Optional[Dict]:
        """
        Fetch vulnerability data for a given notification ID.

        Args:
            notification_id (int): The notification ID to fetch.

        Returns:
            Optional[Dict]: Processed vulnerability data or None if fetch fails.
        """
        url = f"{self.base_url}{notification_id}"
        try:
            response = requests.get(url, timeout=10, verify=False)  # SSL verification disabled
            response.raise_for_status()
            data = response.json()
            
            # Handle CVSS metrics (set to 0 if null or missing)
            cvss_metrics = data.get("cvss_v3_metrics", {})
            base_score = cvss_metrics.get("base_score", 0) if cvss_metrics else 0
            temporal_score = cvss_metrics.get("temporal_score", 0) if cvss_metrics else 0
            overall_score = cvss_metrics.get("overall_score", 0) if cvss_metrics else 0
            vector = cvss_metrics.get("vector", "") if cvss_metrics else ""

            # Extract required fields
            processed_data = {
                "notification_id": data.get("notification_id"),
                "title": data.get("title"),
                "solution": data.get("solution_details"),
                "impact": data.get("impact"),
                "description": data.get("description"),
                "synopsis": data.get("description_template"),
                "cvss_base_score": base_score,
                "cvss_temporal_score": temporal_score,
                "cvss_overall_score": overall_score,
                "vector": self.parse_vector(vector)
            }
            
            logger.info(f"Successfully fetched data for notification {notification_id}")
            return processed_data
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to fetch data for notification {notification_id}: {e}")
            return None
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON response for notification {notification_id}: {e}")
            return None

    def save_data(self, data: List[Dict]) -> None:
        """Save the combined data to the output JSON file."""
        combined_data = self.existing_data + data
        with open(self.output_file, 'w', encoding='utf-8') as f:
            json.dump(combined_data, f, indent=2)
        logger.info(f"Saved data to {self.output_file} with {len(combined_data)} entries")

    def process_notifications(self, start_id: int, max_requests: int) -> List[Dict]:
        """
        Process sequential notification IDs starting from start_id.

        Args:
            start_id (int): The base notification ID to start from (e.g., 68429).
            max_requests (int): Maximum number of requests to make.

        Returns:
            List[Dict]: List of processed vulnerability data.
        """
        results = []
        current_id = start_id
        
        for i in range(max_requests):
            logger.info(f"Fetching data for notification ID: {current_id}")
            data = self.fetch_vulnerability(current_id)
            if data:
                results.append(data)
            else:
                logger.info(f"Skipping invalid notification ID {current_id}, proceeding to next ID")
            
            current_id += 1
        
        self.save_data(results)
        return results

def main() -> None:
    parser = argparse.ArgumentParser(description='Fetch vulnerability data from Siemens ProductCERT API with sequential IDs')
    parser.add_argument('--start-id', '-s', type=int, default=68429, help='Base notification ID to start from (default: 68429)')
    parser.add_argument('--max-requests', '-m', type=int, default=10, help='Maximum number of requests to make (default: 10)')
    parser.add_argument('--output-dir', '-o', default='./output', help='Directory to save the output JSON file')
    
    args = parser.parse_args()
    
    fetcher = SiemensVulnFetcher(output_dir=args.output_dir)
    entries = fetcher.process_notifications(args.start_id, args.max_requests)
    
    if entries:
        print("\nProcessed Vulnerabilities:")
        for entry in entries:
            print(f"\nNotification ID: {entry['notification_id']}")
            print(f"Title: {entry['title']}")
            print(f"Synopsis: {entry['synopsis']}")
            print(f"Description: {entry['description']}")
            print(f"Impact: {entry['impact']}")
            print(f"Solution: {entry['solution']}")
            print(f"CVSS Base Score: {entry['cvss_base_score']}")
            print(f"CVSS Temporal Score: {entry['cvss_temporal_score']}")
            print(f"CVSS Overall Score: {entry['cvss_overall_score']}")
            print("Vector:")
            for key, value in entry['vector'].items():
                print(f"  {key}: {value}")
    else:
        print("No vulnerabilities processed.")

if __name__ == "__main__":
    main()