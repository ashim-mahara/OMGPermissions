import json
import sqlite3
import logging
from datetime import datetime
from typing import List, Dict, Optional
import litellm
from litellm import completion
from concurrent.futures import ThreadPoolExecutor, as_completed
from prompts import GPT_5_PROMPT

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class PermissionRiskAnalyzer:
    """
    Analyzes Microsoft Graph API permissions and assigns risk scores using LLMs.
    """

    def __init__(self, db_path: str = "permission_analysis.db"):
        """
        Initialize the analyzer with database connection.

        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        self._init_database()

    def _init_database(self):
        """Initialize SQLite database with required tables."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS permission_analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                permission_name TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                model_name TEXT NOT NULL,
                reasoning TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(permission_name, model_name)
            )
        """)

        conn.commit()
        conn.close()
        logger.info("Database initialized successfully")

    def _get_prompt(self, permission_data: Dict) -> str:
        """
        Generate prompt for risk analysis.

        Args:
            permission_data: Dictionary containing permission information

        Returns:
            Formatted prompt string
        """
        return (
            GPT_5_PROMPT
            + f"""
            Permission Data: {json.dumps(permission_data, indent=2)}
            """
        )

    def analyze_permission(
        self,
        permission_data: Dict,
        model: str = "gpt-3.5-turbo",
        api_base_url: Optional[str] = None,
        api_key: Optional[str] = None,
    ) -> Optional[Dict]:
        """
        Analyze a single permission and return risk assessment.

        Args:
            permission_data: Permission data dictionary
            model: LLM model to use for analysis

        Returns:
            Dictionary with risk analysis or None if failed
        """
        try:
            # Check if already processed
            if self._is_processed(permission_data.get("permission", ""), model):
                logger.info(
                    f"Permission {permission_data.get('permission')} already processed with {model}"
                )
                return None

            prompt = self._get_prompt(permission_data)

            response = completion(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.1,  # Low temperature for consistent scoring
                base_url=api_base_url,
                api_key=api_key,
            )

            # Extract JSON from response
            content = response.choices[0].message.content
            json_str = self._extract_json(content)
            risk_data = json.loads(json_str)

            result = {
                "permission_name": permission_data.get("permission", ""),
                "risk_score": risk_data.get("risk_score"),
                "model_name": model,
                "reasoning": risk_data.get("reasoning", ""),
            }

            # Save to database
            self._save_to_db(result)

            logger.info(
                f"Analyzed {result['permission_name']} - Risk: {result['risk_score']}"
            )
            return result

        except Exception as e:
            logger.error(
                f"Error analyzing permission {permission_data.get('name', 'unknown')}: {str(e)}"
            )
            logger.debug("result: ", result)
            return None

    def _extract_json(self, text: str) -> str:
        """
        Extract JSON string from LLM response.

        Args:
            text: Raw response text from LLM

        Returns:
            Extracted JSON string
        """
        # Simple JSON extraction - looks for { ... } pattern
        start = text.find("{")
        end = text.rfind("}") + 1

        if start != -1 and end != 0:
            return text[start:end]
        else:
            raise ValueError("No JSON found in response")

    def _is_processed(self, permission_name: str, model_name: str) -> bool:
        """
        Check if permission was already processed with given model.

        Args:
            permission_name: Name of the permission
            model_name: Name of the model used

        Returns:
            Boolean indicating if already processed
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            "SELECT 1 FROM permission_analysis WHERE permission_name = ? AND model_name = ?",
            (permission_name, model_name),
        )

        exists = cursor.fetchone() is not None
        conn.close()

        return exists

    def _save_to_db(self, result: Dict):
        """
        Save analysis result to database.

        Args:
            result: Dictionary containing analysis results
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT OR REPLACE INTO permission_analysis
            (permission_name, risk_score, model_name, reasoning)
            VALUES (?, ?, ?, ?)
        """,
            (
                result["permission_name"],
                result["risk_score"],
                result["model_name"],
                result["reasoning"],
            ),
        )

        conn.commit()
        conn.close()

    def process_jsonl_file(
        self,
        file_path: str,
        models: List[str] = None,
        api_base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        num_workers: int = 5,
    ) -> List[Dict]:
        """
        Process a JSONL file and analyze all permissions using parallel requests.
        """
        if models is None:
            models = ["gpt-3.5-turbo"]

        results = []

        try:
            with open(file_path, "r", encoding="utf-8") as file:
                lines = [line.strip() for line in file if line.strip()]

            # Process in parallel
            with ThreadPoolExecutor(max_workers=num_workers) as executor:
                futures = []

                for line_num, line in enumerate(lines, 1):
                    future = executor.submit(
                        self._process_line_with_models,
                        line,
                        line_num,
                        models,
                        api_base_url,
                        api_key,
                    )
                    futures.append(future)

                # Collect results
                for future in as_completed(futures):
                    try:
                        line_results = future.result()
                        results.extend(line_results)
                    except Exception as e:
                        logger.error(f"Error in parallel processing: {str(e)}")

        except FileNotFoundError:
            logger.error(f"File not found: {file_path}")
            return []

        logger.info(f"Processed {len(results)} permission analyses")
        return results

    def _process_line_with_models(
        self,
        line: str,
        line_num: int,
        models: List[str],
        api_base_url: Optional[str],
        api_key: Optional[str],
    ) -> List[Dict]:
        """Helper method to process a single line with all models."""
        try:
            permission_data = json.loads(line)
            line_results = []

            for model in models:
                result = self.analyze_permission(
                    permission_data, model, api_base_url, api_key
                )
                if result:
                    line_results.append(result)

            return line_results

        except json.JSONDecodeError as e:
            logger.error(f"Error parsing line {line_num}: {str(e)}")
            return []

    def get_analysis_results(self, permission_name: str = None) -> List[Dict]:
        """
        Retrieve analysis results from database.

        Args:
            permission_name: Optional filter for specific permission

        Returns:
            List of analysis results
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        if permission_name:
            cursor.execute(
                "SELECT permission_name, risk_score, model_name, reasoning, created_at FROM permission_analysis WHERE permission_name = ?",
                (permission_name,),
            )
        else:
            cursor.execute(
                "SELECT permission_name, risk_score, model_name, reasoning, created_at FROM permission_analysis"
            )

        results = []
        for row in cursor.fetchall():
            results.append(
                {
                    "permission_name": row[0],
                    "risk_score": row[1],
                    "model_name": row[2],
                    "reasoning": row[3],
                    "created_at": row[4],
                }
            )

        conn.close()
        return results


# Standalone function for simple usage
def analyze_permissions_file(
    file_path: str,
    models: List[str] = None,
    db_path: str = "permission_analysis.db",
    api_base_url: Optional[str] = None,
    api_key: Optional[str] = None,
    num_workers: int = 5,
):
    """
    Standalone function to analyze permissions from JSONL file.

    Args:
        file_path: Path to JSONL file
        models: List of models to use
        db_path: Path to SQLite database
    """
    analyzer = PermissionRiskAnalyzer(db_path)
    return analyzer.process_jsonl_file(
        file_path, models, api_base_url, api_key, num_workers
    )


if __name__ == "__main__":
    # Example usage
    import argparse

    parser = argparse.ArgumentParser(
        description="Analyze Microsoft Graph API permissions for risk"
    )
    parser.add_argument("--file", "-f", required=True, help="Path to JSONL file")
    parser.add_argument("--api_base_url", "-a", default=None, help="LLM API base URL")
    parser.add_argument("--api_key", "-k", default=None, help="LLM API key")
    parser.add_argument(
        "--num_workers",
        "-n",
        type=int,
        default=5,
        help="Number of worker threads for requests",
    )
    parser.add_argument(
        "--models",
        "-m",
        nargs="+",
        default=["gpt-3.5-turbo"],
        help="Models to use for analysis",
    )
    parser.add_argument(
        "--db", "-d", default="permission_analysis.db", help="SQLite database path"
    )

    args = parser.parse_args()

    # Set your API keys (configure based on your LLM provider)
    # litellm.configure_azure_key()  # For Azure
    # os.environ["OPENROUTER_API_KEY"] = "your-key"  # For OpenRouter

    print(f"Starting analysis of {args.file} using models: {args.models}")

    results = analyze_permissions_file(
        args.file,
        args.models,
        args.db,
        args.api_base_url,
        args.api_key,
        args.num_workers,
    )

    if results:
        print(f"Successfully analyzed {len(results)} permissions")
        print("\nSample results:")
        for result in results[:3]:  # Show first 3 results
            print(
                f"- {result['permission_name']}: Risk {result['risk_score']} ({result['model_name']})"
            )
    else:
        print("No new permissions analyzed (may have been processed already)")
