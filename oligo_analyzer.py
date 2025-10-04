"""Batch primer analysis using the IDT OligoAnalyzer API."""
from __future__ import annotations

import argparse
import json
import os
from base64 import b64encode
from typing import Dict, Iterable, List, Tuple
from urllib import error, parse, request


def get_access_token(client_id: str, client_secret: str, idt_username: str, idt_password: str) -> str:
    """Return an OAuth access token for the IDT APIs."""
    authorization_string = b64encode(bytes(client_id + ":" + client_secret, "utf-8")).decode()
    request_headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": "Basic " + authorization_string,
    }

    data_dict = {
        "grant_type": "password",
        "scope": "test",
        "username": idt_username,
        "password": idt_password,
    }
    request_data = parse.urlencode(data_dict).encode()

    post_request = request.Request(
        "https://www.idtdna.com/Identityserver/connect/token",
        data=request_data,
        headers=request_headers,
        method="POST",
    )

    response = request.urlopen(post_request)
    body = response.read().decode()

    if response.status != 200:
        raise RuntimeError(
            "Request failed with error code:" + str(response.status) + "\nBody:\n" + body
        )

    body_dict = json.loads(body)
    return body_dict["access_token"]


DEFAULT_ANALYZE_REQUEST: Dict[str, object] = {
    # These defaults can be overridden via --payload-template if needed.
    "Sequence": "",
    "OligoType": "DNA",
    "NucleotideType": "DNA",
    "NaConc": 50.0,
    "MgConc": 0.0,
    "DntpConc": 0.0,
    "TrisConc": 0.0,
    "OligoConc": 0.25,
    "OligoConcUnits": "uM",
    "AnalysisType": "MeltCurve",
}


API_ENDPOINT = "https://www.idtdna.com/restapi/v1/OligoAnalyzer/Analyze"


class PrimerAnalysisError(RuntimeError):
    """Raised when an analysis request fails."""


def read_sequences(path: str) -> List[Tuple[int, str]]:
    """Return a list of (line_number, sequence) pairs from ``path``."""
    sequences: List[Tuple[int, str]] = []
    with open(path, "r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            sequence = line.strip()
            if not sequence or sequence.startswith("#"):
                continue
            sequences.append((line_number, sequence))

    if not sequences:
        raise ValueError("No primer sequences were found in the provided file.")

    return sequences


def load_template(path: str | None) -> Dict[str, object]:
    """Load the optional payload template used for the analysis request."""
    if path is None:
        return dict(DEFAULT_ANALYZE_REQUEST)

    with open(path, "r", encoding="utf-8") as handle:
        template = json.load(handle)

    if "Sequence" not in template:
        template["Sequence"] = ""

    return template


def resolve_secret(value: str | None, env_name: str, description: str) -> str:
    """Resolve a secret either from the CLI argument or the environment."""
    if value:
        return value

    env_value = os.getenv(env_name)
    if env_value:
        return env_value

    raise SystemExit(f"Missing {description}. Provide it via the CLI or the {env_name} environment variable.")


def analyze_sequence(sequence: str, token: str, base_payload: Dict[str, object]) -> Dict[str, object]:
    """Submit ``sequence`` for analysis and return the API response."""
    payload = dict(base_payload)
    payload["Sequence"] = sequence

    request_headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    data = json.dumps(payload).encode("utf-8")

    req = request.Request(API_ENDPOINT, data=data, headers=request_headers, method="POST")

    try:
        resp = request.urlopen(req)
        body = resp.read().decode("utf-8")
        if resp.status != 200:
            raise PrimerAnalysisError(
                f"Analysis request failed with HTTP {resp.status}: {body}"
            )
        return json.loads(body)
    except error.HTTPError as exc:  # pragma: no cover - requires live API
        raise PrimerAnalysisError(
            f"HTTPError during analysis request (status {exc.code}): {exc.read().decode('utf-8', 'ignore')}"
        ) from exc
    except error.URLError as exc:  # pragma: no cover - requires network failure
        raise PrimerAnalysisError(f"URLError during analysis request: {exc.reason}") from exc


def run_batch_analysis(
    sequences: Iterable[Tuple[int, str]],
    token: str,
    base_payload: Dict[str, object],
) -> List[Dict[str, object]]:
    """Analyze each sequence and return a list of result objects."""
    results: List[Dict[str, object]] = []
    for line_number, sequence in sequences:
        try:
            response = analyze_sequence(sequence, token, base_payload)
            results.append({
                "line": line_number,
                "sequence": sequence,
                "response": response,
            })
        except PrimerAnalysisError as exc:
            results.append({
                "line": line_number,
                "sequence": sequence,
                "error": str(exc),
            })
    return results


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze primer sequences using the IDT OligoAnalyzer API",
    )
    parser.add_argument("primer_file", help="Path to the text file containing one primer sequence per line.")
    parser.add_argument(
        "--client-id",
        dest="client_id",
        help="IDT API client identifier. Defaults to the IDT_CLIENT_ID environment variable.",
    )
    parser.add_argument(
        "--client-secret",
        dest="client_secret",
        help="IDT API client secret. Defaults to the IDT_CLIENT_SECRET environment variable.",
    )
    parser.add_argument(
        "--username",
        dest="username",
        help="IDT username. Defaults to the IDT_USERNAME environment variable.",
    )
    parser.add_argument(
        "--password",
        dest="password",
        help="IDT password. Defaults to the IDT_PASSWORD environment variable.",
    )
    parser.add_argument(
        "--payload-template",
        dest="payload_template",
        help=(
            "Optional JSON file containing the base payload sent to the analysis endpoint. "
            "The sequence field is automatically overwritten for each primer."
        ),
    )
    parser.add_argument(
        "--output",
        dest="output",
        default="analysis_results.json",
        help="Path to the JSON file where results will be written. Defaults to analysis_results.json.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_arguments()

    sequences = read_sequences(args.primer_file)
    payload_template = load_template(args.payload_template)

    client_id = resolve_secret(args.client_id, "IDT_CLIENT_ID", "client ID")
    client_secret = resolve_secret(args.client_secret, "IDT_CLIENT_SECRET", "client secret")
    username = resolve_secret(args.username, "IDT_USERNAME", "username")
    password = resolve_secret(args.password, "IDT_PASSWORD", "password")

    token = get_access_token(client_id, client_secret, username, password)

    results = run_batch_analysis(sequences, token, payload_template)

    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump({"results": results}, handle, indent=2)

    failures = sum(1 for item in results if "error" in item)
    successes = len(results) - failures

    print(f"Analysis complete. {successes} succeeded, {failures} failed. Results written to {args.output}.")


if __name__ == "__main__":
    main()
