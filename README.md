# IDTOligoAnalyzer

Python script to enable batch mode primer analysis using the IDT OligoAnalyzer API.

## Usage

1. Create a text file containing one primer sequence per line. Blank lines and lines beginning with `#` are ignored.
2. Export your IDT API credentials as environment variables or supply them on the command line:
   - `IDT_CLIENT_ID`
   - `IDT_CLIENT_SECRET`
   - `IDT_USERNAME`
   - `IDT_PASSWORD`
3. Run the batch analyzer:

```bash
python oligo_analyzer.py primers.txt --output results.json
```

Optional arguments:

- `--client-id`, `--client-secret`, `--username`, `--password`: Provide credentials explicitly instead of using environment variables.
- `--payload-template`: Path to a JSON file containing the base payload for the analysis request if you need to customize the API options. The script automatically inserts each sequence.
- `--output`: Path to the JSON file where results will be stored (default: `analysis_results.json`).

The script retrieves an access token, submits each sequence to the IDT OligoAnalyzer API, and writes the responses to the output JSON file. Failures are captured alongside successful responses for easier troubleshooting.
