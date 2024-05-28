**NexaJS**

![Python](https://img.shields.io/badge/Python-3.x-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Contributions](https://img.shields.io/badge/Contributions-Welcome-orange.svg)

NexaJS is a Python script designed to scrape and analyze JavaScript files from a specified website. It detects various patterns such as sensitive information, API endpoints, and suspicious keywords, and generates a comprehensive report in JSON or text format.

## Features

- ![Sensitive Information Detection](https://img.shields.io/badge/Sensitive%20Information%20Detection-%E2%9C%85-brightgreen.svg) : Identifies API keys, JWT tokens, URLs, emails, and passwords in JavaScript files.
- ![Library Detection](https://img.shields.io/badge/Library%20Detection-%E2%9C%85-brightgreen.svg) : Detects the usage of popular libraries like jQuery, React, AngularJS, and Vue.js, and checks for vulnerable versions.
- ![Obfuscated Code Detection](https://img.shields.io/badge/Obfuscated%20Code%20Detection-%E2%9C%85-brightgreen.svg) : Identifies obfuscated JavaScript code.
- ![Code Complexity Measurement](https://img.shields.io/badge/Code%20Complexity%20Measurement-%E2%9C%85-brightgreen.svg) : Measures the complexity of JavaScript code based on lines of code and control structures.
- ![External API Call Analysis](https://img.shields.io/badge/External%20API%20Call%20Analysis-%E2%9C%85-brightgreen.svg) : Detects external API calls made from the JavaScript files.
- ![Deprecated API Detection](https://img.shields.io/badge/Deprecated%20API%20Detection-%E2%9C%85-brightgreen.svg) : Identifies the usage of deprecated JavaScript APIs.
- ![GDPR/Privacy Compliance](https://img.shields.io/badge/GDPR/Privacy%20Compliance-%E2%9C%85-brightgreen.svg) : Detects scripts related to GDPR and privacy compliance.

## Installation


1. Clone the repository:
    git clone https://github.com/Ly0kha/NexaJS.git
   
    cd NexaJS

3. Install the required dependencies:
    pip install -r requirements.txt

## Usage

Run the script with the necessary arguments:

python nexajs.py --url <website_url> --output <output_file> --format <output_format> --timeout <timeout> --retries <retries> --exclude <exclude_patterns> --verbose

### Arguments

- `--url`: The URL of the website to scrape.
- `--output`: The output file for the report (default: `report.json`).
- `--format`: The format of the output report (`json` or `text`, default: `json`).
- `--timeout`: Timeout for network requests (default: `10` seconds).
- `--retries`: Number of retries for network requests (default: `3`).
- `--exclude`: Patterns to exclude from analysis.
- `--verbose`: Enable verbose output.

## Example

python nexajs.py --url https://example.com --output report.json --format json --timeout 10 --retries 3 --exclude "example\.com" --verbose

## Contact

For any inquiries or issues, please open an issue on the [GitHub repository](https://github.com/Ly0kha/NexaJS/issues)
