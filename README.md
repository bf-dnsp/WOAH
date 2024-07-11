# WOAH - Website OSINT and Help Tool
Welcome to WOAH, the Website OSINT and Help tool. This script is designed to scrape and analyze information from websites for scoping and reconnaissance purposes.

## Features
- Detects CMS and SaaS platforms
- Analyzes website content for purpose
- Checks for deprecated features
- Counts cookies, scripts, and styles
- Detects cloud providers and login pages
- Estimates sitemap size
- Measures SSL certificate age and performance metrics
- Detects AJAX requests and interactive elements
- Extracts and analyzes HTTP response headers

## Installation
To use WOAH, you need to install a few Python packages:

    pip install requests beautifulsoup4 builtwith
 
## Usage
Run the script and input URLs separated by lines. Submit an empty line to start the analysis.

    python woah.py


## Output
The output file contains the following sections for each URL:

- Basics: URL, Title, Website Purpose Analysis, First 250 Characters
- Tech: Tech Stack, Cloud Provider, External APIs Count, Detected CMS/SaaS Platforms
- Features: Login Page Detected, Auth-required, Sitemap Size Estimate
- Jank: SSL Age Start, Performance Metrics, Script and Stylesheet - Count, Interactive Elements Count, AJAX Requests Count, Server - Header, Deprecated Features, Cookies Count

### Thanks!
Thanks to everyone who has tested this tool and provided feedback.
