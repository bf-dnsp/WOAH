import requests
from bs4 import BeautifulSoup
import builtwith
from urllib.parse import urljoin, urlparse
import xml.etree.ElementTree as ET
import time
import ssl
import socket
from datetime import datetime
import subprocess

# Must include URL for visibility in the results
def ensure_scheme(url):
    if not url.startswith(('http://', 'https://')):
        return 'https://' + url
    return url

def count_scripts_and_styles(soup):
    scripts = len(soup.find_all('script', src=True))
    stylesheets = len(soup.find_all('link', {'rel': 'stylesheet'}))
    return {'Scripts': scripts, 'Stylesheets': stylesheets}

def count_interactive_elements(soup):
    forms = len(soup.find_all('form'))
    buttons = len(soup.find_all('button'))
    inputs = len(soup.find_all('input'))
    return {'Forms': forms, 'Buttons': buttons, 'Inputs': inputs}

def detect_ajax_requests(soup):
    scripts = soup.find_all('script')
    ajax_count = sum(1 for script in scripts if script.string and 'XMLHttpRequest' in script.string)
    return ajax_count

def count_external_apis(soup, base_url):
    scripts = soup.find_all('script', src=True)
    external_apis = sum(1 for script in scripts if urlparse(script['src']).netloc != urlparse(base_url).netloc)
    return external_apis

def format_output(info):
    formatted = []
    for key, value in info.items():
        if isinstance(value, dict):
            value = "\n\t".join(f"{k}: {v}" for k, v in value.items())
        formatted.append(f"{key}: {value}")
    return "\n".join(formatted)

def get_sitemap_size(url):
    sitemap_url = urljoin(url, '/sitemap.xml')
    try:
        response = requests.get(sitemap_url)
        if response.status_code == 200:
            tree = ET.fromstring(response.content)
            urls = [elem.text for elem in tree.iter() if elem.tag.endswith('loc')]
            return f"Number of URLs in Sitemap: {len(urls)}"
        return "Sitemap not found or inaccessible"
    except Exception as e:
        return f"Sitemap Error: {str(e)}"

def get_performance_metrics(url):
    start_time = time.time()
    response = requests.get(url)
    end_time = time.time()
    return {
        'Response Time': f"{(end_time - start_time):.2f} seconds",
        'Status Code': response.status_code
    }


def detect_login_page(content):
    lower_content = content.lower()
    if any(word in lower_content for word in ["login", "sign in", "sign up", "username", "password"]):
        return True
    return False

def analyze_content_for_purpose(soup):
    description = soup.find('meta', attrs={'name': 'description'})
    description_content = description['content'] if description else ''
    headings = [h.get_text() for h in soup.find_all(['h1', 'h2', 'h3'])]
    content_analysis = description_content + ' ' + ' '.join(headings)
    return content_analysis[:300]


def detect_cloud_provider(headers):
    server_header = headers.get('Server', '').lower()

    if 'aws' in server_header or 'amazon' in server_header:
        return 'Amazon Web Services (AWS)'
    elif 'cloudflare' in server_header:
        return 'Cloudflare'
    elif 'gws' in server_header or 'google' in server_header:
        return 'Google Cloud'
    elif 'microsoft' in server_header or 'azure' in server_header or 'windows-azure' in server_header:
        return 'Microsoft Azure'
    elif 'oracle' in server_header or 'oraclecloud' in server_header:
        return 'Oracle Cloud'
    elif 'cloudfront' in server_header:
        return 'Amazon CloudFront'
    elif 'ibm' in server_header or 'ibmcloud' in server_header:
        return 'IBM Cloud'
    elif 'alibaba' in server_header or 'aliyun' in server_header:
        return 'Alibaba Cloud'
    elif 'digitalocean' in server_header:
        return 'DigitalOcean'
    elif 'heroku' in server_header:
        return 'Heroku'
    elif 'rackspace' in server_header:
        return 'Rackspace'
    elif 'akamai' in server_header:
        return 'Akamai'
    else:
        return 'Cloud Provider Not Detected'


def format_output(info):
    basics = {
        'URL': info.get('URL', 'N/A'),
        'Title': info.get('Title', 'N/A'),
        'Website Purpose Analysis': info.get('Website Purpose Analysis', 'N/A')
    }

    tech = {
        'Tech Stack': info.get('Tech Stack', 'N/A'),
        'Cloud Provider': info.get('Detected Cloud Provider', 'N/A'),
        'External APIs Count': info.get('External APIs Count', 'N/A'),
        'Server Header': info.get('Server Header', 'N/A'),  # Include 'Server Header'
    }

    features = {
        'Login Page Detected': info.get('Login Page Detected', 'N/A'),
        'Auth-required': info.get('WWW-Authenticate (auth-required)', 'N/A'),
        'Script and Stylesheet Count': info.get('Script and Stylesheet Count', 'N/A'),
        'Interactive Elements Count': info.get('Interactive Elements Count', 'N/A'),
        'AJAX Requests Count': info.get('AJAX Requests Count', 'N/A'),
        'HTML Size in Bytes': info.get('HTML Size in Bytes', 'N/A'),
        'Sitemap Size Estimate': info.get('Sitemap Size Estimate', 'N/A'),
        'Performance Metrics': info.get('Performance Metrics', 'N/A'),
        'Server-side-framework': info.get('X-Powered-By (server-side-framework)', 'N/A'),
        'Proxies-Gateways': info.get('Via Header (proxies-gateways)', 'N/A'),
        # Add any other features here
    }

    # Format each section
    formatted_basics = "\n".join(f"\t{key}: {value}" for key, value in basics.items())
    formatted_tech = "\n".join(f"\t{key}: {value}" for key, value in tech.items())
    formatted_features = "\n".join(f"\t{key}: {value}" for key, value in features.items())

    # Combine all sections
    formatted = f"Basics:\n{formatted_basics}\n\nTech:\n{formatted_tech}\n\nFeatures:\n{formatted_features}"
    return formatted

def get_http_response_headers(url):
    try:
        url_with_scheme = ensure_scheme(url)
        response = requests.get(url_with_scheme, timeout=120)
        response.raise_for_status()
        
        # Extract X-Powered-By header
        x_powered_by = response.headers.get('X-Powered-By', 'N/A')
        
        # Extract Via header
        via_header = response.headers.get('Via', 'N/A')
        
        # Extract WWW-Authenticate header
        www_authenticate = response.headers.get('WWW-Authenticate', 'N/A')

        return {
            'X-Powered-By (server-side-framework)': x_powered_by,
            'Via Header (proxies-gateways)': via_header,
            'WWW-Authenticate (auth-required)': www_authenticate
        }

    except requests.exceptions.RequestException as e:
        return {
            'X-Powered-By (server-side-framework)': 'N/A',
            'Via Header (proxies-gateways)': 'N/A',
            'WWW-Authenticate (auth-required)': 'N/A'
        }


def get_website_info(url, timeout=120):
    try:
        url_with_scheme = ensure_scheme(url)
        response = requests.get(url_with_scheme, timeout=120)  # Set a custom timeout value
        response.raise_for_status()  # Raise an exception for HTTP errors

        soup = BeautifulSoup(response.content, 'html.parser')

        title = soup.title.string if soup.title else 'No title found'

        tech_stack = builtwith.parse(url_with_scheme)
        sitemap_size = get_sitemap_size(url_with_scheme)
        performance = get_performance_metrics(url_with_scheme)
        login_page_detected = detect_login_page(response.text)
        website_purpose = analyze_content_for_purpose(soup)
        website_text = soup.get_text()

        script_style_count = count_scripts_and_styles(soup)
        interactive_elements_count = count_interactive_elements(soup)
        ajax_requests_count = detect_ajax_requests(soup)
        external_apis_count = count_external_apis(soup, url_with_scheme)
        cloud_provider = detect_cloud_provider(response.headers)

        return {
            'URL': url_with_scheme,
            'Title': title,
            'Tech Stack': tech_stack,
            'Sitemap Size Estimate': sitemap_size,
            'Performance Metrics': performance,
            'Login Page Detected': 'Yes' if login_page_detected else 'No',
            'Website Purpose Analysis': website_purpose,
            'Detected Cloud Provider': cloud_provider,
            'Script and Stylesheet Count': script_style_count,
            'Interactive Elements Count': interactive_elements_count,
            'AJAX Requests Count': ajax_requests_count,
            'External APIs Count': external_apis_count,
        }
    except requests.exceptions.RequestException as e:
        return {'URL': url, 'Error': str(e)}
    except Exception as e:
        return {'URL': url, 'Error': f"An unexpected error occurred: {str(e)}"}

# This is the primary function of the app. Most troubleshooting is done here

def get_website_info(url, timeout=120):
    try:
        url_with_scheme = ensure_scheme(url)

        # First attempt with the provided timeout
        response = requests.get(url_with_scheme, timeout=120)  # Set a custom timeout value
        response.raise_for_status()  # Raise an exception for HTTP errors

        soup = BeautifulSoup(response.content, 'html.parser')

        title = soup.title.string if soup.title else 'No title found'

        tech_stack = builtwith.parse(url_with_scheme)
        performance = get_performance_metrics(url_with_scheme)
        login_page_detected = detect_login_page(response.text)
        website_text = soup.get_text()
        script_style_count = count_scripts_and_styles(soup)
        interactive_elements_count = count_interactive_elements(soup)
        ajax_requests_count = detect_ajax_requests(soup)
        external_apis_count = count_external_apis(soup, url_with_scheme)
        cloud_provider = detect_cloud_provider(response.headers)
        server_header = response.headers.get('server', 'N/A')
        proxy_auth_header = response.headers.get('proxy-authorization', 'N/A')
        

        # Extract X-Powered-By, Via, and WWW-Authenticate headers from response
    # These don't work well right now
        x_powered_by = response.headers.get('X-Powered-By', 'N/A')
        via_header = response.headers.get('Via', 'N/A')
        www_authenticate = response.headers.get('WWW-Authenticate', 'N/A')

        result = {
            'URL': url_with_scheme,
            'Title': title,
            'Tech Stack': tech_stack,
            'Performance Metrics': performance,
            'Login Page Detected': 'Yes' if login_page_detected else 'No',
            'Script and Stylesheet Count': script_style_count,
            'Interactive Elements Count': interactive_elements_count,
            'AJAX Requests Count': ajax_requests_count,
            'External APIs Count': external_apis_count,
            'Detected Cloud Provider': cloud_provider,
            'Sitemap Size Estimate': 'N/A',
            'Website Purpose Analysis': 'N/A',
            'X-Powered-By (server-side-framework)': x_powered_by,
            'Via Header (proxies-gateways)': via_header,
            'WWW-Authenticate (auth-required)': www_authenticate,
            'Server Header': server_header,  # Include the 'server' header
            'Proxy-Authorization Header': proxy_auth_header,  # Include the 'Proxy-Authorization' header
            'Error': None  # Initialize the error field to None
        }

        # As of version 1.1 this part still isn't working, but we're leaving it here until I can figure out how to fix it.
        # Check if response time exceeds 120 seconds
    # Custom error message is not working well
        if response.elapsed.total_seconds() > timeout:
            result['Error'] = 'Sorry, this website is too large for this script. Please assess manually. Apologies for the inconvenience.'
            return result  # Return the result with the custom error message

        # Proceed with sitemap and content analysis
        sitemap_size = get_sitemap_size(url_with_scheme)
        website_purpose = analyze_content_for_purpose(soup)
        result['Sitemap Size Estimate'] = sitemap_size
        result['Website Purpose Analysis'] = website_purpose

        return result

    except requests.exceptions.RequestException as e:
        return {'URL': url_with_scheme, 'Error': str(e)}
    except Exception as e:
        return {'URL': url_with_scheme, 'Error': f"An unexpected error occurred: {str(e)}"}


# This part above needs the most work


def main():
    print("Enter URLs separated by line. Submit an empty line to run the script.")
    urls = []
    while True:
        url = input().strip()
        if not url:
            break
        urls.append(url)

    total_urls = len(urls)
    print(f"Processing {total_urls} URLs...")

    results = []
    for i, url in enumerate(urls, 1):
        print(f"Processing {i}/{total_urls}: {url}")
        
        # Get website information including headers
        result = get_website_info(url)
        
        # Get HTTP response headers
        headers_info = get_http_response_headers(url)
        
        # Add the extracted headers to the result
        result.update(headers_info)

        results.append(result)

    # Get current date and time
    current_datetime = datetime.now().strftime("%Y%m%d_%H%M%S")
    file_name = f'website_info_output_{current_datetime}.txt'

    # Writing results to a file
    with open(file_name, 'w') as file:
        for result in results:
            # Print the URL in the file
            file.write(f"URL: {result['URL']}\n")

            if result['Error'] is not None:
                # Print the custom error message in the file
                file.write(result['Error'] + "\n")
            else:
                # Print results of all features in the file
                formatted_result = format_output(result)
                file.write(formatted_result + "\n" + "\n")
            # Separate each result in the file with a boarder
            file.write("-*" * 16 + "\n")

    print(f"Information gathered and saved to {file_name}")

if __name__ == "__main__":
    main()
