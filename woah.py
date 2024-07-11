# I like comments more than you dislike them. So I'm keeping in comments, you're welcome.
# Welcome to WOAH - the Website OSINT and Help tool.
# Must install a few python packages for this to work:
# pip install requests beautifulsoup4 builtwith

#                                    /$$
#                                   | $$
#  /$$  /$$  /$$  /$$$$$$   /$$$$$$ | $$$$$$$
# | $$ | $$ | $$ /$$__  $$ |____  $$| $$__  $$
# | $$ | $$ | $$| $$  \ $$  /$$$$$$$| $$  \ $$
# | $$ | $$ | $$| $$  | $$ /$$__  $$| $$  | $$
# |  $$$$$/$$$$/|  $$$$$$/|  $$$$$$$| $$  | $$
#  \_____/\___/  \______/  \_______/|__/  |__/

import requests
from bs4 import BeautifulSoup
import re
from datetime import datetime
import time
import ssl
import socket
import builtwith
from urllib.parse import urljoin, urlparse

# List of CMSs for detect_cms_sass
cms_signatures = {
    "WordPress": ["wp-content", "wp-includes"],
    "Joomla": ["Joomla!"],
    "Drupal": ["Drupal"],
    "Shopify": ["shopify.com"],
    "Magento": ["Magento"],
    "Squarespace": ["squarespace.com"],
    "Wix": ["wix.com"],
    "Blogger": ["blogger.com"],
    "PrestaShop": ["PrestaShop"],
    "TYPO3": ["TYPO3"],
    "Bitrix": ["bitrix"],
    "OpenCart": ["OpenCart"],
    "Weebly": ["weebly.com"],
    "Jimdo": ["jimdo.com"],
    "BigCommerce": ["bigcommerce"],
    "vBulletin": ["vBulletin"],
    "WooCommerce": ["woocommerce"],
    "Zen Cart": ["zen-cart"],
    "Ghost": ["ghost.org"],
    "ExpressionEngine": ["ExpressionEngine", "exp:"],
    "SilverStripe": ["SilverStripe"],
    "Textpattern": ["textpattern"],
    "Movable Type": ["Movable Type", "mt-static"],
    "Concrete5": ["concrete5"],
    "MODX": ["MODX"],
    "XenForo": ["XenForo"],
    "Umbraco": ["umbraco"],
    "Duda": ["duda.co"]
}

def detect_cms_sass(soup):
    detected_platforms = []
    for platform, signatures in cms_signatures.items():
        for signature in signatures:
            if soup.find(string=re.compile(signature)):
                detected_platforms.append(platform)
                break
    return detected_platforms

def detect_deprecated_features(soup):
    deprecated_tags = ['applet', 'basefont', 'center', 'dir', 'font', 'frame', 'frameset', 'noframes', 'isindex', 'strike', 'u', 'bgsound', 'big', 'blink', 'marquee', 'spacer', 'tt', 'xmp', 'acronym', 'menu']
    deprecated_functions = ['document.write', 'alert', 'escape', 'unescape', 'eval', 'captureEvents', 'releaseEvents', 'getYear', 'setYear', 'sync', 'atob', 'btoa', 'showModalDialog']
    count = 0
    for tag in deprecated_tags:
        count += len(soup.find_all(tag))
    for function in deprecated_functions:
        count += soup.text.count(function)
    return count

def count_cookies(response_headers):
    return len(response_headers.get('Set-Cookie', '').split(','))

def get_ssl_cert_age(hostname):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=30) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
        issue_date_str = cert['notBefore']
        issue_date = datetime.strptime(issue_date_str, '%b %d %H:%M:%S %Y %Z')
        current_date = datetime.now()
        age_years = current_date.year - issue_date.year - ((current_date.month, current_date.day) < (issue_date.month, issue_date.day))
        return age_years
    except Exception as e:
        return 'N/A'  # Return 'N/A' for any exceptions

def ensure_scheme(url):
    if not url.startswith(('http://', 'https://')):
        return 'https://' + url
    return url

def get_performance_metrics(url):
    start_time = time.time()
    response = requests.get(url)
    end_time = time.time()
    return {
        'Response Time': f"{(end_time - start_time):.2f} seconds",
        'Status Code': response.status_code
    }

def detect_login_page(html_content):
    login_indicators = ['login', 'sign in', 'sign up', 'username', 'password']
    return any(indicator in html_content.lower() for indicator in login_indicators)

def count_scripts_and_styles(soup):
    scripts = len(soup.find_all('script', src=True))
    styles = len(soup.find_all('link', {'rel': 'stylesheet'}))
    return {'Scripts': scripts, 'Styles': styles}

def count_interactive_elements(soup):
    forms = len(soup.find_all('form'))
    buttons = len(soup.find_all('button'))
    inputs = len(soup.find_all('input', {'type': ['text', 'password', 'submit', 'checkbox', 'radio']}))
    return {'Forms': forms, 'Buttons': buttons, 'Inputs': inputs}

def detect_ajax_requests(soup):
    return sum(1 for script in soup.find_all('script') if 'XMLHttpRequest' in script.text)

def count_external_apis(soup, base_url):
    external_apis = set()
    for script in soup.find_all('script', src=True):
        if urlparse(script['src']).netloc != urlparse(base_url).netloc:
            external_apis.add(script['src'])
    return len(external_apis)

def detect_cloud_provider(headers):
    server_header = headers.get('Server', '').lower()
    cloud_providers = {
        'Amazon Web Services (AWS)': ['aws', 'amazon'],
        'Cloudflare': ['cloudflare'],
        'Google Cloud': ['gws', 'google'],
        'Microsoft Azure': ['microsoft', 'azure', 'windows-azure'],
        'Oracle Cloud': ['oracle', 'oraclecloud'],
        'Amazon CloudFront': ['cloudfront'],
        'IBM Cloud': ['ibm', 'ibmcloud'],
        'Alibaba Cloud': ['alibaba', 'aliyun'],
        'DigitalOcean': ['digitalocean'],
        'Heroku': ['heroku'],
        'Rackspace': ['rackspace'],
        'Akamai': ['akamai']
    }
    for provider, signatures in cloud_providers.items():
        if any(signature in server_header for signature in signatures):
            return provider
    return 'Cloud Provider Not Detected'

def get_sitemap_size(url):
    try:
        sitemap_url = urljoin(url, '/sitemap.xml')
        response = requests.get(sitemap_url)
        response.raise_for_status()
        return len(response.content)
    except requests.exceptions.RequestException:
        return 'Unable to retrieve sitemap'

def analyze_content_for_purpose(soup):
    text_content = soup.get_text().lower()
    categories = []

    keyword_categories = {
        'E-commerce': ['shop', 'purchase', 'cart', 'ecommerce', 'store', 'checkout'],
        'Blog/News': ['blog', 'article', 'post', 'news', 'write-up', 'editorial', 'commentary'],
        'Corporate/Business': ['contact', 'about us', 'services', 'corporate', 'business', 'company', 'professional', 'client'],
        'Educational/Institutional': ['course', 'academy', 'education', 'research', 'curriculum', 'syllabus', 'institute', 'university', 'school'],
        'Entertainment': ['entertainment', 'movie', 'music', 'game', 'celebrity', 'show', 'performance', 'theatre'],
        'Technology': ['tech', 'gadget', 'software', 'hardware', 'device', 'computer', 'programming', 'development'],
        'Health and Wellness': ['health', 'wellness', 'medical', 'fitness', 'nutrition', 'exercise', 'yoga', 'meditation'],
        'Non-profit/Charity': ['non-profit', 'charity', 'donate', 'volunteer', 'cause', 'fundraise', 'ngo', 'nonprofit'],
        'Personal/Portfolio': ['portfolio', 'personal', 'resume', 'cv', 'bio', 'hobby', 'my work', 'projects'],
        'Forums/Community': ['forum', 'discussion', 'community', 'thread', 'board', 'member', 'topic']
    }

    for category, keywords in keyword_categories.items():
        if any(keyword in text_content for keyword in keywords):
            categories.append(category)

    return categories if categories else ['General Information']

def get_http_response_headers(url):
    try:
        url_with_scheme = ensure_scheme(url)
        response = requests.get(url_with_scheme, timeout=120)
        response.raise_for_status()
        return {
            'X-Powered-By (server-side-framework)': response.headers.get('X-Powered-By', 'N/A'),
            'Via Header (proxies-gateways)': response.headers.get('Via', 'N/A'),
            'WWW-Authenticate (auth-required)': response.headers.get('WWW-Authenticate', 'N/A')
        }
    except requests.exceptions.RequestException:
        return {
            'X-Powered-By (server-side-framework)': 'N/A',
            'Via Header (proxies-gateways)': 'N/A',
            'WWW-Authenticate (auth-required)': 'N/A'
        }

def format_output(info):
    sections = {
        'Basics': {
            'URL': info.get('URL', 'N/A'),
            'Title': info.get('Title', 'N/A'),
            'Website Purpose Analysis': info.get('Website Purpose Analysis', 'N/A'),
            'First 250 Characters': info.get('First 250 Characters', 'N/A')
        },
        'Tech': {
            'Tech Stack': info.get('Tech Stack', 'N/A'),
            'Cloud Provider': info.get('Detected Cloud Provider', 'N/A'),
            'External APIs Count': info.get('External APIs Count', 'N/A'),
            'Detected CMS/SaaS Platforms': info.get('Detected CMS/SaaS Platforms', 'None')
        },
        'Features': {
            'Login Page Detected': info.get('Login Page Detected', 'N/A'),
            'Auth-required': info.get('WWW-Authenticate (auth-required)', 'N/A'),
            'Sitemap Size Estimate': info.get('Sitemap Size Estimate', 'N/A')
        },
        'Jank': {
            'SSL Age Start': info.get('SSL Age Start', 'N/A'),
            'Performance Metrics': info.get('Performance Metrics', 'N/A'),
            'Script and Stylesheet Count': info.get('Script and Stylesheet Count', 'N/A'),
            'Interactive Elements Count': info.get('Interactive Elements Count', 'N/A'),
            'AJAX Requests Count': info.get('AJAX Requests Count', 'N/A'),
            'Server Header': info.get('Server Header', 'N/A'),
            'Deprecated Features': info.get('Deprecated Features', 'N/A'),
            'Cookies Count': info.get('Cookies Count', 'N/A')
        }
    }

    formatted_output = ""
    for section, values in sections.items():
        formatted_output += f"{section}:\n"
        for key, value in values.items():
            formatted_output += f"\t{key}: {value}\n"
        formatted_output += "\n"

    return formatted_output.strip()

def get_website_info(url, timeout=120):
    try:
        url_with_scheme = ensure_scheme(url)
        response = requests.get(url_with_scheme, timeout=timeout)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')

        title = soup.title.string if soup.title else 'No title found'
        tech_stack = builtwith.parse(url_with_scheme)
        cms_sass_platforms = detect_cms_sass(soup)
        ssl_cert_age = get_ssl_cert_age(urlparse(url).hostname)
        performance = get_performance_metrics(url_with_scheme)
        login_page_detected = detect_login_page(response.text)
        website_text = soup.get_text()
        script_style_count = count_scripts_and_styles(soup)
        interactive_elements_count = count_interactive_elements(soup)
        ajax_requests_count = detect_ajax_requests(soup)
        external_apis_count = count_external_apis(soup, url_with_scheme)
        cloud_provider = detect_cloud_provider(response.headers)
        server_header = response.headers.get('server', 'N/A')
        sitemap_size = get_sitemap_size(url_with_scheme)
        website_purpose = analyze_content_for_purpose(soup)
        first_250_chars = ' '.join(website_text.strip()[:250].split())
        deprecated_features_count = detect_deprecated_features(soup)
        cookies_count = count_cookies(response.headers)

        result = {
            'URL': url_with_scheme,
            'Title': title,
            'Tech Stack': tech_stack,
            'Detected CMS/SaaS Platforms': ', '.join(cms_sass_platforms) if cms_sass_platforms else 'None',
            'SSL Age Start': f"{ssl_cert_age} years" if ssl_cert_age != 'Error' else 'N/A',
            'Performance Metrics': performance,
            'Login Page Detected': 'Yes' if login_page_detected else 'No',
            'Script and Stylesheet Count': script_style_count,
            'Interactive Elements Count': interactive_elements_count,
            'AJAX Requests Count': ajax_requests_count,
            'External APIs Count': external_apis_count,
            'Detected Cloud Provider': cloud_provider,
            'Server Header': server_header,
            'Sitemap Size Estimate': sitemap_size,
            'Website Purpose Analysis': website_purpose,
            'First 250 Characters': first_250_chars,
            'Deprecated Features': deprecated_features_count,
            'Cookies Count': cookies_count,
            'Error': None
        }

        if response.elapsed.total_seconds() > timeout:
            result['Error'] = 'Sorry, this website is too large for this script. Please assess manually.'

        return result

    except requests.exceptions.RequestException as e:
        return {'URL': ensure_scheme(url), 'Error': str(e)}
    except Exception as e:
        return {'URL': ensure_scheme(url), 'Error': f"An unexpected error occurred: {str(e)}"}

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

        result = get_website_info(url)

        headers_info = get_http_response_headers(url)
        result.update(headers_info)

        results.append(result)

    current_datetime = datetime.now().strftime("%Y%m%d_%H%M%S")
    file_name = f'website_info_output_{current_datetime}.txt'

    with open(file_name, 'w') as file:
        for result in results:
            file.write(f"URL: {result['URL']}\n")
            if result['Error'] is not None:
                file.write(result['Error'] + "\n")
            else:
                formatted_result = format_output(result)
                file.write(formatted_result + "\n\n")
            file.write("-*" * 16 + "\n")

    print(f"Information gathered and saved to {file_name}")

if __name__ == "__main__":
    main()
