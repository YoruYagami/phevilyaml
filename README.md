# phevilyaml

This Python script generates a custom `phevilyaml` YAML file for Evilginx2 by intercepting and analyzing HTTP/HTTPS traffic using `mitmproxy`. The script dynamically captures and logs credentials, authentication tokens, subdomains, and other important parameters required for a phishing attack. It is designed to work seamlessly with complex multi-step login processes and can handle multiple domains.

## Features

- **Multi-Step Login Detection**: Automatically detects and handles multi-step login flows, such as username → password → MFA, and configures the `phishlet` accordingly.
- **Enhanced Subdomain Handling**: Detects and logs all relevant subdomains used during the session, ensuring a comprehensive `phishlet`.
- **Custom Error Page Detection**: Identifies custom error pages and suggests sub-filters to handle these cases.
- **Detailed Credential Logging**: Captures all relevant credential fields, including username, password, and additional custom fields like `MFA codes`.
- **Auto-Generation of `auth_urls`**: Automatically detects and logs post-login URLs to populate the `auth_urls` section of the `phishlet`.
- **Support for Multiple Domains**: Handles websites that span multiple domains, ensuring that all necessary domains are included in the `phishlet`.

## Requirements

- Python 3.x
- `mitmproxy`
- `PyYAML`
- `termcolor`

Install the dependencies using pip:

```bash
pip install mitmproxy PyYAML termcolor
```

## Usage
Clone the repository:

```bash
git clone https://github.com/yourusername/phevilyaml.git
cd phevilyaml
```

Run the script:

You can specify the target domain and the port for mitmproxy to listen on:

```bash
python3 phyaml.py -u 'https://example.com' --listen-port 8080

-u or --url: The target domain for generating the phishlet.
--listen-port: The port mitmproxy will listen on (default is 8080).
```

Navigating Through the Site:

While the script is running, use your browser to navigate through the target site. The script will intercept and log the traffic, capturing all necessary data to generate the phishlet YAML file.

Stopping the Script:

Once you are done capturing the necessary data, stop the script by pressing Ctrl + C. The phishlet will be saved as domain.yaml (where domain is the name of the target domain).

Example
Running the script for https://example.com would generate a file named example_com.yaml containing the structured and populated phishlet.

```bash
python3 phyaml.py -u 'https://example.com' --listen-port 8080
```

## Log Output 
As you navigate the target site, the script will log the captured data in real-time. The logging is designed to be clean and minimal, showing only the tree structure of the site, status codes, and relevant information for the phishlet YAML.

## Contributing
Feel free to contribute to this project by submitting issues, feature requests, or pull requests. Any feedback is appreciated!