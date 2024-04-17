
# IoT Device Security Analyzer

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.x-brightgreen.svg)

## Overview

IoT Device Security Analyzer is a Python-based tool designed to scan and analyze the security of IoT devices. It identifies vulnerabilities, attempts to bypass common security barriers, and suggests mitigations to secure the device. The tool can handle multiple devices and is flexible, allowing the use of custom credentials.

## Features

- **Port Scanning**: Scans all TCP ports on the device and identifies open ports.
- **SSH Login Attempts**: Attempts to login using default or provided credentials.
- **SSL Certificate Validation**: Checks the SSL certificate of the device's web interface.
- **CVE Vulnerability Check**: Queries public CVE databases for known vulnerabilities associated with the device.
- **Mitigation Suggestions**: Provides actionable steps to mitigate identified security risks.
- **Batch Processing**: Supports bulk analysis of devices from a JSON file.
- **Custom Credentials**: Allows the use of custom credentials for more thorough security testing.

## Installation

```bash
git clone https://github.com/your-username/iot-device-security-analyzer.git
cd iot-device-security-analyzer
pip install -r requirements.txt
```

## Usage

### Analyze a Single Device
```bash
python iot_analyzer.py --ip 192.168.1.1 --url https://192.168.1.1
```

### Analyze Multiple Devices from a File
```bash
python iot_analyzer.py --file devices.json
```

### Provide Custom Credentials
```bash
python iot_analyzer.py --ip 192.168.1.1 --credentials custom_credentials.json
```

### Get Help
```bash
python iot_analyzer.py --help
```

## JSON File Formats

### Device List
`devices.json`:
```json
[
    {"ip": "192.168.1.1", "url": "https://192.168.1.1"},
    {"ip": "192.168.1.2", "url": "https://192.168.1.2"}
]
```

### Custom Credentials
`custom_credentials.json`:
```json
{
    "admin": "admin123",
    "user": "password",
    "root": "root123"
}
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Feel free to submit pull requests or open issues to improve this tool.
