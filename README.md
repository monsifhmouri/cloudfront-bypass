# CloudFront Bypass Toolkit

A toolkit for testing and bypassing AWS CloudFront edge protection mechanisms.  
**For educational and authorized security testing only.**

## Features

- Detects if a target is behind CloudFront
- Attempts to bypass CloudFront protections using:
  - Forged HTTP headers
  - WebSocket upgrade requests
  - Direct IP access testing
- Provides recommendations for next steps
- Comprehensive, modular, and easily extendable

## Usage

```bash
python3 cloudfront_bypass.py <target_url>
````

**Example:**

```bash
python3 cloudfront_bypass.py https://example.com
```

## Output

* Detects CloudFront headers in target responses
* Tests multiple bypass techniques and summarizes results
* Suggests follow-up actions for further security testing

## Requirements

* Python 3.x
* `requests` module (`pip install requests`)

## Legal Disclaimer

This tool is intended for **educational purposes only**.
Use it **only** on targets you are explicitly authorized to test.
The author is not responsible for any misuse or damage caused by this tool.

## Contributing

Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.

## License

MIT License
