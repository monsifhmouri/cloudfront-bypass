# cloudfront-bypass-toolkit

Toolkit for testing and bypassing AWS CloudFront edge protection.  
Automates detection + header forgery + WebSocket tricks + and backend IP checks

## Features

- CloudFront detection via HTTP headers
- Header forgery with various X-Forwarded-* and CF-* tricks
- WebSocket upgrade and bypass test
- Direct IP discovery and access test
- Summarized results and suggested next steps

## Usage

```bash
python3 cloudfront_bypass.py <target_url>
````

**Example:**

```bash
python3 cloudfront_bypass.py https://example.com
```

## Output

* Shows if CloudFront is detected
* Indicates if header or WebSocket bypass is possible
* Prints any discovered backend IPs

## Requirements

* Python 3
* requests module (`pip install requests`)

## Contributing

Open PRs or issues for suggestions and improvements

## License

MIT
