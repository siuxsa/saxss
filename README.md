# saxss - Simple XSS Scanner

`saxss` is a lightweight Go-based tool designed to detect potential Cross-Site Scripting (XSS) vulnerabilities in web applications. It checks for Content Security Policy (CSP) headers, reflects special characters and custom payloads in URL parameters, and detects Web Application Firewalls (WAFs) using `wafw00f`. The tool is optimized for efficiency with parallel processing and a two-step reflection testing approach.

## Features
- **CSP Detection**: Identifies the presence and details of CSP headers.
- **Reflection Testing**: Checks for parameter reflection with normal text (`sabdop`) and special characters (`sabdop<`, `sabdop>`, etc.).
- **Custom Payload Support**: Allows testing with user-defined payloads (e.g., `<script>alert('xss')</script>`).
- **WAF Detection**: Uses `wafw00f` to detect WAFs behind domains.
- **Parallel Processing**: Supports configurable parallel threads (default: 10) for faster reflection checks.
- **Efficiency**: Skips special character tests if normal text is not reflected.
- **Interrupt Handling**: Saves processed data to `processed.txt` on interruption (Ctrl+C).

## Installation

### Prerequisites
- Go (version 1.16 or later)
- `wafw00f` (install via `pip3 install wafw00f` and ensure it’s in your PATH)

### Build from Source
1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/saxss.git
   cd saxss
   ````
### Install dependencies (assumed in go.mod):

```bash
go mod tidy
````

Build the binary:
bash

    go build -o saxss saxss.go
    sudo mv saxss /usr/local/bin/

## Usage

saxss reads URLs from standard input (e.g., piped from a file) and processes them with various options.
Command-Line Options
````bash
saxss [flags]
  -h string
        Custom header (e.g., 'Key: Value')
  -o string
        Output file to save results
  -p string
        Custom payload to test (e.g., '<script>alert('xss')</script>')
  -w    Enable WAF detection with wafw00f
  -d int
        Number of parallel threads for reflection checking (default: 10)
````
### Example Commands
Basic Usage (Default 10 Threads):
   ```` bash

cat url.txt | saxss > output.txt
````

# How It Works

   ### Initial Reflection Check:
  - Tests each parameter with sabdop.
  - If sabdop is not reflected, logs "Not reflected" and skips to the next URL.
   ### Special Character Testing:
  - If sabdop is reflected, tests special characters by appending them (e.g., sabdop<, sabdop>).
  - Uses parallel processing with the -d flag to speed up checks.
  ### Custom Payload Testing:
  - Tests the custom payload by appending it to sabdop (e.g., sabdopscript>alert('xss')</script>).
  - Reports reflection status.
  ### Output:
  - Displays results in the terminal with colored output (green for success, red for errors, yellow for warnings, blue for headers).
  - Saves results to the specified output file (stripping colors) or processed.txt on interruption.
