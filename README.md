# ipUtil
Get information about IP addresses

## Requirements
To run this program, you need the following:
- `nmap`
- `masscan`
- `ipinfo` API key
1. Obtain your API key from [ipinfo.io](https://ipinfo.io/).
2. Set the API key as an environment variable:
   - **Linux/macOS**:
     ```sh
     export IPINFO_API_KEY="your_api_key_here"
     ```
   - **Windows**:
     ```cmd
     set IPINFO_API_KEY="your_api_key_here"
     ```
## Usage
```sh
iputil <ip address> [options]
```

### Options
- `-n`: Use `nmap` for scanning.
- `-m`: Use `masscan` for scanning.
- `-s`: Use `internetdb` (default option).

When using the `-n` option, the program will run `nmap` with the following options:

- `--top-ports 1000`: Scan the top 1000 most common ports.
- `-T4`: Set the timing template to level 4 (aggressive).
- `-Pn`: Treat all hosts as online; don't ping.

### Example
```sh
iputil 192.168.1.1 -n --top-ports 3000 -A
```

This command will run `nmap` on the IP address `192.168.1.1` with `--top-ports 3000 -A`.

---
