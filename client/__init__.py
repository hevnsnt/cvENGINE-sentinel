"""The Sentinel client: a small, dependency-light daemon that registers with a CVEngine instance and runs the scan work it
is leased (nmap, naabu, nuclei, testssl.sh, an nmap UDP sweep, WPScan, OpenVAS and, on an internal Sentinel, an nmap discover
sweep), reporting typed results back. It has no Django dependency and ships as a standalone
Docker image (see ../Dockerfile, ../docker-compose.yml); its only coupling to the web app is the REST contract
documented in docs/AGENT-API.md.
"""
