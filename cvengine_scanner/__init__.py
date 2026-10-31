"""The scanner library shared by the cvENGINE Sentinel and the cvENGINE server: ``flags`` (the command lines and policy constants), ``parsers`` (tool
output to typed results), ``scope`` (the floor of addresses a scanner never touches), ``contract`` (the result contract as JSON Schema) and, beside
them, the contract's fixtures as package data."""
from importlib import metadata

try:
    __version__ = metadata.version('cvengine-scanner')
except metadata.PackageNotFoundError:  # run from a checkout that was never installed
    __version__ = '0.0.0.dev0'
