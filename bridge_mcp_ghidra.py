# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2,<3",
#     "mcp>=1.2.0,<2",
# ]
# ///

import requests
import argparse
import logging

from mcp.server.fastmcp import FastMCP

DEFAULT_GHIDRA_SERVER = "http://127.0.0.1:8080/"

logger = logging.getLogger(__name__)

mcp = FastMCP("ghidra-mcp")

# Initialize ghidra_server_url with default value
ghidra_server_url = DEFAULT_GHIDRA_SERVER

ENDPOINTS = {
    "methods": "methods",
    "fun": "fun",
    "fun_address": "funAddress",
    "classes": "classes",
    "decompile": "decompile",
    "decompile_address": "decompileAddress",
    "rename_function": "renameFunction",
    "rename_data": "renameData",
    "rename_variable": "renameVariable",
    "segments": "segments",
    "imports": "imports",
    "exports": "exports",
    "namespaces": "namespaces",
    "data": "data",
    "types": "types",
    "type": "type",
    "rename_data_type": "renameDataType",
    "create_structure": "createStructure",
    "set_structure_field": "setStructureField",
    "search_functions": "searchFunctions",
}

def safe_get(endpoint: str, params: dict = None) -> list:
    """
    Perform a GET request with optional query parameters.
    """
    if params is None:
        params = {}

    url = f"{ghidra_server_url.rstrip('/')}/{endpoint}"

    try:
        response = requests.get(url, params=params, timeout=5)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.splitlines()
        else:
            return [f"Error {response.status_code}: {response.text.strip()}"]
    except Exception as e:
        return [f"Request failed: {str(e)}"]

def safe_post(endpoint: str, data: dict | str) -> str:
    try:
        url = f"{ghidra_server_url.rstrip('/')}/{endpoint}"
        if isinstance(data, dict):
            response = requests.post(url, data=data, timeout=5)
        else:
            response = requests.post(url, data=data.encode("utf-8"), timeout=5)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"

@mcp.tool()
def list_methods(offset: int = 0, limit: int = 100) -> list:
    """
    List all function names in the program with pagination.
    """
    return safe_get(ENDPOINTS["methods"], {"offset": offset, "limit": limit})

@mcp.tool()
def get_function(name: str) -> str:
    """
    Get detailed function metadata (name, address, parameters, calls, pseudocode, and assembly) by name.
    """
    return "\n".join(safe_get(ENDPOINTS["fun"], {"name": name}))

@mcp.tool()
def get_function_by_address(address: str) -> str:
    """
    Get detailed function metadata (name, address, parameters, calls, pseudocode, and assembly) by address.
    """
    return "\n".join(safe_get(ENDPOINTS["fun_address"], {"address": address}))

@mcp.tool()
def list_classes(offset: int = 0, limit: int = 100) -> list:
    """
    List all namespace/class names in the program with pagination.
    """
    return safe_get(ENDPOINTS["classes"], {"offset": offset, "limit": limit})

@mcp.tool()
def decompile_function(name: str) -> str:
    """
    Decompile a specific function by name and return the decompiled C code.
    """
    return safe_post(ENDPOINTS["decompile"], name)

@mcp.tool()
def decompile_function_by_address(address: str) -> str:
    """
    Decompile a specific function by address and return the decompiled C code.
    """
    return safe_post(ENDPOINTS["decompile_address"], address)

@mcp.tool()
def rename_function(old_name: str, new_name: str) -> str:
    """
    Rename a function by its current name to a new user-defined name.
    """
    return safe_post(ENDPOINTS["rename_function"], {"oldName": old_name, "newName": new_name})

@mcp.tool()
def rename_data(address: str, new_name: str) -> str:
    """
    Rename a data label at the specified address.
    """
    return safe_post(ENDPOINTS["rename_data"], {"address": address, "newName": new_name})

@mcp.tool()
def list_segments(offset: int = 0, limit: int = 100) -> list:
    """
    List all memory segments in the program with pagination.
    """
    return safe_get(ENDPOINTS["segments"], {"offset": offset, "limit": limit})

@mcp.tool()
def list_imports(offset: int = 0, limit: int = 100) -> list:
    """
    List imported symbols in the program with pagination.
    """
    return safe_get(ENDPOINTS["imports"], {"offset": offset, "limit": limit})

@mcp.tool()
def list_exports(offset: int = 0, limit: int = 100) -> list:
    """
    List exported functions/symbols with pagination.
    """
    return safe_get(ENDPOINTS["exports"], {"offset": offset, "limit": limit})

@mcp.tool()
def list_namespaces(offset: int = 0, limit: int = 100) -> list:
    """
    List all non-global namespaces in the program with pagination.
    """
    return safe_get(ENDPOINTS["namespaces"], {"offset": offset, "limit": limit})

@mcp.tool()
def list_data_items(offset: int = 0, limit: int = 100, bytesourceoffset: bool = False) -> list:
    """
    List defined data labels and their values with pagination.
    """
    return safe_get(ENDPOINTS["data"], {
        "offset": offset,
        "limit": limit,
        "bytesourceoffset": str(bytesourceoffset).lower(),
    })

@mcp.tool()
def list_data_types(offset: int = 0, limit: int = 100, kind: str = "all", query: str = "") -> str:
    """
    List program data types and structures. Optional filters: kind=all|structure|union|enum|typedef|pointer|array|composite|builtin.
    """
    return "\n".join(safe_get(ENDPOINTS["types"], {
        "offset": offset,
        "limit": limit,
        "kind": kind,
        "query": query,
    }))

@mcp.tool()
def get_data_type(name: str) -> str:
    """
    Get detailed information about a specific data type or structure by name or full path.
    """
    return "\n".join(safe_get(ENDPOINTS["type"], {"name": name}))

@mcp.tool()
def rename_data_type(old_name: str, new_name: str) -> str:
    """
    Rename a data type by its current name or full path.
    """
    return safe_post(ENDPOINTS["rename_data_type"], {"oldName": old_name, "newName": new_name})

@mcp.tool()
def create_structure(name: str, size: int = 0, category_path: str = "/") -> str:
    """
    Create a new structure in the program data type manager.
    """
    return safe_post(ENDPOINTS["create_structure"], {
        "name": name,
        "size": size,
        "categoryPath": category_path,
    })

@mcp.tool()
def set_structure_field(struct_name: str, offset: int, field_type: str, field_name: str = "", comment: str = "") -> str:
    """
    Insert or replace a field in a non-packed structure at the given offset.
    """
    return safe_post(ENDPOINTS["set_structure_field"], {
        "structName": struct_name,
        "offset": offset,
        "fieldType": field_type,
        "fieldName": field_name,
        "comment": comment,
    })

@mcp.tool()
def search_functions_by_name(query: str, offset: int = 0, limit: int = 100) -> list:
    """
    Search for functions whose name contains the given substring.
    """
    if not query:
        return ["Error: query string is required"]
    return safe_get(ENDPOINTS["search_functions"], {"query": query, "offset": offset, "limit": limit})

@mcp.tool()
def rename_variable(function_name: str, old_name: str, new_name: str) -> str:
    """
    Rename a local variable within a function.
    """
    return safe_post(ENDPOINTS["rename_variable"], {
        "functionName": function_name,
        "oldName": old_name,
        "newName": new_name
    })

def main():
    parser = argparse.ArgumentParser(description="MCP server for Ghidra")
    parser.add_argument("--ghidra-server", type=str, default=DEFAULT_GHIDRA_SERVER,
                        help=f"Ghidra server URL, default: {DEFAULT_GHIDRA_SERVER}")
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1",
                        help="Host to run MCP server on (only used for sse), default: 127.0.0.1")
    parser.add_argument("--mcp-port", type=int,
                        help="Port to run MCP server on (only used for sse), default: 8081")
    parser.add_argument("--transport", type=str, default="stdio", choices=["stdio", "sse"],
                        help="Transport protocol for MCP, default: stdio")
    args = parser.parse_args()
    
    global ghidra_server_url
    if args.ghidra_server:
        ghidra_server_url = args.ghidra_server
    
    if args.transport == "sse":
        try:
            # Set up logging
            log_level = logging.INFO
            logging.basicConfig(level=log_level)
            logging.getLogger().setLevel(log_level)

            # Configure MCP settings
            mcp.settings.log_level = "INFO"
            if args.mcp_host:
                mcp.settings.host = args.mcp_host
            else:
                mcp.settings.host = "127.0.0.1"

            if args.mcp_port:
                mcp.settings.port = args.mcp_port
            else:
                mcp.settings.port = 8081

            logger.info(f"Connecting to Ghidra server at {ghidra_server_url}")
            logger.info(f"Starting MCP server on http://{mcp.settings.host}:{mcp.settings.port}/sse")
            logger.info(f"Using transport: {args.transport}")

            mcp.run(transport="sse")
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
    else:
        mcp.run()
        
if __name__ == "__main__":
    main()
