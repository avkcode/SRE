import yaml

def parse_dependencies(content: str):
    """
    Parse YAML content to extract dependencies.
    """
    try:
        parsed = yaml.safe_load(content)
        return parsed.get("dependencies", [])
    except Exception as e:
        print(f"Error parsing dependencies: {e}")
        return []
