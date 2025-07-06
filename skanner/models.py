from pydantic import BaseModel

class RepoURL(BaseModel):
    """
    Model for validating repository URL input.
    """
    repo_url: str
