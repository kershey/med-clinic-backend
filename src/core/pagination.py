"""
Core pagination utilities for API endpoints.
"""
from typing import TypeVar, Generic, List, Optional, Dict, Any
from pydantic import BaseModel
from fastapi import Query
from sqlalchemy.orm import Query as SQLAlchemyQuery
import math

T = TypeVar("T")

class PageParams:
    """
    Page parameters for pagination.
    
    Attributes:
        page: Page number (1-indexed)
        size: Number of items per page
    """
    def __init__(
        self,
        page: int = Query(1, ge=1, description="Page number"),
        size: int = Query(10, ge=1, le=100, description="Items per page")
    ):
        self.page = page
        self.size = size
        self.offset = (page - 1) * size


class PageResponse(BaseModel, Generic[T]):
    """
    Paginated response model.
    
    Attributes:
        items: List of items for the current page
        total: Total number of items
        page: Current page number
        size: Number of items per page
        pages: Total number of pages
        has_next: Whether there is a next page
        has_prev: Whether there is a previous page
    """
    items: List[T]
    total: int
    page: int
    size: int
    pages: int
    has_next: bool
    has_prev: bool


def paginate(
    query: SQLAlchemyQuery,
    page_params: PageParams,
    schema_class = None
) -> PageResponse:
    """
    Paginate a SQLAlchemy query.
    
    Args:
        query: SQLAlchemy query to paginate
        page_params: Pagination parameters
        schema_class: Optional Pydantic model to convert items to
        
    Returns:
        PageResponse: Paginated response
    """
    total = query.count()
    items = query.offset(page_params.offset).limit(page_params.size).all()
    
    # Convert to Pydantic models if schema_class is provided
    if schema_class:
        items = [schema_class.from_orm(item) for item in items]
    
    pages = math.ceil(total / page_params.size) if total > 0 else 0
    
    return PageResponse(
        items=items,
        total=total,
        page=page_params.page,
        size=page_params.size,
        pages=pages,
        has_next=page_params.page < pages,
        has_prev=page_params.page > 1
    )


def get_pagination_params(
    query_params: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Extract pagination parameters from query parameters.
    
    Args:
        query_params: Query parameters dictionary
        
    Returns:
        Dict: Dictionary with pagination parameters
    """
    page = int(query_params.get("page", 1))
    size = int(query_params.get("size", 10))
    
    # Ensure valid values
    page = max(1, page)
    size = max(1, min(100, size))
    
    return {
        "page": page,
        "size": size,
        "offset": (page - 1) * size
    }
