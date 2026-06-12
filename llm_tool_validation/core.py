"""
LLM Tool Call Validation & Recovery Framework
Production-grade middleware for safely executing LLM-generated API calls.

Handles:
- Structural validation (Pydantic schemas)
- Semantic validation (business logic constraints)
- Fuzzy tool name matching (HGuard-inspired)
- Graceful error recovery (PALADIN-inspired trajectory recovery)
- Runtime error handling and retry logic
"""

import re
import logging
from typing import Any, Callable, Dict, List, Optional, Tuple
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass
import json

from pydantic import BaseModel, Field, field_validator, ValidationError
from difflib import get_close_matches


logger = logging.getLogger(__name__)


# ============================================================================
# 1. SCHEMA DEFINITIONS
# ============================================================================

class RefundRequest(BaseModel):
    """Represents a refund operation with strict semantic constraints."""
    order_id: str = Field(
        ..., 
        description="The unique order ID, formatted as ORD-XXXXX (e.g., ORD-12345)"
    )
    amount: float = Field(
        ...,
        description="The refund amount in USD. Must be a positive value.",
        gt=0  # Pydantic constraint: amount must be > 0
    )
    customer_id: str = Field(
        ...,
        description="The validated customer ID initiating the refund."
    )
    reason: str = Field(
        ...,
        description="A brief explanation for the refund request.",
        min_length=5,
        max_length=500
    )

    @field_validator("order_id")
    @classmethod
    def validate_order_id(cls, v: str) -> str:
        """Enforce order ID format: ORD-XXXXX (5 digits)."""
        if not re.match(r"^ORD-\d{5}$", v):
            raise ValueError(
                f"Invalid order_id format: '{v}'. Expected format: ORD-XXXXX (e.g., ORD-12345)"
            )
        return v

    @field_validator("customer_id")
    @classmethod
    def validate_customer_id(cls, v: str) -> str:
        """Ensure customer_id is non-empty and alphanumeric."""
        if not v or not v.isalnum():
            raise ValueError(f"Invalid customer_id: '{v}'. Must be alphanumeric and non-empty.")
        return v


class OrderStatusRequest(BaseModel):
    """Request to fetch order status from shipping carrier."""
    order_id: str = Field(
        ...,
        description="The unique order ID"
    )
    customer_id: str = Field(
        ...,
        description="The customer ID (for authorization)"
    )

    @field_validator("order_id")
    @classmethod
    def validate_order_id(cls, v: str) -> str:
        """Enforce order ID format."""
        if not re.match(r"^ORD-\d{5}$", v):
            raise ValueError(f"Invalid order_id format: '{v}'")
        return v


# ============================================================================
# 2. RUNTIME ERROR RECOVERY TYPES
# ============================================================================

class ErrorSeverity(str, Enum):
    """Classifies error severity for retry and escalation logic."""
    TRANSIENT = "transient"  # Recoverable (retry with backoff)
    VALIDATION = "validation"  # Permanent (fix and retry)
    PERMISSION = "permission"  # Authorization failure (escalate)
    UNKNOWN = "unknown"  # Unclassified (treat conservatively)


@dataclass
class ToolExecutionError:
    """Represents a tool call failure with recovery guidance."""
    error_code: str
    message: str
    severity: ErrorSeverity
    http_status: Optional[int] = None
    retry_after_seconds: Optional[int] = None
    recovery_guidance: Optional[str] = None

    def to_llm_message(self) -> Dict[str, Any]:
        """Format error as a structured message for LLM consumption."""
        return {
            "error": self.error_code,
            "message": self.message,
            "severity": self.severity.value,
            "retry_after_seconds": self.retry_after_seconds,
            "recovery_guidance": self.recovery_guidance,
        }


# ============================================================================
# 3. SEMANTIC/BUSINESS LOGIC VALIDATORS
# ============================================================================

class BusinessLogicValidator:
    """
    Executes semantic validation rules BEFORE executing tool calls.
    This layer prevents logically invalid operations from hitting APIs.
    """

    def __init__(self):
        # Mock database of orders (in production, this queries real DB)
        self.order_store = {
            "ORD-12345": {"customer_id": "cust_001", "total_amount": 150.00},
            "ORD-67890": {"customer_id": "cust_002", "total_amount": 75.50},
        }

    def validate_refund_request(self, req: RefundRequest) -> Optional[ToolExecutionError]:
        """
        Semantic validation for refund requests.
        Returns an error if validation fails, None if all checks pass.
        """
        # 1. Check if order exists
        if req.order_id not in self.order_store:
            return ToolExecutionError(
                error_code="ORDER_NOT_FOUND",
                message=f"Order {req.order_id} not found in system.",
                severity=ErrorSeverity.VALIDATION,
                recovery_guidance="Verify the order ID and try again.",
            )

        order = self.order_store[req.order_id]

        # 2. Check customer ownership
        if order["customer_id"] != req.customer_id:
            return ToolExecutionError(
                error_code="CUSTOMER_MISMATCH",
                message=f"Customer {req.customer_id} does not own order {req.order_id}.",
                severity=ErrorSeverity.PERMISSION,
                recovery_guidance="Ensure you are requesting a refund for your own order.",
            )

        # 3. Check refund amount does not exceed order total
        if req.amount > order["total_amount"]:
            return ToolExecutionError(
                error_code="REFUND_EXCEEDS_ORDER",
                message=f"Refund amount (${req.amount}) exceeds order total (${order['total_amount']}).",
                severity=ErrorSeverity.VALIDATION,
                recovery_guidance=f"Refund amount must be <= ${order['total_amount']}.",
            )

        # All checks passed
        return None


# ============================================================================
# 4. FUZZY TOOL NAME MATCHING (HGuard-inspired)
# ============================================================================

class ToolRegistry:
    """
    Registry of available tools with fuzzy matching fallback.
    Prevents "phantom tool" hallucinations by matching LLM tool names
    to registered tools with configurable similarity threshold.
    """

    def __init__(self):
        self.tools: Dict[str, Callable] = {}
        self.tool_schemas: Dict[str, type] = {}

    def register(
        self, 
        name: str, 
        handler: Callable, 
        schema: type
    ):
        """Register a tool with its handler and Pydantic schema."""
        self.tools[name] = handler
        self.tool_schemas[name] = schema
        logger.info(f"Registered tool: {name}")

    def resolve_tool(
        self, 
        requested_name: str, 
        similarity_threshold: float = 0.7
    ) -> Tuple[Optional[str], Optional[Callable], Optional[type]]:
        """
        Resolve a tool name with fuzzy matching.
        
        Returns:
            (resolved_name, handler, schema) or (None, None, None) if not found
        """
        # Exact match
        if requested_name in self.tools:
            return (
                requested_name,
                self.tools[requested_name],
                self.tool_schemas[requested_name],
            )

        # Fuzzy match
        candidates = get_close_matches(
            requested_name, 
            self.tools.keys(), 
            n=1, 
            cutoff=similarity_threshold
        )

        if candidates:
            resolved_name = candidates[0]
            logger.warning(
                f"Tool '{requested_name}' not found. Fuzzy matched to '{resolved_name}'."
            )
            return (
                resolved_name,
                self.tools[resolved_name],
                self.tool_schemas[resolved_name],
            )

        # No match found
        logger.error(f"Tool '{requested_name}' not found (no fuzzy match candidates).")
        return None, None, None


# ============================================================================
# 5. MULTI-STAGE VALIDATION PIPELINE
# ============================================================================

class ToolCallValidator:
    """
    Multi-stage validation pipeline for LLM-generated tool calls.
    
    Stages:
    1. Structural Validation: Pydantic schema conformance
    2. Fuzzy Name Resolution: Match tool names with similarity
    3. Semantic Validation: Business logic constraints
    4. Rate Limit / Authorization checks
    """

    def __init__(
        self,
        tool_registry: ToolRegistry,
        business_validator: BusinessLogicValidator,
    ):
        self.registry = tool_registry
        self.business_validator = business_validator
        self.call_history: List[Dict[str, Any]] = []

    def validate_and_execute(
        self,
        tool_name: str,
        tool_arguments: Dict[str, Any],
        trace_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Execute the full validation pipeline.
        
        Returns a structured result dict with:
        - success: bool
        - data: Any (if successful)
        - error: ToolExecutionError (if failed)
        """
        trace_id = trace_id or f"trace_{datetime.utcnow().isoformat()}"
        
        # ---- STAGE 1: Fuzzy Tool Name Resolution ----
        resolved_name, handler, schema = self.registry.resolve_tool(tool_name)
        
        if resolved_name is None:
            error = ToolExecutionError(
                error_code="TOOL_NOT_FOUND",
                message=f"Tool '{tool_name}' not found in registry (no fuzzy match).",
                severity=ErrorSeverity.VALIDATION,
                recovery_guidance=f"Available tools: {list(self.registry.tools.keys())}",
            )
            return self._format_failure(trace_id, error)

        # ---- STAGE 2: Structural Validation (Pydantic) ----
        try:
            validated_args = schema(**tool_arguments)
        except ValidationError as e:
            error = ToolExecutionError(
                error_code="VALIDATION_ERROR",
                message=f"Invalid arguments for tool '{resolved_name}': {e.errors()}",
                severity=ErrorSeverity.VALIDATION,
                recovery_guidance="Check parameter types and constraints, then retry.",
            )
            return self._format_failure(trace_id, error)

        # ---- STAGE 3: Semantic Validation (Business Logic) ----
        if resolved_name == "process_refund":
            semantic_error = self.business_validator.validate_refund_request(validated_args)
            if semantic_error:
                return self._format_failure(trace_id, semantic_error)

        # ---- STAGE 4: Execute Handler ----
        try:
            result = handler(validated_args)
            return self._format_success(trace_id, result, resolved_name)
        except Exception as e:
            # Classify runtime error
            error = self._classify_runtime_error(e)
            return self._format_failure(trace_id, error)

    def _classify_runtime_error(self, exception: Exception) -> ToolExecutionError:
        """Classify runtime errors into recoverable vs. permanent failures."""
        error_msg = str(exception)

        # Rate limit
        if "429" in error_msg or "rate" in error_msg.lower():
            return ToolExecutionError(
                error_code="RATE_LIMIT_EXCEEDED",
                message="API rate limit exceeded.",
                severity=ErrorSeverity.TRANSIENT,
                http_status=429,
                retry_after_seconds=5,
                recovery_guidance="Wait 5 seconds, then retry the operation.",
            )

        # Service unavailable (transient)
        if "503" in error_msg or "service unavailable" in error_msg.lower():
            return ToolExecutionError(
                error_code="SERVICE_UNAVAILABLE",
                message="External service temporarily unavailable.",
                severity=ErrorSeverity.TRANSIENT,
                http_status=503,
                retry_after_seconds=10,
                recovery_guidance="Wait 10 seconds, then retry the operation.",
            )

        # Timeout
        if "timeout" in error_msg.lower() or "408" in error_msg:
            return ToolExecutionError(
                error_code="REQUEST_TIMEOUT",
                message="Request to external API timed out.",
                severity=ErrorSeverity.TRANSIENT,
                http_status=408,
                retry_after_seconds=3,
                recovery_guidance="Retry the operation after 3 seconds.",
            )

        # Permission denied
        if "permission" in error_msg.lower() or "401" in error_msg or "403" in error_msg:
            return ToolExecutionError(
                error_code="PERMISSION_DENIED",
                message="Access denied. Check authentication/authorization.",
                severity=ErrorSeverity.PERMISSION,
                http_status=403,
                recovery_guidance="Verify credentials and permissions, then retry.",
            )

        # Unknown error (treat conservatively)
        return ToolExecutionError(
            error_code="UNKNOWN_ERROR",
            message=f"Unexpected error: {error_msg}",
            severity=ErrorSeverity.UNKNOWN,
            recovery_guidance="Contact support or review logs for details.",
        )

    def _format_success(
        self, 
        trace_id: str, 
        result: Any, 
        tool_name: str
    ) -> Dict[str, Any]:
        """Format successful tool execution."""
        response = {
            "success": True,
            "trace_id": trace_id,
            "tool": tool_name,
            "data": result,
        }
        self.call_history.append(response)
        logger.info(f"[{trace_id}] Tool '{tool_name}' executed successfully.")
        return response

    def _format_failure(
        self, 
        trace_id: str, 
        error: ToolExecutionError
    ) -> Dict[str, Any]:
        """Format tool execution failure."""
        response = {
            "success": False,
            "trace_id": trace_id,
            "error": error.to_llm_message(),
        }
        self.call_history.append(response)
        logger.warning(f"[{trace_id}] Tool execution failed: {error.error_code}")
        return response


# ============================================================================
# 6. MOCK TOOL HANDLERS
# ============================================================================

def process_refund_handler(req: RefundRequest) -> Dict[str, Any]:
    """Mock Stripe/Payment processor refund endpoint."""
    logger.info(f"Processing refund: {req.order_id}, amount: ${req.amount}")
    # In production, this would call Stripe/PayPal/etc.
    return {
        "refund_id": f"ref_{req.order_id}_{int(req.amount*100)}",
        "status": "completed",
        "amount": req.amount,
        "order_id": req.order_id,
        "timestamp": datetime.utcnow().isoformat(),
    }


def get_order_status_handler(req: OrderStatusRequest) -> Dict[str, Any]:
    """Mock shipping carrier status endpoint."""
    logger.info(f"Fetching status for order: {req.order_id}")
    # Mock order data (in production, queries carrier API)
    return {
        "order_id": req.order_id,
        "status": "in_transit",
        "tracking_number": "1Z999AA10123456784",
        "eta": (datetime.utcnow() + timedelta(days=2)).isoformat(),
    }
