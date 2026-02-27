"""
OpenSearch PPL backend for Sigma rules.

This backend converts Sigma detection rules (both regular and correlation rules)
into PPL (Piped Processing Language) queries for OpenSearch.

Supports:
- Regular Sigma detection rules
- Correlation rules (event_count, value_count, temporal, temporal_ordered)
- All standard Sigma modifiers and features
"""
from typing import ClassVar, Optional, Pattern, Dict, Union, Any, List
import re
from enum import Enum

from sigma.conversion.base import TextQueryBackend
from sigma.conversion.state import ConversionState
from sigma.correlations import (
    SigmaCorrelationRule,
    SigmaCorrelationTypeLiteral,
    SigmaCorrelationType,
)
from sigma.exceptions import SigmaConversionError
from sigma.processing.pipeline import ProcessingPipeline
from sigma.rule import SigmaRule
from sigma.types import SigmaCompareExpression
from sigma.conditions import ConditionItem, ConditionAND, ConditionOR, ConditionNOT


# ============================================================================
# Custom Attributes
# ============================================================================

class OpenSearchPPLCustomAttributes(Enum):
    """
    Custom attributes that can be set in Sigma rules to configure OpenSearch PPL backend behavior.
    
    These can be used in a Sigma rule YAML like:
    
    custom:
      opensearch_ppl_index: "my-custom-index-*"
      opensearch_ppl_time_field: "event_timestamp"
      opensearch_ppl_min_time: "-7d"
      opensearch_ppl_max_time: "now"
    """
    INDEX = "opensearch_ppl_index"
    TIME_FIELD = "opensearch_ppl_time_field"
    MIN_TIME = "opensearch_ppl_min_time"
    MAX_TIME = "opensearch_ppl_max_time"


class OpenSearchPPLBackend(TextQueryBackend):
    """
    OpenSearch PPL backend for both regular and correlation Sigma rules.
    
    This backend leverages pySigma's built-in conversion infrastructure,
    requiring only configuration through class variables and minimal
    method overrides for PPL-specific behavior.
    
    Features:
    - Converts regular Sigma detection rules to PPL queries
    - Supports correlation rules with multiple correlation types
    - Handles all standard Sigma modifiers (contains, startswith, etc.)
    - Supports CIDR notation, regex, field references, and more
    """
    
    # Backend metadata
    name: ClassVar[str] = "OpenSearch PPL Backend"
    formats: ClassVar[Dict[str, str]] = {
        "default": "Plain PPL queries",
        "kibana": "Kibana dashboard format (future)",
    }
    requires_pipeline: ClassVar[bool] = False
    
    # Operator precedence (NOT > AND > OR)
    precedence: ClassVar[tuple] = (ConditionNOT, ConditionAND, ConditionOR)
    group_expression: ClassVar[str] = "({expr})"
    
    # Boolean operators for PPL
    token_separator: str = " "
    or_token: ClassVar[str] = "OR"
    and_token: ClassVar[str] = "AND"
    not_token: ClassVar[str] = "NOT"
    eq_token: ClassVar[str] = "="
    
    # Field quoting - PPL allows unquoted alphanumeric field names
    field_quote: ClassVar[str] = "`"  # Backticks for fields with special chars
    field_quote_pattern: ClassVar[Pattern] = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")
    field_quote_pattern_negation: ClassVar[bool] = True  # Quote if pattern does NOT match
    
    # String quoting and escaping  
    str_quote: ClassVar[str] = '"'  # Double quotes for string values
    escape_char: ClassVar[str] = '\\'
    wildcard_multi: ClassVar[str] = "%"  # PPL uses % for multi-character wildcard
    wildcard_single: ClassVar[str] = "_"  # PPL uses _ for single-character wildcard
    # Note: PPL LIKE patterns don't support backslash escape sequences
    # We need to remove backslashes from LIKE patterns in post-processing
    add_escaped: ClassVar[str] = ""  # Empty to avoid escaping backslashes
    filter_chars: ClassVar[str] = "\\"  # Remove backslashes from patterns
    
    # String matching operators with PPL's LIKE() function
    # PPL uses: LIKE(field, "pattern") with % for wildcards  
    # PPL uses: field = "exact" for exact match
    # Template values will be auto-quoted by str_quote
    startswith_expression: ClassVar[str] = 'LIKE({field}, {value}%)'
    endswith_expression: ClassVar[str] = 'LIKE({field}, %{value})'
    contains_expression: ClassVar[str] = 'LIKE({field}, %{value}%)'
    wildcard_match_expression: ClassVar[str] = 'LIKE({field}, {value})'
    
    # Case-sensitive string matching with 'cased' modifier
    # PPL LIKE function with third parameter set to true enables case-sensitive matching
    # Format: LIKE(field, "pattern", true)
    case_sensitive_match_expression: ClassVar[str] = '{field}={value}'
    case_sensitive_startswith_expression: ClassVar[str] = 'LIKE({field}, {value}%, true)'
    case_sensitive_endswith_expression: ClassVar[str] = 'LIKE({field}, %{value}, true)'
    case_sensitive_contains_expression: ClassVar[str] = 'LIKE({field}, %{value}%, true)'
    
    # CIDR notation support
    # PPL supports: cidrmatch(field, "cidr")
    cidr_expression: ClassVar[str] = 'cidrmatch({field}, "{value}")'
    
    # Regular expressions in PPL
    # PPL supports: field match 'regex' or match(field, 'regex')
    # Note: Backslashes in regex are NOT escaped because they're already within single quotes
    # Only single quotes need escaping by doubling them
    re_expression: ClassVar[str] = "match({field}, '{regex}')"
    re_escape_char: ClassVar[str] = "'"
    re_escape: ClassVar[tuple] = ("'",)
    
    # Comparison operators for numeric values
    compare_op_expression: ClassVar[str] = "{field}{operator}{value}"
    compare_operators: ClassVar[Dict[Any, str]] = {
        SigmaCompareExpression.CompareOperators.LT: "<",
        SigmaCompareExpression.CompareOperators.LTE: "<=",
        SigmaCompareExpression.CompareOperators.GT: ">",
        SigmaCompareExpression.CompareOperators.GTE: ">=",
    }
    
    # Field existence checks
    field_exists_expression: ClassVar[str] = "isnotnull({field})"
    field_not_exists_expression: ClassVar[str] = "isnull({field})"
    
    # Null value handling - in PPL use isnull() function
    field_null_expression: ClassVar[str] = "isnull({field})"
    
    # Field-to-field comparison (fieldref modifier)
    # PPL supports direct field comparison: field1=field2
    field_equals_field_expression: ClassVar[str] = "{field1}={field2}"
    
    # List expressions (IN operator)
    convert_or_as_in: ClassVar[bool] = True
    convert_and_as_in: ClassVar[bool] = False
    in_expressions_allow_wildcards: ClassVar[bool] = False
    field_in_list_expression: ClassVar[str] = "{field} in ({list})"
    or_in_operator: ClassVar[str] = "in"
    list_separator: ClassVar[str] = ", "
    
    # Value expressions (for unbound values - used in keywords)
    # Note: Don't add quotes here - pySigma adds them automatically via str_quote
    unbound_value_str_expression: ClassVar[str] = '{value}'
    unbound_value_num_expression: ClassVar[str] = '{value}'
    
    # Query expression template - just the condition, we add source in finish_query
    query_expression: ClassVar[str] = "{query}"
    
    ### Correlation support ###
    
    # Correlation methods supported by this backend
    correlation_methods: ClassVar[Dict[str, str]] = {
        "default": "Default method",
    }
    
    # All correlation types use the same query structure:
    # {search} | stats {aggregate} | where {condition}
    default_correlation_query: ClassVar[Dict[str, str]] = {
        "default": "{search} | stats {aggregate} | where {condition}"
    }
    
    # Joiner between multiple rule queries (unused but kept for compatibility)
    correlation_search_multi_rule_query_expression_joiner: ClassVar[str] = " "
    
    # Aggregation expressions for different correlation types
    default_aggregation_expression: ClassVar[Dict[str, str]] = {
        "default": "count() as event_count by {groupby}"
    }
    
    event_count_aggregation_expression: ClassVar[Dict[str, str]] = default_aggregation_expression
    
    # Temporal correlations need to count distinct EventIDs to verify all rules matched
    # and use span() for time-based grouping
    temporal_aggregation_expression: ClassVar[Dict[str, str]] = {
        "default": "dc(EventID) as unique_rules by span({time_field}, {timespan}), {groupby}"
    }
    temporal_ordered_aggregation_expression: ClassVar[Dict[str, str]] = {
        "default": "dc(EventID) as unique_rules by span({time_field}, {timespan}), {groupby}"
    }
    
    value_count_aggregation_expression: ClassVar[Dict[str, str]] = {
        "default": "dc({field}) as value_count by {groupby}"
    }
    
    # Group-by expression templates
    groupby_expression: ClassVar[Dict[str, str]] = {"default": "{fields}"}
    groupby_field_expression: ClassVar[Dict[str, str]] = {"default": "{field}"}
    groupby_field_expression_joiner: ClassVar[Dict[str, str]] = {"default": ", "}
    
    # Correlation condition expressions
    default_condition_expression: ClassVar[Dict[str, str]] = {
        "default": "event_count {op} {count}",
    }
    
    event_count_condition_expression: ClassVar[Dict[str, str]] = default_condition_expression
    
    # Temporal correlations check that all rules matched (distinct EventIDs)
    temporal_condition_expression: ClassVar[Dict[str, str]] = {
        "default": "unique_rules >= {rule_count}"
    }
    temporal_ordered_condition_expression: ClassVar[Dict[str, str]] = {
        "default": "unique_rules >= {rule_count}"
    }
    
    value_count_condition_expression: ClassVar[Dict[str, str]] = {
        "default": "value_count {op} {count}",
    }
    
    # Operator mapping for conditions
    correlation_condition_op: ClassVar[Dict[str, str]] = {
        "eq": "=", "ne": "!=", "lt": "<", "lte": "<=", "gt": ">", "gte": ">=",
    }
    
    def __init__(
        self,
        processing_pipeline: Optional[ProcessingPipeline] = None,
        collect_errors: bool = False,
        min_time: Optional[str] = None,
        max_time: Optional[str] = None,
        **backend_options: Dict,
    ):
        """
        Initialize the OpenSearch PPL backend.
        
        Args:
            processing_pipeline: Optional processing pipeline for rule transformation
            collect_errors: If True, collect errors instead of raising them
            min_time: Minimum time filter (earliest). Examples: "-30d", "-7d", "2024-01-01T00:00:00"
            max_time: Maximum time filter (latest). Examples: "now", "2024-12-31T23:59:59"
            **backend_options: Additional backend options:
                - custom_logsource: Custom index pattern to override logsource-based pattern (default: None)
        """
        super().__init__(processing_pipeline, collect_errors=collect_errors, **backend_options)
        self._custom_logsource: Optional[str] = backend_options.get("custom_logsource", None)
        self._time_field: str = "@timestamp"  # Default timestamp field for correlation rules
        self._min_time: Optional[str] = min_time
        self._max_time: Optional[str] = max_time
    
    ### Regular rule conversion methods ###
    
    def finalize_query_default(
        self, rule: SigmaRule, query: str, index: int, state: ConversionState
    ) -> str:
        """
        Finalize the query by adding the source command.
        
        This method is called after the condition has been converted to add
        PPL-specific elements like the source index pattern.
        
        Args:
            rule: The Sigma rule being converted
            query: The converted condition query
            index: Query index (if rule generates multiple queries)
            state: Conversion state
            
        Returns:
            Complete PPL query with source command
        """
        # Correlation rules are already finalized
        if isinstance(rule, SigmaCorrelationRule):
            return query
        
        # Get index pattern from logsource
        index_pattern = self._get_index_pattern(rule)
        
        # Build complete PPL query
        # The query_expression template is already applied in finish_query
        # We just need to ensure the state has the index
        state.processing_state["index"] = index_pattern
        
        return query
    
    def finalize_output_default(self, queries: list[str]) -> list[str]:
        """
        Finalize the output by returning the list of queries.
        
        Args:
            queries: List of generated PPL queries
            
        Returns:
            List of PPL query strings
        """
        return queries
    
    def _get_index_pattern(self, rule: SigmaRule) -> str:
        """
        Extract OpenSearch index pattern from Sigma logsource.
        
        Maps Sigma logsource (product, category, service) to OpenSearch
        index patterns. Can be overridden with custom_logsource backend option
        or via custom attribute in the rule YAML.
        
        Priority:
        1. Custom attribute in rule YAML (opensearch_ppl_index)
        2. Backend option (custom_logsource)
        3. Logsource-based mapping
        
        Args:
            rule: Sigma rule containing logsource information
            
        Returns:
            OpenSearch index pattern (e.g., "windows-process_creation-*" or custom pattern)
        """
        # Priority 1: Check for custom attribute in rule YAML
        # Custom attributes are nested under 'custom' key
        if ('custom' in rule.custom_attributes and 
            OpenSearchPPLCustomAttributes.INDEX.value in rule.custom_attributes['custom']):
            return rule.custom_attributes['custom'][OpenSearchPPLCustomAttributes.INDEX.value]
        
        # Priority 2: If custom logsource is provided via backend option, use it
        if self._custom_logsource:
            return self._custom_logsource
        
        # Priority 3: Map logsource to index pattern
        logsource = rule.logsource
        product = getattr(logsource, 'product', None)
        category = getattr(logsource, 'category', None)
        service = getattr(logsource, 'service', None)
        
        # Build index pattern from logsource components
        index_parts = []
        
        if product:
            index_parts.append(product)
        
        if category:
            index_parts.append(category)
        
        if service:
            index_parts.append(service)
        
        # Build final index pattern
        if index_parts:
            return '-'.join(index_parts) + '-*'
        else:
            # Fallback to wildcard if no logsource specified
            return '*'
    
    def finish_query(
        self, rule: SigmaRule, query: str, state: ConversionState
    ) -> str:
        """
        Finish the query before finalization.
        
        This is called before finalize_query and is where we can add
        the search command and other PPL-specific structure.
        
        Args:
            rule: The Sigma rule being converted
            query: The converted condition
            state: Conversion state
            
        Returns:
            Query with PPL search command added
        """
        # Get index pattern from logsource
        index_pattern = self._get_index_pattern(rule)
        
        # Handle deferred expressions (if any)
        query = super().finish_query(rule, query, state)
        
        # Fix LIKE expressions: move wildcards inside quotes
        # Handle all patterns in one comprehensive replacement
        def fix_wildcards(match):
            leading = match.group(1) or ''  # % before "
            content = match.group(2)         # content between quotes
            trailing = match.group(3) or ''  # % after "
            return f'"{leading}{content}{trailing}"'
        
        query = re.sub(r'(%?)"([^"]*)\"(%?)', fix_wildcards, query)
        
        # Build time modifiers using custom attributes or backend options
        min_time = self._get_min_time(rule)
        max_time = self._get_max_time(rule)
        
        # If we have time modifiers, use 'search' command syntax
        # Otherwise, use 'source=... | where ...' syntax for backward compatibility
        if min_time or max_time:
            # Build time modifiers for search command
            time_modifiers = []
            if min_time:
                time_modifiers.append(f"earliest={self._format_time_modifier(min_time)}")
            if max_time:
                time_modifiers.append(f"latest={self._format_time_modifier(max_time)}")
            
            # Construct search command: search [time_modifiers] <query> source=<index>
            time_str = " ".join(time_modifiers)
            ppl_query = f"search {time_str} {query} source={index_pattern}"
        else:
            # Use traditional source | where syntax when no time filters
            ppl_query = f"source={index_pattern} | where {query}"
        
        return ppl_query
    
    def _get_time_field(self, rule: SigmaRule) -> str:
        """
        Get the time field for the query.
        
        Priority:
        1. Custom attribute in rule YAML (opensearch_ppl_time_field)
        2. Backend default (@timestamp)
        
        Args:
            rule: Sigma rule
            
        Returns:
            Time field name
        """
        if ('custom' in rule.custom_attributes and 
            OpenSearchPPLCustomAttributes.TIME_FIELD.value in rule.custom_attributes['custom']):
            return rule.custom_attributes['custom'][OpenSearchPPLCustomAttributes.TIME_FIELD.value]
        return self._time_field
    
    def _get_min_time(self, rule: SigmaRule) -> Optional[str]:
        """
        Get the minimum time filter.
        
        Priority:
        1. Custom attribute in rule YAML (opensearch_ppl_min_time)
        2. Backend option (min_time)
        
        Args:
            rule: Sigma rule
            
        Returns:
            Minimum time value or None
        """
        if ('custom' in rule.custom_attributes and 
            OpenSearchPPLCustomAttributes.MIN_TIME.value in rule.custom_attributes['custom']):
            return rule.custom_attributes['custom'][OpenSearchPPLCustomAttributes.MIN_TIME.value]
        return self._min_time
    
    def _get_max_time(self, rule: SigmaRule) -> Optional[str]:
        """
        Get the maximum time filter.
        
        Priority:
        1. Custom attribute in rule YAML (opensearch_ppl_max_time)
        2. Backend option (max_time)
        
        Args:
            rule: Sigma rule
            
        Returns:
            Maximum time value or None
        """
        if ('custom' in rule.custom_attributes and 
            OpenSearchPPLCustomAttributes.MAX_TIME.value in rule.custom_attributes['custom']):
            return rule.custom_attributes['custom'][OpenSearchPPLCustomAttributes.MAX_TIME.value]
        return self._max_time
    
    def _format_time_modifier(self, time_str: str) -> str:
        """
        Format time modifier for PPL search command.
        
        Args:
            time_str: Time string like "-30d", "now", "2024-01-01T00:00:00", "-1month@month"
            
        Returns:
            Formatted time modifier for PPL search command
        """
        # Handle "now"
        if time_str.lower() == "now":
            return "now"
        
        # Handle relative time with rounding like "-1month@month", "+1d@d"
        if "@" in time_str:
            # Wrap in quotes for time rounding expressions
            return f"'{time_str}'"
        
        # Handle simple relative time like "-30d", "-7d", "-1h"
        if time_str.startswith("-") or time_str.startswith("+"):
            # Remove the dash/plus and keep the time unit as-is
            return time_str
        
        # Handle absolute timestamps - wrap in quotes
        # Support both formats: "2024-01-01T00:00:00" and "2024-01-01 00:00:00"
        return f"'{time_str}'"
    
    ### Correlation rule conversion methods ###
    
    def convert_rule(self, rule: SigmaRule, output_format: str = "default", callback=None) -> list[str]:
        """
        Convert a Sigma rule (regular or correlation) to PPL query.
        
        Args:
            rule: The Sigma rule to convert (can be regular or correlation)
            output_format: Output format to use
            callback: Optional callback function
            
        Returns:
            List of generated PPL queries
        """
        # Check if this is a correlation rule using isinstance
        if isinstance(rule, SigmaCorrelationRule):
            return self.convert_correlation_rule(rule, method="default")
        else:
            return super().convert_rule(rule, output_format, callback)
    
    def convert_correlation_rule(
        self, rule: SigmaCorrelationRule, output_format: str = None, method: str = None, correlation_method: str = None
    ) -> list[str]:
        """
        Convert a Sigma correlation rule to PPL query.
        
        Args:
            rule: The correlation rule to convert
            output_format: Output format (not used, for compatibility)
            method: Correlation method (deprecated, use correlation_method)
            correlation_method: Correlation method to use (default: "default")
            
        Returns:
            List containing the generated PPL query
        """
        # Support both 'method' and 'correlation_method' for backward compatibility
        final_method = correlation_method or method or "default"
        return self.convert_correlation_rule_from_template(rule, rule.type, final_method)
    
    def convert_correlation_rule_from_template(
        self,
        rule: SigmaCorrelationRule,
        correlation_type: SigmaCorrelationTypeLiteral,
        method: str,
    ) -> list[str]:
        """
        Convert correlation rule using templates.
        
        Orchestrates the three phases: Search, Aggregate, Condition.
        
        Args:
            rule: The correlation rule to convert
            correlation_type: Type of correlation (event_count, value_count, etc.)
            method: Correlation method to use
            
        Returns:
            List containing the generated PPL query
        """
        # Get template - all types use default_correlation_query now
        template = self.default_correlation_query
        
        if template is None or method not in template:
            raise SigmaConversionError(
                f"Correlation method '{method}' is not supported by backend for "
                f"correlation type '{correlation_type}'."
            )
        
        # Generate the three phases
        search = self.convert_correlation_search(rule)
        aggregate = self.convert_correlation_aggregation_from_template(
            rule, correlation_type, method, search
        )
        condition = self.convert_correlation_condition_from_template(
            rule.condition, rule.rules, correlation_type, method, rule
        )
        
        # Build final query from template
        query = template[method].format(
            search=search,
            aggregate=aggregate,
            condition=condition,
        )
        
        # Note: Time filters are now applied individually per detection rule in convert_correlation_search()
        # This allows both correlation-level and detection-level time filters
        
        return [query]
    
    def convert_correlation_search(self, rule: SigmaCorrelationRule, **kwargs) -> str:
        """
        Convert the search phase of a correlation rule.
        
        Uses OpenSearch 3.4+ multisearch command for correlation rules with multiple
        subsearches, or a single search command if only one rule is referenced.
        
        Time filters logic:
        - If detection rule has custom time attributes → use them for that specific rule
        - If correlation rule has custom time attributes → apply to all detection rules without their own
        
        Args:
            rule: The correlation rule
            **kwargs: Additional arguments
            
        Returns:
            Multisearch expression combining all referred detection rules, or a
            single search query if only one rule is referenced
        """
        # Get correlation-level time filters (fallback for detection rules without their own)
        corr_min_time = self._get_min_time(rule)
        corr_max_time = self._get_max_time(rule)
        
        # Collect complete queries from all referred rules
        subsearches = []
        
        for rule_reference in rule.rules:
            referred_rule = rule_reference.rule
            for query in referred_rule.get_conversion_result():
                # Check if this detection rule has its own time attributes
                detection_min_time = self._get_min_time(referred_rule)
                detection_max_time = self._get_max_time(referred_rule)
                
                # Use detection rule's time filters if present, otherwise use correlation's
                min_time = detection_min_time if detection_min_time else corr_min_time
                max_time = detection_max_time if detection_max_time else corr_max_time
                
                # Apply time filters to this specific subsearch if needed
                # Only apply if the query doesn't already have time filters (from detection rule)
                needs_time_filters = (min_time or max_time) and not query.startswith("search ")
                
                if needs_time_filters:
                    time_modifiers = []
                    if min_time:
                        time_modifiers.append(f"earliest={self._format_time_modifier(min_time)}")
                    if max_time:
                        time_modifiers.append(f"latest={self._format_time_modifier(max_time)}")
                    
                    time_str = " ".join(time_modifiers)
                    
                    # Add time modifiers to the query
                    if query.startswith("source="):
                        # Convert "source=... | where ..." to "search earliest=... source=... | where ..."
                        query = f"search {time_str} {query}"
                
                # Store complete query for multisearch
                subsearches.append(query)
        
        # If only one subsearch, return it directly (multisearch requires at least 2)
        if len(subsearches) == 1:
            query = subsearches[0]
            if not query.startswith("search "):
                query = f"search {query}"
            return f"| {query}"
        
        # Use multisearch command for multiple subsearches
        # Format: | multisearch [search source=index1 | where ...] [search source=index2 | where ...]
        formatted_subsearches = []
        for query in subsearches:
            # Wrap each query in square brackets and ensure it starts with 'search'
            if not query.startswith("search "):
                query = f"search {query}"
            formatted_subsearches.append(f"[{query}]")
        
        return "| multisearch " + " ".join(formatted_subsearches)
    
    def _format_timespan(self, timespan) -> str:
        """Format timespan for PPL query ("5m", "30m", "2h")."""
        if hasattr(timespan, 'spec'):
            return str(timespan.spec)
        elif hasattr(timespan, 'total_seconds'):
            seconds = int(timespan.total_seconds())
            if seconds % 3600 == 0:
                return f"{seconds // 3600}h"
            elif seconds % 60 == 0:
                return f"{seconds // 60}m"
            else:
                return f"{seconds}s"
        else:
            return str(timespan)
    
    def convert_correlation_aggregation_from_template(
        self,
        rule: SigmaCorrelationRule,
        correlation_type: SigmaCorrelationTypeLiteral,
        method: str,
        search: str,
    ) -> str:
        """Convert the aggregation phase of a correlation rule."""
        templates = getattr(self, f"{correlation_type}_aggregation_expression", self.default_aggregation_expression)
        template = templates[method]
        
        # Get field for value_count correlation
        field = ""
        if (correlation_type == "value_count" or 
            correlation_type == SigmaCorrelationType.VALUE_COUNT) and rule.condition:
            if hasattr(rule.condition, 'fieldref') and rule.condition.fieldref:
                field = rule.condition.fieldref
        
        # Format timespan for temporal correlations
        timespan = self._format_timespan(rule.timespan) if hasattr(rule, 'timespan') else "5m"
        
        return template.format(
            groupby=self.convert_correlation_aggregation_groupby_from_template(rule.group_by, method),
            field=field,
            time_field=self._time_field,
            timespan=timespan
        )
    
    def convert_correlation_aggregation_groupby_from_template(
        self, group_by: Optional[list[str]], method: str
    ) -> str:
        """Convert group-by fields to PPL format."""
        if not group_by:
            return ""
        
        fields = self.groupby_field_expression_joiner[method].join(
            self.groupby_field_expression[method].format(field=field)
            for field in group_by
        )
        
        return self.groupby_expression[method].format(fields=fields)
    
    def convert_correlation_condition_from_template(
        self,
        condition: Any,
        rules: list,
        correlation_type: SigmaCorrelationTypeLiteral,
        method: str,
        rule: SigmaCorrelationRule,
    ) -> str:
        """Convert the condition phase of a correlation rule."""
        templates = getattr(self, f"{correlation_type}_condition_expression", self.default_condition_expression)
        template = templates[method]
        
        # For temporal correlations, we need to check that all rules matched
        # So the count should be the number of rules in the correlation
        if correlation_type in [SigmaCorrelationType.TEMPORAL, SigmaCorrelationType.TEMPORAL_ORDERED, "temporal", "temporal_ordered"]:
            rule_count = len(rules)
            return template.format(rule_count=rule_count)
        
        # For other correlation types, extract operator and count from condition
        if hasattr(condition, 'op') and hasattr(condition, 'count'):
            op_str = condition.op.name  # Get enum name ('GTE')
            count = condition.count
        elif isinstance(condition, dict):
            op_str = list(condition.keys())[0].upper()
            count = list(condition.values())[0]
        else:
            raise SigmaConversionError(f"Unsupported condition format: {condition}")
        
        # Map operator to PPL format
        op_str_lower = op_str.lower()
        if op_str_lower not in self.correlation_condition_op:
            raise SigmaConversionError(f"Unsupported condition operator: {op_str}")
        
        op = self.correlation_condition_op[op_str_lower]
        
        # Get field if needed for value_count
        field = ""
        if correlation_type == "value_count" and hasattr(condition, 'fieldref'):
            field = condition.fieldref or ""
        
        return template.format(op=op, count=count, field=field)
