"""
OpenSearch PPL backend for Sigma rules.

This backend converts Sigma detection rules (both regular and correlation rules)
into PPL (Piped Processing Language) queries for OpenSearch.

Supports:
- Regular Sigma detection rules
- Correlation rules (event_count, value_count, temporal, temporal_ordered)
- All standard Sigma modifiers and features
"""

from typing import ClassVar, Optional, Pattern, Dict, Any, List
import re
from enum import Enum

from sigma.conversion.base import TextQueryBackend  # pyright: ignore[reportMissingTypeStubs]
from sigma.conversion.deferred import (  # pyright: ignore[reportMissingTypeStubs]
    DeferredQueryExpression,
    DeferredTextQueryExpression,
)
from sigma.conversion.state import ConversionState  # pyright: ignore[reportMissingTypeStubs]
from sigma.correlations import (
    SigmaCorrelationRule,
)
from sigma.exceptions import SigmaValueError
from sigma.processing.pipeline import ProcessingPipeline  # pyright: ignore[reportMissingTypeStubs]
from sigma.rule import SigmaRule  # pyright: ignore[reportMissingTypeStubs]
from sigma.types import CompareOperators, SigmaCompareExpression
from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionItem,
    ConditionOR,
    ConditionNOT,
)


class PPLDeferredRegexExpression(DeferredTextQueryExpression):
    template: ClassVar[str] = 'regex {field}{op}"{value}"'
    operators: ClassVar[Dict[bool, str]] = {
        True: "!=",
        False: "=",
    }
    # OpenSearch does not really have an equivalent to Splunk's `_raw`
    # We chose message as it is closest in meaning, but it is not equivalent.
    default_field: ClassVar[str | None] = "message"


class OpenSearchPPLCustomAttributes(Enum):
    """
    Custom attributes that can be set in Sigma rules to configure OpenSearch PPL backend behavior.

    These can be used in a Sigma rule YAML like:

    opensearch_ppl_backend:
      index: "my-custom-index-*"
    """

    INDEX = "index"


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
        # "kibana": "Kibana dashboard format (future)",
    }
    requires_pipeline: ClassVar[bool] = False

    # Operator precedence (NOT > AND > OR)
    precedence: ClassVar[
        tuple[type[ConditionItem], type[ConditionItem], type[ConditionItem]]
    ] = (ConditionNOT, ConditionAND, ConditionOR)
    group_expression: ClassVar[str | None] = "({expr})"

    # Generated query tokens
    token_separator: str = " "
    or_token: ClassVar[str] = "OR"
    and_token: ClassVar[str] = "AND"
    not_token: ClassVar[str] = "NOT"
    eq_token: ClassVar[str] = "="

    # Query structure
    query_expression: ClassVar[str] = "{query}"

    # String output
    ## Fields
    ### Quoting
    # PPL allows unquoted alphanumeric field names
    field_quote: ClassVar[str | None] = "`"  # Backticks for fields with special chars
    field_quote_pattern: ClassVar[Pattern[str] | None] = re.compile(
        r"^[a-zA-Z_][a-zA-Z0-9_]*$"
    )
    field_quote_pattern_negation: ClassVar[bool] = (
        True  # Quote if pattern does NOT match
    )

    ## Values
    ### String quoting
    str_quote: ClassVar[str] = '"'  # Double quotes for string values
    ### String escaping and filtering
    escape_char: ClassVar[str | None] = "\\"
    wildcard_multi: ClassVar[str | None] = (
        "%"  # PPL LIKE function uses % for multi-character wildcard
    )
    wildcard_single: ClassVar[str | None] = (
        "_"  # PPL LIKE function uses _ for single-character wildcard
    )
    # Note: At the time of writing, there is an issue with backslashes used in
    # PPL LIKE patterns. Queries are emmitted with the expected behaviour, even
    # if it doesn't work for now.
    # https://github.com/opensearch-project/sql/issues/5627
    add_escaped: ClassVar[str] = "\\"  # escape backslashes

    ### Booleans
    bool_values: ClassVar[
        dict[bool, str | None]
    ] = {  # Values to which boolean values are mapped.
        True: "true",
        False: "false",
    }

    # String matching operators with PPL's LIKE() function
    # PPL uses LIKE(field, "pattern") with % for wildcards
    # PPL uses field="exact" for exact matches
    startswith_expression: ClassVar[str | None] = "LIKE({field}, {value}%, false)"
    endswith_expression: ClassVar[str | None] = "LIKE({field}, %{value}, false)"
    contains_expression: ClassVar[str | None] = "LIKE({field}, %{value}%, false)"
    wildcard_match_expression: ClassVar[str | None] = "LIKE({field}, {value}, false)"

    # TODO fix this, needs to be deferred
    # Regular expressions in PPL
    # PPL supports: field match 'regex' or match(field, 'regex')
    # Note: Backslashes in regex are NOT escaped because they're already within single quotes
    # Only single quotes need escaping by doubling them
    re_expression: ClassVar[str | None] = "{regex}"
    re_escape_char: ClassVar[str] = "\\"
    re_escape: ClassVar[list[str]] = [
        '"',
    ]

    # Case-sensitive string matching with 'cased' modifier
    # PPL LIKE function with third parameter set to true enables case-sensitive matching
    case_sensitive_match_expression: ClassVar[str | None] = "{field}={value}"
    case_sensitive_startswith_expression: ClassVar[str | None] = (
        "LIKE({field}, {value}%, true)"
    )
    case_sensitive_endswith_expression: ClassVar[str | None] = (
        "LIKE({field}, %{value}, true)"
    )
    case_sensitive_contains_expression: ClassVar[str | None] = (
        "LIKE({field}, %{value}%, true)"
    )

    # CIDR expressions
    cidr_expression: ClassVar[str | None] = 'cidrmatch({field}, "{value}")'

    # Numeric comparison operators
    compare_op_expression: ClassVar[str | None] = "{field}{operator}{value}"
    compare_operators: ClassVar[Dict[CompareOperators, str] | None] = {
        SigmaCompareExpression.CompareOperators.LT: "<",
        SigmaCompareExpression.CompareOperators.LTE: "<=",
        SigmaCompareExpression.CompareOperators.GT: ">",
        SigmaCompareExpression.CompareOperators.GTE: ">=",
    }

    # Expression for comparing two event fields
    field_equals_field_expression: ClassVar[str | None] = "{field1}={field2}"

    # Null/None expressions
    field_null_expression: ClassVar[str | None] = "isnull({field})"

    # Field existence condition expressions.
    field_exists_expression: ClassVar[str | None] = "isnotnull({field})"
    field_not_exists_expression: ClassVar[str | None] = "isnull({field})"

    # Field value in list
    field_in_list_expression: ClassVar[str | None] = "{field} in ({list})"
    or_in_operator: ClassVar[str | None] = "in"
    list_separator: ClassVar[str | None] = ", "
    convert_or_as_in: ClassVar[bool] = True
    convert_and_as_in: ClassVar[bool] = False
    in_expressions_allow_wildcards: ClassVar[bool] = False

    # Value not bound to a field
    unbound_value_str_expression: ClassVar[str | None] = "query_string({value})"
    unbound_value_num_expression: ClassVar[str | None] = "query_string({value})"

    # Query finalization: appending and concatenating deferred query part
    deferred_start: ClassVar[str | None] = "| "
    deferred_separator: ClassVar[str | None] = " | "
    deferred_only_query: ClassVar[str] = ""

    ### Correlation support ###
    # Correlation methods supported by this backend
    correlation_methods: ClassVar[Dict[str, str] | None] = {
        "default": "Default method",
    }
    default_correlation_method: ClassVar[str] = "default"

    ### Correlation rule templates
    ## Correlation query frame
    # All correlation types use the same query structure:
    # {search} | stats {aggregate} | where {condition}
    default_correlation_query: ClassVar[Dict[str, str] | None] = {
        "default": "{search} | stats {aggregate} | where {condition}"
    }

    ## Correlation query search phase
    correlation_search_single_rule_expression: ClassVar[str | None] = "{query}"
    correlation_search_multi_rule_expression: ClassVar[str | None] = (
        "| multisearch {queries}"
    )
    correlation_search_multi_rule_query_expression: ClassVar[str | None] = (
        '[search {query} | eval event_type="{ruleid}"{normalization}]'
    )
    correlation_search_multi_rule_query_expression_joiner: ClassVar[str | None] = " "
    # Event field normalization expression.
    correlation_search_field_normalization_expression: ClassVar[str | None] = (
        " | rename {field} as {alias}"
    )
    correlation_search_field_normalization_expression_joiner: ClassVar[str | None] = " "

    ## Correlation query aggregation phase
    event_count_aggregation_expression: ClassVar[Dict[str, str] | None] = {
        "default": "count() as event_count by span(@timestamp, {timespan}){groupby}"
    }
    value_count_aggregation_expression: ClassVar[Dict[str, str] | None] = {
        "default": "dc({field}) as value_count by span(@timestamp, {timespan}){groupby}"
    }
    temporal_aggregation_expression: ClassVar[Dict[str, str] | None] = {
        "default": "dc(event_type) as unique_rules by span(@timestamp, {timespan}){groupby}"
    }

    # Group-by expression templates
    groupby_expression: ClassVar[Dict[str, str] | None] = {"default": ", {fields}"}
    groupby_field_expression: ClassVar[Dict[str, str] | None] = {"default": "{field}"}
    groupby_field_expression_joiner: ClassVar[Dict[str, str] | None] = {"default": ", "}
    groupby_expression_nofield: ClassVar[dict[str, str] | None] = {"default": ""}

    # Correlation condition expressions
    event_count_condition_expression: ClassVar[Dict[str, str] | None] = {
        "default": "event_count {op} {count}",
    }

    # Temporal correlations check that all rules matched (distinct EventIDs)
    temporal_condition_expression: ClassVar[Dict[str, str] | None] = {
        "default": "unique_rules {op} {count}"
    }

    value_count_condition_expression: ClassVar[Dict[str, str] | None] = {
        "default": "value_count {op} {count}",
    }

    def __init__(  # pyright: ignore[reportInconsistentConstructor]
        self,
        processing_pipeline: Optional[ProcessingPipeline] = None,
        collect_errors: bool = False,
        min_time: str | None = None,
        max_time: str | None = None,
        custom_logsource: str | None = None,
        **kwargs: Dict[str, Any],
    ):
        """
        Initialize the OpenSearch PPL backend.

        Args:
            processing_pipeline: Optional processing pipeline for rule transformation
            collect_errors: If True, collect errors instead of raising them
            min_time: Minimum time filter (earliest). Examples: "-30d", "-7d", "2024-01-01T00:00:00"
            max_time: Maximum time filter (latest). Examples: "now", "2024-12-31T23:59:59"
            custom_logsource: Custom index pattern to override logsource-based pattern (default: None)
        """
        super().__init__(processing_pipeline, collect_errors=collect_errors, **kwargs)
        self._custom_logsource: Optional[str] = custom_logsource
        self._min_time: Optional[str] = min_time
        self._max_time: Optional[str] = max_time

    ### Regular rule conversion methods ###

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
        custom_attributes = rule.custom_attributes.get("opensearch_ppl_backend")
        if custom_attributes is not None:
            index = custom_attributes.get(OpenSearchPPLCustomAttributes.INDEX.value)
            if index is not None:
                return index

        # Priority 2: If custom logsource is provided via backend option, use it
        if self._custom_logsource:
            return self._custom_logsource

        # Priority 3: Map logsource to index pattern
        logsource = rule.logsource

        # Build index pattern from logsource components
        raw_index_parts: List[str | None] = [
            logsource.product,
            logsource.category,
            logsource.service,
        ]
        index_parts: List[str] = [x for x in raw_index_parts if x is not None]

        return "-".join([*index_parts, ""]) + "*"

    def finish_query(
        self,
        rule: SigmaRule | SigmaCorrelationRule,
        query: str | DeferredQueryExpression,
        state: ConversionState,
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
        if isinstance(rule, SigmaCorrelationRule):
            return super().finish_query(rule, query, state)

        # Get index pattern from logsource
        index_pattern = self._get_index_pattern(rule)

        only_deferred = False
        if isinstance(query, DeferredQueryExpression):
            only_deferred = True

        # Handle deferred expressions (if any)
        finished_query: str = super().finish_query(rule, query, state)

        # Fix LIKE expressions: move wildcards inside quotes
        # Handle all patterns in one comprehensive replacement
        def fix_wildcards(match: re.Match[str]) -> str:
            leading = match.group(1) or ""  # % before "
            content = match.group(2)  # content between quotes
            trailing = match.group(3) or ""  # % after "
            return f'"{leading}{content}{trailing}"'

        finished_query = re.sub(r'(%?)"(.*?)"(%?)', fix_wildcards, finished_query)

        # Build time modifiers using custom attributes or backend options
        min_time = self._min_time
        max_time = self._max_time

        time_str = ""
        if min_time or max_time:
            # Build time modifiers for search command
            time_modifiers: List[str] = []
            if min_time:
                time_modifiers.append(
                    f"earliest={self._format_time_modifier(min_time)}"
                )
            if max_time:
                time_modifiers.append(f"latest={self._format_time_modifier(max_time)}")

            time_str = " ".join([*time_modifiers, ""])

        # Construct search command: "[time_modifiers] source=<index> | where <query>"
        # The query condition must come AFTER source with | where
        ppl_query = f"{time_str}source={index_pattern} {'| where ' if not only_deferred else ''}{finished_query}"

        return ppl_query

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
        # PPL doesn't accept ISO8601 format with 'T', so convert to space
        # Convert "2024-01-01T00:00:00" to "2024-01-01 00:00:00"
        time_str = time_str.replace("T", " ")
        return f"'{time_str}'"

    ### Deferred conversion methods ###

    def convert_condition_field_eq_val_re(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> PPLDeferredRegexExpression:
        """Defer regular expression matching to pipelined regex command after main search expression."""

        if cond.parent_condition_chain_contains(ConditionOR):
            # While technically it could be implemented similar to the Splunk backend with rex,
            # there is no equivalent to the _raw field in OpenSearch. Another option is to use
            # multisearch and generate separate subqueries for each or, but that gets messy
            # if you combine it with other Sigma conditions. Lastly, It might be easier to implement
            # using the append command in PPL, but for now the effort is not worth it: regex
            # are pretty inefficient/expensive and might not even work properly depending on the
            # base field type (fields that are tokenized - i.e text - do not work properly).
            raise NotImplementedError(
                "OpenSearch PPL backend does not support regex expressions chained by OR"
            )

        val = super().convert_condition_field_eq_val_re(cond, state)
        if isinstance(val, str):
            return PPLDeferredRegexExpression(
                conversion_state=state, field=cond.field, value=val
            )
        else:
            # This should not be hit, but it's here to tame the type checker
            raise SigmaValueError
