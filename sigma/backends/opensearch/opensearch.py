from sigma.conversion.state import ConversionState
from sigma.rule import SigmaRule
import sigma
import json
from typing import ClassVar, Dict, List, Optional
from sigma.backends.elasticsearch import LuceneBackend

class OpensearchLuceneBackend(LuceneBackend):
    """OpensearchLuceneBackend backend."""

    def __init__(self, processing_pipeline: Optional["sigma.processing.pipeline.ProcessingPipeline"] = None,
        collect_errors: bool = False, index_names : List = ["beats-*"], monitor_interval : int = 5,
        monitor_interval_unit : str = "MINUTES", **kwargs):

        super().__init__(processing_pipeline, collect_errors, **kwargs)
        self.index_names = index_names or ["beats-*"]
        self.monitor_interval = monitor_interval or 5
        self.monitor_interval_unit = monitor_interval_unit or "MINUTES"

    def finalize_query_monitor_rule(self, rule: SigmaRule, query: str, index: int, state: ConversionState) -> dict:
        # TODO: implement the per-query output for the output format lql here. Usually, the generated query is
        # embedded into a template, e.g. a JSON format with additional information from the Sigma rule.
        severity_mapping = {
            5: 1,
            4: 2,
            3: 3,
            2: 4,
            1: 5
        }
        monitor_rule = {
            "type": "monitor",
            "name": "SIGMA - {}".format(rule.title),
            "description": rule.description,
            "enabled": True,
            "schedule": {
                "period": {
                    "interval": self.monitor_interval,
                    "unit": self.monitor_interval_unit
                }
            },
            "inputs": [
                {
                    "search": {
                        "indices": self.index_names,
                        "query": {
                            "size": 1,
                            "query": {
                                "bool": {
                                    "must": [
                                        {
                                            "query_string": {
                                                "query": query,
                                                "analyze_wildcard": True
                                            }
                                        }
                                    ]
                                }
                            }
                        }
                    }
                }
            ],
            "tags": ["{}-{}".format(n.namespace, n.name) for n in rule.tags],
            "triggers": [
                {
                    "name": "generated-trigger",
                    "severity": severity_mapping[rule.level.value] if rule.level is not None else 1,
                    "condition": {
                        "script": {
                            "source": "ctx.results[0].hits.total.value > 0",
                            "lang": "painless"
                        }
                    },
                    "actions": []
                }
            ],
            "sigma_meta_data": {
                "rule_id": str(rule.id),
                "threat": []
            },
            "references": rule.references
        }

        return monitor_rule

    def finalize_output_monitor_rule(self, queries: List[str]) -> str:
        # TODO: implement the output finalization for all generated queries for the format lql here. Usually,
        # the single generated queries are embedded into a structure, e.g. some JSON or XML that can be imported into
        # the SIEM.
        return list(queries)

    def finalize_query_dashboards_ndjson(self, rule: SigmaRule, query: str, index: int, state: ConversionState) -> str:
        """Alias to Kibana NDJSON query finalization."""
        return self.finalize_query_kibana_ndjson(rule, query, index, state)

    def finalize_output_dashboards_ndjson(self, queries: List[str]) -> str:
        """Alias to Kibana NDJSON output finalization."""
        return self.finalize_output_kibana_ndjson(queries)