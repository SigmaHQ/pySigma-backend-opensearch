from .opensearch import OpensearchLuceneBackend
from .opensearch_ppl import OpenSearchPPLBackend

backends = {
    "opensearch": OpensearchLuceneBackend,
    "opensearch-ppl": OpenSearchPPLBackend,
}
