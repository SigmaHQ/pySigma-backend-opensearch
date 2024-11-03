import time
import pytest
import requests
from sigma.backends.opensearch import OpensearchLuceneBackend
from sigma.collection import SigmaCollection


def os_available_test():
    try:
        requests.get('http://localhost:9200/', timeout=120)
    except requests.exceptions.ConnectionError:
        return False
    return True


@pytest.fixture(scope="class")
def prepare_es_data():
    if os_available_test():
        requests.delete('http://localhost:9200/test-index', timeout=120)
        requests.put("http://localhost:9200/test-index", timeout=120)
        requests.put("http://localhost:9200/test-index/_mapping", timeout=120, json={
            "properties": {
                "field": {
                    "type": "ip"
                }
            }
        }
        )
        requests.post("http://localhost:9200/test-index/_doc/", timeout=120,
                      json={"fieldA": "valueA", "fieldB": "valueB"})
        requests.post("http://localhost:9200/test-index/_doc/", timeout=120,
                      json={"fieldA": "valueA1", "fieldB": "valueB1"})
        requests.post("http://localhost:9200/test-index/_doc/", timeout=120,
                      json={"fieldA": "valueA2", "fieldB": "valueB2"})
        requests.post("http://localhost:9200/test-index/_doc/", timeout=120,
                      json={"fieldA": "foosamplebar", "fieldB": "foo"})
        requests.post("http://localhost:9200/test-index/_doc/", timeout=120,
                      json={"field": "192.168.1.1"})
        requests.post("http://localhost:9200/test-index/_doc/", timeout=120,
                      json={"field name": "value"})
        # Wait a bit for Documents to be indexed
        time.sleep(1)


@pytest.fixture
def lucene_backend():
    return OpensearchLuceneBackend()


@pytest.mark.skipif(os_available_test() == False, reason="OpenSearch not available")
class TestConnectOpensearch:

    def query_backend_hits(self, query, num_wanted=0):
        r = requests.post(
            'http://localhost:9200/test-index/_search', timeout=120, json=query)
        assert r.status_code == 200
        rjson = r.json()
        assert 'hits' in rjson
        assert 'total' in rjson['hits']
        assert rjson['hits']['total']['value'] == num_wanted
        return rjson

    def test_connect_lucene_and_expression(self, prepare_es_data, lucene_backend: OpensearchLuceneBackend):
        rule = SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel:
                        fieldA: valueA
                        fieldB: valueB
                    condition: sel
            """)

        result_dsl = lucene_backend.convert(
            rule, output_format="dsl_lucene")[0]
        es_query_result = self.query_backend_hits(result_dsl, num_wanted=1)

    def test_connect_lucene_or_expression(self, prepare_es_data, lucene_backend: OpensearchLuceneBackend):
        rule = SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel1:
                        fieldA: valueA
                    sel2:
                        fieldB: valueB
                    condition: 1 of sel*
            """)
        result_dsl = lucene_backend.convert(
            rule, output_format="dsl_lucene")[0]
        es_query_result = self.query_backend_hits(result_dsl, num_wanted=1)

    def test_connect_lucene_and_or_expression(self, prepare_es_data, lucene_backend: OpensearchLuceneBackend):
        rule = SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel:
                        fieldA:
                            - valueA1
                            - valueA2
                        fieldB:
                            - valueB1
                            - valueB2
                    condition: sel
            """)
        result_dsl = lucene_backend.convert(
            rule, output_format="dsl_lucene")[0]
        result_dsl = lucene_backend.convert(
            rule, output_format="dsl_lucene")[0]
        es_query_result = self.query_backend_hits(result_dsl, num_wanted=2)

    def test_connect_lucene_or_and_expression(self, prepare_es_data, lucene_backend: OpensearchLuceneBackend):
        rule = SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel1:
                        fieldA: valueA1
                        fieldB: valueB1
                    sel2:
                        fieldA: valueA2
                        fieldB: valueB2
                    condition: 1 of sel*
            """)
        result_dsl = lucene_backend.convert(
            rule, output_format="dsl_lucene")[0]
        es_query_result = self.query_backend_hits(result_dsl, num_wanted=2)

    def test_connect_lucene_in_expression(self, prepare_es_data, lucene_backend: OpensearchLuceneBackend):
        rule = SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel:
                        fieldA:
                            - valueA
                            - valueB
                            - valueC*
                    condition: sel
            """)
        result_dsl = lucene_backend.convert(
            rule, output_format="dsl_lucene")[0]
        es_query_result = self.query_backend_hits(result_dsl, num_wanted=1)

    def test_connect_lucene_regex_query(self, prepare_es_data, lucene_backend: OpensearchLuceneBackend):
        rule = SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel:
                        fieldA|re: foo.*bar
                        fieldB: foo
                    condition: sel
            """)
        result_dsl = lucene_backend.convert(
            rule, output_format="dsl_lucene")[0]
        es_query_result = self.query_backend_hits(result_dsl, num_wanted=1)

    def test_connect_lucene_cidr_query(self, prepare_es_data, lucene_backend: OpensearchLuceneBackend):
        rule = SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel:
                        field|cidr: 192.168.0.0/16
                    condition: sel
            """)

        result_dsl = lucene_backend.convert(
            rule, output_format="dsl_lucene")[0]
        es_query_result = self.query_backend_hits(result_dsl, num_wanted=1)

    def test_connect_lucene_field_name_with_whitespace(self, prepare_es_data, lucene_backend: OpensearchLuceneBackend):
        rule = SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel:
                        field name: value
                    condition: sel
            """)
        result_dsl = lucene_backend.convert(
            rule, output_format="dsl_lucene")[0]
        es_query_result = self.query_backend_hits(result_dsl, num_wanted=1)
