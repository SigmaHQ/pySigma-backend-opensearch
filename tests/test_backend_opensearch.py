import pytest
from sigma.backends.opensearch import OpensearchLuceneBackend
from sigma.collection import SigmaCollection

@pytest.fixture
def es_qs_backend():
    return OpensearchLuceneBackend()

def test_os_qs_and_expression(es_qs_backend : OpensearchLuceneBackend):
    assert es_qs_backend.convert(
        SigmaCollection.from_yaml("""
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
    ) == ['fieldA:valueA AND fieldB:valueB']

def test_os_qs_or_expression(es_qs_backend : OpensearchLuceneBackend):
    assert es_qs_backend.convert(
        SigmaCollection.from_yaml("""
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
    ) == ['fieldA:valueA OR fieldB:valueB']

def test_os_qs_and_or_expression(es_qs_backend : OpensearchLuceneBackend):
    assert es_qs_backend.convert(
        SigmaCollection.from_yaml("""
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
    ) == ['(fieldA:(valueA1 OR valueA2)) AND (fieldB:(valueB1 OR valueB2))']

def test_os_qs_or_and_expression(es_qs_backend : OpensearchLuceneBackend):
    assert es_qs_backend.convert(
        SigmaCollection.from_yaml("""
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
    ) == ['(fieldA:valueA1 AND fieldB:valueB1) OR (fieldA:valueA2 AND fieldB:valueB2)']

def test_os_qs_in_expression(es_qs_backend : OpensearchLuceneBackend):
    assert es_qs_backend.convert(
        SigmaCollection.from_yaml("""
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
    ) == ['fieldA:(valueA OR valueB OR valueC*)']

def test_os_qs_regex_query(es_qs_backend : OpensearchLuceneBackend):
    assert es_qs_backend.convert(
        SigmaCollection.from_yaml("""
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
    ) == ['fieldA:/foo.*bar/ AND fieldB:foo']

def test_os_qs_cidr_query(es_qs_backend : OpensearchLuceneBackend):
    assert es_qs_backend.convert(
        SigmaCollection.from_yaml("""
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
    ) == ['field:192.168.0.0/16']

def test_os_qs_field_name_with_whitespace(es_qs_backend : OpensearchLuceneBackend):
    assert es_qs_backend.convert(
        SigmaCollection.from_yaml("""
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
    ) == ['field\\ name:value']

def test_os_qs_listmapmix_all(es_qs_backend : OpensearchLuceneBackend):
    assert es_qs_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    - fieldA: valueA
                    - fieldB: valueB
                sel2:
                    fieldC: valueC
                condition: all of sel*
        """)
    ) == ['(fieldA:valueA OR fieldB:valueB) AND fieldC:valueC']

def test_elasticsearch_dql_output(es_qs_backend : OpensearchLuceneBackend):
    """Test for output format dql."""
    # TODO: implement a test for the output format
    pass

