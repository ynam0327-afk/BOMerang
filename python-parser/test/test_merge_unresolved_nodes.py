
from python_parser import PythonParser
from dependency_node import DependencyNode


def make_node(name, version, declared_version, purl, depth=2,
              dependencies=None):
    return DependencyNode(
        name=name,
        ecosystem="pypi",
        declared_version=declared_version,
        resolved_version=version,
        purl=purl,
        depth=depth,
        scope=None,
        source_file="requirements.txt",
        parse_status="success",
        dependencies=dependencies or [],
    )


def test_merge_unresolved_node_when_version_is_compatible():
    parser = PythonParser(pypi_client=object())

    unresolved = make_node(
        "colorama", None, ">=0.2.4", "pkg:pypi/colorama"
    )
    resolved = make_node(
        "colorama", "0.4.6", "==0.4.6",
        "pkg:pypi/colorama@0.4.6"
    )
    parent = make_node(
        "click", "8.1.7", "==8.1.7",
        "pkg:pypi/click@8.1.7",
        dependencies=["pkg:pypi/colorama"]
    )

    nodes = {
        unresolved.purl: unresolved,
        resolved.purl: resolved,
        parent.purl: parent,
    }

    parser._merge_unresolved_nodes(nodes)

    assert "pkg:pypi/colorama" not in nodes
    assert "pkg:pypi/colorama@0.4.6" in nodes
    assert parent.dependencies == ["pkg:pypi/colorama@0.4.6"]
    assert nodes["pkg:pypi/colorama@0.4.6"].resolved_version == "0.4.6"


def test_keep_unresolved_node_when_multiple_versions_exist():
    parser = PythonParser(pypi_client=object())

    unresolved = make_node(
        "colorama", None, ">=0.2.4", "pkg:pypi/colorama"
    )
    v1 = make_node(
        "colorama", "0.4.6", "==0.4.6",
        "pkg:pypi/colorama@0.4.6"
    )
    v2 = make_node(
        "colorama", "0.4.7", "==0.4.7",
        "pkg:pypi/colorama@0.4.7"
    )

    nodes = {
        unresolved.purl: unresolved,
        v1.purl: v1,
        v2.purl: v2,
    }

    parser._merge_unresolved_nodes(nodes)

    assert "pkg:pypi/colorama" in nodes
    assert "pkg:pypi/colorama@0.4.6" in nodes
    assert "pkg:pypi/colorama@0.4.7" in nodes


def test_do_not_merge_when_version_constraint_conflicts():
    parser = PythonParser(pypi_client=object())

    unresolved = make_node(
        "colorama", None, ">=1.0", "pkg:pypi/colorama"
    )
    resolved = make_node(
        "colorama", "0.4.6", "==0.4.6",
        "pkg:pypi/colorama@0.4.6"
    )

    nodes = {
        unresolved.purl: unresolved,
        resolved.purl: resolved,
    }

    parser._merge_unresolved_nodes(nodes)

    assert "pkg:pypi/colorama" in nodes
    assert "pkg:pypi/colorama@0.4.6" in nodes
