import pytest
from src.plugins.registry import PluginRegistry, registry

def test_plugin_registry_initialization():
    pr = PluginRegistry()
    assert pr.plugins == {}

def test_register_capability():
    pr = PluginRegistry()
    handler = lambda x: x
    pr.register_capability("test_cap", handler)
    assert "test_cap" in pr.plugins
    assert pr.plugins["test_cap"] == handler

def test_get_capability_existing():
    pr = PluginRegistry()
    handler = lambda x: x
    pr.register_capability("test_cap", handler)
    retrieved_handler = pr.get_capability("test_cap")
    assert retrieved_handler == handler

def test_get_capability_missing():
    pr = PluginRegistry()
    retrieved_handler = pr.get_capability("non_existent")
    assert retrieved_handler is None

def test_global_registry():
    # Test the globally exported registry
    handler = lambda x: x
    registry.register_capability("global_test_cap", handler)
    assert registry.get_capability("global_test_cap") == handler
    # Cleanup to avoid affecting other potential tests
    del registry.plugins["global_test_cap"]
