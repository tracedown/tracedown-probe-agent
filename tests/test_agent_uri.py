"""The URI an agent registers: PROBE_AGENT_ADVERTISED_HOST, else its own FQDN."""

from unittest.mock import patch

from config import AgentSettings
from mtls.bootstrap import advertised_agent_uri


def test_defaults_to_the_machine_fqdn():
    settings = AgentSettings(port=8443, advertised_host="")
    with patch("socket.getfqdn", return_value="runner.example.internal"):
        assert advertised_agent_uri(settings) == "https://runner.example.internal:8443"


def test_advertised_host_wins_over_the_fqdn():
    settings = AgentSettings(port=9443, advertised_host="eu-west-1.railway.internal")
    with patch("socket.getfqdn", return_value="ignored"):
        assert advertised_agent_uri(settings) == "https://eu-west-1.railway.internal:9443"


def test_blank_advertised_host_is_unset():
    settings = AgentSettings(port=8443, advertised_host="   ")
    with patch("socket.getfqdn", return_value="runner"):
        assert advertised_agent_uri(settings) == "https://runner:8443"
