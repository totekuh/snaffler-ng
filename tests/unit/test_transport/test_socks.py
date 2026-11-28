"""Tests for SOCKS proxy URL parsing and setup."""

import socket
from unittest.mock import MagicMock, patch

import pytest

from snaffler.transport.socks import (
    SOCKS4,
    SOCKS5,
    parse_socks_url,
    setup_socks_proxy,
)


# ---------- parse_socks_url ----------

class TestParseSocksUrl:

    def test_socks5_url(self):
        result = parse_socks_url("socks5://127.0.0.1:1080")
        assert result == (SOCKS5, "127.0.0.1", 1080, None, None)

    def test_socks4_url(self):
        result = parse_socks_url("socks4://10.0.0.1:9050")
        assert result == (SOCKS4, "10.0.0.1", 9050, None, None)

    def test_bare_host_port_defaults_to_socks5(self):
        result = parse_socks_url("127.0.0.1:1080")
        assert result == (SOCKS5, "127.0.0.1", 1080, None, None)

    def test_authenticated_proxy(self):
        result = parse_socks_url("socks5://admin:s3cret@proxy.local:1080")
        assert result == (SOCKS5, "proxy.local", 1080, "admin", "s3cret")

    def test_missing_port_raises(self):
        with pytest.raises(ValueError, match="Missing port"):
            parse_socks_url("socks5://127.0.0.1")

    def test_missing_host_raises(self):
        with pytest.raises(ValueError, match="Missing host"):
            parse_socks_url("socks5://:1080")

    def test_bad_scheme_raises(self):
        with pytest.raises(ValueError, match="Unsupported SOCKS scheme"):
            parse_socks_url("http://127.0.0.1:1080")

    def test_uppercase_scheme(self):
        result = parse_socks_url("SOCKS5://127.0.0.1:1080")
        assert result == (SOCKS5, "127.0.0.1", 1080, None, None)

    def test_hostname_target(self):
        result = parse_socks_url("socks5://proxy.corp.local:1080")
        assert result == (SOCKS5, "proxy.corp.local", 1080, None, None)


# ---------- setup_socks_proxy ----------

class TestSetupSocksProxy:

    def test_patches_socket(self):
        mock_socks = MagicMock()
        original_socket = socket.socket

        with patch.dict("sys.modules", {"socks": mock_socks}):
            setup_socks_proxy("socks5://127.0.0.1:1080")

            mock_socks.set_default_proxy.assert_called_once_with(
                proxy_type=SOCKS5,
                addr="127.0.0.1",
                port=1080,
                rdns=True,
                username=None,
                password=None,
            )
            assert socket.socket is mock_socks.socksocket

        # restore
        socket.socket = original_socket

    def test_raises_import_error_without_pysocks(self):
        with patch.dict("sys.modules", {"socks": None}):
            with pytest.raises(ImportError, match="PySocks is required"):
                setup_socks_proxy("socks5://127.0.0.1:1080")


# ---------- getaddrinfo passthrough ----------

class TestGetaddrinfoPassthrough:

    @pytest.fixture(autouse=True)
    def _restore_socket(self):
        original_socket = socket.socket
        original_getaddrinfo = socket.getaddrinfo
        yield
        socket.socket = original_socket
        socket.getaddrinfo = original_getaddrinfo

    def _setup_with_sentinel(self):
        sentinel = MagicMock()
        socket.getaddrinfo = sentinel
        mock_socks = MagicMock()
        with patch.dict("sys.modules", {"socks": mock_socks}):
            setup_socks_proxy("socks5://127.0.0.1:1080")
        return sentinel

    def test_hostname_passes_through_without_resolving(self):
        sentinel = self._setup_with_sentinel()
        result = socket.getaddrinfo("fake.internal.host", 389)
        assert sentinel.call_count == 0
        assert result == [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("fake.internal.host", 389))]

    def test_ip_delegates_to_original(self):
        sentinel = self._setup_with_sentinel()
        sentinel.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.2.3.4", 389))]
        result = socket.getaddrinfo("1.2.3.4", 389)
        assert sentinel.call_count == 1
        assert sentinel.call_args[0][0] == "1.2.3.4"
        assert result == [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.2.3.4", 389))]

    def test_none_host_delegates_to_original(self):
        sentinel = self._setup_with_sentinel()
        sentinel.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("0.0.0.0", 389))]
        socket.getaddrinfo(None, 389)
        assert sentinel.call_count == 1
        assert sentinel.call_args[0][0] is None

    def test_bytes_hostname_decoded(self):
        sentinel = self._setup_with_sentinel()
        result = socket.getaddrinfo(b"fake.internal.host", 389)
        assert sentinel.call_count == 0
        assert result[0][4][0] == "fake.internal.host"

    def test_string_port_becomes_zero(self):
        sentinel = self._setup_with_sentinel()
        result = socket.getaddrinfo("fake.internal.host", "ldap")
        assert sentinel.call_count == 0
        assert result[0][4][1] == 0
