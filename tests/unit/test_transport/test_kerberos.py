"""Unit tests for snaffler.transport.kerberos — TGS-REQ with checksum."""

from unittest.mock import MagicMock, patch

import pytest
from pyasn1.codec.der import decoder, encoder

from snaffler.transport.kerberos import (
    _CKSUM_FOR_ETYPE,
    _KEY_USAGE_TGS_REQ_AUTH,
    _KEY_USAGE_TGS_REQ_CKSUM,
    _strip_context_tag,
    get_tgt_and_tgs,
)


class TestStripContextTag:
    def test_bare_sequence_unchanged(self):
        data = b"\x30\x05\x02\x01\x01\x02\x01\x02"
        assert _strip_context_tag(data) == data

    def test_strips_short_form_tag(self):
        # 0xa4 + 1-byte length 0x05 + bare sequence
        bare = b"\x30\x03\x02\x01\x01"
        tagged = b"\xa4\x05" + bare
        assert _strip_context_tag(tagged) == bare

    def test_strips_long_form_tag(self):
        # 0xa4 + 0x81 + 1-byte length + bare sequence
        bare = b"\x30" + b"\x81\x80" + b"\x00" * 128
        tagged = b"\xa4\x81\x83" + bare
        result = _strip_context_tag(tagged)
        assert result[0] == 0x30


class TestChecksumTypeMapping:
    def test_aes256_maps_to_type_16(self):
        assert _CKSUM_FOR_ETYPE[18] == 16

    def test_aes128_maps_to_type_15(self):
        assert _CKSUM_FOR_ETYPE[17] == 15

    def test_rc4_maps_to_type_neg138(self):
        assert _CKSUM_FOR_ETYPE[23] == -138


class TestKeyUsageConstants:
    def test_checksum_key_usage(self):
        assert _KEY_USAGE_TGS_REQ_CKSUM == 6

    def test_authenticator_key_usage(self):
        assert _KEY_USAGE_TGS_REQ_AUTH == 7


class TestGetTgtAndTgs:
    def test_calls_get_kerberos_tgt_then_our_tgs(self):
        auth = MagicMock()
        auth.domain = "CORP.LOCAL"
        auth.username = "admin"
        auth.password = "pass"
        auth.nthash = ""
        auth.dc_host = "10.0.0.1"

        mock_tgt = b"FAKE_TGT"
        mock_cipher = MagicMock()
        mock_session_key = MagicMock()
        mock_tgs = b"FAKE_TGS"
        mock_old_key = MagicMock()

        with (
            patch(
                "snaffler.transport.kerberos.getKerberosTGT",
                return_value=(mock_tgt, mock_cipher, None, mock_session_key),
            ) as mock_get_tgt,
            patch(
                "snaffler.transport.kerberos.get_kerberos_tgs",
                return_value=(mock_tgs, mock_cipher, mock_old_key, mock_session_key),
            ) as mock_get_tgs,
        ):
            tgt_dict, tgs_dict = get_tgt_and_tgs(auth, "cifs/fs01.corp.local", "10.0.0.2")

        assert tgt_dict["KDC_REP"] == mock_tgt
        assert tgt_dict["cipher"] == mock_cipher
        assert tgt_dict["sessionKey"] == mock_session_key
        assert tgs_dict["KDC_REP"] == mock_tgs
        assert tgs_dict["cipher"] == mock_cipher
        assert tgs_dict["sessionKey"] == mock_session_key

        mock_get_tgt.assert_called_once()
        call_args = mock_get_tgt.call_args
        assert call_args.kwargs.get("kdcHost") == "10.0.0.1"

        mock_get_tgs.assert_called_once()

    def test_uses_remote_host_when_no_dc_host(self):
        auth = MagicMock()
        auth.domain = "CORP.LOCAL"
        auth.username = "admin"
        auth.password = "pass"
        auth.nthash = ""
        auth.dc_host = None

        with (
            patch(
                "snaffler.transport.kerberos.getKerberosTGT",
                return_value=(b"TGT", MagicMock(), None, MagicMock()),
            ) as mock_get_tgt,
            patch(
                "snaffler.transport.kerberos.get_kerberos_tgs",
                return_value=(b"TGS", MagicMock(), None, MagicMock()),
            ),
        ):
            get_tgt_and_tgs(auth, "cifs/host", "10.0.0.5")

        assert mock_get_tgt.call_args.kwargs.get("kdcHost") == "10.0.0.5"

    def test_domain_uppercased(self):
        auth = MagicMock()
        auth.domain = "corp.local"
        auth.username = "admin"
        auth.password = "pass"
        auth.nthash = ""
        auth.dc_host = "10.0.0.1"

        with (
            patch(
                "snaffler.transport.kerberos.getKerberosTGT",
                return_value=(b"TGT", MagicMock(), None, MagicMock()),
            ) as mock_get_tgt,
            patch(
                "snaffler.transport.kerberos.get_kerberos_tgs",
                return_value=(b"TGS", MagicMock(), None, MagicMock()),
            ),
        ):
            get_tgt_and_tgs(auth, "cifs/host", "10.0.0.1")

        client_name = mock_get_tgt.call_args[0][0]
        domain_arg = mock_get_tgt.call_args[0][2]
        assert domain_arg == "CORP.LOCAL"
