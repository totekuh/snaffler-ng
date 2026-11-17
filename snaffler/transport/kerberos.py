"""RFC 4120-compliant TGS-REQ builder with Authenticator checksum.

impacket's getKerberosTGS() omits the Authenticator checksum in TGS-REQ.
Samba 4.17+ enforces the checksum and rejects requests without it
(KRB_AP_ERR_INAPP_CKSUM). This module provides a compliant replacement.
"""

import datetime
import random

from impacket.krb5 import constants
from impacket.krb5.asn1 import (
    AP_REQ,
    AS_REP,
    TGS_REP,
    TGS_REQ,
    Authenticator,
    seq_set,
    seq_set_iter,
)
from impacket.krb5.crypto import _checksum_table
from impacket.krb5.kerberosv5 import getKerberosTGT, sendReceive
from impacket.krb5.types import KerberosTime, Principal, Ticket
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue

_CKSUM_FOR_ETYPE = {
    18: 16,  # AES256 -> hmac-sha1-96-aes256
    17: 15,  # AES128 -> hmac-sha1-96-aes128
    23: -138,  # RC4    -> hmac-md5
}

_KEY_USAGE_TGS_REQ_CKSUM = 6
_KEY_USAGE_TGS_REQ_AUTH = 7


def _strip_context_tag(encoded):
    """Strip DER context tag to get bare SEQUENCE bytes.

    The req-body in KDC-REQ is context-tagged [4] (0xa4), but RFC 4120
    Section 5.5.1 specifies the checksum is over the bare SEQUENCE (0x30).
    """
    if encoded[0] == 0x30:
        return encoded
    idx = 1
    if encoded[idx] & 0x80:
        num_len_bytes = encoded[idx] & 0x7F
        idx += 1 + num_len_bytes
    else:
        idx += 1
    return encoded[idx:]


def get_kerberos_tgs(server_name, domain, kdc_host, tgt, cipher, session_key):
    """Request a TGS with a proper Authenticator checksum.

    Drop-in replacement for impacket's getKerberosTGS(). Returns the same
    (tgs, cipher, oldSessionKey, sessionKey) tuple.
    """
    try:
        decoded_tgt = decoder.decode(tgt, asn1Spec=AS_REP())[0]
    except Exception:
        decoded_tgt = decoder.decode(tgt, asn1Spec=TGS_REP())[0]

    domain = domain.upper()

    ticket = Ticket()
    ticket.from_asn1(decoded_tgt["ticket"])

    client_name = Principal()
    client_name.from_asn1(decoded_tgt, "crealm", "cname")

    # Build TGS-REQ — req-body first (needed for checksum)
    tgs_req = TGS_REQ()
    tgs_req["pvno"] = 5
    tgs_req["msg-type"] = int(constants.ApplicationTagNumbers.TGS_REQ.value)

    req_body = seq_set(tgs_req, "req-body")
    opts = [
        constants.KDCOptions.forwardable.value,
        constants.KDCOptions.renewable.value,
        constants.KDCOptions.renewable_ok.value,
        constants.KDCOptions.canonicalize.value,
    ]
    req_body["kdc-options"] = constants.encodeFlags(opts)
    seq_set(req_body, "sname", server_name.components_to_asn1)
    req_body["realm"] = domain

    now = datetime.datetime.now(datetime.timezone.utc)
    req_body["till"] = KerberosTime.to_asn1(now + datetime.timedelta(days=1))
    req_body["nonce"] = random.getrandbits(31)
    seq_set_iter(req_body, "etype", (18, 17, 23))

    # Checksum over bare SEQUENCE of req-body
    bare_req_body = _strip_context_tag(encoder.encode(req_body))

    cksum_type_id = _CKSUM_FOR_ETYPE.get(session_key.enctype, 16)
    cksum_fn = _checksum_table[cksum_type_id]
    cksum_value = cksum_fn.checksum(session_key, _KEY_USAGE_TGS_REQ_CKSUM, bare_req_body)

    # Authenticator with checksum
    authenticator = Authenticator()
    authenticator["authenticator-vno"] = 5
    authenticator["crealm"] = decoded_tgt["crealm"].asOctets()
    seq_set(authenticator, "cname", client_name.components_to_asn1)
    authenticator["cusec"] = now.microsecond
    authenticator["ctime"] = KerberosTime.to_asn1(now)
    authenticator["cksum"]["cksumtype"] = cksum_type_id
    authenticator["cksum"]["checksum"] = cksum_value

    encrypted_auth = cipher.encrypt(session_key, _KEY_USAGE_TGS_REQ_AUTH, encoder.encode(authenticator), None)

    # AP-REQ
    ap_req = AP_REQ()
    ap_req["pvno"] = 5
    ap_req["msg-type"] = int(constants.ApplicationTagNumbers.AP_REQ.value)
    ap_req["ap-options"] = constants.encodeFlags([])
    seq_set(ap_req, "ticket", ticket.to_asn1)
    ap_req["authenticator"] = noValue
    ap_req["authenticator"]["etype"] = cipher.enctype
    ap_req["authenticator"]["cipher"] = encrypted_auth

    # PA-DATA
    tgs_req["padata"] = noValue
    tgs_req["padata"][0] = noValue
    tgs_req["padata"][0]["padata-type"] = int(constants.PreAuthenticationDataTypes.PA_TGS_REQ.value)
    tgs_req["padata"][0]["padata-value"] = encoder.encode(ap_req)

    # Send and decode response
    message = encoder.encode(tgs_req)
    r = sendReceive(message, domain, kdc_host)

    tgs_rep = decoder.decode(r, asn1Spec=TGS_REP())[0]

    # Decrypt the TGS-REP enc-part to get the new session key
    cipher_text = tgs_rep["enc-part"]["cipher"].asOctets()
    from impacket.krb5.crypto import Key, _enctype_table

    enc_etype = tgs_rep["enc-part"]["etype"]
    new_cipher_obj = _enctype_table[int(enc_etype)]
    decrypted = new_cipher_obj.decrypt(session_key, 8, cipher_text)

    from impacket.krb5.asn1 import EncTGSRepPart

    dec_tgs = decoder.decode(decrypted, asn1Spec=EncTGSRepPart())[0]

    new_session_key_data = dec_tgs["key"]["keyvalue"].asOctets()
    new_session_key_type = dec_tgs["key"]["keytype"]
    new_session_key = Key(int(new_session_key_type), bytes(new_session_key_data))

    return r, new_cipher_obj, session_key, new_session_key


def get_tgt_and_tgs(auth, server_name_str, remote_host):
    """Get TGT via impacket, then TGS via our fixed function.

    Returns (TGT_dict, TGS_dict) in the format impacket's
    kerberosLogin expects.
    """
    domain = auth.domain.upper()
    username = auth.username or ""
    password = auth.password or ""
    nthash = auth.nthash or ""
    kdc_host = auth.dc_host or remote_host

    client_name = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

    tgt, cipher, _, session_key = getKerberosTGT(
        client_name,
        password,
        domain,
        lmhash="",
        nthash=nthash,
        aesKey="",
        kdcHost=kdc_host,
    )

    server_name = Principal(
        server_name_str,
        type=constants.PrincipalNameType.NT_SRV_INST.value,
    )

    tgs, tgs_cipher, tgs_old_key, tgs_session_key = get_kerberos_tgs(
        server_name,
        domain,
        kdc_host,
        tgt,
        cipher,
        session_key,
    )

    tgt_dict = {"KDC_REP": tgt, "cipher": cipher, "sessionKey": session_key}
    tgs_dict = {
        "KDC_REP": tgs,
        "cipher": tgs_cipher,
        "oldSessionKey": tgs_old_key,
        "sessionKey": tgs_session_key,
    }

    return tgt_dict, tgs_dict
