"""
The utilites in this module are used to verify and parse an apple pay token.  The
utilities assume the token is a python dictionary.  See the #ApplePaySpec below for
more documentation and guidelines on the steps taken here.

#ApplePaySpec: https://developer.apple.com/library/content/documentation/PassKit/Reference/PaymentTokenJSON/PaymentTokenJSON.html#//apple_ref/doc/uid/TP40014929-CH8-SW2
"""
import base64
import binascii
from datetime import timedelta, datetime
from functools import partial
from itertools import ifilter
import hashlib
import logging

from asn1crypto import cms, parser
from ecdsa import VerifyingKey, BadSignatureError, curves, util
from pytz import utc
from OpenSSL import crypto

import payment


logger = logging.getLogger(__name__)


def retrieve_signature_signing_time(signature):
    """ Return the 'signingTime' CMS attribute from the detached PKCS signature.
    This parsing depends on the structure of 'ContentInfo' objects defined in
    RFC-5652 (specifically the inner OID 1.2.840.113549.1.9.5):
      https://tools.ietf.org/html/rfc5652#section-11.3

    This function is deprecated. Use of `verify_signature` with an optional threshold
    is preferred.

    :param signature: Base64 encoded signature data (of a 'ContentInfo' object).
    :type: str
    :return: A datetime object representing the inner 'signingTime' object.
    :rtype: datetime
    :raises: AttributeError if no 'signing_time' object can be found.
    """
    data = base64.b64decode(signature)
    content_info = cms.ContentInfo.load(data)
    signer_data = content_info['content']
    signer_infos = signer_data['signer_infos']
    signer_info = signer_infos[0]  # We expect only one item in the list.
    signed_attrs = signer_info['signed_attrs']
    for signed_attr in signed_attrs:
        if 'signing_time' == signed_attr['type'].native:
            value = signed_attr['values']
            return value.native[0]  # datetime object, only item in the list.
    raise AttributeError('No signing_time attribute found in signature.')


def signing_time_is_valid(signature, current_time, threshold):
    """ Given a detached top-level CMS signature, validate the 'signingTime'
    attribute against the current time and a time-delta threshold.
    If the difference between the current time and the 'signingTime' exceeds
    the threshold, the token should be considered invalid.

    This function is deprecated. Use of `verify_signature` with an optional threshold
    is preferred.

    :param signature: Base64 encoded detached CMS signature data.
    :type: str
    :param current_time: Current system time to compare the token against.
    :type: offset-aware datetime
    :param threshold: Amount of time to consider the token valid.
    :type: timedelta
    :return: False if the signing time exceeds the threshold, otherwise True
    :rtype: bool
    :raises: AttributeError if no 'signingTime' attribute can be found,
    indicating an invalid token. May also raise if signature data is in an
    unexpected format, inconsistent with the CMS 'ContentInfo' object.
    """
    signing_time = retrieve_signature_signing_time(signature)
    return valid_signing_time(signing_time, current_time, threshold)


def valid_signing_time(signing_time, current_time, threshold):
    """ Validate that the signing time occurred within the current time minus
    the threshold and the current time.

    Args:
        signing_time (timezone-aware datetime): Signing time to
            validate.
        current_time (timezone-aware datetime): Current system time
            to compare the token against.
        threshold (datetime.timedelta): Amount of time to consider the token
            valid.
    Returns:
        boolean: indicates if the signing time falls within the defined range
            or not.
    """
    is_valid = timedelta(0) <= (current_time - signing_time) <= threshold
    logger.debug((
        "Signing time is {is_valid}. "
        "Signing time: {signing_time:%Y-%m-%d %H:%M:%S %Z}, "
        "Current time: {current_time:%Y-%m-%d %H:%M:%S %Z}, "
        "Threshold: {threshold}.").format(
        is_valid='valid' if is_valid else 'invalid',
        signing_time=signing_time,
        current_time=current_time,
        threshold=threshold)
    )
    return is_valid


def valid_chain_of_trust(root_cert_der, intermediate_cert_der, leaf_cert_der):
    """Validate the chain of trust for the provided der encoded root, intermediate,
    and leaf certificates.

    From: #ApplePaySpec
       Part C: Ensure that there is a valid X.509 chain of trust from the
       signature to the root CA. Specifically, ensure that the signature
       was created using the private key corresponding to the leaf certificate,
       that the leaf certificate is signed by the intermediate CA, and that the
       intermediate CA is signed by the Apple Root CA - G3.

    Args:
        root_cert_der (str): der-encoded root cert
        intermediate_cert_der (str): der-encoded intermediate cert
        leaf_cert_der (str): der-encoded leaf cert
    Returns:
        Boolean: If there is a valid chain of trust for the provided certificates
    """
    root_cert = crypto.load_certificate(crypto.FILETYPE_ASN1, root_cert_der)

    # Only add certs we trust, starting with the implicitly trusted root cert.
    store = crypto.X509Store()
    store.add_cert(root_cert)

    # validate the intermediate cert against root
    intermediate_cert = crypto.load_certificate(crypto.FILETYPE_ASN1, intermediate_cert_der)
    store_ctx = crypto.X509StoreContext(store, intermediate_cert)
    # throws 'X509StoreContextError' when cert is invalid.
    try:
        store_ctx.verify_certificate()
    except crypto.X509StoreContextError:
        logger.warning("Intermediate cert not signed by the Apple Root CA - G3.")
        return False
    else:
        store.add_cert(intermediate_cert)

    # validate the leaf cert against intermediate.
    leaf_cert = crypto.load_certificate(crypto.FILETYPE_ASN1, leaf_cert_der)
    store_ctx = crypto.X509StoreContext(store, leaf_cert)
    # throws 'X509StoreContextError' when cert is invalid.
    try:
        store_ctx.verify_certificate()
    except crypto.X509StoreContextError:
        logger.warning("Leaf cert not signed by the intermediate cert.")
        return False
    else:
        store.add_cert(leaf_cert)

    return True


def get_leaf_and_intermediate_certs(candidate_certificates):
    """Iterate over the provided candidate_certificates
    to find the leaf and intermediate certificates based
    on their OIDs.

    Args:
        candidate_certificate (asn1crypto.cms.CertificateSet): Unordered iterable of
            candidate certificates
    Returns:
        tuple: The leaf and intermediate cert.  Each will default to None
            if not found.
    """
    found_leaf_cert = None
    found_intermediate_cert = None
    for certificate in candidate_certificates:
        if found_leaf_cert and found_intermediate_cert:
            break

        candidate_cert = certificate.chosen

        leaf_cert_ext = get_first_from_iterable(
            filter_func=lambda ext: ext['extn_id'].native == payment.OID_LEAF_CERTIFICATE,
            iterable=candidate_cert['tbs_certificate']['extensions']
        )
        if leaf_cert_ext:
            found_leaf_cert = candidate_cert
            continue

        intermediate_cert_ext = get_first_from_iterable(
            filter_func=lambda ext: ext['extn_id'].native == payment.OID_INTERMEDIATE_CERTIFICATE,
            iterable=candidate_cert['tbs_certificate']['extensions']
        )
        if intermediate_cert_ext:
            found_intermediate_cert = candidate_cert
            continue

    return found_leaf_cert, found_intermediate_cert


def get_payment_data(token):
    """Build a string of the concatenated payment
    data provided in the apple pay token, including
    the ephemeral public key, payload, transaction id
    and the optional application data.

    This assumes the provided token contains an ECDSA
    signature.  RSA is not supported.

    Args:
        token (dict): the decoded apple pay token
    Returns:
        str: the concatenated payment data
    """
    ephemeral_public_key = token['header']['ephemeralPublicKey']
    payload = token['data']
    transaction_id = token['header']['transactionId']
    application_data = token['header'].get('applicationData')  # optional

    concatenated_data = base64.b64decode(ephemeral_public_key)
    concatenated_data += base64.b64decode(payload)
    concatenated_data += binascii.unhexlify(transaction_id)
    if application_data:
        concatenated_data += binascii.unhexlify(application_data)

    return concatenated_data


def get_ber_encoded_signed_attributes(signed_attrs):
    """Get the BER-encoded signed attributes.

    class_, method, and tag are needed to emit the BER
    encoded version of the header + content.
    These values are not exposed on SignerInfo
    so we get them from the parent class.

    Args:
        signed_attrs (asn1crypto.cms.CMSAttributes): The signed
            attributes from the signature
    Returns:
        str: The BER-encoded signed attributes as a string
            of bytes
    """
    class_ = super(signed_attrs.__class__, signed_attrs).class_
    method = super(signed_attrs.__class__, signed_attrs).method
    tag = super(signed_attrs.__class__, signed_attrs).tag

    return parser.emit(class_, method, tag, signed_attrs.contents)


def remove_ec_point_prefix(point):
    """Remove the prefix from the uncompressed ec point.

    We expect the point to be in the uncompressed
    format described here: https://tools.ietf.org/html/rfc5480#section-2.2
    This means the first byte must be "\x04" otherwise consider
    the public key not usable.  ecdsa.keys.VerifyingKey does not
    handle this first byte so its chopped off before turning the public
    key bytes.

    Args:
        point (str): The uncompressed byte string of an EC Point
    Returns:
        str: The EC point byte string minus the uncompressed
            byte prefix indicator
    """
    if not point.startswith("\x04"):
        logger.warning("Expected uncompressed EC point.")
        return None

    return point[1:]


def get_first_from_iterable(filter_func, iterable):
    """Get the first filtered item from an iterable.

    Args:
        filter_func (callable): the function to filter on
        iterable (iterable): the iterable to filter on
    Returns:
        object: the first filtered item from iterable or None
            if no items matching the filter are found
    """
    filtered = ifilter(filter_func, iterable)
    return next(filtered, None)


def get_hashfunc_by_name(name, data):
    """
    Get a callable hashfunc by name.

    This function can be used directly or with functools.partial, for example:

    >>> hashfunc = functools.partial(get_hashfunc_by_name, 'sha256')
    >>> hashfunc('sir robin').digest()

    Args:
        name (str): The string name of the desired algorithm
        data (buffer): The buffer to hash
    Returns:
        callable: The callable hash function of the provided
            algorithm updated with the data to be hashed
    """
    hashfunc = hashlib.new(name)
    hashfunc.update(data)
    return hashfunc


def validate_message_digest(signed_attrs, hashed_payment_data):
    """Validate the message_digest matches the provided payment.

    Args:
        signed_attrs (asn1crypto.cms.CMSAttributes): The signed
            attributes from the signature
        payment_data (str): the hashed payment data to validate
            against
    Returns:
        boolean: True if the message digest matches the hashed
            payment data, otherwise False.

    """
    message_digest_attr = get_first_from_iterable(
        filter_func=lambda signed_attr: signed_attr['type'].dotted == payment.OID_MESSAGE_DIGEST,
        iterable=signed_attrs
    )

    if not message_digest_attr:
        logger.warning("No message digest found for the leaf cert.")
        return False

    message_digest = message_digest_attr['values'][0].native

    if hashed_payment_data != message_digest:
        logger.warning("Message digest does not match provided data.")
        return False

    return True


def verify_signature(token, threshold=None):
    """Verify the signature within an apple pay token according to
    the #ApplePaySpec documentation.

    Args:
        token (dict): the PKPaymentToken object defined within the #ApplePaySpec
    Kwargs:
        threshold (timedelta, None): Amount of time to consider the token valid.
            No validation will be performed if a threshold is not provided
    Returns:
        boolean: Indicates if the signature is valid or not
    """

    # We only bother to validate EC_v1.  RSA is only used
    # for transactions from China and is not supported at this time.
    if token['version'] != 'EC_v1':
        logger.warning("Unsupported version {}".format(token['version']))
        return False

    # Extract and decode the signature object into a CMS object.
    signature = token['signature']
    signature_data = base64.b64decode(signature)
    content_info = cms.ContentInfo.load(signature_data)
    signed_data = content_info['content']
    certificates = signed_data['certificates']

    # There should be exactly 2 certificates present.
    if len(certificates) != 2:
        logger.warning("Expected 2 certificates, found {}".format(len(certificates)))
        return False

    leaf_cert, intermediate_cert = get_leaf_and_intermediate_certs(certificates)

    if not leaf_cert:
        logger.warning("Leaf Certificate OID not found")
        return False

    if not intermediate_cert:
        logger.warning("Intermediate certificate OID not found")
        return False

    root_der = open(payment.ROOT_CA_FILE, 'r').read()
    # Pass the der-encoded representation of the certs.
    if not valid_chain_of_trust(root_der, intermediate_cert.dump(), leaf_cert.dump()):
        return False

    # Build the signer information from the signer that matches the leaf cert.
    signer_info = get_first_from_iterable(
        filter_func=lambda signer: signer['sid'].chosen['serial_number'].native == leaf_cert.serial_number,
        iterable=signed_data['signer_infos']
    )
    if not signer_info:
        logger.warning("No signature found for the leaf cert.")
        return False

    # Use the signed attrs to verify the data was signed within the threshold
    # provided and is from who it says its from.
    signed_attrs = signer_info['signed_attrs']

    # Only check the signing time if a threshold was provided.
    if threshold:
        signing_time_attr = get_first_from_iterable(
            filter_func=lambda signed_attr: signed_attr['type'].dotted == payment.OID_SIGNING_TIME,
            iterable=signed_attrs
        )

        if not valid_signing_time(signing_time_attr['values'][0].native, datetime.now(utc), threshold):
            logger.warning("Signing time outside of threshold.")
            return False

    payment_data = get_payment_data(token)
    # Build the hashfunc from the leaf_cert's defined algorithm.
    hashfunc = partial(get_hashfunc_by_name, leaf_cert.hash_algo)
    hashed_payemnt_data = hashfunc(payment_data).digest()
    if not validate_message_digest(signed_attrs, hashed_payemnt_data):
        return False

    signed_attrs_ber = get_ber_encoded_signed_attributes(signed_attrs)
    public_key_point = remove_ec_point_prefix(leaf_cert.public_key['public_key'].native)
    if not public_key_point:
        return False

    sigdecode = util.sigdecode_der  # The signature is der-encoded
    sig_octets = signer_info['signature'].native  # The actual signature to verify
    vk = VerifyingKey.from_string(public_key_point, curve=curves.NIST256p, hashfunc=hashfunc)
    # Verify that the signature matches the signed data.
    try:
        vk.verify(sig_octets, signed_attrs_ber, hashfunc=hashfunc, sigdecode=sigdecode)
    except BadSignatureError:
        logger.warning("Invalid signature.")
        return False

    return True
