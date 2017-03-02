import base64
from datetime import timedelta
import logging

from asn1crypto import cms


logger = logging.getLogger('applepay.utils')


def retrieve_signature_signing_time(signature):
    """ Return the 'signingTime' CMS attribute from the detached PKCS signature.

    This parsing depends on the structure of 'ContentInfo' objects defined in
    RFC-5652 (specifically the inner OID 1.2.840.113549.1.9.5):
      https://tools.ietf.org/html/rfc5652#section-11.3

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
    is_valid = timedelta(0) <= (current_time - signing_time) <= threshold
    logger.debug((
        "Signing time is {is_valid}. "
        "Signing time: {signing_time:%Y-%m-%d %H:%M:%S %Z}, "
        "Current time: {current_time:%Y-%m-%d %H:%M:%S %Z}, "
        "Threshold: {threshold}.").format(
        is_valid='valid' if is_valid else 'invalid',
        signing_time=signing_time,
        threshold=threshold,
        current_time=current_time)
    )
    return is_valid
