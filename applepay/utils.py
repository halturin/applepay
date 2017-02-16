import base64

from asn1crypto import cms


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
