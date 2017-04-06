import base64
import binascii
import copy
from datetime import datetime, timedelta
from functools import partial
import hashlib
import logging


from asn1crypto import cms
from freezegun import freeze_time
import pytest
from pytz import utc

from applepay import payment, utils as applepay_utils

import utils as test_utils


@pytest.fixture(scope='session')
def token_fixture():
    return test_utils.load_json_fixture('tests/fixtures/token.json')


@pytest.fixture(scope='session')
def root_der_fixture():
    with open(payment.ROOT_CA_FILE, 'r') as root_ca:
        return root_ca.read()


@pytest.fixture(scope='session')
def signed_data_fixture(token_fixture):
    """Returns the certificates from the apple pay token."""
    signature = token_fixture['signature']
    signature_data = base64.b64decode(signature)
    content_info = cms.ContentInfo.load(signature_data)
    signed_data = content_info['content']

    return signed_data


@pytest.fixture(scope='session')
def certificates_fixture(candidate_certificates_fixture):
    """Returns a tuple of valid der-encoded root, intermeidate
    and leaf certificates"""
    return applepay_utils.get_leaf_and_intermediate_certs(candidate_certificates_fixture)


@pytest.fixture(scope='session')
def signed_attributes_fixture(signed_data_fixture, certificates_fixture):
    leaf_cert, _ = certificates_fixture
    signer_info = applepay_utils.get_first_from_iterable(
        filter_func=lambda signer: signer['sid'].chosen['serial_number'].native == leaf_cert.serial_number,
        iterable=signed_data_fixture['signer_infos']
    )
    return signer_info['signed_attrs']


@pytest.fixture(scope='session')
def candidate_certificates_fixture(signed_data_fixture):
    """Returns the certificates from the apple pay token."""
    return signed_data_fixture['certificates']


@pytest.fixture(scope='session')
def certificates_der_fixture(root_der_fixture, certificates_fixture):
    """Returns a tuple of valid der-encoded root, intermeidate
    and leaf certificates"""
    leaf_cert, intermediate_cert = certificates_fixture

    return (root_der_fixture, intermediate_cert.dump(), leaf_cert.dump())


def test_retrieve_signature_signing_time(token_fixture):
    # Given a detached CMS signature in the token,
    signature = token_fixture['signature']

    # when we attempt to retrieve the signing time from the signature,
    signing_time = applepay_utils.retrieve_signature_signing_time(signature)

    # then the signing time matches the datetime we expect.
    expected_time = datetime(2014, 10, 27, 19, 51, 43, tzinfo=utc)
    assert signing_time == expected_time


def test_signing_time_is_valid(token_fixture):
    # Given a detached CMS signature in the token,
    signature = token_fixture['signature']

    # and a current time exactly one hour past the signing time,
    current_time = datetime(2014, 10, 27, 20, 51, 43, tzinfo=utc)

    # and a time-delta threshold of one hour,
    threshold = timedelta(hours=1)

    # when we attempt to validate the signing time against the threshold,
    valid = applepay_utils.signing_time_is_valid(signature, current_time, threshold)

    # then the token should be considered valid.
    assert valid is True


def test_expired_signing_time_is_invalid(token_fixture):
    # Given a detached CMS signature in the token,
    signature = token_fixture['signature']

    # and a current time well past the signing time,
    current_time = datetime(2017, 2, 16, 17, 9, 55, tzinfo=utc)

    # and a time-delta threshold of only one day,
    threshold = timedelta(days=1)

    # when we attempt to validate the signing time against the threshold,
    valid = applepay_utils.signing_time_is_valid(signature, current_time, threshold)

    # then the token should be considered invalid.
    assert valid is False


def test_future_signing_time_is_invalid(token_fixture):
    # Given a detached CMS signature in the token,
    signature = token_fixture['signature']

    # and a current time which is well before the signing time,
    current_time = datetime(2010, 1, 2, 5, 22, 13, tzinfo=utc)

    # and a time-delta threshold of five weeks,
    threshold = timedelta(weeks=5)

    # when we attempt to validate the signing time against the threshold,
    valid = applepay_utils.signing_time_is_valid(signature, current_time, threshold)

    # then the token should be considered invalid.
    assert valid is False


def test_signing_time_equals_current_time_is_valid(token_fixture):
    # Given a detached CMS signature in the token,
    signature = token_fixture['signature']

    # and a current time that exactly matches the signing time,
    current_time = datetime(2014, 10, 27, 19, 51, 43, tzinfo=utc)

    # and a time-delta of zero,
    threshold = timedelta(0)

    # when we attempt to validate the signing time against the threshold,
    valid = applepay_utils.signing_time_is_valid(signature, current_time, threshold)

    # then the token should be considered valid.
    assert valid is True


def test_valid_signing_time():
    # Given an timezone-aware signing time
    signing_time = datetime(2014, 10, 27, 20, 51, 43, tzinfo=utc)

    # and a current time exactly one hour past the signing time,
    current_time = signing_time + timedelta(hours=1)

    # and a time-delta threshold of one hour,
    threshold = timedelta(hours=1)

    # when we attempt to validate the signing time against the threshold,
    valid = applepay_utils.valid_signing_time(signing_time, current_time, threshold)

    # then the token shosuld be considered valid.
    assert valid is True


def test_expired_signing_time():
    # Given an timezone-aware signing time
    signing_time = datetime(2014, 10, 27, 20, 51, 43, tzinfo=utc)

    # and a current time well past the signing time,
    current_time = signing_time + timedelta(days=100)

    # and a time-delta threshold of only one day,
    threshold = timedelta(days=1)

    # when we attempt to validate the signing time against the threshold,
    valid = applepay_utils.valid_signing_time(signing_time, current_time, threshold)

    # then the token should be considered invalid.
    assert valid is False


def test_future_signing_time():
    # Given an timezone-aware signing time
    signing_time = datetime(2014, 10, 27, 20, 51, 43, tzinfo=utc)

    # and a current time which is well before the signing time,
    current_time = signing_time - timedelta(weeks=10)

    # and a time-delta threshold of five weeks,
    threshold = timedelta(weeks=5)

    # when we attempt to validate the signing time against the threshold,
    valid = applepay_utils.valid_signing_time(signing_time, current_time, threshold)

    # then the token should be considered invalid.
    assert valid is False


def test_signing_time_equals_current_time():
    # Given an timezone-aware signing time
    signing_time = datetime(2014, 10, 27, 20, 51, 43, tzinfo=utc)

    # and a current time that exactly matches the signing time,
    current_time = signing_time

    # and a time-delta of zero,
    threshold = timedelta(0)

    # when we attempt to validate the signing time against the threshold,
    valid = applepay_utils.valid_signing_time(signing_time, current_time, threshold)

    # then the token should be considered valid.
    assert valid is True


def test_valid_signing_time_data_is_logged(caplog):
    # Given: a valid signing time
    signing_time = datetime(2014, 10, 27, 20, 51, 43, tzinfo=utc)
    current_time = signing_time + timedelta(minutes=5)
    threshold = timedelta(hours=1)

    # When we attempt to validate the signing time against the threshold,
    with caplog.atLevel(logging.DEBUG):
        valid = applepay_utils.valid_signing_time(signing_time, current_time, threshold)

    # Then the signign time is valid
    assert valid is True

    # Then a new debug log is captured
    # filter on DEBUG log records only
    records = filter(lambda log_record: log_record.levelno == logging.DEBUG, caplog.records())
    assert len(records) == 1
    assert records[0].name == 'applepay.utils'
    assert records[0].message == 'Signing time is valid. Signing time: 2014-10-27 20:51:43 UTC, Current time: 2014-10-27 20:56:43 UTC, Threshold: 1:00:00.'


def test_invalid_signing_time_data_is_logged(caplog):
    # Given: an invalid signing time
    signing_time = datetime(2014, 10, 27, 20, 51, 43, tzinfo=utc)
    current_time = signing_time + timedelta(hours=5)
    threshold = timedelta(hours=1)

    # When we attempt to validate the signing time against the threshold,
    with caplog.atLevel(logging.DEBUG):
        valid = applepay_utils.valid_signing_time(signing_time, current_time, threshold)

    # Then the signing time is not valid
    assert valid is False

    # Then a new debug log is captured
    # filter on DEBUG log records only
    records = filter(lambda log_record: log_record.levelno == logging.DEBUG, caplog.records())
    assert len(records) == 1
    assert records[0].name == 'applepay.utils'
    assert records[0].message == 'Signing time is invalid. Signing time: 2014-10-27 20:51:43 UTC, Current time: 2014-10-28 01:51:43 UTC, Threshold: 1:00:00.'


def test_verify_signature(token_fixture):
    """Test that a token known to be valid has a valid
    signature"""
    assert applepay_utils.verify_signature(token_fixture) is True


def test_verify_signature_with_threshold(token_fixture):
    """Test that a token known to be valid has a valid
    signature and the signing time is within the provided threshold"""
    with freeze_time("2017-04-06 23:20:50'", tz_offset=0):
        valid_signature = applepay_utils.verify_signature(
            token_fixture, threshold=timedelta(days=1000)
        )

    assert valid_signature is True


def test_valid_chain_of_trust(certificates_der_fixture):
    # Given a valid root, intermediate, and leaf cert
    root_der, intermediate_der, leaf_der = certificates_der_fixture

    # When: we test for a valid chain of trust
    is_valid = applepay_utils.valid_chain_of_trust(root_der, intermediate_der, leaf_der)

    # Then: the chain is valid
    assert is_valid


def test_invalid_leaf_cert(certificates_der_fixture):
    # Given a valid root, intermediate, and leaf cert
    root_der, intermediate_der, leaf_der = certificates_der_fixture

    # Given: the leaf cert is not valid
    leaf_der = leaf_der.replace("\x86H", "\x86G")  # some arbitrary change

    # When: we test for a valid chain of trust
    is_valid = applepay_utils.valid_chain_of_trust(root_der, intermediate_der, leaf_der)

    # Then: the chain is valid
    assert not is_valid


def test_invalid_intermediate_cert(certificates_der_fixture):
    # Given a valid root, intermediate, and leaf cert
    root_der, intermediate_der, leaf_der = certificates_der_fixture

    # Given: the intermediate cert is not valid
    intermediate_der = intermediate_der.replace("\x86H", "\x86G")  # some arbitrary change

    # When: we test for a valid chain of trust
    is_valid = applepay_utils.valid_chain_of_trust(root_der, intermediate_der, leaf_der)

    # Then: the chain is valid
    assert not is_valid


def test_found_both_certificates(candidate_certificates_fixture):
    # Given two candidate certificates that match the leaf and intermediate OIDs
    candidate_certificates = candidate_certificates_fixture

    # When the leaf and intermediate certifcates are extracted from the list of candidates
    leaf_cert, intermediate_cert = applepay_utils.get_leaf_and_intermediate_certs(candidate_certificates)

    # Then a leaf and intermediate certificate are found
    assert leaf_cert
    assert intermediate_cert


def test_missing_leaf_certificate(candidate_certificates_fixture):
    # Given only one candidate certificate that matches the intermediate OID
    candidate_certificates = candidate_certificates_fixture[-1:]

    # When the leaf and intermediate certifcates are extracted from the list of candidates
    leaf_cert, intermediate_cert = applepay_utils.get_leaf_and_intermediate_certs(candidate_certificates)

    # Then not leaf certifice is found
    assert not leaf_cert

    # Then the intermediate certificate is found
    assert intermediate_cert


def test_no_matching_leaf_certificate(candidate_certificates_fixture):
    # Given two candidate certificates where the intermediate cert matches the OID
    # but the leaf does not.  This is accomplished by removing the last extension which is
    # the leaf cert OID extension.
    candidate_certificates = copy.deepcopy(candidate_certificates_fixture)  # copy the fixture since we are modifying it
    i = len(candidate_certificates[0].chosen['tbs_certificate']['extensions']) - 1
    del candidate_certificates[0].chosen['tbs_certificate']['extensions'][i]

    # When the leaf and intermediate certifcates are extracted from the list of candidates
    leaf_cert, intermediate_cert = applepay_utils.get_leaf_and_intermediate_certs(candidate_certificates)

    # Then no leaf certifice is found
    assert not leaf_cert

    # Then the intermediate certificate is found
    assert intermediate_cert


def test_no_matching_intermediate_certificate(candidate_certificates_fixture):
    # Given two candidate certificates where the leaf cert matches the OID
    # but the intermediate does not.  This is accomplished by removing the last extension which is
    # the intermediate cert OID extension.
    candidate_certificates = copy.deepcopy(candidate_certificates_fixture)  # copy the fixture since we are modifying it
    i = len(candidate_certificates[1].chosen['tbs_certificate']['extensions']) - 1
    del candidate_certificates[1].chosen['tbs_certificate']['extensions'][i]

    # When the leaf and intermediate certifcates are extracted from the list of candidates
    leaf_cert, intermediate_cert = applepay_utils.get_leaf_and_intermediate_certs(candidate_certificates)

    # Then the leaf certifice is found
    assert leaf_cert

    # Then no intermediate certificate is found
    assert not intermediate_cert


def test_missing_intermediate_certificate(candidate_certificates_fixture):
    # Given only one candidate certificate that matches the leaf OID
    candidate_certificates = candidate_certificates_fixture[:1]

    # When the leaf and intermediate certifcates are extracted from the list of candidates
    leaf_cert, intermediate_cert = applepay_utils.get_leaf_and_intermediate_certs(candidate_certificates)

    # Then a leaf certifice is found
    assert leaf_cert

    # Then no intermediate certificate is found
    assert not intermediate_cert


def test_missing_both_certificates(candidate_certificates_fixture):
    # Given no certificates
    candidate_certificates = []

    # When the leaf and intermediate certifcates are extracted from the list of candidates
    leaf_cert, intermediate_cert = applepay_utils.get_leaf_and_intermediate_certs(candidate_certificates)

    # Then not leaf certifice is found
    assert not leaf_cert

    # Then no intermediate certificate is found
    assert not intermediate_cert


def test_get_payment_data():
    # Given an apple pay token  with minimal data
    token = {
        "version": "does not matter",
        "data": base64.b64encode('sir robin;'),
        "signature": "does not matter",
        "header": {
            "transactionId": binascii.hexlify('sir lancelot;'),
            "ephemeralPublicKey": base64.b64encode('king arthur;'),
            "publicKeyHash": "does not matter"
        }
    }

    # When the payment data is accessed and decoded
    payment_data = applepay_utils.get_payment_data(token)

    # Then it is the expected value
    expected_payment_data = 'king arthur;sir robin;sir lancelot;'
    assert expected_payment_data == payment_data


def test_get_payment_data_includes_application_data():
    # Given an apple pay token including application data
    token = {
        "version": "does not matter",
        "data": base64.b64encode('sir robin;'),
        "signature": "does not matter",
        "header": {
            "transactionId": binascii.hexlify('sir lancelot;'),
            "ephemeralPublicKey": base64.b64encode('king arthur;'),
            "publicKeyHash": "does not matter",
            "applicationData": binascii.hexlify('sir galahad;')
        }
    }

    # When the payment data is accessed and decoded
    payment_data = applepay_utils.get_payment_data(token)

    # Then it is the expected value
    expected_payment_data = 'king arthur;sir robin;sir lancelot;sir galahad;'
    assert expected_payment_data == payment_data


def test_get_ber_encoded_signed_attributes(signed_attributes_fixture):
    # Given: some signed attributes
    # from the signed_attributes_fixture

    # When the ber-encoded attributes are retrieved
    signed_attrs_ber = applepay_utils.get_ber_encoded_signed_attributes(signed_attributes_fixture)

    # Then the result is the expected value
    expected_ber_attributes = '1i0\x18\x06\t*\x86H\x86\xf7\r\x01\t\x031\x0b\x06\t*\x86H\x86\xf7\r\x01\x07\x010\x1c\x06\t*\x86H\x86\xf7\r\x01\t\x051\x0f\x17\r141027195143Z0/\x06\t*\x86H\x86\xf7\r\x01\t\x041"\x04 {M_{\x87\xb5\xfb\n\x11\x9d\xa5w\xa3\xc6\xd9/\xbb\xe6L\xb1\x03\xb2v_M\n\xbe\x0f\xb1\x98\x8er'
    assert expected_ber_attributes == signed_attrs_ber


def test_remove_ec_point_prefix(certificates_fixture):
    # Given a string that stars with the EC point uncompressed prefix
    point = '\x04\xc2\x15w\xed'

    # When we remove the ec point prefix from the point string
    public_key_point = applepay_utils.remove_ec_point_prefix(point)

    # Then the returned bytes are the remaining bytes minus the prefix
    assert len(public_key_point) == 4
    assert not public_key_point.startswith("\x04")


def test_remove_ec_point_prefix_finds_unexpected_format(certificates_fixture):
    # Given a point that is not in the uncompressed format
    point = '\xc2\x15w\xed\xeb\xd6\xc7\xb2!\x8fh\xddp\x90\xa1!\x8d\xc7\xb0\xbdo,(=\x84`\x95\xd9J\xf4\xa5A\x1b\x83B\x0e\xd8\x11\xf3@~\x833\x1f\x1cT\xc3\xf7\xeb2 \xd6\xba\xd5\xd4\xef\xf4\x92\x89\x89>|\x0f\x13'

    # When we remove the ec point prefix from the point string
    public_key_bytes = applepay_utils.remove_ec_point_prefix(point)

    # Then no bytes are returned due to the point not being uncompressed
    assert not public_key_bytes


def test_get_first_from_iterable_finds_single_match():
    # Given an iterable
    i = range(5)

    # Given a filter function which will find 1 match
    def f(x):
        return x == 3

    # When we get the first match from the iterable
    first_match = applepay_utils.get_first_from_iterable(f, i)

    # Then the returned match is the expected value
    assert first_match == 3


def test_get_first_from_iterable_finds_first_of_many_matches():
    # Given an iterable
    i = range(5)

    # Given a filter function which will find more than 1 match
    def f(x):
        return x in range(1, 5)

    # When we get the first match from the iterable
    first_match = applepay_utils.get_first_from_iterable(f, i)

    # Then the returned match is the expected value
    assert first_match == 1


def test_get_first_from_iterable_does_not_match():
    # Given an iterable
    i = range(5)

    # Given a filter function which will not find any matches
    def f(x):
        return False

    # When we get the first match get_first_from_iterableom the iterable
    first_match = applepay_utils.get_first_from_iterable(f, i)

    # Then the returned match is None
    assert first_match is None


def test_get_hashfunc_by_name():
    # Given a hashing algorithm
    name = 'sha256'

    # Given some data to hash
    data = 'sir robin'

    # When a hashfunc is created by that name
    hashfunc = applepay_utils.get_hashfunc_by_name(name, data)

    # The digest of the hashfunc is the same as the built-in algorithm
    assert hashlib.sha256(data).digest() == hashfunc.digest()


def test_unknown_hash_algoritm_not_support():
    # Given an unknown hashing algorithm
    name = 'fake'

    # When a hashfunc is created
    with pytest.raises(ValueError):
        # Then a ValueError is raised
        applepay_utils.get_hashfunc_by_name(name, '')


def test_message_digest_valid(signed_attributes_fixture, token_fixture):
    # Given signed attributes
    signed_attrs = signed_attributes_fixture

    # Given a payment data from the same token
    # hashed via the sha256 hashfunc
    hashed_payment_data = hashlib.sha256(applepay_utils.get_payment_data(token_fixture)).digest()

    # When the message digest is validated
    is_valid = applepay_utils.validate_message_digest(signed_attrs, hashed_payment_data)

    # Then the message digest is valid
    assert is_valid is True


def test_missing_message_digest(token_fixture):
    # Given some signed attrs that are missing the message digest
    signed_attrs = []

    # Given a payment data from the same token
    # hashed via the sha256 hashfunc
    hashed_payment_data = hashlib.sha256(applepay_utils.get_payment_data(token_fixture)).digest()

    # When the message digest is validated
    is_valid = applepay_utils.validate_message_digest(signed_attrs, hashed_payment_data)

    # Then the message digest is not valid
    assert is_valid is False


def test_mismatched_payment_data(signed_attributes_fixture):
    # Given some signed attrs
    signed_attrs = signed_attributes_fixture

    # Given a payment data object that will not match
    hashed_payment_data = hashlib.sha256('sir robin').digest()

    # When the message digest is validated
    is_valid = applepay_utils.validate_message_digest(signed_attrs, hashed_payment_data)

    # Then the message digest is not valid
    assert is_valid is False
