from datetime import datetime, timedelta
import logging

import pytest
from pytz import utc

from applepay import payment, utils as applepay_utils

import utils as test_utils


@pytest.fixture(scope='session')
def token_fixture():
    return test_utils.load_json_fixture('tests/fixtures/token.json')


@pytest.fixture(scope='session')
def private_key_fixture():
    with open('tests/fixtures/private_key.pem', 'r') as f:
        return f.read()


@pytest.fixture(scope='session')
def certificate_fixture():
    with open('tests/fixtures/certificate.pem', 'r') as f:
        return f.read()


def test_retrieve_signature_signing_time(token_fixture):
    # Given a detached CMS signature in the token,
    signature = token_fixture['signature']

    # when we attempt to retrieve the signing time from the signature,
    signing_time = applepay_utils.retrieve_signature_signing_time(signature)

    # then the signing time matches the datetime we expect.
    expected_time = datetime(2014, 10, 27, 19, 51, 43, tzinfo=utc)
    assert signing_time == expected_time


def test_valid_signing_time(token_fixture):
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


def test_expired_signing_time(token_fixture):
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


def test_future_signing_time(token_fixture):
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


def test_signing_time_equals_current_time(token_fixture):
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


def test_valid_signing_time_data_is_logged(token_fixture, caplog):
    # Given: a valid signature for a current time and threshold
    signature = token_fixture['signature']
    current_time = datetime(2014, 10, 27, 20, 51, 43, tzinfo=utc)
    threshold = timedelta(hours=1)

    # When we attempt to validate the signing time against the threshold,
    with caplog.atLevel(logging.DEBUG):
        applepay_utils.signing_time_is_valid(signature, current_time, threshold)

    # Then a new debug log is captured
    records = caplog.records()
    assert len(records) == 1
    assert records[0].name == 'applepay.utils'
    assert records[0].message == 'Signing time is valid. Signing time: 2014-10-27 19:51:43 UTC+00:00, Current time: 2014-10-27 20:51:43 UTC, Threshold: 1:00:00.'


def test_invalid_signing_time_data_is_logged(token_fixture, caplog):
    # Given: a invalid signature for a current time and threshold
    signature = token_fixture['signature']
    current_time = datetime(2010, 1, 2, 5, 22, 13, tzinfo=utc)
    threshold = timedelta(hours=1)

    # When we attempt to validate the signing time against the threshold,
    with caplog.atLevel(logging.DEBUG):
        applepay_utils.signing_time_is_valid(signature, current_time, threshold)

    # Then a new debug log is captured
    records = caplog.records()
    assert len(records) == 1
    assert records[0].name == 'applepay.utils'
    assert records[0].message == 'Signing time is invalid. Signing time: 2014-10-27 19:51:43 UTC+00:00, Current time: 2010-01-02 05:22:13 UTC, Threshold: 1:00:00.'


def test_signature_is_valid(token_fixture):
    """Test that a token known to be valid has a valid
    signature"""
    assert applepay_utils.signature_is_valid(token_fixture)
