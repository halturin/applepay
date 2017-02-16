from datetime import datetime, timedelta

from pytz import utc

from applepay import payment
from applepay import utils as applepay_utils

import utils as test_utils


def test_retrieve_signature_signing_time():
    # Given a detached CMS signature in the token,
    token = test_utils.load_json_fixture('tests/fixtures/token.json')
    signature = token['signature']

    # when we attempt to retrieve the signing time from the signature,
    signing_time = applepay_utils.retrieve_signature_signing_time(signature)

    # then the signing time matches the datetime we expect.
    expected_time = datetime(2014, 10, 27, 19, 51, 43, tzinfo=utc)
    assert signing_time == expected_time


def test_valid_signing_time():
    # Given a detached CMS signature in the token,
    token = test_utils.load_json_fixture('tests/fixtures/token.json')
    signature = token['signature']

    # and a current time exactly one hour past the signing time,
    current_time = datetime(2014, 10, 27, 20, 51, 43, tzinfo=utc)

    # and a time-delta threshold of one hour,
    threshold = timedelta(hours=1)

    # when we attempt to validate the signing time against the threshold,
    valid = payment.Payment.signing_time_is_valid(signature, current_time, threshold)

    # then the token should be considered valid.
    assert valid is True


def test_expired_signing_time():
    # Given a detached CMS signature in the token,
    token = test_utils.load_json_fixture('tests/fixtures/token.json')
    signature = token['signature']

    # and a current time well past the signing time,
    current_time = datetime(2017, 2, 16, 17, 9, 55, tzinfo=utc)

    # and a time-delta threshold of only one day,
    threshold = timedelta(days=1)

    # when we attempt to validate the signing time against the threshold,
    valid = payment.Payment.signing_time_is_valid(signature, current_time, threshold)

    # then the token should be considered invalid.
    assert valid is False


def test_future_signing_time():
    # Given a detached CMS signature in the token,
    token = test_utils.load_json_fixture('tests/fixtures/token.json')
    signature = token['signature']

    # and a current time which is well before the signing time,
    current_time = datetime(2010, 1, 2, 5, 22, 13, tzinfo=utc)

    # and a time-delta threshold of five weeks,
    threshold = timedelta(weeks=5)

    # when we attempt to validate the signing time against the threshold,
    valid = payment.Payment.signing_time_is_valid(signature, current_time, threshold)

    # then the token should be considered invalid.
    assert valid is False


def test_signing_time_equals_current_time():
    # Given a detached CMS signature in the token,
    token = test_utils.load_json_fixture('tests/fixtures/token.json')
    signature = token['signature']

    # and a current time that exactly matches the signing time,
    current_time = datetime(2014, 10, 27, 19, 51, 43, tzinfo=utc)

    # and a time-delta of zero,
    threshold = timedelta(0)

    # when we attempt to validate the signing time against the threshold,
    valid = payment.Payment.signing_time_is_valid(signature, current_time, threshold)

    # then the token should be considered valid.
    assert valid is True
