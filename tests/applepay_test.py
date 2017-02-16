from datetime import datetime
from pytz import utc

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
