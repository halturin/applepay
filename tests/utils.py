import json


def load_json_fixture(path):
    """ Return the Python representation of the JSON fixture stored in path.
    :param path: Local path to JSON fixture file.
    :type: str
    :return: Python representation of JSON content.
    :rtype: object
    """
    with open(path, 'r') as f:
        return json.load(f)
