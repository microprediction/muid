from muid import create, validate

def test_create():
    key = create(difficulty=7)
    assert validate(key)
