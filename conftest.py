import pytest
import sys


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    if "-vv" in sys.argv:
        outcome = yield
        report = outcome.get_result()

        test_fn = item.obj
        docstring = getattr(test_fn, '__doc__')
        if docstring:
            report.nodeid = docstring
    else:
        outcome = yield

# @pytest.fixture(scope='session')
# def django_db_modify_db_settings():
#     pass
