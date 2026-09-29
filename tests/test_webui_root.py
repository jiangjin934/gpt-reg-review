from webui.app import root


def test_root_disables_html_shell_caching():
    response = root()

    assert response.headers["cache-control"] == "no-store, max-age=0"
