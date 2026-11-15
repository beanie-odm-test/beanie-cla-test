"""Entry point of the CLA workflow (issues #85 and #86).

Reads the GitHub event, runs the check, and sets the status. Settings come
from environment variables:

- GITHUB_TOKEN, GITHUB_REPOSITORY, GITHUB_EVENT_NAME, GITHUB_EVENT_PATH:
  given by GitHub Actions.
- CLA_API_TOKEN: the secret the signing service expects as a bearer token.
- CLA_SERVICE_URL: the address of the signing service.
  Default: https://cla.beanie-odm.dev
- CLA_ALLOWLIST: logins that do not need to sign, separated by commas. Only
  * is a wildcard. Default: roman-right,*[bot],web-flow
- CLA_FILE: path of the CLA text. Default: CLA.md
"""

import json
import os
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from cla.core import CheckResult, ClaChecker, Comment
from cla.github_api import (
    GitHubApi,
    ServiceError,
    Transport,
    urllib_transport,
)

DEFAULT_ALLOWLIST = "roman-right,*[bot],web-flow"
DEFAULT_SERVICE = "https://cla.beanie-odm.dev"


def build_api(
    env: Mapping[str, str], transport: Transport = urllib_transport
) -> GitHubApi:
    service = env.get("CLA_SERVICE_URL") or DEFAULT_SERVICE
    return GitHubApi(
        repository=env["GITHUB_REPOSITORY"],
        token=env["GITHUB_TOKEN"],
        service_url=service,
        service_token=env["CLA_API_TOKEN"],
        transport=transport,
        details_url=f"{service.rstrip('/')}/cla",
    )


def run(
    env: Mapping[str, str],
    event_name: str,
    event: dict[str, Any],
    api: GitHubApi,
) -> int:
    cla_text = Path(env.get("CLA_FILE", "CLA.md")).read_text(encoding="utf-8")
    allowlist = [
        item.strip()
        for item in (env.get("CLA_ALLOWLIST") or DEFAULT_ALLOWLIST).split(",")
        if item.strip()
    ]
    checker = ClaChecker(
        api,
        cla_text,
        allowlist=allowlist,
        service_url=env.get("CLA_SERVICE_URL") or DEFAULT_SERVICE,
        repository=env["GITHUB_REPOSITORY"],
    )

    if event_name == "pull_request_target":
        pull_request = event["pull_request"]
        number = int(pull_request["number"])
        head = str(pull_request["head"]["sha"])
    elif event_name == "issue_comment":
        issue = event["issue"]
        if event.get("action") != "created" or "pull_request" not in issue:
            return 0
        number = int(issue["number"])
        head = api.head_sha(number)
    else:
        return 0

    result: CheckResult | None
    try:
        if event_name == "pull_request_target":
            result = checker.check(number, head)
        else:
            payload = event["comment"]
            comment = Comment(
                user_login=str(payload["user"]["login"]),
                body=str(payload["body"]),
            )
            result = checker.handle_comment(number, head, comment)
    except ServiceError:
        # Do not leave the pull request without an answer.
        api.set_status(
            head,
            "error",
            "The CLA service did not answer. Post 'recheck' later.",
        )
        return 1
    if result is None:
        return 0
    return 0 if result.ok else 1


def main() -> int:
    env = os.environ
    event = json.loads(Path(env["GITHUB_EVENT_PATH"]).read_text("utf-8"))
    api = build_api(env)
    # The check only reports. A failing check is shown by the status, so the
    # workflow itself stays green unless something is broken.
    run(env, env["GITHUB_EVENT_NAME"], event, api)
    return 0


if __name__ == "__main__":
    sys.exit(main())
