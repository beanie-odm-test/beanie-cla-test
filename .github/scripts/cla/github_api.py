"""GitHub and signing service adapter of the CLA check (issues #85, #86).

Talks to the GitHub REST API and to the signing service with the standard
library. The HTTP call is a function (`Transport`), so tests can replace it.
"""

import json
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any
from urllib.parse import urlencode

from cla.core import COMMENT_MARKER, STATUS_CONTEXT, Commit, Person, Signature

API = "https://api.github.com"

# (method, url, token, body) -> (http status, parsed json or None)
Transport = Callable[[str, str, str, dict[str, Any] | None], tuple[int, Any]]


def urllib_transport(
    method: str, url: str, token: str, body: dict[str, Any] | None
) -> tuple[int, Any]:
    data = None if body is None else json.dumps(body).encode("utf-8")
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Authorization", f"Bearer {token}")
    request.add_header("Accept", "application/vnd.github+json")
    request.add_header("X-GitHub-Api-Version", "2022-11-28")
    request.add_header("User-Agent", "beanie-cla-check")
    if data is not None:
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as error:
        raw = error.read()
        try:
            parsed = json.loads(raw) if raw else None
        except ValueError:
            parsed = None
        return error.code, parsed
    except urllib.error.URLError as error:
        raise ServiceError(f"no answer from {url}: {error.reason}") from error


class GitHubError(Exception):
    pass


class ServiceError(Exception):
    """The signing service did not answer, or answered with an error."""


class GitHubApi:
    def __init__(
        self,
        repository: str,
        token: str,
        service_url: str,
        service_token: str,
        transport: Transport = urllib_transport,
        details_url: str | None = None,
    ) -> None:
        self.repository = repository
        self.token = token
        self.service_url = service_url.rstrip("/")
        self.service_token = service_token
        self.transport = transport
        self.details_url = details_url

    def _call(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        ok: tuple[int, ...] = (200, 201),
    ) -> Any:
        status, data = self.transport(method, f"{API}{path}", self.token, body)
        if status not in ok:
            raise GitHubError(f"{method} {path} failed with {status}")
        return data

    def _pages(self, path: str) -> list[Any]:
        items: list[Any] = []
        page = 1
        while True:
            separator = "&" if "?" in path else "?"
            data = self._call(
                "GET", f"{path}{separator}per_page=100&page={page}"
            )
            items.extend(data)
            if len(data) < 100:
                return items
            page += 1

    @staticmethod
    def _person(user: Any, git_part: dict[str, Any]) -> Person:
        has_user = isinstance(user, dict)
        return Person(
            login=user.get("login") if has_user else None,
            id=user.get("id") if has_user else None,
            email=str(git_part.get("email", "")),
            name=str(git_part.get("name", "")),
        )

    def list_commits(self, pr_number: int) -> list[Commit]:
        raw = self._pages(
            f"/repos/{self.repository}/pulls/{pr_number}/commits"
        )
        return [
            Commit(
                sha=item["sha"],
                author=self._person(
                    item.get("author"), item["commit"]["author"]
                ),
                committer=self._person(
                    item.get("committer"), item["commit"]["committer"]
                ),
            )
            for item in raw
        ]

    def head_sha(self, pr_number: int) -> str:
        data = self._call("GET", f"/repos/{self.repository}/pulls/{pr_number}")
        return str(data["head"]["sha"])

    def lookup(self, github_id: int, cla_sha256: str) -> Signature | None:
        """Ask the signing service whether this account has signed."""
        query = urlencode({"github_id": github_id, "sha256": cla_sha256})
        status, data = self.transport(
            "GET",
            f"{self.service_url}/api/v1/signed?{query}",
            self.service_token,
            None,
        )
        if status != 200 or not isinstance(data, dict):
            raise ServiceError(f"the signing service answered {status}")
        if not data.get("signed"):
            return None
        return Signature(
            record_id=int(data["record_id"]),
            record_hash=str(data["record_hash"]),
            signed_at=str(data["signed_at"]),
            emails=tuple(str(item) for item in data.get("emails", [])),
        )

    def set_status(self, sha: str, state: str, description: str) -> None:
        body: dict[str, Any] = {
            "state": state,
            "context": STATUS_CONTEXT,
            "description": description,
        }
        if self.details_url:
            body["target_url"] = self.details_url
        self._call("POST", f"/repos/{self.repository}/statuses/{sha}", body)

    def upsert_comment(
        self, pr_number: int, body: str, create_if_missing: bool
    ) -> None:
        existing = None
        for comment in self._pages(
            f"/repos/{self.repository}/issues/{pr_number}/comments"
        ):
            if COMMENT_MARKER in str(comment.get("body", "")):
                existing = comment
                break
        if existing is not None:
            if existing["body"] != body:
                self._call(
                    "PATCH",
                    f"/repos/{self.repository}/issues/comments/"
                    f"{existing['id']}",
                    {"body": body},
                )
        elif create_if_missing:
            self._call(
                "POST",
                f"/repos/{self.repository}/issues/{pr_number}/comments",
                {"body": body},
            )
