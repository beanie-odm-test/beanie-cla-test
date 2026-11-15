"""Logic of the CLA check for pull requests (issues #85 and #86).

This module has no network code. It talks to GitHub and to the signing
service through a small `Api` object, so it can be tested with a fake.

Rules:
- The author of every commit in the pull request must have signed the
  current text of CLA.md on the signing page. Bots and an allowlist (the
  maintainer) do not sign.
- The signing service keeps the records. This check only asks it, by the
  GitHub id of the author and the SHA-256 of the text.
- The email of the commit must be one of the verified emails of the account
  that signed (or the noreply address GitHub makes for the account).
- When the text of CLA.md changes, its hash changes, and people sign again.
- Co-authored-by lines in commit messages are not checked.
"""

import hashlib
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Protocol

RECHECK_PHRASE = "recheck"
STATUS_CONTEXT = "cla"
COMMENT_MARKER = "<!-- beanie-cla -->"
NOREPLY = re.compile(
    r"^(?:(?P<id>\d+)\+)?(?P<login>[^@]+)@users\.noreply\.github\.com$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Person:
    login: str | None
    id: int | None
    email: str
    name: str


@dataclass(frozen=True)
class Commit:
    sha: str
    author: Person
    committer: Person


@dataclass(frozen=True)
class Signature:
    record_id: int
    record_hash: str
    signed_at: str
    emails: tuple[str, ...]


@dataclass(frozen=True)
class Comment:
    user_login: str
    body: str


@dataclass
class CheckResult:
    unsigned: list[str] = field(default_factory=list)
    unlinked: list[str] = field(default_factory=list)
    wrong_email: list[tuple[str, str]] = field(default_factory=list)
    signed: dict[str, Signature] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return not (self.unsigned or self.unlinked or self.wrong_email)


class Api(Protocol):
    def list_commits(self, pr_number: int) -> list[Commit]: ...

    def lookup(self, github_id: int, cla_sha256: str) -> Signature | None: ...

    def set_status(self, sha: str, state: str, description: str) -> None: ...

    def upsert_comment(
        self, pr_number: int, body: str, create_if_missing: bool
    ) -> None: ...


def hash_text(text: str) -> str:
    """SHA-256 of the CLA text, the same on every platform.

    The signing service (repository beanie-cla) has the same function. A
    change here needs the same change there.
    """
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    normalized = "\n".join(line.rstrip() for line in lines).strip("\n")
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def email_belongs(person: Person, signature: Signature) -> bool:
    """Is the commit email one of the verified emails of the signer?"""
    email = person.email.lower()
    if email in {item.lower() for item in signature.emails}:
        return True
    match = NOREPLY.match(email)
    if match is None:
        return False
    same_id = match["id"] is not None and match["id"] == str(person.id)
    same_login = (
        person.login is not None and match["login"] == person.login.lower()
    )
    return same_id or same_login


class ClaChecker:
    def __init__(
        self,
        api: Api,
        cla_text: str,
        allowlist: Sequence[str] = (),
        service_url: str = "https://cla.beanie-odm.dev",
        repository: str = "BeanieODM/beanie",
    ) -> None:
        self.api = api
        self.cla_hash = hash_text(cla_text)
        self.allowlist = [self._pattern(item) for item in allowlist]
        self.service_url = service_url.rstrip("/")
        self.repository = repository

    @staticmethod
    def _pattern(item: str) -> "re.Pattern[str]":
        """An allowlist item. Only * is a wildcard, [bot] is plain text."""
        escaped = re.escape(item.lower()).replace(r"\*", ".*")
        return re.compile(escaped)

    def is_exempt(self, login: str) -> bool:
        lowered = login.lower()
        return any(
            pattern.fullmatch(lowered) is not None
            for pattern in self.allowlist
        )

    def check(self, pr_number: int, head_sha: str) -> CheckResult:
        result = CheckResult()
        for commit in self.api.list_commits(pr_number):
            author = commit.author
            if author.login is None or author.id is None:
                result.unlinked.append(commit.sha[:7])
                continue
            if self.is_exempt(author.login):
                continue
            if author.login in result.signed:
                signature = result.signed[author.login]
            elif author.login in result.unsigned:
                signature = None
            else:
                signature = self.api.lookup(author.id, self.cla_hash)
                if signature is None:
                    result.unsigned.append(author.login)
                else:
                    result.signed[author.login] = signature
            if signature is not None and not email_belongs(author, signature):
                pair = (author.login, author.email)
                if pair not in result.wrong_email:
                    result.wrong_email.append(pair)
        self._report(pr_number, head_sha, result)
        return result

    def handle_comment(
        self, pr_number: int, head_sha: str, comment: Comment
    ) -> CheckResult | None:
        if comment.body.strip() != RECHECK_PHRASE:
            return None
        return self.check(pr_number, head_sha)

    def sign_url(self, pr_number: int) -> str:
        return f"{self.service_url}/sign?repo={self.repository}&pr={pr_number}"

    def _report(
        self, pr_number: int, head_sha: str, result: CheckResult
    ) -> None:
        if result.ok:
            self.api.set_status(
                head_sha, "success", "All authors have signed the CLA"
            )
            self.api.upsert_comment(
                pr_number,
                self._success_body(result),
                create_if_missing=bool(result.signed),
            )
            return
        self.api.set_status(
            head_sha, "failure", self._description(result)[:140]
        )
        self.api.upsert_comment(
            pr_number, self._body(pr_number, result), create_if_missing=True
        )

    @staticmethod
    def _description(result: CheckResult) -> str:
        parts = []
        if result.unsigned:
            parts.append("Not signed: " + ", ".join(result.unsigned))
        if result.unlinked:
            parts.append("Commit author not linked to GitHub")
        if result.wrong_email:
            parts.append("Commit email is not a verified email of the signer")
        return "; ".join(parts)

    def _success_body(self, result: CheckResult) -> str:
        lines = [
            COMMENT_MARKER,
            "All authors of this pull request have signed the Beanie "
            "Contributor License Agreement. Thank you.",
        ]
        if result.signed:
            lines.append("")
            lines.append(
                "Public receipts, they do not show any personal data:"
            )
            for login, signature in sorted(result.signed.items()):
                lines.append(
                    f"- @{login}: record #{signature.record_id}, hash "
                    f"`{signature.record_hash[:16]}`, "
                    f"[verify]({self.service_url}/verify/{signature.record_id})"
                )
        return "\n".join(lines) + "\n"

    def _body(self, pr_number: int, result: CheckResult) -> str:
        url = self.sign_url(pr_number)
        lines = [COMMENT_MARKER, "## Contributor License Agreement needed", ""]
        lines.append(
            "Thank you for the contribution. Before it can be merged, the "
            "authors of its commits must agree to the Beanie Contributor "
            "License Agreement."
        )
        lines.append("")
        if result.unsigned:
            lines.append("Not signed yet:")
            lines.extend(f"- @{login}" for login in result.unsigned)
            lines.append("")
            lines.append(
                f"To sign, open [the signing page]({url}), sign in with "
                "GitHub, read the agreement, type your full name and tick "
                "the box. It takes a minute. Then come back here and post "
                f"the comment `{RECHECK_PHRASE}`, or push a new commit, and "
                "the check runs again."
            )
            lines.append("")
        if result.unlinked:
            shas = ", ".join(f"`{sha}`" for sha in result.unlinked)
            lines.append(
                "These commits have an author email that is not linked to a "
                f"GitHub account: {shas}"
            )
            lines.append(
                "Add the email to your GitHub account, or change the author "
                "of the commits, then push again."
            )
            lines.append("")
        if result.wrong_email:
            for login, email in result.wrong_email:
                lines.append(
                    f"The commits of @{login} use the email `{email}`. It is "
                    "not a verified email of the GitHub account that signed. "
                    "Use an email that is verified on your account, then "
                    "push again."
                )
            lines.append("")
        return "\n".join(lines).rstrip() + "\n"
