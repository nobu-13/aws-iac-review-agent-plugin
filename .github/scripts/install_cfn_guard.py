#!/usr/bin/env python3
"""Install a pinned, digest-verified ``cfn-guard`` release binary.

``iacreview.toolcheck`` resolves ``cfn-guard`` on ``PATH`` and refuses anything
below :data:`iacreview.toolcheck.TOOL_REQUIREMENTS`'s minimum, so continuous
integration has to put a suitable build there. The upstream project documents
three ways to do that, and none of them is directly usable here:

``curl ... install-guard.sh | sh``
    The documented one-liner. It fetches a script from a mutable branch and pipes
    it into a shell, and it installs whatever the latest release happens to be.
    steering/security.md asks for pinned versions rather than floating ones, and
    piping a mutable remote script into a shell is the opposite of that.

``brew install cloudformation-guard``
    macOS only, and the formula tracks the latest release.

``cargo install cfn-guard``
    Pinnable and available on both runner images, but it compiles a Rust project
    from source on every job. Minutes per job, for a binary that is published
    prebuilt.

So this script does what the install script does, minus the parts that make it
unpinnable: it downloads one named release asset over HTTPS, checks its SHA-256
against a value recorded here, and extracts the single ``cfn-guard`` member. A
tampered or substituted asset fails the digest check and the job stops.

Updating the pin
----------------

Change :data:`CFN_GUARD_VERSION` and replace all three digests in
:data:`ASSETS`. The digests are published with the release; ``gh release view
<version> --json assets`` prints them, as does the releases API. A digest that is
merely re-copied from the old release will fail on the first run, which is the
intended outcome -- an unverified pin is worse than an obvious failure.

Platform coverage
-----------------

Three of the published assets are needed, one per platform this project's CI
runs on. Linux arm64 is not among them because no supported runner uses it; a
platform with no entry fails with a message naming what it detected rather than
guessing at an asset name.

Exit codes
----------

===== ==========================================================
0     Installed, and ``cfn-guard --version`` ran.
1     Unsupported platform, or download, digest, extraction or
      verification failed.
2     Bad arguments (from the argument parser).
===== ==========================================================
"""

from __future__ import annotations

import argparse
import hashlib
import platform
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, NamedTuple, Optional, Sequence, Tuple

__all__ = [
    "ASSETS",
    "BINARY_NAME",
    "CFN_GUARD_VERSION",
    "DOWNLOAD_TIMEOUT_S",
    "EXIT_FAILURE",
    "EXIT_OK",
    "EXIT_USAGE",
    "Asset",
    "asset_for",
    "download_url",
    "extract_binary",
    "main",
    "platform_key",
    "verify_digest",
]

EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_USAGE = 2

#: The pinned release. Above the 3.0.0 minimum ``iacreview.toolcheck`` enforces,
#: and the version this project is developed against.
CFN_GUARD_VERSION = "3.2.1"

#: The executable inside the archive, and the name ``PATH`` resolution needs.
BINARY_NAME = "cfn-guard"

#: Seconds to wait on the download. Generous for a 3 MB asset, bounded so a
#: hanging mirror fails the job instead of occupying a runner for six hours.
DOWNLOAD_TIMEOUT_S = 120

#: Where the assets live. The release tag is a path component, so a floating
#: "latest" URL is not expressible here by accident.
RELEASE_URL_TEMPLATE = (
    "https://github.com/aws-cloudformation/cloudformation-guard/releases/"
    "download/{version}/{asset}"
)


class Asset(NamedTuple):
    """One published archive.

    Attributes:
        name: File name of the release asset.
        sha256: Hex SHA-256 of the archive, as published with the release.
    """

    name: str
    sha256: str


#: Release assets by ``(system, machine)``, using the normalized values
#: :func:`platform_key` produces. Keys cover the runner images this project's CI
#: uses: Linux x86_64 (``ubuntu-latest``), macOS arm64 (``macos-latest``) and
#: macOS x86_64 (``macos-*-intel``, which the workflow uses for the Python 3.9
#: job because upstream publishes no arm64 CPython 3.9).
ASSETS: Dict[Tuple[str, str], Asset] = {
    ("linux", "x86_64"): Asset(
        name="cfn-guard-v3-x86_64-ubuntu-latest.tar.gz",
        sha256="09c2b8cfd81d513374a8da89d4805dc55006a3da52bbf598e272022d4d198e94",
    ),
    ("darwin", "aarch64"): Asset(
        name="cfn-guard-v3-aarch64-macos-latest.tar.gz",
        sha256="4c1eb10c061731159eaaf0e7dbd465db9fa4b767b82186a4ab489671cc00b7d0",
    ),
    ("darwin", "x86_64"): Asset(
        name="cfn-guard-v3-x86_64-macos-latest.tar.gz",
        sha256="5089dfaa05a766cf118a020518e62f77eddbd43acf3a0b69d36b23175c6c6fda",
    ),
}


class InstallError(Exception):
    """Anything that stops the install, reported as one message."""


def platform_key(system: str, machine: str) -> Tuple[str, str]:
    """Normalize a platform into an :data:`ASSETS` key.

    ``platform.machine()`` reports ``arm64`` on macOS and ``aarch64`` on Linux
    for the same architecture, and ``amd64`` appears in place of ``x86_64`` on
    some systems. Both are folded here so :data:`ASSETS` has one spelling per
    architecture.
    """
    architectures = {
        "arm64": "aarch64",
        "aarch64": "aarch64",
        "x86_64": "x86_64",
        "amd64": "x86_64",
    }
    return system.strip().lower(), architectures.get(machine.strip().lower(), machine.strip().lower())


def asset_for(system: str, machine: str) -> Asset:
    """The asset for one platform.

    Raises:
        InstallError: No asset is pinned for it. The message names what was
            detected, because the fix is either a new entry in :data:`ASSETS` or
            a different runner.
    """
    key = platform_key(system, machine)
    asset = ASSETS.get(key)
    if asset is None:
        raise InstallError(
            "no pinned cfn-guard asset for platform {0}/{1}; known platforms: "
            "{2}".format(
                key[0], key[1], ", ".join(sorted("/".join(k) for k in ASSETS))
            )
        )
    return asset


def download_url(version: str, asset: Asset) -> str:
    """The HTTPS URL of one asset of one release."""
    return RELEASE_URL_TEMPLATE.format(version=version, asset=asset.name)


def download(
    url: str, destination: Path, timeout_s: int = DOWNLOAD_TIMEOUT_S
) -> None:
    """Fetch ``url`` into ``destination``.

    Raises:
        InstallError: The URL is not HTTPS, or the request failed. The scheme is
            checked rather than assumed so that an edited template cannot
            silently downgrade the transport.
    """
    if not url.lower().startswith("https://"):
        raise InstallError("refusing to download over a non-HTTPS URL: {0}".format(url))
    request = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout_s) as response:
            if not response.geturl().lower().startswith("https://"):
                raise InstallError(
                    "the download redirected to a non-HTTPS URL: {0}".format(
                        response.geturl()
                    )
                )
            with destination.open("wb") as handle:
                shutil.copyfileobj(response, handle)
    except (urllib.error.URLError, OSError) as exc:
        raise InstallError("could not download {0}: {1}".format(url, exc)) from exc


def verify_digest(path: Path, expected_sha256: str) -> str:
    """Check the SHA-256 of ``path``.

    Returns:
        The computed digest, so a caller can log it.

    Raises:
        InstallError: The digests differ. Both are named in the message: the
            expected one identifies the pin that needs updating, the computed one
            identifies what actually arrived.
    """
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    computed = digest.hexdigest()
    if computed != expected_sha256.lower():
        raise InstallError(
            "digest mismatch for {0}: expected {1}, got {2}".format(
                path.name, expected_sha256, computed
            )
        )
    return computed


def extract_binary(archive: Path, destination: Path) -> None:
    """Extract the single ``cfn-guard`` member of ``archive`` to ``destination``.

    The member is located by base name and written out with
    :meth:`tarfile.TarFile.extractfile`, never with ``extractall``. An archive
    member is untrusted input: ``extractall`` honours absolute paths and ``..``
    in member names and would let a substituted archive write outside the target
    directory. Copying one stream to one path this function chose cannot.

    Raises:
        InstallError: The archive is unreadable, or holds no regular file named
            ``cfn-guard``.
    """
    try:
        with tarfile.open(archive, mode="r:gz") as handle:
            member = None
            for candidate in handle.getmembers():
                if candidate.isfile() and Path(candidate.name).name == BINARY_NAME:
                    member = candidate
                    break
            if member is None:
                raise InstallError(
                    "{0} holds no regular file named {1}".format(
                        archive.name, BINARY_NAME
                    )
                )
            source = handle.extractfile(member)
            if source is None:
                raise InstallError(
                    "{0}: member {1} could not be read".format(
                        archive.name, member.name
                    )
                )
            with source:
                with destination.open("wb") as target:
                    shutil.copyfileobj(source, target)
    except (tarfile.TarError, OSError) as exc:
        raise InstallError(
            "could not extract {0}: {1}".format(archive.name, exc)
        ) from exc
    destination.chmod(
        stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH
    )


def report_version(binary: Path) -> str:
    """Run ``cfn-guard --version`` and return its first line.

    The installed binary is exercised before the job depends on it, so a
    wrong-architecture asset fails here with a clear message rather than inside a
    test run.

    Raises:
        InstallError: The binary could not be started, or exited non-zero.
    """
    try:
        completed = subprocess.run(
            [str(binary), "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise InstallError(
            "the installed {0} could not be run: {1}".format(BINARY_NAME, exc)
        ) from exc
    output = completed.stdout.decode("utf-8", "replace").strip()
    if completed.returncode != 0:
        raise InstallError(
            "{0} --version exited {1}: {2}".format(
                BINARY_NAME, completed.returncode, output
            )
        )
    return output.splitlines()[0] if output else ""


def build_parser() -> argparse.ArgumentParser:
    """The command line: where to install, and which version."""
    parser = argparse.ArgumentParser(
        prog="install_cfn_guard.py",
        description=(
            "Install a pinned, digest-verified cfn-guard release binary into a "
            "directory of your choosing."
        ),
    )
    parser.add_argument(
        "--bin-dir",
        metavar="DIR",
        required=True,
        help="Directory to install into. Created if absent.",
    )
    parser.add_argument(
        "--version",
        metavar="VERSION",
        default=CFN_GUARD_VERSION,
        help=(
            "Release to install. Defaults to the pinned {0}. A different value "
            "will fail the digest check unless ASSETS is updated too.".format(
                CFN_GUARD_VERSION
            )
        ),
    )
    return parser


def install(bin_dir: Path, version: str) -> Path:
    """Download, verify and install the binary. Returns its path."""
    asset = asset_for(platform.system(), platform.machine())
    url = download_url(version, asset)
    bin_dir.mkdir(parents=True, exist_ok=True)
    target = bin_dir / BINARY_NAME

    with tempfile.TemporaryDirectory(prefix="cfn-guard-install-") as workspace:
        archive = Path(workspace) / asset.name
        print("downloading {0}".format(url))
        download(url, archive)
        digest = verify_digest(archive, asset.sha256)
        print("sha256 verified: {0}".format(digest))
        extract_binary(archive, target)

    print("installed {0}".format(target))
    print(report_version(target))
    return target


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Entry point. See the module docstring for the exit codes."""
    arguments = build_parser().parse_args(argv)
    try:
        install(Path(arguments.bin_dir).expanduser(), arguments.version)
    except InstallError as exc:
        print("install cfn-guard: {0}".format(exc), file=sys.stderr)
        return EXIT_FAILURE
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
