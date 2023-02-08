import os
import subprocess
import sys

VERSION = "0.1.0"
CURL_REQ_VERSION = "CurlReq/" + VERSION

# Serialization format version. This is displayed nowhere, it just needs to be incremented by one
# for each change in the file format.
FLOW_FORMAT_VERSION = 20


def get_dev_version() -> str:
    """
    Return a detailed version string, sourced either from VERSION or obtained dynamically using git.
    """

    curl_req_version = VERSION

    here = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    try:  # pragma: no cover
        # Check that we're in the curlreq repository
        # 4814183a6c1ce9bf452ab3310a8a892a2213a9a0 is the first curlreq commit.
        subprocess.run(
            ["git", "cat-file", "-e", "4814183a6c1ce9bf452ab3310a8a892a2213a9a0"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=here,
            check=True,
        )
        git_describe = subprocess.check_output(
            ["git", "describe", "--tags", "--long"],
            stderr=subprocess.STDOUT,
            cwd=here,
        )
        last_tag, tag_dist_str, commit = git_describe.decode().strip().rsplit("-", 2)
        commit = commit.lstrip("g")[:7]
        tag_dist = int(tag_dist_str)
    except Exception:
        pass
    else:
        # Add commit info for non-tagged releases
        if tag_dist > 0:
            curl_req_version += f" (+{tag_dist}, commit {commit})"

    # PyInstaller build indicator, if using precompiled binary
    if getattr(sys, "frozen", False):
        curl_req_version += " binary"

    return curl_req_version


def version():
    """version name"""
    return CURL_REQ_VERSION


if __name__ == "__main__":  # pragma: no cover
    print(VERSION)
