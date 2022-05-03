#!/usr/bin/env python3
"""
An example of using the Soteri Scanning API - https://docs.soteri.io/scanning-service
"""
import asyncio
import argparse
import os
import httpx
import urllib.parse
import json
import sys
import time
import sty
from sty import fg, bg
from typing import List, Tuple, Callable, Optional, Sequence
from contextlib import ExitStack


async def scan_files(api_server: str, filenames: List[str],
                     include_allowlisted: bool = False, include_empty: bool = False,
                     include_skipped: bool = False) -> dict:
    """Use the Soteri Scanning API to scan the given files.

    Args:
        api_server: The API Server URL to use.
        filenames: The names of the files to scan.
        include_allowlisted: If true, include allowlisted findings.
        include_empty: If true, the response includes a status for files with no findings.
        include_skipped: If true, include results for skipped files.

    Returns:
        JSON-parsed results from the API.
    """
    scan_url = urllib.parse.urljoin(api_server, "rest/scan")

    params = {
        "includeAllowlisted": include_allowlisted,
        "includeEmpty": include_empty,
        "includeSkipped": include_skipped,
    }

    with ExitStack() as stack:
        files = [
            ('file', (filename, stack.enter_context(open(filename, 'rb')))) for filename in filenames
        ]

        async with httpx.AsyncClient(http2=True, timeout=httpx.Timeout(5.0, read=300.0)) as client:
            response = await client.post(scan_url, params=params, files=files)
            response.raise_for_status()
            return response.json()


class BatchProcessor:
    """Handles batch processing of files."""
    MAX_BATCH_SIZE = 1024 * 1024 * 30  # in bytes
    MAX_BATCH_LENGTH = 128  # Number of files that can be open at once
    TRIES = 2
    RETRY_DELAY = 5  # in seconds

    def __init__(self, items_to_scan: List[str], api_server: str,
                 include_allowlisted: bool, include_empty: bool, include_skipped: bool,
                 response_callback: Optional[Callable[[dict], None]], ignore: Optional[Sequence[str]] = None):
        """
        Args:
            items_to_scan: The items to scan. These can be files or directories.
            api_server: The URL of the API server.
        include_allowlisted: If true, include allowlisted findings.
        include_empty: If true, the response includes a status for files with no findings.
        include_skipped: If true, include results for skipped files.
            response_callback: A callback to pass results to after every API response.
            ignore: Any files to ignore.
        """
        self.items_to_scan = items_to_scan
        self.api_server = api_server
        self.include_allowlisted = include_allowlisted
        self.include_empty = include_empty
        self.include_skipped = include_skipped
        self.response_callback = response_callback
        self.ignore = set() if ignore is None else set(ignore)

        self.files = []
        self.size = 0
        self.response = None

    def process_inputs(self) -> dict:
        """Process all items. Returns JSON parsed API response"""
        for item in self.items_to_scan:
            if os.path.isfile(item):
                self._add_file(item)
            elif os.path.isdir(item):
                for dir_path, dir_names, filenames in os.walk(item):
                    for filename in filenames:
                        file = os.path.join(dir_path, filename)
                        self._add_file(file)
            else:
                raise RuntimeError(f"invalid input {item}")

        self._flush()
        return self.get_response()

    def get_response(self):
        return self.response

    def _add_file(self, filename: str) -> None:
        """Add the file to the batch, and if conditions warrant, send the batch."""
        if filename not in self.ignore:
            self.files.append(filename)
            self.size = self.size + os.path.getsize(filename)
            if self.size >= BatchProcessor.MAX_BATCH_SIZE or len(self.files) >= BatchProcessor.MAX_BATCH_LENGTH:
                self._flush()

    def _flush(self) -> None:
        """Send the batched up files to the scanning API and reset the batch."""
        if len(self.files) == 0:
            return

        tries = BatchProcessor.TRIES
        while tries > 0:
            try:
                tries -= 1
                response = asyncio.run(scan_files(
                    self.api_server, self.files, self.include_allowlisted, self.include_empty, self.include_skipped))

                self._combine_responses(response)

                if self.response_callback is not None:
                    self.response_callback(response)

                self.files = []
                self.size = 0
                break

            except httpx.HTTPError as exc:
                print("The following error occurred: ", exc.__class__)
                if tries > 0:
                    print(f"Delaying {BatchProcessor.RETRY_DELAY}s and then retrying (retries left: {tries})...")
                    time.sleep(BatchProcessor.RETRY_DELAY)
                else:
                    print("Giving up.")
                    raise exc

    def _combine_responses(self, response: dict) -> None:
        """Combine the current response with previous responses."""
        if self.response is None:
            self.response = response
        else:
            self.response['status'] = "SUCCESS" if (
                    self.response['status'] == "SUCCESS" and response['status'] == "SUCCESS") else "FAILURE"
            self.response['results'] += response['results']
            self.response['numScanned'] += response['numScanned']
            self.response['numFailed'] += response['numFailed']
            self.response['numSkipped'] += response['numSkipped']


def get_progress_callback(quiet: bool) -> Callable[[dict], None]:
    """Get a callback to pass to BatchProcessor."""
    if not quiet:
        print("Scanning ", end="", flush=True)

    def callback(response: dict) -> None:
        if not quiet:
            print("." if response['status'] == "SUCCESS" else "x", end="", flush=True)

    return callback


CLEAR_EOL = "\033[0m\033[K"
INDENT = "    "


def colorize_line(finding: dict) -> Tuple[str, bool]:
    """
    Args:
        finding: The finding from the API.

    Returns:
        The colorized line, and a boolean indicating if this is the full line.
    """
    line_present = finding['line'] is not None
    line = finding['line'] if line_present else finding['finding']
    start = finding['startOffset'] if line_present else 0
    end = finding['endOffset'] if line_present else len(line)
    line = line[:start] + bg(255, 249, 196) + fg.black + line[start:end] + fg.rs + bg.rs + CLEAR_EOL + line[end:]
    return line.strip(), line_present


def display_finding(finding: dict) -> None:
    """Print an individual finding to stdout."""
    print(f"{INDENT}{finding['ruleName']}, line number: {finding['lineNumber']}, allowlisted: {finding['allowlisted']}")
    colorized_line, full_line = colorize_line(finding)
    print(f"{INDENT}{INDENT}{'line' if full_line else 'finding'}: {colorized_line}")


def colorize_status(status: str) -> str:
    """Return a colorized string representing a success status."""
    if status in ("SUCCESS", "CLEAN"):
        return fg.green + status + fg.rs + CLEAR_EOL
    if status == "SKIPPED":
        return fg.yellow + status + fg.rs + CLEAR_EOL
    if status == "ISSUES FOUND":
        return fg(245, 162, 83) + status + fg.rs + CLEAR_EOL
    if status == "FAILURE":
        return fg.red + status + fg.rs + CLEAR_EOL
    return status


def report_findings(response: dict, include_skipped: bool) -> None:
    """Print scan findings to stdout."""
    print("")

    if response is None:
        print("No files scanned.")
        return

    for file_result in sorted(response['results'], key=lambda r: (r['status'], len(r['findings']))):
        status = file_result['status']
        if status == "SUCCESS":
            num_findings = len([finding for finding in file_result['findings'] if not finding['allowlisted']])
            status = "CLEAN" if num_findings == 0 else "ISSUES FOUND"
        reason = ""
        if file_result['failureReason'] == "UNKNOWN":
            reason = ": Unknown failure. Contact us at https://support.soteri.io"
        elif file_result['failureReason'] == "TOO_MANY_FINDINGS":
            reason = ": The file was partially scanned, but there were too many findings, and scanning was stopped."
        elif file_result['skipReason'] == "UNSUPPORTED_FORMAT":
            reason = ": The file could not be decoded as UTF-8."
        print(f"File {fg.white + file_result['filename'] + fg.rs + CLEAR_EOL}: {colorize_status(status)}{reason}")
        for finding in file_result['findings']:
            display_finding(finding)

    print(f"Overall status: {colorize_status(response['status'])}")
    print(f"{response['numScanned']} files scanned.")

    if response['numSkipped'] != 0:
        include_skipped_hint = "" if include_skipped else " Pass --include-skipped for details."
        print(f"{response['numSkipped']} files skipped due to being an unsupported file format.{include_skipped_hint}")

    if response['numFailed'] != 0:
        print(f"{response['numFailed']} files failed to scan.")


def write_results_to_file(outfile_name: Optional[str], response: dict) -> None:
    """Write the output to file."""
    if outfile_name is not None:
        with open(outfile_name, 'w') as outfile:
            outfile.write(json.dumps(response))


def return_code(response: dict) -> int:
    """Turn an API response into a return code. 0 indicates success and no findings."""
    if response is None or response['status'] == "FAILURE":
        return 1

    for file_result in response['results']:
        if len(file_result['findings']) > 0:
            return 1

    return 0


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Script which scans files or directories using the Soteri Scanning Service.")

    parser.add_argument("items_to_scan", metavar="FILE_OR_DIR", nargs="+", type=str,
                        help="Scan each of these files and directories.")

    parser.add_argument("-s", "--server", dest="api_server", type=str, default="https://api.soteri.io",
                        help="The Soteri Scanning Server Endpoint. (default: %(default)s)")

    parser.add_argument("-o", "--outfile", type=str, default=None,
                        help="Write JSON formatted results to the specified file")

    parser.add_argument("-a", "--include-allowlisted", action="store_true",
                        help="Include allowlisted findings.")

    parser.add_argument("-e", "--include-empty", action="store_true",
                        help="Include empty results for files where no findings were detected.")

    parser.add_argument("-k", "--include-skipped", action="store_true",
                        help="Include results for files which were skipped because they could not be scanned.")

    parser.add_argument("-c", "--color", type=str, choices=["auto", "always", "never"], default="auto",
                        help="Choose when to colorize scan results. Auto disables colors when redirecting output.")

    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Do not print scan results to screen. Requires specifying --outfile")

    args = parser.parse_args()

    if args.quiet and args.outfile is None:
        sys.exit("Specifying --quiet requires --out-file")

    for item in args.items_to_scan:
        if not os.path.exists(item):
            sys.exit(f"{item} does not exist.")

    return args


def main() -> None:
    """Main program entrypoint."""
    args = parse_args()

    # Turn off colors if requested, or stdout is not a TTY (e.g. script is piped to somewhere else).
    if args.color == "never" or (args.color == "auto" and not sys.stdout.isatty()):
        sty.mute(fg, bg)

    processor = BatchProcessor(args.items_to_scan, args.api_server,
                               args.include_allowlisted, args.include_empty, args.include_skipped,
                               get_progress_callback(args.quiet), [args.outfile])

    try:
        results = processor.process_inputs()

        if not args.quiet:
            report_findings(results, args.include_skipped)

        write_results_to_file(args.outfile, results)

        sys.exit(return_code(results))

    except KeyboardInterrupt:
        print("\nScan interrupted.")
        write_results_to_file(args.outfile, processor.get_response())
        sys.exit(130)


if __name__ == '__main__':
    main()
