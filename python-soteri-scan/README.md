# Python Soteri Scan

This example uses Python and the Soteri Scanning API to scan files and directories on the command line. This example
demonstrates:

* Constructing REST requests using an HTTP/2 compatible python library, [HTTPX](https://www.python-httpx.org/).
* Batching up scanning of many files into multiple requests.

To use it, first install requirements:

```shell
pip install -r requirements.txt
```

Then, you can scan files or directories by passing them as arguments:

```shell
./soteri-scan.py $HOME/dir1 $HOME/dir2 $HOME/file.txt
```

To show detailed files which didn't have any findings, or skipped because they could not be scanned, pass corresponding
flags (which correspond to API request parameters):

```shell
./soteri-scan.py --include-empty --include-skipped $FILES_OR_DIRS
```

To write JSON formatted results to file, specify an outfile:

```shell
./soteri-scan.py --outfile results.json $FILES_OR_DIRS
```

For information on all available options, run:

```shell
./soteri-scan.py --help
```
