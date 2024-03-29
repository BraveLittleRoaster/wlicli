*Making this public now. RIP in pieces WeLeakInfo, you made pentesting easymode.*


We Leak Info Command Line Utility
=================================
### Installation


Run `git clone git@github.com:BraveLittleRoaster/wlicli.git`

Next, install with `python3 setup.py install`

Then initialize your key. You can get your key by visiting: https://weleakinfo.com/api/overview
Click the button to generate your Public Key and Private Key.

Now you can initialize them like so: `wli --init-key <private_api_key> --key-type private`

If you have a public api key instead of private, you can initialize that with: `wli --init-key <public_api_key> --key-type public`

If you have both keys installed, it will always default to using the `private API` search, but you can override this with
the `--use-public` command.


### Usage


<a href="https://asciinema.org/a/xND07dxs7FP2hNasVgEnGxHcz" target="_blank"><img src="https://asciinema.org/a/xND07dxs7FP2hNasVgEnGxHcz.svg" /></a>
```
https://weleakinfo.com/ CLI Tool

optional arguments:
  -h, --help            show this help message and exit
  -q QUERY, --query QUERY
                        The value to search. If using wildcard or regex,
                        specify so with the -r or -w switches.
  --query-list QUERY_LIST
                        A list of searches to perform, separated by newlines.
                        If you use a regex pattern, be sure to specify
                        'regex:' in front of your query, like
                        regex:(.*)yahoo.com.
  -t TYPE, --type TYPE  The query type to perform. VALID FIELDS: username,
                        email, password, hash, ip, name, phone, domain,
                        ip_range
  -l LIMIT, --limit LIMIT
                        Limit the number of results to the specified number.
  -w, --wildcard        Toggle the wildcard flag. Necessary if searching for a
                        wildcard like: *@domain.com
  -r, --regex           Toggle the regex flag for regex queries. Supported on
                        the following types: Email, Username, Password.
  --crack               Attempt to crack all found hashes.

Output options:
  -c COMBO_LIST, --combo-list COMBO_LIST
                        Create a <username>:<password> combo list for the
                        query, and save it to the specified path.
  -u USER_LIST, --user-list USER_LIST
                        Store a file of all unique usernames and emails to the
                        the file specified.
  -p PASS_LIST, --pass-list PASS_LIST
                        Store a file of all unique passwords to the file
                        specified.
  --csv CSV             Dump all results to CSV file at specified location.
  --json JSON           Dump all results to JSON file at specified location.
  --hash-dump HASH_DUMP
                        Dump all the hashes and salts to the file at specified
                        location.
  -v, --verbose         Enable verbose-mode output.

API Key options:
  --init-key INIT_KEY   Install the API key to the current user's environment,
                        under WLI_API_KEY.
  --key-type KEY_TYPE   Specify the type of API key: public or private
  --use-public          If we have both public and private API keys, override
                        the default action of using the Private API and use
                        the Public API instead.
  --dont-show-keys      Don't display API keys to STDOUT when using verbose
                        mode.

```

#### --query-list

The `--query-list` param will automatically determine regular searches and wild-card searches, however, you have to
specify within the input file on each line that requires a regex search using the `regex:` tag. For example, you have an input file, `input_list.txt` that looks like this:

```
john.doe@yahoo.com
john.doe@*.*
regex:^[^\s]{4}$\.doe\@(.*)\.com
jane.doe@*.com
```

Lines 2 and 4 will be performed as wildcard search, while line 3 will be a regex, and line 1 a normal search.

#### --crack

Because of We Leak Info's rate limit, the `--crack` option will take a long time to run. Depneding on the size of each 
search and the number of hashes found, it can take hours to run. The best approach is to run the other dumps you need 
first, then rerun the search with the `--crack` command, and output all your dumps to a different file. This will give 
you time to analyze and import the plaintext credentials into tools like Metasploit and NMap, while waiting on the hash
cracker to finish. You can also export all the hashes with `--hash-dump` for offline cracking.
