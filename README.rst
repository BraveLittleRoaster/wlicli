We Leak Info Command Line Utility
=================================
Installation
############

Run ``git@github.com:BraveLittleRoaster/wlicli.git``

Next, install with ``python3 setup.py install``

Then initialize your key. You can get your key by visiting: https://weleakinfo.com/api/overview
Click the button to generate your Public Key and Private Key.

Now you can initialize them like so: ``wli --init-key <private_api_key> --key-type private``

If you have a public api key instead of private, you can initialize that with: ``wli --init-key <public_api_key> --key-type public``

If you have both keys installed, it will always default to using the ``private API`` search, but you can override this with
the ``--use-public`` command.

Usage
#####

<script id="asciicast-xND07dxs7FP2hNasVgEnGxHcz" src="https://asciinema.org/a/xND07dxs7FP2hNasVgEnGxHcz.js" async></script>

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
  --json JSON           Dump all results to JSON file at specified location
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
