from typing import Dict, Union
import requests
import csv
import json
import os
import sys
import time, random
import logging
import argparse
from colorama import Fore
from tenacity import retry, retry_if_exception_type, wait_fixed
from functools import partial
from multiprocessing.dummy import Pool


class WLIFormatter(logging.Formatter):

    def __init__(self):

        logging.Formatter.__init__(self, "%(bullet)s %(msg)s", None)

    def format(self, record):
        if record.levelno == logging.INFO:
            record.bullet = Fore.WHITE + '[*]'
        elif record.levelno == logging.DEBUG:
            record.bullet = Fore.LIGHTBLACK_EX + '[-]'
        elif record.levelno == logging.WARNING:
            record.bullet = Fore.YELLOW + '[+]'
        elif record.levelno == logging.ERROR:
            record.bullet = Fore.RED + '[!]'
        else:
            record.bullet = Fore.LIGHTBLUE_EX + '[?]'

        return logging.Formatter.format(self, record)


def init_logger(v=False):

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(WLIFormatter())
    logging.getLogger().addHandler(handler)
    if v:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)


class APIRetryException(Exception):
    # Raise me if we hit API limit
    def __init__(self):

        pass


class WLIApi:

    __formData: Dict[str, Union[None, int, str]]

    def __init__(self, **kwargs):
        # Parse keyword args.
        self.__v = kwargs.get('verbose')
        self.__comboList = kwargs.get('combo_list')
        self.__userList = kwargs.get('user_list')
        self.__passList = kwargs.get('pass_list')
        self.__crackHash = kwargs.get('crack')
        self.__csv = kwargs.get('csv')
        self.__json = kwargs.get('json')
        self.__Limiter = kwargs.get('limit')
        self.__showKeys = kwargs.get('showKeys')
        # Load the API keys by calling self.read_apikey()
        self.__apiPubKey = None
        self.__apiPrivKey = None
        self.__profile_path = f"{os.path.expanduser('~')}/.wli"
        # Define the dict to store all results in for processing post-search.
        self.__all_res = {
            "Total": 0,
            "UniqUsers": [],
            "UniqPasswords": [],
            "Data": []
        }
        # Define unique lists for building combo lists.
        self.__foundDatatypes = set()
        self.__users = set()
        self.__passwords = set()
        self.__combo_list = set()
        # Define the API headers.
        self.__headers = {
            "User-Agent": "WLI CLI Search Tool",
            "Authorization": None,  # Specify the API key like Bearer <apiKey>
            "Accept": "application/json, text/plain, */*",
            "Referer": "https://docs.weleakinfo.com/v3/private/postsearch",
            "Origin": "https://docs.weleakinfo.com",
        }
        # Define POST information.
        self.__timeout = 30
        self.__formData = {
            "query": None,
            "type": None,
            "limit": 10000,
            "offset": 0,
            "wildcard": "false",  # These take a string. Python bool objs won't work. Do not change this here.
            "regex": "false"  # Instead specify them when calling search(wildcard=True|False).
        }
        # Define the API base URIs
        self.__priv_url = "https://api.weleakinfo.com/v3"
        self.__pub_url = "https://api.weleakinfo.com/v3/public"

    def init_key(self, apiKey, apiKeyType):
        """
        Installs the API key to the user's environment.
        :param apiKey: The API key
        :param apiKeyType: The type of API key. Acceptable values: public, private.
        """
        if apiKeyType.lower() == 'private':
            env = "WLI_PRIV_KEY"
        elif apiKeyType.lower() == 'public':
            env = "WLI_PUB_KEY"
        else:
            logging.error("Please specify the --key-type option with the correct value. "
                          "Acceptable values: public, private")
            sys.exit(1)

        if not os.path.exists(self.__profile_path):
            # Create the directory if it doesn't exist.
            os.makedirs(self.__profile_path)
        with open(f"{self.__profile_path}/{env}", 'w') as f:
            f.write(f"{apiKey}")

    def read_apikey(self):
        """
        Gets the API key from the users environment
        :return: Returns the API keys.
        """
        priv_key_file = f"{self.__profile_path}/WLI_PRIV_KEY"
        pub_key_file = f"{self.__profile_path}/WLI_PUB_KEY"

        try:
            with open(priv_key_file, 'r') as fpriv:
                priv_key = fpriv.read()
                if not self.__showKeys:
                    logging.debug(f"Using private API key: {priv_key}")
        except (FileNotFoundError, PermissionError) as err:
            logging.warning(f"Could not access private API key. ERR: {err}")
        try:
            with open(pub_key_file, 'r') as fpub:
                pub_key = fpub.read()
                if not self.__showKeys:
                    logging.debug(f"Using public API key: {pub_key}")
        except (FileNotFoundError, PermissionError) as err:
            logging.warning(f"Could not access public API key. ERR: {err}")

        self.__apiPrivKey = priv_key
        self.__apiPubKey = pub_key

        if not (priv_key or pub_key):
            logging.error("Could not find API keys!. Please install the API key via --init-key. "
                          "See --help for more information")
            sys.exit(1)

        return {"priv_key": priv_key, "pub_key": pub_key}

    @retry(retry=retry_if_exception_type(APIRetryException), wait=wait_fixed(10))
    def search(self, query, type, limit=10000, offset=0, wildcard=False, regex=False):
        """
        Perform the private search function specified
        :param query: (String) The query to perform against the WLI API.
        :param type: The type of query. VALID FIELDS: username, email, password, hash, ip, name, phone, domain, ip_range
        :param limit: Limit the results per page to this number.
        :param offset: The offset or page number of results to get.
        :param wildcard: Toggle a wildcard search.
        :param regex: Toggle a regex search.
        :return: Total number of results and the type of data found.
        """
        if not self.__apiPrivKey:
            logging.error("You need a private API key to perform this search!")
            sys.exit(1)
        self.__headers["Authorization"] = f"Bearer {self.__apiPrivKey}"  # Set the API key to private.
        url = f"{self.__priv_url}/search"
        data = self.__formData

        data["query"] = query
        data["type"] = type
        data["offset"] = offset

        if self.__Limiter:
            data["limit"] = self.__Limiter
        else:
            data["limit"] = limit
        if wildcard:
            data["wildcard"] = "true"
        if regex:
            data["regex"] = "true"

        # our query will always be at offset 0 to start.
        try:
            req = requests.post(url, headers=self.__headers, data=data, timeout=self.__timeout)
        except requests.exceptions.Timeout as err:
            logging.error(f"API Timed out on initial query: {err}. Retrying in 10s.")
            raise APIRetryException

        if req.status_code == 429:
            logging.warning("We are being rate limited. Retrying request in 10s.")
            raise APIRetryException  # WLI has 3 req/second rate limit
        resp = json.loads(req.content, encoding='utf-8')
        total = resp.get('Total')
        self.__all_res["Total"] = total
        if total is None:
            logging.error(f"Received unknown API response: {req.content}")
            sys.exit(1)

        if self.__comboList or self.__userList or self.__passList:
            
            logging.debug(f"Adding {data['limit']} results to specified lists.")
            p = Pool()
            p.map(self.combo_lister, resp.get("Data"))
            p.close()
            p.join()

        for result in resp.get("Data"):
            self.__all_res["Data"].append(result)  # Throw all results into the all_res for processing.

        self.log_results(resp)
        
        if total > limit and not self.__Limiter:
            # Scroll the results if we got more results than the limit. Do not scroll if --limit was specified.
            offsets = []
            p = Pool(processes=4)
            chunks = self.chunk_work(list(range(1, total)), limit)  # get the total num offsets.
            if len(chunks) > 10:
                logging.warning("More than 10 chunks detected. This could take a while. "
                                "Try increasing limit to 10,000 or using a query that returns less data.")
            for chunk in chunks:
                offsets.append(chunks.index(chunk))  # get the offset number.

            func = partial(self.search_helper, data=data, url=url)
            p.map(func, offsets)
            p.close()
            p.join()

        return {"Total": total, "Datatypes": self.__foundDatatypes}

    @retry(retry=retry_if_exception_type(APIRetryException), wait=wait_fixed(10))
    def search_helper(self, offset, url, data):
        """
        Helper function for paged searches, where the total results is larger than the page limit.
        :param offset: The page of results to get.
        :param url: The URL we are searching on.
        :param data: the POST data used in the original request.
        :return: True if successful. False if failed.
        """
        time.sleep(0.5)
        data['offset'] = offset  # set the offset to the appropriate slice.

        try:
            req = requests.post(url, headers=self.__headers, data=data, timeout=self.__timeout)
        except requests.exceptions.Timeout as err:
            logging.error(f"API Timed out on scroll query (offset={offset}): {err}. Retrying in 10s.")
            raise APIRetryException

        if req.status_code == 429:
            logging.warning("We are being rate limited. Retrying request in 10s.")
            raise APIRetryException
        try:
            resp = json.loads(req.content, encoding='utf-8')
        except json.JSONDecodeError as err:
            logging.error(f"JSON Decode error on page {offset}: {err}, Response: {req.content}")
            return False

        if self.__comboList or self.__userList or self.__passList:

            logging.debug(f"Adding {data['limit']} results to specified lists.")
            p = Pool()
            p.map(self.combo_lister, resp.get("Data"))
            p.close()
            p.join()

        for result in resp.get("Data"):
            self.__all_res["Data"].append(result)  # Throw all results into the all_res for processing.

        self.log_results(resp)  # Log the results

        return True

    def combo_lister(self, result):
        """
        Pass an interable of self.__all_res["Data"]
        :param result: A row inside of self.__all_res["Data"]
        """
        password = result.get("Password")
        username = result.get("Username")
        email = result.get("Email")

        if self.__comboList:
            # If our results contain Username + Password or Email + Password, add em to the combo list (user:pass).
            if username and password:
                self.__combo_list.add(f"{username}:{password}")

            if email and password:
                self.__combo_list.add(f"{email}:{password}")

        if self.__userList:
            # If our results contain Username or Email, add em to the unique user list.
            if username:
                self.__users.add(username)
            if email:
                self.__users.add(email)

        if self.__passList:
            # If our results contains a Password, add em to the unique password list.
            if password:
                self.__passwords.add(password)

    def log_results(self, resp):
        """
        Logs results to the console, and adds the found datatype to the list of dict keys.
        :param resp: a parsed json response from the WLI api.
        """
        response = resp.get("Data")
        for result in response:
            output = []
            for key in result:
                self.__foundDatatypes.add(key)  # needed for CSV output headers
                if key == "Password":
                    output.append(f"{Fore.LIGHTRED_EX}{key}: {result[key]}{Fore.LIGHTBLACK_EX}")
                else:
                    output.append(f"{key}: {result[key]}")
            logging.debug(", ".join(output))

    @staticmethod
    def chunk_work(l, n):
        """
        Helper function for thread pool searches where the total results are a lot larger than
        :param l: The list to chunkify
        :param n: The number of values in each chunk.
        :return: Returns a list containing all chunks that can be iterated over a multiprocess map func.
        """
        chunks = []
        for i in range(0, len(l), n):
            chunks.append(l[i:i + n])
        return chunks

    def pub_search(self):
        # Not implemented yet.
        pass

    def crack_hashes(self):
        """
        Cracks hashes. This tends to be slow because of the aggressive rate limit. 
        If you have something like 10,000 hashes, expect it to take a couple hours. Be sure to run the query in screen.
        """
        hash_checks = self.__all_res.get("Data")
        hashes = 0
        salts = 0
        for data in hash_checks:
            if data.get("Hash"):
                hashes += 1
            if data.get("Salt"):
                salts += 1

        logging.info(f"Processing {hashes - salts} hashes and {salts} salted hashes ({hashes} total).")
        if hashes > 100:
            logging.warning(f"Processing {hashes} total hashes could take a long time!")

        p = Pool(processes=6)  # The rate limit is aggressive. Any more threads than this, cloudflare complains.
        cracked = p.map(self.hashcrack_helper, hash_checks)
        logging.info(f"Cracked {sum(cracked)}/{hashes} hashes.")
        if self.__passList or self.__userList or self.__comboList:
            logging.info("Adding decrypted hashes to combo lists.")
            p = Pool()
            p.map(self.hash_to_combo, self.__all_res.get("Data"))
            p.join()
            p.close()

    def hash_to_combo(self, result):

        decrypted = result.get("DecryptedHash")
        username = result.get("Username")
        email = result.get("Email")

        if self.__comboList:
            # If our results contain Username + Decrypted or Email + Decrypted, add em to the combo list (user:pass).
            if username and decrypted:
                self.__combo_list.add(f"{username}:{decrypted}")

            if email and decrypted:
                self.__combo_list.add(f"{email}:{decrypted}")

        if self.__passList:
            # If our results contains a Decrypted Hash, add em to the unique password list.
            if decrypted:
                self.__passwords.add(decrypted)

    @retry(retry=retry_if_exception_type(APIRetryException), wait=wait_fixed(10))
    def hashcrack_helper(self, result):
        """
        Query the hash checking API to see if the hash has been decrypted. If so, update its result in self.__all_res
        :param result: A row from self.__all_res["Data"]
        :return: 1 if the hash was successfuly decrypted, 0 if not.
        """
        url = f"{self.__priv_url}/hash"
        hash = result.get("Hash")
        salt = result.get("Salt")
        self.__foundDatatypes.add("DecryptedHash")
        if hash:

            if salt:
                data = {"hash": hash, "salt": salt}
            else:
                data = {"hash": hash}

            try:
                time.sleep(random.randint(1, 3))  # Wait two seconds or because of Cloudflare.
                req = requests.post(url, headers=self.__headers, data=data)
            except requests.exceptions.Timeout as err:
                logging.error(f"API timed out when checking hash. Retrying in 10s.")
                raise APIRetryException

            if req.status_code == 429:
                #logging.debug("We are being rate limited. Retrying request in 10s.")
                raise APIRetryException
            try:
                resp = json.loads(req.content)
            except json.JSONDecodeError:
                #logging.debug(f"We are probably being rate limited by Cloudflare. Waiting random time and retrying.")
                time.sleep(random.randint(1, 3))
                raise APIRetryException

            if resp.get("Success"):
                decrypted = resp.get("Decrypted")
                logging.info(f"{Fore.LIGHTGREEN_EX}Got a decrypted hash: {decrypted}{Fore.RESET}")

                try:
                    # We need the index number of this row.
                    indexVal = self.__all_res.get("Data").index(result)
                except ValueError as err:
                    logging.error(f"Could not find index number for result! Skipping this result. Error: {err}")
                    return 0
                # Add the decrypted hash to the all_res
                self.__all_res.get("Data")[indexVal]["DecryptedHash"] = decrypted
                return 1
            else:
                logging.debug(f"Failed to decrypt hash: {resp}")
                return 0
        return 0

    def csv_dump(self):
        # Dump results to CSV file
        with open(self.__csv, 'w', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=self.__foundDatatypes)
            writer.writeheader()
            writer.writerows(self.__all_res.get("Data"))

    def json_dump(self):
        # Dump results to json file.
        with open(self.__json, 'wb') as f:
            f.write(json.dumps(self.__all_res, indent=4, sort_keys=True, ensure_ascii=False).encode('utf-8'))

    def combo_dump(self):
        # Dump all the combo lists.
        if self.__comboList:
            logging.info(f"Dumping a combo list containing {len(self.__combo_list)} unique uname:pass combinations.")
            with open(self.__comboList, 'wb') as f:
                for line in self.__combo_list:
                    f.write(f"{line}\n".encode('utf-8'))
        if self.__userList:
            logging.info(f"Dumping a user list containing {len(self.__users)} unique users.")
            with open(self.__userList, 'wb') as f:
                for line in self.__users:
                    f.write(f"{line}\n".encode('utf-8'))
        if self.__passList:
            logging.info(f"Dumping a user list containing {len(self.__passwords)} unique passwords.")
            with open(self.__passList, 'wb') as f:
                for line in self.__passwords:
                    f.write(f"{line}\n".encode('utf-8'))

    def list_finished(self):
        """
        Helper function for listing off all the results of all searches for --query-list
        """
        logging.info(f"All searches finished! Found {len(self.__all_res.get('Data'))} results "
                     f"with types: {self.__foundDatatypes}")


# Type check the argument inputs.
def acceptable_api_key(key):

    if len(key) != 40:
        raise argparse.ArgumentTypeError("Invalid API key. Please double check key. (Does it contain spaces?)")
    return key


def acceptable_api_type(type):
    # verify that the api key type is correct.
    acceptable_values = [
        'private',
        'public'
    ]
    if type.lower() not in acceptable_values:
        raise argparse.ArgumentTypeError("Must specify either 'private' or 'public' for --key-type")
    return type


def check_positive_int(n):
    """
    Type checking for the --limit argument.
    :param n: whatever the user entered for the -l arg.
    :return: return the object back if it is an integer, and is > 0 and < 10000, else raise.
    :raises: argparse.ArgumentTypeErr, ValueError
    """
    try:
        n = int(n)
    except ValueError as err:
        # ya done fucked up
        logging.error("-clean-old-snaps requires an number.")
    if n <= 1 or n > 10000:
        raise argparse.ArgumentTypeError("Must specify a an integer between 1 and 10,000!")
    return n


def acceptable_query_type(type):
    # verify the user supplied the correct input: username, email, password, hash, ip, name, phone, domain, ip_range
    acceptable_values = [
        'username',
        'email',
        'password'
        'hash',
        'ip',
        'name',
        'phone',
        'domain',
        'ip_range'
    ]
    if type.lower() not in acceptable_values:
        raise argparse.ArgumentTypeError("Must specify a valid type: "
                                         "username, email, password, hash, ip, name, phone, domain, ip_range")
    return type


if __name__ == "wli.__main__":

    banner = """
     _       __     __               __   ____      ____    
    | |     / /__  / /   ___  ____ _/ /__/  _/___  / __/___ 
    | | /| / / _ \\/ /   / _ \\/ __ `/ //_// // __ \\/ /_/ __ \\
    | |/ |/ /  __/ /___/  __/ /_/ / ,< _/ // / / / __/ /_/ /
    |__/|__/\\___/_____/\\___/\\__,_/_/|_/___/_/ /_/_/  \\____/ 
                                                            
     {}World's Fastest and Largest Data Breach Search Engine
    """.format(Fore.LIGHTGREEN_EX)
    print(Fore.GREEN + banner + Fore.RESET)

    parser = argparse.ArgumentParser(add_help=True,
                                     description=f"{Fore.LIGHTGREEN_EX}https://weleakinfo.com/{Fore.RESET} CLI Tool")
    # Add arguments
    parser.add_argument("-q", "--query", action="store",
                        help="The value to search. If using wildcard or regex, specify so with the -r or -w switches.")
    parser.add_argument("--query-list", action="store",
                        help="A list of searches to perform, separated by newlines. "
                             "If you use a regex pattern, be sure to specify 'regex:' "
                             "in front of your query, like regex:(.*)yahoo.com.")
    parser.add_argument("-t", "--type", action="store", type=acceptable_query_type,
                        help="The query type to perform. "
                             "VALID FIELDS: username, email, password, hash, ip, name, phone, domain, ip_range")
    parser.add_argument("-l", "--limit", type=check_positive_int,
                        help="Limit the number of results to the specified number.")
    parser.add_argument("-w", "--wildcard", action="store_true", default=False,
                        help="Toggle the wildcard flag. Necessary if searching for a wildcard like: *@domain.com")
    parser.add_argument("-r", "--regex", action="store_true", default=False,
                        help=f"Toggle the regex flag for regex queries. "
                             f"Supported on the following types: Email, Username, Password.{Fore.RED}")
    parser.add_argument("--crack", action="store_true", default=False,
                        help="Attempt to crack all found hashes.")
    # Define display or dumping output options.
    output_group = parser.add_argument_group("Output options")
    output_group.add_argument("-c", "--combo-list", action="store",
                              help=f"Create a <username>:<password> combo list for the query, "
                              f"and save it to the specified path.{Fore.RESET}")
    output_group.add_argument("-u", "--user-list", action="store",
                              help="Store a file of all unique usernames and emails to the the file specified.")
    output_group.add_argument("-p", "--pass-list", action="store",
                              help="Store a file of all unique passwords to the file specified.")
    output_group.add_argument("--csv", action="store", help="Dump all results to CSV file at specified location.")
    output_group.add_argument("--json", action="store", help="Dump all results to JSON file at specified location.")
    output_group.add_argument("--hash-dump", action="store",
                              help="Dump all the hashes and salts to the file at specified location.")
    output_group.add_argument("-v", "--verbose", action="store_true", default=False,
                              help="Enable verbose-mode output.")

    # Define API Key options
    api_group = parser.add_argument_group("API Key options")
    api_group.add_argument("--init-key", action="store", type=acceptable_api_key,
                           help="Install the API key to the current user's environment, under WLI_API_KEY.")
    api_group.add_argument("--key-type", action="store", type=acceptable_api_type,
                           help="Specify the type of API key: public or private")
    api_group.add_argument("--use-public", action="store_true", default=False,
                           help="If we have both public and private API keys, override the default action of using "
                                "the Private API and use the Public API instead.")
    api_group.add_argument("--dont-show-keys", action="store_true", default=False,
                           help="Don't display API keys to STDOUT when using verbose mode.")

    args = parser.parse_args()
    # setup logger
    init_logger()
    logging.getLogger()
    # enable verbosity if requested
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not (args.combo_list or args.user_list or args.pass_list or args.csv or args.json) and args.verbose:
        logging.warning("Automatically enabling verbose mode since no output method was defined.")
        logging.getLogger().setLevel(logging.DEBUG)

        args.verbose = True

    # Override the urllib logger log level.
    urllib3_log = logging.getLogger("urllib3")
    urllib3_log.setLevel(logging.WARNING)
    # Init WLI API instance with options.
    wli = WLIApi(verbose=args.verbose, combo_list=args.combo_list, user_list=args.user_list, pass_list=args.pass_list,
                 crack=args.crack, csv=args.csv, json=args.json, limit=args.limit, showKeys=args.dont_show_keys)

    if args.init_key:
        wli.init_key(args.init_key, args.key_type)
        sys.exit(1)

    if args.query and args.query_list:

        logging.error("You can't specify both query and query-list. Use one or the other.")
        sys.exit(1)

    if args.query or args.query_list and args.type:
        # Do search
        wli.read_apikey()  # load the API keys.
        if args.query_list:

            if args.wildcard or args.regex:
                logging.warning("The wildcard or regex flag is ignored and will be overridden. "
                                "They will be enabled automatically, as needed.")
            try:
                with open(args.query_list, 'r') as f:
                    for query in f.readlines():
                        search = query.rstrip('\n')
                        # Check for wildcards
                        if "*" in search:
                            wildcard_flag = True
                        else:
                            wildcard_flag = False
                        # Check for regex:
                        if "regex:" in search:
                            search = search.lstrip("regex:")
                            regex_flag = True
                        else:
                            regex_flag = False

                        if regex_flag and wildcard_flag:
                            wildcard_flag = False  # If the query is a regex, we might trigger the wildcard flag.

                        if wildcard_flag:
                            logging.info(f"Starting requested wildcard search for {args.type}:{search}")
                        elif regex_flag:
                            logging.info(f"Starting requested regex search for {args.type}:{search}")
                        else:
                            logging.info(f"Starting requested search for {args.type}:{search}")

                        results = wli.search(query=search, type=args.type, wildcard=wildcard_flag, regex=regex_flag)
                        if results.get('Total') == 0:
                            logging.error("Search finished! Found 0 results. :(")
                        else:
                            logging.info(f"Search finished! Found: {results.get('Total')} total results "
                                         f"containing {results.get('Datatypes')}")
            except (FileNotFoundError, PermissionError) as err:
                logging.error(f"Could not open file specified! Error: {err}")
                sys.exit(1)
            wli.list_finished()

        if args.query:
            logging.info(f"Starting requested search for {args.type}:{args.query}")
            results = wli.search(query=args.query, type=args.type, wildcard=args.wildcard, regex=args.regex)
            if results.get('Total') == 0:
                logging.error("Search finished! Found 0 results. :(")
            else:
                logging.info(f"Search finished! Found: {results.get('Total')} total results "
                             f"containing {results.get('Datatypes')}")

        logging.info("Now performing hash cracking or dump options, if specified.")
        if args.crack:
            wli.crack_hashes()
        if args.combo_list or args.user_list or args.pass_list:
            wli.combo_dump()
        if args.csv:
            wli.csv_dump()
        if args.json:
            wli.json_dump()

        logging.info("Done.")
        sys.exit(0)

    else:
        logging.warning("Must specify both -q or --query-type and -t options.")
        sys.exit(1)
