# coding: utf-8

from __future__ import print_function
import json, locale, platform, re, sys, jcp_config


def print_stderr(*s):
    utf8_supported = not hook_platform.windows() or hook_platform.git()
    if utf8_supported:
        encoding = "utf-8"
    else:
        encoding = hook_platform.windows_encoding()
    for part in s:
        if hook_platform.python3():
            # to print utf-8 correctly, use raw interface for stderr
            if isinstance(part, str):    # raw interface might need manual encoding
                part = part.encode(encoding, errors="ignore")
            sys.stderr.buffer.write(part)
        else:
            if isinstance(part, unicode):
                part = part.encode(encoding, errors="ignore")
            print(part, file=sys.stderr, end="")


class Logger:
    """Provides simple console logging for hook scripts"""

    verbose_enabled = False

    def __init__(self, verbose_enabled=False):
        self.verbose_enabled = verbose_enabled

    def info(self, msg):
        print_stderr(msg, "\n")

    def verbose(self, msg):
        if self.verbose_enabled:
            self.info(msg)

    def script_start(self):
        self.verbose("\n==== START OF COMMIT POLICY PLUGIN HOOK SCRIPT OUTPUT ====\n")

    def script_end(self):
        self.verbose("\n===== END OF COMMIT POLICY PLUGIN HOOK SCRIPT OUTPUT =====\n")


class Diagnostics(object):
    """Diagnostic tool to test the environment and the script's configuration"""

    __IS_VERSION_OKAY = "Check whether the hook script version matches the Commit Policy Plugin version: http://bit.ly/1cizbRC"

    failure_info = None

    def __init__(self, policy_id, jira_base_url, jira_login, jira_password, hook_script_version, repository_id):
        self.policy_id = policy_id
        self.jira_base_url = jira_base_url
        self.jira_login = jira_login
        self.jira_password = jira_password
        self.hook_script_version = hook_script_version
        self.repository_id = repository_id

    def run(self):
        sys.stdout.write("Hook script (version %s) running in DIAGNOSTIC mode (see http://bit.ly/1ESav9t)\n" % \
                         self.hook_script_version)
        passed = \
            self.test_config() and \
            self.test_service_integrity() and \
            self.test_service_i18n()

        success = passed and self.failure_info is None
        warning = passed and self.failure_info is not None and self.failure_info[-1] is True
        failure = not passed

        if warning or failure:
            sys.stdout.write("\n")

        status_msg = "TEST SUCCESS" if success or warning else "TEST FAILED"
        if warning:
            status_msg += " - WITH WARNINGS"

        sys.stdout.write("------------------------------------------------------------------------\n")
        sys.stdout.write("%s\n" % status_msg)
        sys.stdout.write("------------------------------------------------------------------------\n")
        if warning or failure:
            (reason, wrong_setting_value, how_to_fix, only_warning) = self.failure_info
            sys.stdout.write("REASON:\n%s" % reason)
            if wrong_setting_value != "":
                sys.stdout.write("\n%s" % wrong_setting_value)
            if how_to_fix != "":
                sys.stdout.write("\nHOW TO FIX:\n%s" % how_to_fix)
            troubleshooting_guide_url = "http://bit.ly/1FYcboU" 
            sys.stdout.write("\nCheck the troubleshooting guide for more help: %s\n" % troubleshooting_guide_url)
            sys.stdout.write("------------------------------------------------------------------------\n")

    def test_config(self):
        sys.stdout.write("Validating configuration parameters... ")
        if not self.__is_integer(self.policy_id) or (self.policy_id < 1):
            return self.failed("Policy ID is invalid", 
                                    "Open jcp_config.py in a text editor, and set the correct policy ID in the policy_id variable.",
                                    "policy_id", self.policy_id)
        if not self.__is_valid_url(self.jira_base_url):
            return self.failed("JIRA base URL is invalid", 
                                    "Open jcp_config.py in a text editor, and set the correct JIRA base URL in the jira_base_url variable.",
                                    "jira_base_url", self.jira_base_url)
        if not self.jira_login:
            return self.failed("JIRA username must not be empty", 
                                    "Open jcp_config.py in a text editor, and set your JIRA username in the jira_login variable.",
                                    "jira_login", self.jira_login)
        if not self.jira_password:
            return self.failed("JIRA password must not be empty", 
                                    "Open jcp_config.py in a text editor, and set your JIRA password in the jira_password variable.",
                                    "jira_password", self.jira_password)
        return self.passed()

    def test_service_integrity(self):
        sys.stdout.write("Sending sample commit data to ")
        return self._test_service("12345", "john@example.com", "ABC-123 This is a commit message...", "test.txt")

    def test_service_i18n(self):
        sys.stdout.write("Sending encoding-tester commit data to ")
        i18n_string = u"Iñtërnâtiônàlizætiøn 巳乂丹M卫乚ヨ ÁRVÍZTŰRŐ"
        i18n_file_name = i18n_string + u".txt"
        return self._test_service("54321", i18n_string, i18n_string, i18n_file_name, fail_on_error=False,
                                  extra_reason="You may encounter problems when using international characters in user names, file names or commit messages.")

    def _test_service(self, test_id, test_user, test_message, test_filename, fail_on_error=True, extra_reason=""):

        if hook_platform.python3():
            import urllib.error
            http_error_exception = urllib.error.HTTPError
            url_error_exception = urllib.error.URLError
        else:
            import urllib2
            http_error_exception = urllib2.HTTPError
            url_error_exception = urllib2.URLError

        url = generate_service_url(self.jira_base_url, self.policy_id)
        sys.stdout.write("%s... " % url)
        sys.stdout.flush()

        method = self.failed if fail_on_error else self.warning
        id, committer, message, file_list, branch = test_id, test_user, test_message, [{"action": "?", "path": test_filename}], "master"
        commit = create_commit_dict(id, committer, message, file_list, branch)
        try:
            r = contact_server(self.policy_id, [commit], self.jira_base_url, self.jira_login, self.jira_password,
                               diagnostic_mode=True, hook_script_version=self.hook_script_version,
                               repository_id=self.repository_id)

            if r.status_code == 401:
                return self.failed("JIRA username or password is incorrect",
                                   "Open jcp_config.py in a text editor, and set your JIRA user name and password in the jira_login and jira_password variables.")
            if r.status_code == 403:
                return self.failed("Login denied",
                                   "This may happen after multiple unsuccessful login attempts.\n" +
                                   "See the \"Maximum Authentication Attempts Allowed\" JIRA setting at: https://confluence.atlassian.com/x/CAISCw\n" +
                                   "Please open JIRA in your web browser, then log out and re-login. (You will probably have to enter a CAPTCHA check.) Then re-try this script.")
            if r.status_code == 404 or r.status_code == 405:
                return self.failed("Could not access the REST endpoint",
                                   "Possible reasons:\n" +
                                   "1 - Check the JIRA base URL by opening jcp_config.py in a text editor, and verifying the jira_base_url variable.\n" +
                                   "2 - " + self.__IS_VERSION_OKAY + "\n" +
                                   "3 - A non-existing policy may be referenced. Log in to JIRA as administrator, go to Administration -> Add-ons -> Commit Policies to see the existing commit policies and their IDs. " +
                                   "Then open jcp_config.py in a text editor, and set the correct policy ID in the policy_id variable.",
                                   "policy_id", self.policy_id)
            if r.status_code == 500:
                return self.failed("Internal server error occurred",
                                   "Please check the JIRA log. " + self.__IS_VERSION_OKAY) ## ! test
            if r.status_code != 200:
                return self.failed("Server responded with HTTP status code %s" % r.status_code)

            try:
                response = r.json()
            except ValueError:
                return method(
                    "Response data is malformed." + ("Response should be a valid JSON value.\nSent: %s" % commit),
                    self.__IS_VERSION_OKAY)

            is_ok, dr = response["ok"], response["diagnosticResponse"]
            if dr != commit:
                return method(
                    "Diagnostic echo response was different from the information sent. %s\nSent:     %s\nResponse: %s" % (
                        extra_reason, commit, dr), self.__IS_VERSION_OKAY)
        except ValueError:
            return method("JSON response does not contain the expected diagnostic values.", self.__IS_VERSION_OKAY)
        except (http_error_exception, url_error_exception) as e:
            return self.failed("Connection failed: %s" % e,
                               "JIRA base URL is incorrect or the JIRA server is down. Please check whether JIRA is accessible with your browser via the URL you provided.",
                               "jira_base_url", self.jira_base_url) # ! double-check whether the url is printed
        return self.passed()

    def passed(self):
        sys.stdout.write("OK\n")
        return True

    def failed(self, reason, how_to_fix="", wrong_setting=None, wrong_value=None, only_warning=False):
        wrong_setting_value = "%s = \"%s\"" % (wrong_setting, wrong_value) if wrong_setting is not None and wrong_value is not None else ""
        self.failure_info = (reason, wrong_setting_value, how_to_fix, only_warning)

    def warning(self, reason, how_to_fix="", wrong_setting=None, wrong_value=None):
        self.failed(reason, how_to_fix, wrong_setting, wrong_value, only_warning=True)
        return True

    def __is_integer(self, s):
        if "." in str(s):
            return False
        try:
            int(s)
            return True
        except ValueError:
            return False

    def __is_valid_url(self, s):  # inspired by Django source, see http://stackoverflow.com/a/7160778/669897
        regex = re.compile(
            r'^(?:http|ftp)s?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
            r'localhost|'  # localhost...
            r'(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)|'  # local machine name
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        return regex.match(s)


class Platform:
    """Provides a simple interface to detect the underlying OS and Python version"""

    vcs = None

    def __init__(self):
        pass

    def windows(self):
        return platform.system() == "Windows"

    def python3(self):
        return sys.version_info[0] >= 3

    def git(self):
        return self._is_vcs("git")

    def hg(self):
        return self._is_vcs("hg")

    def svn(self):
        return self._is_vcs("svn")

    def _is_vcs(self, vcs_name):
        return self.vcs is not None and self.vcs == vcs_name

    def windows_encoding(self):
        return jcp_config.windows_default_encoding if jcp_config.windows_default_encoding is not None else locale.getpreferredencoding()


class JcpServiceResult(object):
    status_code = None
    body_as_json = None

    def __init__(self, status_code, body_as_json):
        self.status_code = status_code
        self.body_as_json = body_as_json

    def json(self):
        return self.body_as_json


def safe_console_encode(s):
    if hook_platform.python3():
        string_type = str
    else:
        string_type = unicode
    if not isinstance(s, string_type):
        s = s.decode("utf-8", errors="replace")
    return s.encode("ascii", errors="replace")


def create_file_descriptor(path, action="?"):
    return {
        "path": path,
        "action": action
    }


def create_commit_dict(id, committer, message, file_list, branch="", is_merge=False):
    return {
        "id": id,
        "userName": committer,
        "message": message,
        "files": file_list,
        "branch": branch,
        "isMerge": is_merge
    }


def has_verbose_logging_marker(message):
    return message.startswith("%s " % verbose_logging_marker) or \
        message.endswith(" %s" % verbose_logging_marker) or \
        (" %s " % verbose_logging_marker) in message


def remove_verbose_logging_marker(message):
    if message == verbose_logging_marker:
        return ""
    elif (" %s" % verbose_logging_marker) in message:
        return message.replace(" %s" % verbose_logging_marker, "")
    elif ("%s " % verbose_logging_marker) in message:
        return message.replace("%s " % verbose_logging_marker, "")
    return message


def generate_service_url(jira_base_url, policy_id):
    return "%s/rest/commit-policy/1.0/commit-policy/%s/verification" % (jira_base_url.rstrip('/'), policy_id)


def contact_server(policy_id, commit_list, jira_base_url, jira_login, jira_password, diagnostic_mode=False,
                   hook_script_version=None, repository_id=None):
    import base64
    if hook_platform.python3():
        import urllib.request
        request = urllib.request.Request
        urlopen = urllib.request.urlopen
        http_error_exception = urllib.error.HTTPError
    else:
        import urllib2
        request = urllib2.Request
        urlopen = urllib2.urlopen
        http_error_exception = urllib2.HTTPError

    payload = {
        "commits": commit_list,
        "vcs": hook_platform.vcs,
        "hookScriptVersion": "%s" % hook_script_version,
        "repositoryId": repository_id
    }
    if diagnostic_mode:
        payload["diagnosticMode"] = True
    url = generate_service_url(jira_base_url, policy_id)

    base64_auth_string = base64.standard_b64encode(("%s:%s" % (jira_login, jira_password)).encode("ascii")).decode("ascii")
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Basic %s" % base64_auth_string
    }
    req = request(url, json.dumps(payload).encode("utf-8"), headers)
    try:
        handler = urlopen(req)
    except http_error_exception as e:
        return JcpServiceResult(e.code, "")

    return JcpServiceResult(handler.getcode(), json.loads(handler.read().decode("utf-8")))


def invoke_verify_service(policy_id, commit_list, jira_base_url, jira_login, jira_password, hook_script_version, repository_id):
    try:
        r = contact_server(policy_id, commit_list, jira_base_url, jira_login, jira_password, hook_script_version=hook_script_version, repository_id=repository_id)
        return handle_request_result(r)
    except Exception as e:
        print_stderr(str(e))
    return 1


def handle_request_result(r):
    if 200 <= r.status_code < 300:
        response = r.json()
        is_ok = response["ok"]
        if not is_ok:
            msg = response["rejectionMessageFormatted"]
            print_stderr(msg)
            return 1
        else:
            return 0
    else:
        print_stderr("ERROR: Commit Policy Plugin responded with HTTP status code %s. Please contact the JIRA administrator or check the JIRA log.\n(You can temporarily disable this policy until the problem is solved: http://bit.ly/1LIQzf2)" % r.status_code)
        return 1


hook_platform = Platform()
verbose_logging_marker = "#jcp_verbose"

# fix for printing output in TortoiseGit on Windows (would display blank lines without that)
if hook_platform.windows():
    import os, msvcrt
    msvcrt.setmode(sys.stderr.fileno(), os.O_BINARY)
