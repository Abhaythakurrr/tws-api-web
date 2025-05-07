import logging
import sys
import re
from getpass import getpass
import os
import json
import base64
import time
import urllib.request
import urllib.error
import urllib.parse

try:
    import requests
    from requests.auth import HTTPBasicAuth
    from urllib3.util.retry import Retry
    from requests.adapters import HTTPAdapter
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# ANSI color codes for vibe
GREEN = "\033[32m"
RESET = "\033[0m"

# Setup console logging with style
logging.basicConfig(
    level=logging.INFO,
    format=f'{GREEN}%(asctime)s - %(levelname)s - %(message)s{RESET}',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Static ASCII art (using raw string to avoid escape sequence issues)
STATIC_ASCII_ART = r"""
{GREEN}
   _ _          _ _      
  / ____| |        (_) |     
 | |    | '_ \ / _` | | '_ \ 
 | |____| | | | (_| | | |_) |
  \_____|_| |_|____|_|_.__/ 
   A B H I I - TWS API CLIENT
{RESET}
"""

def generate_ascii_art():
    """Return static ASCII art."""
    return STATIC_ASCII_ART

def configure_session():
    """Configure a requests session with retries and timeout."""
    if REQUESTS_AVAILABLE:
        session = requests.Session()
        retries = Retry(total=3, backoff_factor=1, status_forcelist=[502, 503, 504])
        session.mount('https://', HTTPAdapter(max_retries=retries))
        return session
    return None

def validate_engine(engine, masters):
    """Validate if the selected engine is in the master list."""
    if engine not in masters:
        print(f"{GREEN}ERROR: Target {engine} not in network.{RESET}")
        return False
    return True

def validate_required_input(value, field_name):
    """Validate that a required input is not empty."""
    if not value:
        print(f"{GREEN}ERROR: {field_name} required.{RESET}")
        return False
    return True

def validate_job_name(job_name):
    """Validate job name: starts with letter, alphanumeric/underscores, <=40 chars."""
    return bool(job_name and len(job_name) <= 40 and re.match(r"^[A-Za-z][A-Za-z0-9_]*$", job_name))

def validate_time(time_str):
    """Validate time format: HHMM, 0000-2359."""
    return bool(re.match(r"^\d{4}$", time_str) and 0 <= int(time_str[:2]) <= 23 and 0 <= int(time_str[2:]) <= 59)

def validate_frequency(freq):
    """Validate frequency: DAILY, WEEKLY, MONTHLY."""
    return freq.upper() in ["DAILY", "WEEKLY", "MONTHLY"]

def validate_workstation(ws):
    """Validate workstation: alphanumeric, <=16 chars."""
    return bool(ws and len(ws) <= 16 and re.match(r"^[A-Za-z0-9_]*$", ws))

def validate_prompt_name(prompt_name):
    """Validate prompt name: alphanumeric, <=40 chars."""
    return bool(prompt_name and len(prompt_name) <= 40 and re.match(r"^[A-Za-z0-9_]*$", prompt_name))

def prompt_proxy_settings():
    """Prompt for proxy settings or use environment variables."""
    use_proxy = input(f"{GREEN}USE PROXY? (y/n) [n]: {RESET}").strip().lower() == 'y'
    if use_proxy:
        proxy_url = input(f"{GREEN}PROXY URL (e.g., http://proxy.abhii.com:8080): {RESET}").strip()
        if proxy_url:
            return {'http': proxy_url, 'https': proxy_url}
    return os.environ.get('HTTPS_PROXY', {})

def prompt_ssl_verification():
    """Prompt for SSL verification preference."""
    disable_ssl = input(f"{GREEN}DISABLE SSL VERIFICATION? (y/n) [n]: {RESET}").strip().lower() == 'y'
    return not disable_ssl

def send_webhook_notification(message, webhook_type="teams"):
    """Send webhook notification to Teams or email."""
    try:
        webhook_url = os.environ.get(
            "TEAMS_WEBHOOK_URL" if webhook_type == "teams" else "EMAIL_WEBHOOK_URL"
        )
        if not webhook_url:
            logger.warning(f"No {webhook_type} webhook URL configured.")
            return
        if webhook_type == "teams":
            payload = json.dumps({"text": message})
        else:  # Email
            payload = json.dumps({
                "from": "tws@yourdomain.com",
                "to": "recipient@yourdomain.com",
                "subject": "TWS Job Notification",
                "body": message
            })
        if REQUESTS_AVAILABLE:
            response = requests.post(
                webhook_url,
                data=payload,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            response.raise_for_status()
        else:
            req = urllib.request.Request(
                webhook_url,
                data=payload.encode('utf-8'),
                headers={'Content-Type': 'application/json'}
            )
            with urllib.request.urlopen(req) as response:
                if response.getcode() >= 400:
                    raise urllib.error.HTTPError(webhook_url, response.getcode(), response.read().decode(), {}, None)
        print(f"{GREEN}{webhook_type.capitalize()} notification sent: {message}{RESET}")
    except Exception as e:
        logger.error(f"Failed to send {webhook_type} notification: {e}")

def parse_chat_input(chat_input):
    """Rule-based parser for chatbot-like input."""
    chat_input = chat_input.lower().strip()
    job_details = {
        "job_type": "",
        "job_name": "",
        "workstation": "",
        "script": "",
        "sap_job_name": "",
        "sap_user": "",
        "sap_password": "",
        "user": "twsuser",
        "description": "Auto-generated job",
        "priority": "10",
        "recovery_action": "CONTINUE"
    }
    schedule_details = {
        "schedule": "",
        "frequency": "",
        "time": "",
        "dependencies": []
    }

    # Parse job type
    if "batch" in chat_input:
        job_details["job_type"] = "batch"
        script_match = re.search(r"script\s+([^\s]+)", chat_input)
        if script_match:
            job_details["script"] = script_match.group(1)
    elif "sap" in chat_input:
        job_details["job_type"] = "sap"
        sap_job_match = re.search(r"sap job\s+([^\s]+)", chat_input)
        if sap_job_match:
            job_details["sap_job_name"] = sap_job_match.group(1)

    # Parse job name
    name_match = re.search(r"job\s+([a-zA-Z][a-zA-Z0-9_]*)", chat_input)
    if name_match and validate_job_name(name_match.group(1)):
        job_details["job_name"] = name_match.group(1).upper()

    # Parse workstation
    ws_match = re.search(r"on\s+([a-zA-Z0-9_]+)", chat_input)
    if ws_match and validate_workstation(ws_match.group(1)):
        job_details["workstation"] = ws_match.group(1).upper()

    # Parse SAP user/password
    if job_details["job_type"] == "sap":
        user_match = re.search(r"user\s+([^\s]+)", chat_input)
        if user_match:
            job_details["sap_user"] = user_match.group(1)
        pwd_match = re.search(r"password\s+([^\s]+)", chat_input)
        job_details["sap_password"] = pwd_match.group(1) if pwd_match else "NONE"

    # Parse priority
    priority_match = re.search(r"priority\s+(\d+)", chat_input)
    if priority_match and 0 <= int(priority_match.group(1)) <= 100:
        job_details["priority"] = priority_match.group(1)

    # Parse schedule
    freq_match = re.search(r"(daily|weekly|monthly)", chat_input)
    if freq_match:
        schedule_details["frequency"] = freq_match.group(1).upper()
        schedule_details["schedule"] = f"{job_details['job_name']}_SCHED"

    time_match = re.search(r"at\s+(\d{4})", chat_input)
    if time_match and validate_time(time_match.group(1)):
        schedule_details["time"] = time_match.group(1)

    # Parse dependencies
    dep_match = re.search(r"follows\s+([a-zA-Z0-9_]+)", chat_input)
    if dep_match:
        schedule_details["dependencies"].append(dep_match.group(1).upper())

    return job_details, schedule_details if schedule_details["frequency"] else None

class TWSApiClient:
    def __init__(self, base_url, username, password, engine, proxies=None, verify_ssl=True):
        """Initialize the TWS API client."""
        self.base_url = base_url
        self.username = username
        self.password = password
        self.engine = engine
        self.proxies = proxies
        self.verify_ssl = verify_ssl
        self.headers = {
            "Content-Type": "application/json",
            "Id-Encoding": "UTF-8"
        }
        self.session = configure_session() if REQUESTS_AVAILABLE else None

    def _urllib_request(self, method, url, data=None):
        """Fallback HTTP request using urllib.request."""
        headers = self.headers.copy()
        auth_str = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
        headers["Authorization"] = f"Basic {auth_str}"

        if data:
            data = json.dumps(data).encode('utf-8')

        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        if self.proxies:
            proxy_handler = urllib.request.ProxyHandler(self.proxies)
            opener = urllib.request.build_opener(proxy_handler)
        else:
            opener = urllib.request.build_opener()

        if not self.verify_ssl:
            import ssl
            context = ssl._create_unverified_context()
            opener.add_handler(urllib.request.HTTPSHandler(context=context))

        try:
            with opener.open(req, timeout=30) as response:
                if response.getcode() >= 400:
                    raise urllib.error.HTTPError(url, response.getcode(), response.read().decode(), headers, None)
                return json.loads(response.read().decode()) if response.getcode() != 204 else {}
        except (urllib.error.HTTPError, urllib.error.URLError) as e:
            logger.error(f"Request failed: {e}")
            raise

    def submit_ad_hoc_job(self, plan_id, job_data):
        """Submit an ad hoc job to the specified plan."""
        logger.info(f"Deploying job: {job_data['task']['jobDefinition']['name']} on {self.engine}")
        url = f"{self.base_url}/v1/{self.engine}/plan/{plan_id}/job/action/submit_ad_hoc_job"
        try:
            if REQUESTS_AVAILABLE:
                response = self.session.post(
                    url,
                    auth=HTTPBasicAuth(self.username, self.password),
                    json=job_data,
                    headers=self.headers,
                    timeout=30,
                    proxies=self.proxies,
                    verify=self.verify_ssl
                )
                response.raise_for_status()
                job_id = response.json().get("jobId")
            else:
                response = self._urllib_request("POST", url, job_data)
                job_id = response.get("jobId")
            logger.info(f"Job deployed with ID: {job_id}")
            return job_id
        except Exception as e:
            logger.error(f"Job deployment failed: {e}")
            raise

    def get_job_status(self, plan_id, job_id):
        """Retrieve the status of a specific job."""
        logger.info(f"Probing job ID: {job_id} on {self.engine}")
        url = f"{self.base_url}/v1/{self.engine}/plan/{plan_id}/job/{job_id}"
        try:
            if REQUESTS_AVAILABLE:
                response = self.session.get(
                    url,
                    auth=HTTPBasicAuth(self.username, self.password),
                    headers=self.headers,
                    timeout=30,
                    proxies=self.proxies,
                    verify=self.verify_ssl
                )
                response.raise_for_status()
                status = response.json().get("status")
            else:
                response = self._urllib_request("GET", url)
                status = response.get("status")
            return status
        except Exception as e:
            logger.error(f"Status probe failed: {e}")
            raise

    def hold_job(self, plan_id, job_id):
        """Hold a job to pause its execution."""
        logger.info(f"Locking job ID: {job_id} on {self.engine}")
        url = f"{self.base_url}/v1/{self.engine}/plan/{plan_id}/job/{job_id}/action/hold"
        try:
            if REQUESTS_AVAILABLE:
                response = self.session.put(
                    url,
                    auth=HTTPBasicAuth(self.username, self.password),
                    headers=self.headers,
                    timeout=30,
                    proxies=self.proxies,
                    verify=self.verify_ssl
                )
                response.raise_for_status()
            else:
                self._urllib_request("PUT", url)
            logger.info(f"Job {job_id} locked")
            return True
        except Exception as e:
            logger.error(f"Lock failed: {e}")
            raise

    def release_job(self, plan_id, job_id):
        """Release a held job to resume execution."""
        logger.info(f"Unlocking job ID: {job_id} on {self.engine}")
        url = f"{self.base_url}/v1/{self.engine}/plan/{plan_id}/job/{job_id}/action/release"
        try:
            if REQUESTS_AVAILABLE:
                response = self.session.put(
                    url,
                    auth=HTTPBasicAuth(self.username, self.password),
                    headers=self.headers,
                    timeout=30,
                    proxies=self.proxies,
                    verify=self.verify_ssl
                )
                response.raise_for_status()
            else:
                self._urllib_request("PUT", url)
            logger.info(f"Job {job_id} unlocked")
            return True
        except Exception as e:
            logger.error(f"Unlock failed: {e}")
            raise

    def cancel_job(self, plan_id, job_id):
        """Cancel a job to stop its execution."""
        logger.info(f"Terminating job ID: {job_id} on {self.engine}")
        url = f"{self.base_url}/v1/{self.engine}/plan/{plan_id}/job/{job_id}/action/cancel"
        try:
            if REQUESTS_AVAILABLE:
                response = self.session.put(
                    url,
                    auth=HTTPBasicAuth(self.username, self.password),
                    headers=self.headers,
                    timeout=30,
                    proxies=self.proxies,
                    verify=self.verify_ssl
                )
                response.raise_for_status()
            else:
                self._urllib_request("PUT", url)
            logger.info(f"Job {job_id} terminated")
            return True
        except Exception as e:
            logger.error(f"Termination failed: {e}")
            raise

    def rerun_job(self, plan_id, job_id):
        """Rerun a completed or failed job."""
        logger.info(f"Rebooting job ID: {job_id} on {self.engine}")
        url = f"{self.base_url}/v1/{self.engine}/plan/{plan_id}/job/{job_id}/action/rerun"
        try:
            if REQUESTS_AVAILABLE:
                response = self.session.put(
                    url,
                    auth=HTTPBasicAuth(self.username, self.password),
                    headers=self.headers,
                    timeout=30,
                    proxies=self.proxies,
                    verify=self.verify_ssl
                )
                response.raise_for_status()
            else:
                self._urllib_request("PUT", url)
            logger.info(f"Job {job_id} rebooted")
            return True
        except Exception as e:
            logger.error(f"Reboot failed: {e}")
            raise

    def create_job_definition(self, job_definition_data):
        """Create a new job definition in the model."""
        logger.info(f"Installing job definition: {job_definition_data['name']} on {self.engine}")
        url = f"{self.base_url}/v1/{self.engine}/model/jobdefinition"
        try:
            if REQUESTS_AVAILABLE:
                response = self.session.post(
                    url,
                    auth=HTTPBasicAuth(self.username, self.password),
                    json=job_definition_data,
                    headers=self.headers,
                    timeout=30,
                    proxies=self.proxies,
                    verify=self.verify_ssl
                )
                response.raise_for_status()
            else:
                self._urllib_request("POST", url, job_definition_data)
            logger.info(f"Job definition {job_definition_data['name']} installed")
            return True
        except Exception as e:
            logger.error(f"Installation failed: {e}")
            raise

    def get_job_definition(self, job_definition_name):
        """Retrieve a job definition from the model."""
        logger.info(f"Extracting job definition: {job_definition_name} on {self.engine}")
        url = f"{self.base_url}/v1/{self.engine}/model/jobdefinition/{job_definition_name}"
        try:
            if REQUESTS_AVAILABLE:
                response = self.session.get(
                    url,
                    auth=HTTPBasicAuth(self.username, self.password),
                    headers=self.headers,
                    timeout=30,
                    proxies=self.proxies,
                    verify=self.verify_ssl
                )
                response.raise_for_status()
                result = response.json()
            else:
                result = self._urllib_request("GET", url)
            return result
        except Exception as e:
            logger.error(f"Extraction failed: {e}")
            raise

    def create_workstation(self, workstation_data):
        """Create a new workstation in the model."""
        logger.info(f"Installing workstation: {workstation_data['name']} on {self.engine}")
        url = f"{self.base_url}/v1/{self.engine}/model/workstation"
        try:
            if REQUESTS_AVAILABLE:
                response = self.session.post(
                    url,
                    auth=HTTPBasicAuth(self.username, self.password),
                    json=workstation_data,
                    headers=self.headers,
                    timeout=30,
                    proxies=self.proxies,
                    verify=self.verify_ssl
                )
                response.raise_for_status()
            else:
                self._urllib_request("POST", url, workstation_data)
            logger.info(f"Workstation {workstation_data['name']} installed")
            return True
        except Exception as e:
            logger.error(f"Installation failed: {e}")
            raise

    def get_workstation(self, workstation_name):
        """Retrieve a workstation from the model."""
        logger.info(f"Extracting workstation: {workstation_name} on {self.engine}")
        url = f"{self.base_url}/v1/{self.engine}/model/workstation/{workstation_name}"
        try:
            if REQUESTS_AVAILABLE:
                response = self.session.get(
                    url,
                    auth=HTTPBasicAuth(self.username, self.password),
                    headers=self.headers,
                    timeout=30,
                    proxies=self.proxies,
                    verify=self.verify_ssl
                )
                response.raise_for_status()
                result = response.json()
            else:
                result = self._urllib_request("GET", url)
            return result
        except Exception as e:
            logger.error(f"Extraction failed: {e}")
            raise

    def update_workstation(self, workstation_name, workstation_data):
        """Update an existing workstation."""
        logger.info(f"Updating workstation: {workstation_name} on {self.engine}")
        url = f"{self.base_url}/v1/{self.engine}/model/workstation/{workstation_name}"
        try:
            if REQUESTS_AVAILABLE:
                response = self.session.put(
                    url,
                    auth=HTTPBasicAuth(self.username, self.password),
                    json=workstation_data,
                    headers=self.headers,
                    timeout=30,
                    proxies=self.proxies,
                    verify=self.verify_ssl
                )
                response.raise_for_status()
            else:
                self._urllib_request("PUT", url, workstation_data)
            logger.info(f"Workstation {workstation_name} updated")
            return True
        except Exception as e:
            logger.error(f"Update failed: {e}")
            raise

    def delete_workstation(self, workstation_name):
        """Delete a workstation from the model."""
        logger.info(f"Removing workstation: {workstation_name} from {self.engine}")
        url = f"{self.base_url}/v1/{self.engine}/model/workstation/{workstation_name}"
        try:
            if REQUESTS_AVAILABLE:
                response = self.session.delete(
                    url,
                    auth=HTTPBasicAuth(self.username, self.password),
                    headers=self.headers,
                    timeout=30,
                    proxies=self.proxies,
                    verify=self.verify_ssl
                )
                response.raise_for_status()
            else:
                self._urllib_request("DELETE", url)
            logger.info(f"Workstation {workstation_name} removed")
            return True
        except Exception as e:
            logger.error(f"Removal failed: {e}")
            raise

    def create_calendar(self, calendar_data):
        """Create a new calendar in the model."""
        logger.info(f"Installing calendar: {calendar_data['name']} on {self.engine}")
        url = f"{self.base_url}/v1/{self.engine}/model/calendar"
        try:
            if REQUESTS_AVAILABLE:
                response = self.session.post(
                    url,
                    auth=HTTPBasicAuth(self.username, self.password),
                    json=calendar_data,
                    headers=self.headers,
                    timeout=30,
                    proxies=self.proxies,
                    verify=self.verify_ssl
                )
                response.raise_for_status()
            else:
                self._urllib_request("POST", url, calendar_data)
            logger.info(f"Calendar {calendar_data['name']} installed")
            return True
        except Exception as e:
            logger.error(f"Installation failed: {e}")
            raise

    def get_calendar(self, calendar_name):
        """Retrieve a calendar from the model."""
        logger.info(f"Extracting calendar: {calendar_name} on {self.engine}")
        url = f"{self.base_url}/v1/{self.engine}/model/calendar/{calendar_name}"
        try:
            if REQUESTS_AVAILABLE:
                response = self.session.get(
                    url,
                    auth=HTTPBasicAuth(self.username, self.password),
                    headers=self.headers,
                    timeout=30,
                    proxies=self.proxies,
                    verify=self.verify_ssl
                )
                response.raise_for_status()
                result = response.json()
            else:
                result = self._urllib_request("GET", url)
            return result
        except Exception as e:
            logger.error(f"Extraction failed: {e}")
            raise

    def update_calendar(self, calendar_name, calendar_data):
        """Update an existing calendar."""
        logger.info(f"Updating calendar: {calendar_name} on {self.engine}")
        url = f"{self.base_url}/v1/{self.engine}/model/calendar/{calendar_name}"
        try:
            if REQUESTS_AVAILABLE:
                response = self.session.put(
                    url,
                    auth=HTTPBasicAuth(self.username, self.password),
                    json=calendar_data,
                    headers=self.headers,
                    timeout=30,
                    proxies=self.proxies,
                    verify=self.verify_ssl
                )
                response.raise_for_status()
            else:
                self._urllib_request("PUT", url, calendar_data)
            logger.info(f"Calendar {calendar_name} updated")
            return True
        except Exception as e:
            logger.error(f"Update failed: {e}")
            raise

    def delete_calendar(self, calendar_name):
        """Delete a calendar from the model."""
        logger.info(f"Removing calendar: {calendar_name} from {self.engine}")
        url = f"{self.base_url}/v1/{self.engine}/model/calendar/{calendar_name}"
        try:
            if REQUESTS_AVAILABLE:
                response = self.session.delete(
                    url,
                    auth=HTTPBasicAuth(self.username, self.password),
                    headers=self.headers,
                    timeout=30,
                    proxies=self.proxies,
                    verify=self.verify_ssl
                )
                response.raise_for_status()
            else:
                self._urllib_request("DELETE", url)
            logger.info(f"Calendar {calendar_name} removed")
            return True
        except Exception as e:
            logger.error(f"Removal failed: {e}")
            raise

    def submit_job_stream(self, plan_id, job_stream_data):
        """Submit a job stream to the specified plan."""
        logger.info(f"Deploying job stream: {job_stream_data['jobStream']['name']} on {self.engine}")
        url = f"{self.base_url}/v1/{self.engine}/plan/{plan_id}/jobstream/action/submit"
        try:
            if REQUESTS_AVAILABLE:
                response = self.session.post(
                    url,
                    auth=HTTPBasicAuth(self.username, self.password),
                    json=job_stream_data,
                    headers=self.headers,
                    timeout=30,
                    proxies=self.proxies,
                    verify=self.verify_ssl
                )
                response.raise_for_status()
                job_stream_id = response.json().get("jobStreamId")
            else:
                response = self._urllib_request("POST", url, job_stream_data)
                job_stream_id = response.get("jobStreamId")
            logger.info(f"Job stream deployed with ID: {job_stream_id}")
            return job_stream_id
        except Exception as e:
            logger.error(f"Job stream deployment failed: {e}")
            raise

    def get_job_stream_status(self, plan_id, job_stream_id):
        """Retrieve the status of a job stream."""
        logger.info(f"Probing job stream ID: {job_stream_id} on {self.engine}")
        url = f"{self.base_url}/v1/{self.engine}/plan/{plan_id}/jobstream/{job_stream_id}"
        try:
            if REQUESTS_AVAILABLE:
                response = self.session.get(
                    url,
                    auth=HTTPBasicAuth(self.username, self.password),
                    headers=self.headers,
                    timeout=30,
                    proxies=self.proxies,
                    verify=self.verify_ssl
                )
                response.raise_for_status()
                status = response.json().get("status")
            else:
                response = self._urllib_request("GET", url)
                status = response.get("status")
            return status
        except Exception as e:
            logger.error(f"Job stream probe failed: {e}")
            raise

    def create_job_stream_definition(self, job_stream_data):
        """Create a new job stream definition in the model."""
        logger.info(f"Installing job stream: {job_stream_data['name']} on {self.engine}")
        url = f"{self.base_url}/v1/{self.engine}/model/jobstream"
        try:
            if REQUESTS_AVAILABLE:
                response = self.session.post(
                    url,
                    auth=HTTPBasicAuth(self.username, self.password),
                    json=job_stream_data,
                    headers=self.headers,
                    timeout=30,
                    proxies=self.proxies,
                    verify=self.verify_ssl
                )
                response.raise_for_status()
            else:
                self._urllib_request("POST", url, job_stream_data)
            logger.info(f"Job stream {job_stream_data['name']} installed")
            return True
        except Exception as e:
            logger.error(f"Installation failed: {e}")
            raise

    def get_job_stream_definition(self, job_stream_name):
        """Retrieve a job stream definition from the model."""
        logger.info(f"Extracting job stream: {job_stream_name} on {self.engine}")
        url = f"{self.base_url}/v1/{self.engine}/model/jobstream/{job_stream_name}"
        try:
            if REQUESTS_AVAILABLE:
                response = self.session.get(
                    url,
                    auth=HTTPBasicAuth(self.username, self.password),
                    headers=self.headers,
                    timeout=30,
                    proxies=self.proxies,
                    verify=self.verify_ssl
                )
                response.raise_for_status()
                result = response.json()
            else:
                result = self._urllib_request("GET", url)
            return result
        except Exception as e:
            logger.error(f"Extraction failed: {e}")
            raise

    def get_engine_status(self):
        """Retrieve the status of the engine."""
        logger.info(f"Probing engine status: {self.engine}")
        url = f"{self.base_url}/v1/{self.engine}/status"
        try:
            if REQUESTS_AVAILABLE:
                response = self.session.get(
                    url,
                    auth=HTTPBasicAuth(self.username, self.password),
                    headers=self.headers,
                    timeout=30,
                    proxies=self.proxies,
                    verify=self.verify_ssl
                )
                response.raise_for_status()
                result = response.json()
            else:
                result = self._urllib_request("GET", url)
            return result
        except Exception as e:
            logger.error(f"Engine status probe failed: {e}")
            raise

    def create_resource(self, resource_data):
        """Create a new resource in the model."""
        logger.info(f"Installing resource: {resource_data['name']} on {self.engine}")
        url = f"{self.base_url}/v1/{self.engine}/model/resource"
        try:
            if REQUESTS_AVAILABLE:
                response = self.session.post(
                    url,
                    auth=HTTPBasicAuth(self.username, self.password),
                    json=resource_data,
                    headers=self.headers,
                    timeout=30,
                    proxies=self.proxies,
                    verify=self.verify_ssl
                )
                response.raise_for_status()
            else:
                self._urllib_request("POST", url, resource_data)
            logger.info(f"Resource {resource_data['name']} installed")
            return True
        except Exception as e:
            logger.error(f"Installation failed: {e}")
            raise

    def get_resource(self, resource_name):
        """Retrieve a resource from the model."""
        logger.info(f"Extracting resource: {resource_name} on {self.engine}")
        url = f"{self.base_url}/v1/{self.engine}/model/resource/{resource_name}"
        try:
            if REQUESTS_AVAILABLE:
                response = self.session.get(
                    url,
                    auth=HTTPBasicAuth(self.username, self.password),
                    headers=self.headers,
                    timeout=30,
                    proxies=self.proxies,
                    verify=self.verify_ssl
                )
                response.raise_for_status()
                result = response.json()
            else:
                result = self._urllib_request("GET", url)
            return result
        except Exception as e:
            logger.error(f"Extraction failed: {e}")
            raise

    def create_prompt(self, prompt_data):
        """Create a new prompt in the model."""
        logger.info(f"Installing prompt: {prompt_data['name']} on {self.engine}")
        url = f"{self.base_url}/v1/{self.engine}/model/prompt"
        try:
            if REQUESTS_AVAILABLE:
                response = self.session.post(
                    url,
                    auth=HTTPBasicAuth(self.username, self.password),
                    json=prompt_data,
                    headers=self.headers,
                    timeout=30,
                    proxies=self.proxies,
                    verify=self.verify_ssl
                )
                response.raise_for_status()
            else:
                self._urllib_request("POST", url, prompt_data)
            logger.info(f"Prompt {prompt_data['name']} installed")
            return True
        except Exception as e:
            logger.error(f"Installation failed: {e}")
            raise

    def get_prompt(self, prompt_name):
        """Retrieve a prompt from the model."""
        logger.info(f"Extracting prompt: {prompt_name} on {self.engine}")
        url = f"{self.base_url}/v1/{self.engine}/model/prompt/{prompt_name}"
        try:
            if REQUESTS_AVAILABLE:
                response = self.session.get(
                    url,
                    auth=HTTPBasicAuth(self.username, self.password),
                    headers=self.headers,
                    timeout=30,
                    proxies=self.proxies,
                    verify=self.verify_ssl
                )
                response.raise_for_status()
                result = response.json()
            else:
                result = self._urllib_request("GET", url)
            return result
        except Exception as e:
            logger.error(f"Extraction failed: {e}")
            raise

    def test_connectivity(self):
        """Test connectivity to the engine."""
        logger.info(f"Pinging {self.engine}")
        url = f"{self.base_url}/v1/{self.engine}/model/jobdefinition"
        try:
            if REQUESTS_AVAILABLE:
                response = self.session.get(
                    url,
                    auth=HTTPBasicAuth(self.username, self.password),
                    headers=self.headers,
                    timeout=10,
                    proxies=self.proxies,
                    verify=self.verify_ssl
                )
                response.raise_for_status()
            else:
                self._urllib_request("GET", url)
            logger.info(f"Ping to {self.engine} successful")
            return True
        except Exception as e:
            logger.error(f"Ping failed: {e}")
            return False

def prompt_credentials():
    """Prompt for username and password, hiding password input."""
    print(f"{GREEN}AUTHENTICATION REQUIRED{RESET}")
    username = input(f"{GREEN}USER: {RESET}").strip()
    password = getpass(f"{GREEN}PASS: {RESET}")
    return username, password

def prompt_create_job(client, masters, chat_input=None):
    """Prompt for creating and scheduling a batch or SAP job."""
    print(f"\n{GREEN}INSTALL JOB AND SCHEDULE{RESET}")
    if not REQUESTS_AVAILABLE:
        print(f"{GREEN}WARNING: Using urllib fallback. Limited functionality.{RESET}")

    engine = input(f"{GREEN}TARGET ENGINE (e.g., BAP051): {RESET}").strip().upper()
    if not validate_engine(engine, masters):
        return

    job_details = {
        "job_type": "",
        "job_name": "",
        "workstation": "",
        "script": "",
        "sap_job_name": "",
        "sap_user": "",
        "sap_password": "",
        "user": "twsuser",
        "description": "Auto-generated job",
        "priority": "10",
        "recovery_action": "CONTINUE",
        "recovery_job": ""
    }
    schedule_details = None

    if chat_input:
        job_details, schedule_details = parse_chat_input(chat_input)
        if not job_details["job_name"]:
            while not job_details["job_name"]:
                job_name = input(f"{GREEN}JOB NAME (e.g., REPORT): {RESET}").strip().upper()
                if validate_job_name(job_name):
                    job_details["job_name"] = job_name
                else:
                    print(f"{GREEN}ERROR: Invalid job name. Must start with letter, alphanumeric/underscores, max 40 chars.{RESET}")
        if not job_details["workstation"]:
            while not job_details["workstation"]:
                ws = input(f"{GREEN}WORKSTATION (e.g., AGENT1) [AGENT1]: {RESET}").strip().upper() or "AGENT1"
                if validate_workstation(ws):
                    job_details["workstation"] = ws
                else:
                    print(f"{GREEN}ERROR: Invalid workstation. Alphanumeric, max 16 chars.{RESET}")
        if not job_details["job_type"]:
            while job_details["job_type"] not in ["batch", "sap"]:
                job_details["job_type"] = input(f"{GREEN}JOB TYPE (batch/sap): {RESET}").strip().lower()
                if job_details["job_type"] not in ["batch", "sap"]:
                    print(f"{GREEN}ERROR: Invalid job type. Choose 'batch' or 'sap'.{RESET}")
        if job_details["job_type"] == "batch" and not job_details["script"]:
            while not job_details["script"]:
                job_details["script"] = input(f"{GREEN}SCRIPT PATH (e.g., /scripts/report.sh): {RESET}").strip()
                if not job_details["script"]:
                    print(f"{GREEN}ERROR: Script path required for batch jobs.{RESET}")
        elif job_details["job_type"] == "sap":
            if not job_details["sap_job_name"]:
                while not job_details["sap_job_name"]:
                    job_details["sap_job_name"] = input(f"{GREEN}SAP JOB NAME (e.g., SAP_JOB): {RESET}").strip()
                    if not job_details["sap_job_name"]:
                        print(f"{GREEN}ERROR: SAP job name required.{RESET}")
            if not job_details["sap_user"]:
                while not job_details["sap_user"]:
                    job_details["sap_user"] = input(f"{GREEN}SAP USER (e.g., SAP_USER): {RESET}").strip()
                    if not job_details["sap_user"]:
                        print(f"{GREEN}ERROR: SAP user required.{RESET}")
            if not job_details["sap_password"]:
                job_details["sap_password"] = input(f"{GREEN}SAP PASSWORD [NONE]: {RESET}").strip() or "NONE"
        if not job_details["user"]:
            job_details["user"] = input(f"{GREEN}STREAMLOGON USER [twsuser]: {RESET}").strip() or "twsuser"
        if not job_details["priority"]:
            priority = input(f"{GREEN}PRIORITY (0-100) [10]: {RESET}").strip() or "10"
            if priority.isdigit() and 0 <= int(priority) <= 100:
                job_details["priority"] = priority
            else:
                print(f"{GREEN}ERROR: Invalid priority. Using default (10).{RESET}")
    else:
        while job_details["job_type"] not in ["batch", "sap"]:
            job_details["job_type"] = input(f"{GREEN}JOB TYPE (batch/sap): {RESET}").strip().lower()
            if job_details["job_type"] not in ["batch", "sap"]:
                print(f"{GREEN}ERROR: Invalid job type. Choose 'batch' or 'sap'.{RESET}")
        while not job_details["job_name"]:
            job_name = input(f"{GREEN}JOB NAME (e.g., REPORT): {RESET}").strip().upper()
            if validate_job_name(job_name):
                job_details["job_name"] = job_name
            else:
                print(f"{GREEN}ERROR: Invalid job name. Must start with letter, alphanumeric/underscores, max 40 chars.{RESET}")
        while not job_details["workstation"]:
            ws = input(f"{GREEN}WORKSTATION (e.g., AGENT1) [AGENT1]: {RESET}").strip().upper() or "AGENT1"
            if validate_workstation(ws):
                job_details["workstation"] = ws
            else:
                print(f"{GREEN}ERROR: Invalid workstation. Alphanumeric, max 16 chars.{RESET}")
        if job_details["job_type"] == "batch":
            while not job_details["script"]:
                job_details["script"] = input(f"{GREEN}SCRIPT PATH (e.g., /scripts/report.sh): {RESET}").strip()
                if not job_details["script"]:
                    print(f"{GREEN}ERROR: Script path required for batch jobs.{RESET}")
        else:  # SAP
            while not job_details["sap_job_name"]:
                job_details["sap_job_name"] = input(f"{GREEN}SAP JOB NAME (e.g., SAP_JOB): {RESET}").strip()
                if not job_details["sap_job_name"]:
                    print(f"{GREEN}ERROR: SAP job name required.{RESET}")
            while not job_details["sap_user"]:
                job_details["sap_user"] = input(f"{GREEN}SAP USER (e.g., SAP_USER): {RESET}").strip()
                if not job_details["sap_user"]:
                    print(f"{GREEN}ERROR: SAP user required.{RESET}")
            job_details["sap_password"] = input(f"{GREEN}SAP PASSWORD [NONE]: {RESET}").strip() or "NONE"
        job_details["user"] = input(f"{GREEN}STREAMLOGON USER [twsuser]: {RESET}").strip() or "twsuser"
        priority = input(f"{GREEN}PRIORITY (0-100) [10]: {RESET}").strip() or "10"
        if priority.isdigit() and 0 <= int(priority) <= 100:
            job_details["priority"] = priority
        else:
            print(f"{GREEN}ERROR: Invalid priority. Using default (10).{RESET}")
        recovery = input(f"{GREEN}RECOVERY ACTION (CONTINUE, RERUN, STOP) [CONTINUE]: {RESET}").strip().upper() or "CONTINUE"
        if recovery in ["CONTINUE", "RERUN", "STOP"]:
            job_details["recovery_action"] = recovery
        else:
            print(f"{GREEN}ERROR: Invalid recovery action. Using default (CONTINUE).{RESET}")
        if recovery == "RERUN":
            job_details["recovery_job"] = input(f"{GREEN}RECOVERY JOB NAME [NONE]: {RESET}").strip() or ""

    # Schedule details
    proceed = input(f"{GREEN}CREATE SCHEDULE? (y/n) [n]: {RESET}").strip().lower()
    if proceed == "y" and not schedule_details:
        schedule_details = {
            "schedule": f"{job_details['job_name']}_SCHED",
            "frequency": "",
            "time": "",
            "dependencies": []
        }
        while not schedule_details["frequency"]:
            freq = input(f"{GREEN}FREQUENCY (DAILY, WEEKLY, MONTHLY) [DAILY]: {RESET}").strip().upper() or "DAILY"
            if validate_frequency(freq):
                schedule_details["frequency"] = freq
            else:
                print(f"{GREEN}ERROR: Invalid frequency. Choose DAILY, WEEKLY, or MONTHLY.{RESET}")
        while not schedule_details["time"]:
            time = input(f"{GREEN}START TIME (HHMM, e.g., 0800): {RESET}").strip()
            if validate_time(time):
                schedule_details["time"] = time
            else:
                print(f"{GREEN}ERROR: Invalid time format. Use HHMM (e.g., 0800).{RESET}")
        dep = input(f"{GREEN}DEPENDENCIES (comma-separated job names, e.g., JOB1,JOB2) [NONE]: {RESET}").strip()
        if dep and dep != "NONE":
            schedule_details["dependencies"] = [d.strip().upper() for d in dep.split(",") if validate_job_name(d.strip())]

    # Generate Composer definition
    job_def = [
        f"JOB {job_details['job_name']}",
        f"WORKSTATION {job_details['workstation']}",
    ]
    if job_details["job_type"] == "batch":
        job_def.append(f"SCRIPTNAME \"{job_details['script']}\"")
        task_type = "unixJob"
    else:  # SAP
        sap_cmd = f"/ -job {job_details['sap_job_name']} -c 001 -i 00 -user {job_details['sap_user']} -passwd {job_details['sap_password']}"
        job_def.append(f"SCRIPTNAME \"{sap_cmd}\"")
        task_type = "sapR3Job"
    job_def.extend([
        f"STREAMLOGON {job_details['user']}",
        f"DESCRIPTION \"{job_details['description']}\"",
        f"PRIORITY {job_details['priority']}",
        f"RECOVERY {job_details['recovery_action']}",
    ])
    if job_details["recovery_job"]:
        job_def.append(f"RECOVERY JOB {job_details['recovery_job']}")

    schedule_def = []
    if schedule_details:
        schedule_def = [
            f"SCHEDULE {schedule_details['schedule']}",
            f"ON {schedule_details['frequency']}",
            f"AT {schedule_details['time']}",
        ]
        for dep in schedule_details["dependencies"]:
            schedule_def.append(f"FOLLOWS {dep}")
        schedule_def.extend([":", job_details["job_name"]])

    definition = "\n".join(job_def + [""] + schedule_def)
    print(f"\n{GREEN}=== GENERATED DEFINITION ==={RESET}")
    print(definition)
    confirm = input(f"{GREEN}CONFIRM DEFINITION? (y/n) [y]: {RESET}").strip().lower() or "y"
    if confirm != "y":
        print(f"{GREEN}Definition cancelled.{RESET}")
        return

    # Write to file
    output_file = f"{job_details['job_name'].lower()}_def.txt"
    with open(output_file, "w") as f:
        f.write(definition)

    # API: Create job definition
    job_definition_data = {
        "name": job_details["job_name"],
        "workstationName": job_details["workstation"],
        "taskString": job_details["script"] if job_details["job_type"] == "batch" else f"/ -job {job_details['sap_job_name']} -c 001 -i 00 -user {job_details['sap_user']} -passwd {job_details['sap_password']}",
        "taskType": task_type,
        "logon": job_details["user"],
        "description": job_details["description"],
        "priority": int(job_details["priority"]),
        "recoveryOption": {
            "action": job_details["recovery_action"],
            "jobName": job_details["recovery_job"] if job_details["recovery_job"] else None
        }
    }
    try:
        client.create_job_definition(job_definition_data)
        print(f"{GREEN}JOB {job_details['job_name']} INSTALLED{RESET}")
    except Exception as e:
        print(f"{GREEN}API ERROR: {e}{RESET}")
        print(f"{GREEN}FALLBACK: Use 'composer create job from {output_file}'{RESET}")
        return

    # API: Create job stream (schedule)
    if schedule_details:
        job_stream_data = {
            "name": schedule_details["schedule"],
            "timeRestrictions": {
                "start": {
                    "time": f"{schedule_details['time'][:2]}:{schedule_details['time'][2:]}:00"
                }
            },
            "runCycleGroups": [
                {
                    "runCycles": [
                        {
                            "rule": {
                                "type": "PERIODIC",
                                "interval": schedule_details["frequency"]
                            }
                        }
                    ]
                }
            ],
            "jobs": [
                {
                    "jobDefinitionName": job_details["job_name"],
                    "workstationName": job_details["workstation"],
                    "dependencies": [
                        {"jobDefinitionName": dep} for dep in schedule_details["dependencies"]
                    ]
                }
            ]
        }
        try:
            client.create_job_stream_definition(job_stream_data)
            print(f"{GREEN}SCHEDULE {schedule_details['schedule']} INSTALLED{RESET}")
            send_webhook_notification(f"Job {job_details['job_name']} and schedule {schedule_details['schedule']} created successfully.", "teams")
            send_webhook_notification(f"Job {job_details['job_name']} and schedule {schedule_details['schedule']} created successfully.", "email")
        except Exception as e:
            print(f"{GREEN}API ERROR (SCHEDULE): {e}{RESET}")
            print(f"{GREEN}FALLBACK: Use 'composer create schedule from {output_file}'{RESET}")

    print(f"{GREEN}DEFINITION SAVED TO: {output_file}{RESET}")

def prompt_submit_ad_hoc_job(client, masters):
    """Prompt for submitting an ad hoc job."""
    print(f"\n{GREEN}DEPLOY AD-HOC JOB{RESET}")
    if not REQUESTS_AVAILABLE:
        print(f"{GREEN}WARNING: Using urllib fallback. Limited functionality.{RESET}")
    engine = input(f"{GREEN}TARGET ENGINE (e.g., BAP051): {RESET}").strip().upper()
    if not validate_engine(engine, masters):
        return
    plan_id = input(f"{GREEN}PLAN ID [CURRENT]: {RESET}").strip() or "CURRENT"
    job_name = input(f"{GREEN}JOB NAME [BATCH_JOB]: {RESET}").strip() or "BATCH_JOB"
    job_type = input(f"{GREEN}JOB TYPE (batch/sap): {RESET}").strip().lower()
    if job_type not in ["batch", "sap"]:
        print(f"{GREEN}ERROR: Invalid job type. Choose 'batch' or 'sap'.{RESET}")
        return
    workstation = input(f"{GREEN}WORKSTATION [AGENT1]: {RESET}").strip().upper() or "AGENT1"
    if not validate_workstation(workstation):
        print(f"{GREEN}ERROR: Invalid workstation. Alphanumeric, max 16 chars.{RESET}")
        return
    if job_type == "batch":
        script = input(f"{GREEN}SCRIPT PATH (e.g., /scripts/report.sh): {RESET}").strip()
        if not script:
            print(f"{GREEN}ERROR: Script path required for batch jobs.{RESET}")
            return
        task_string = script
        task_type = "unixJob"
    else:  # SAP
        sap_job = input(f"{GREEN}SAP JOB NAME (e.g., SAP_JOB): {RESET}").strip()
        sap_user = input(f"{GREEN}SAP USER (e.g., SAP_USER): {RESET}").strip()
        sap_password = input(f"{GREEN}SAP PASSWORD [NONE]: {RESET}").strip() or "NONE"
        if not sap_job or not sap_user:
            print(f"{GREEN}ERROR: SAP job name and user required.{RESET}")
            return
        task_string = f"/ -job {sap_job} -c 001 -i 00 -user {sap_user} -passwd {sap_password}"
        task_type = "sapR3Job"
    logon = input(f"{GREEN}STREAMLOGON USER [twsuser]: {RESET}").strip() or "twsuser"

    job_data = {
        "task": {
            "type": task_type,
            "jobDefinition": {
                "name": job_name,
                "taskString": task_string,
                "workstationName": workstation
            },
            "logon": logon
        }
    }

    try:
        job_id = client.submit_ad_hoc_job(plan_id, job_data)
        print(f"{GREEN}JOB DEPLOYED: ID {job_id}{RESET}")
    except Exception as e:
        print(f"{GREEN}CRITICAL ERROR: {e}{RESET}")

def prompt_get_job_status(client, masters):
    """Prompt for retrieving job status."""
    print(f"\n{GREEN}PROBE JOB STATUS{RESET}")
    if not REQUESTS_AVAILABLE:
        print(f"{GREEN}WARNING: Using urllib fallback. Limited functionality.{RESET}")
    engine = input(f"{GREEN}TARGET ENGINE (e.g., BAP051): {RESET}").strip().upper()
    if not validate_engine(engine, masters):
        return
    plan_id = input(f"{GREEN}PLAN ID [CURRENT]: {RESET}").strip() or "CURRENT"
    job_id = input(f"{GREEN}JOB ID: {RESET}").strip()
    if not validate_required_input(job_id, "Job ID"):
        return
    try:
        status = client.get_job_status(plan_id, job_id)
        print(f"{GREEN}JOB {job_id} STATUS: {status}{RESET}")
    except Exception as e:
        print(f"{GREEN}CRITICAL ERROR: {e}{RESET}")

def prompt_hold_job(client, masters):
    """Prompt for holding a job."""
    print(f"\n{GREEN}LOCK JOB{RESET}")
    if not REQUESTS_AVAILABLE:
        print(f"{GREEN}WARNING: Using urllib fallback. Limited functionality.{RESET}")
    engine = input(f"{GREEN}TARGET ENGINE (e.g., BAP051): {RESET}").strip().upper()
    if not validate_engine(engine, masters):
        return
    plan_id = input(f"{GREEN}PLAN ID [CURRENT]: {RESET}").strip() or "CURRENT"
    job_id = input(f"{GREEN}JOB ID: {RESET}").strip()
    if not validate_required_input(job_id, "Job ID"):
        return
    try:
        client.hold_job(plan_id, job_id)
        print(f"{GREEN}JOB {job_id} LOCKED{RESET}")
    except Exception as e:
        print(f"{GREEN}CRITICAL ERROR: {e}{RESET}")

def prompt_release_job(client, masters):
    """Prompt for releasing a job."""
    print(f"\n{GREEN}UNLOCK JOB{RESET}")
    if not REQUESTS_AVAILABLE:
        print(f"{GREEN}WARNING: Using urllib fallback. Limited functionality.{RESET}")
    engine = input(f"{GREEN}TARGET ENGINE (e.g., BAP051): {RESET}").strip().upper()
    if not validate_engine(engine, masters):
        return
    plan_id = input(f"{GREEN}PLAN ID [CURRENT]: {RESET}").strip() or "CURRENT"
    job_id = input(f"{GREEN}JOB ID: {RESET}").strip()
    if not validate_required_input(job_id, "Job ID"):
        return
    try:
        client.release_job(plan_id, job_id)
        print(f"{GREEN}JOB {job_id} UNLOCKED{RESET}")
    except Exception as e:
        print(f"{GREEN}CRITICAL ERROR: {e}{RESET}")

def prompt_cancel_job(client, masters):
    """Prompt for canceling a job."""
    print(f"\n{GREEN}TERMINATE JOB{RESET}")
    if not REQUESTS_AVAILABLE:
        print(f"{GREEN}WARNING: Using urllib fallback. Limited functionality.{RESET}")
    engine = input(f"{GREEN}TARGET ENGINE (e.g., BAP051): {RESET}").strip().upper()
    if not validate_engine(engine, masters):
        return
    plan_id = input(f"{GREEN}PLAN ID [CURRENT]: {RESET}").strip() or "CURRENT"
    job_id = input(f"{GREEN}JOB ID: {RESET}").strip()
    if not validate_required_input(job_id, "Job ID"):
        return
    try:
        client.cancel_job(plan_id, job_id)
        print(f"{GREEN}JOB {job_id} TERMINATED{RESET}")
    except Exception as e:
        print(f"{GREEN}CRITICAL ERROR: {e}{RESET}")

def prompt_rerun_job(client, masters):
    """Prompt for rerunning a job."""
    print(f"\n{GREEN}REBOOT JOB{RESET}")
    if not REQUESTS_AVAILABLE:
        print(f"{GREEN}WARNING: Using urllib fallback. Limited functionality.{RESET}")
    engine = input(f"{GREEN}TARGET ENGINE (e.g., BAP051): {RESET}").strip().upper()
    if not validate_engine(engine, masters):
        return
    plan_id = input(f"{GREEN}PLAN ID [CURRENT]: {RESET}").strip() or "CURRENT"
    job_id = input(f"{GREEN}JOB ID: {RESET}").strip()
    if not validate_required_input(job_id, "Job ID"):
        return
    try:
        client.rerun_job(plan_id, job_id)
        print(f"{GREEN}JOB {job_id} REBOOTED{RESET}")
    except Exception as e:
        print(f"{GREEN}CRITICAL ERROR: {e}{RESET}")

def prompt_get_job_definition(client, masters):
    """Prompt for retrieving a job definition."""
    print(f"\n{GREEN}EXTRACT JOB DEFINITION{RESET}")
    if not REQUESTS_AVAILABLE:
        print(f"{GREEN}WARNING: Using urllib fallback. Limited functionality.{RESET}")
    engine = input(f"{GREEN}TARGET ENGINE (e.g., BAP051): {RESET}").strip().upper()
    if not validate_engine(engine, masters):
        return
    job_definition_name = input(f"{GREEN}DEFINITION NAME: {RESET}").strip()
    if not validate_required_input(job_definition_name, "Definition name"):
        return
    try:
        definition = client.get_job_definition(job_definition_name)
        print(f"{GREEN}DEFINITION: {json.dumps(definition, indent=2)}{RESET}")
    except Exception as e:
        print(f"{GREEN}CRITICAL ERROR: {e}{RESET}")

def prompt_create_workstation(client, masters):
    """Prompt for creating a workstation."""
    print(f"\n{GREEN}INSTALL WORKSTATION{RESET}")
    if not REQUESTS_AVAILABLE:
        print(f"{GREEN}WARNING: Using urllib fallback. Limited functionality.{RESET}")
    engine = input(f"{GREEN}TARGET ENGINE (e.g., BAP051): {RESET}").strip().upper()
    if not validate_engine(engine, masters):
        return
    workstation_name = input(f"{GREEN}WORKSTATION NAME: {RESET}").strip().upper()
    if not validate_workstation(workstation_name):
        print(f"{GREEN}ERROR: Invalid workstation name. Alphanumeric, max 16 chars.{RESET}")
        return
    workstation_type = input(f"{GREEN}TYPE [AGENT]: {RESET}").strip() or "AGENT"
    workstation_data = {
        "name": workstation_name,
        "type": workstation_type
    }
    try:
        client.create_workstation(workstation_data)
        print(f"{GREEN}WORKSTATION {workstation_name} INSTALLED{RESET}")
    except Exception as e:
        print(f"{GREEN}CRITICAL ERROR: {e}{RESET}")

def prompt_get_workstation(client, masters):
    """Prompt for retrieving a workstation."""
    print(f"\n{GREEN}EXTRACT WORKSTATION{RESET}")
    if not REQUESTS_AVAILABLE:
        print(f"{GREEN}WARNING: Using urllib fallback. Limited functionality.{RESET}")
    engine = input(f"{GREEN}TARGET ENGINE (e.g., BAP051): {RESET}").strip().upper()
    if not validate_engine(engine, masters):
        return
    workstation_name = input(f"{GREEN}WORKSTATION NAME: {RESET}").strip().upper()
    if not validate_required_input(workstation_name, "Workstation name"):
        return
    try:
        workstation = client.get_workstation(workstation_name)
        print(f"{GREEN}WORKSTATION: {json.dumps(workstation, indent=2)}{RESET}")
    except Exception as e:
        print(f"{GREEN}CRITICAL ERROR: {e}{RESET}")

def prompt_update_workstation(client, masters):
    """Prompt for updating a workstation."""
    print(f"\n{GREEN}UPDATE WORKSTATION{RESET}")
    if not REQUESTS_AVAILABLE:
        print(f"{GREEN}WARNING: Using urllib fallback. Limited functionality.{RESET}")
    engine = input(f"{GREEN}TARGET ENGINE (e.g., BAP051): {RESET}").strip().upper()
    if not validate_engine(engine, masters):
        return
    workstation_name = input(f"{GREEN}WORKSTATION NAME: {RESET}").strip().upper()
    if not validate_required_input(workstation_name, "Workstation name"):
        return
    workstation_type = input(f"{GREEN}TYPE [AGENT]: {RESET}").strip() or "AGENT"
    workstation_data = {
        "name": workstation_name,
        "type": workstation_type
    }
    try:
        client.update_workstation(workstation_name, workstation_data)
        print(f"{GREEN}WORKSTATION {workstation_name} UPDATED{RESET}")
    except Exception as e:
        print(f"{GREEN}CRITICAL ERROR: {e}{RESET}")

def prompt_delete_workstation(client, masters):
    """Prompt for deleting a workstation."""
    print(f"\n{GREEN}REMOVE WORKSTATION{RESET}")
    if not REQUESTS_AVAILABLE:
        print(f"{GREEN}WARNING: Using urllib fallback. Limited functionality.{RESET}")
    engine = input(f"{GREEN}TARGET ENGINE (e.g., BAP051): {RESET}").strip().upper()
    if not validate_engine(engine, masters):
        return
    workstation_name = input(f"{GREEN}WORKSTATION NAME: {RESET}").strip().upper()
    if not validate_required_input(workstation_name, "Workstation name"):
        return
    try:
        client.delete_workstation(workstation_name)
        print(f"{GREEN}WORKSTATION {workstation_name} REMOVED{RESET}")
    except Exception as e:
        print(f"{GREEN}CRITICAL ERROR: {e}{RESET}")

def prompt_create_calendar(client, masters):
    """Prompt for creating a calendar."""
    print(f"\n{GREEN}INSTALL CALENDAR{RESET}")
    if not REQUESTS_AVAILABLE:
        print(f"{GREEN}WARNING: Using urllib fallback. Limited functionality.{RESET}")
    engine = input(f"{GREEN}TARGET ENGINE (e.g., BAP051): {RESET}").strip().upper()
    if not validate_engine(engine, masters):
        return
    calendar_name = input(f"{GREEN}CALENDAR NAME: {RESET}").strip()
    dates = input(f"{GREEN}DATES (comma-separated, e.g., 2025-05-06): {RESET}").strip()
    if not validate_required_input(calendar_name, "Calendar name"):
        return
    calendar_data = {
        "name": calendar_name,
        "dates": dates.split(",") if dates else []
    }
    try:
        client.create_calendar(calendar_data)
        print(f"{GREEN}CALENDAR {calendar_name} INSTALLED{RESET}")
    except Exception as e:
        print(f"{GREEN}CRITICAL ERROR: {e}{RESET}")

def prompt_get_calendar(client, masters):
    """Prompt for retrieving a calendar."""
    print(f"\n{GREEN}EXTRACT CALENDAR{RESET}")
    if not REQUESTS_AVAILABLE:
        print(f"{GREEN}WARNING: Using urllib fallback. Limited functionality.{RESET}")
    engine = input(f"{GREEN}TARGET ENGINE (e.g., BAP051): {RESET}").strip().upper()
    if not validate_engine(engine, masters):
        return
    calendar_name = input(f"{GREEN}CALENDAR NAME: {RESET}").strip()
    if not validate_required_input(calendar_name, "Calendar name"):
        return
    try:
        calendar = client.get_calendar(calendar_name)
        print(f"{GREEN}CALENDAR: {json.dumps(calendar, indent=2)}{RESET}")
    except Exception as e:
        print(f"{GREEN}CRITICAL ERROR: {e}{RESET}")

def prompt_update_calendar(client, masters):
    """Prompt for updating a calendar."""
    print(f"\n{GREEN}UPDATE CALENDAR{RESET}")
    if not REQUESTS_AVAILABLE:
        print(f"{GREEN}WARNING: Using urllib fallback. Limited functionality.{RESET}")
    engine = input(f"{GREEN}TARGET ENGINE (e.g., BAP051): {RESET}").strip().upper()
    if not validate_engine(engine, masters):
        return
    calendar_name = input(f"{GREEN}CALENDAR NAME: {RESET}").strip()
    dates = input(f"{GREEN}DATES (comma-separated, e.g., 2025-05-06): {RESET}").strip()
    if not validate_required_input(calendar_name, "Calendar name"):
        return
    calendar_data = {
        "name": calendar_name,
        "dates": dates.split(",") if dates else []
    }
    try:
        client.update_calendar(calendar_name, calendar_data)
        print(f"{GREEN}CALENDAR {calendar_name} UPDATED{RESET}")
    except Exception as e:
        print(f"{GREEN}CRITICAL ERROR: {e}{RESET}")

def prompt_delete_calendar(client, masters):
    """Prompt for deleting a calendar."""
    print(f"\n{GREEN}REMOVE CALENDAR{RESET}")
    if not REQUESTS_AVAILABLE:
        print(f"{GREEN}WARNING: Using urllib fallback. Limited functionality.{RESET}")
    engine = input(f"{GREEN}TARGET ENGINE (e.g., BAP051): {RESET}").strip().upper()
    if not validate_engine(engine, masters):
        return
    calendar_name = input(f"{GREEN}CALENDAR NAME: {RESET}").strip()
    if not validate_required_input(calendar_name, "Calendar name"):
        return
    try:
        client.delete_calendar(calendar_name)
        print(f"{GREEN}CALENDAR {calendar_name} REMOVED{RESET}")
    except Exception as e:
        print(f"{GREEN}CRITICAL ERROR: {e}{RESET}")

def prompt_submit_job_stream(client, masters):
    """Prompt for submitting a job stream."""
    print(f"\n{GREEN}DEPLOY JOB STREAM{RESET}")
    if not REQUESTS_AVAILABLE:
        print(f"{GREEN}WARNING: Using urllib fallback. Limited functionality.{RESET}")
    engine = input(f"{GREEN}TARGET ENGINE (e.g., BAP051): {RESET}").strip().upper()
    if not validate_engine(engine, masters):
        return
    plan_id = input(f"{GREEN}PLAN ID [CURRENT]: {RESET}").strip() or "CURRENT"
    job_stream_name = input(f"{GREEN}JOB STREAM NAME: {RESET}").strip()
    if not validate_required_input(job_stream_name, "Job stream name"):
        return
    start_time = input(f"{GREEN}START TIME (HHMM, e.g., 0800): {RESET}").strip()
    if not validate_time(start_time):
        print(f"{GREEN}ERROR: Invalid time format. Use HHMM (e.g., 0800).{RESET}")
        return
    frequency = input(f"{GREEN}FREQUENCY (DAILY, WEEKLY, MONTHLY) [DAILY]: {RESET}").strip().upper() or "DAILY"
    if not validate_frequency(frequency):
        print(f"{GREEN}ERROR: Invalid frequency. Choose DAILY, WEEKLY, or MONTHLY.{RESET}")
        return
    job_names = input(f"{GREEN}JOB NAMES (comma-separated, e.g., JOB1,JOB2): {RESET}").strip()
    if not job_names:
        print(f"{GREEN}ERROR: At least one job name required.{RESET}")
        return
    jobs = []
    for job_name in job_names.split(","):
        job_name = job_name.strip().upper()
        if not validate_job_name(job_name):
            print(f"{GREEN}ERROR: Invalid job name {job_name}. Must start with letter, alphanumeric/underscores, max 40 chars.{RESET}")
            return
        workstation = input(f"{GREEN}WORKSTATION FOR {job_name} [AGENT1]: {RESET}").strip().upper() or "AGENT1"
        if not validate_workstation(workstation):
            print(f"{GREEN}ERROR: Invalid workstation for {job_name}. Alphanumeric, max 16 chars.{RESET}")
            return
        dependencies = input(f"{GREEN}DEPENDENCIES FOR {job_name} (comma-separated job names, e.g., JOB1,JOB2) [NONE]: {RESET}").strip()
        job_deps = [dep.strip().upper() for dep in dependencies.split(",") if dep.strip() and validate_job_name(dep.strip())] if dependencies and dependencies != "NONE" else []
        jobs.append({
            "jobDefinitionName": job_name,
            "workstationName": workstation,
            "dependencies": [{"jobDefinitionName": dep} for dep in job_deps]
        })

    job_stream_data = {
        "jobStream": {
            "name": job_stream_name,
            "timeRestrictions": {
                "start": {
                    "time": f"{start_time[:2]}:{start_time[2:]}:00"
                }
            },
            "runCycleGroups": [
                {
                    "runCycles": [
                        {
                            "rule": {
                                "type": "PERIODIC",
                                "interval": frequency
                            }
                        }
                    ]
                }
            ],
            "jobs": jobs
        }
    }

    try:
        job_stream_id = client.submit_job_stream(plan_id, job_stream_data)
        print(f"{GREEN}JOB STREAM DEPLOYED: ID {job_stream_id}{RESET}")
        send_webhook_notification(f"Job stream {job_stream_name} deployed successfully.", "teams")
        send_webhook_notification(f"Job stream {job_stream_name} deployed successfully.", "email")
    except Exception as e:
        print(f"{GREEN}CRITICAL ERROR: {e}{RESET}")

def prompt_get_job_stream_status(client, masters):
    """Prompt for retrieving job stream status."""
    print(f"\n{GREEN}PROBE JOB STREAM STATUS{RESET}")
    if not REQUESTS_AVAILABLE:
        print(f"{GREEN}WARNING: Using urllib fallback. Limited functionality.{RESET}")
    engine = input(f"{GREEN}TARGET ENGINE (e.g., BAP051): {RESET}").strip().upper()
    if not validate_engine(engine, masters):
        return
    plan_id = input(f"{GREEN}PLAN ID [CURRENT]: {RESET}").strip() or "CURRENT"
    job_stream_id = input(f"{GREEN}JOB STREAM ID: {RESET}").strip()
    if not validate_required_input(job_stream_id, "Job stream ID"):
        return
    try:
        status = client.get_job_stream_status(plan_id, job_stream_id)
        print(f"{GREEN}JOB STREAM {job_stream_id} STATUS: {status}{RESET}")
    except Exception as e:
        print(f"{GREEN}CRITICAL ERROR: {e}{RESET}")

def prompt_create_job_stream_definition(client, masters):
    """Prompt for creating a job stream definition."""
    print(f"\n{GREEN}INSTALL JOB STREAM DEFINITION{RESET}")
    if not REQUESTS_AVAILABLE:
        print(f"{GREEN}WARNING: Using urllib fallback. Limited functionality.{RESET}")
    engine = input(f"{GREEN}TARGET ENGINE (e.g., BAP051): {RESET}").strip().upper()
    if not validate_engine(engine, masters):
        return
    job_stream_name = input(f"{GREEN}JOB STREAM NAME: {RESET}").strip()
    if not validate_required_input(job_stream_name, "Job stream name"):
        return
    start_time = input(f"{GREEN}START TIME (HHMM, e.g., 0800): {RESET}").strip()
    if not validate_time(start_time):
        print(f"{GREEN}ERROR: Invalid time format. Use HHMM (e.g., 0800).{RESET}")
        return
    frequency = input(f"{GREEN}FREQUENCY (DAILY, WEEKLY, MONTHLY) [DAILY]: {RESET}").strip().upper() or "DAILY"
    if not validate_frequency(frequency):
        print(f"{GREEN}ERROR: Invalid frequency. Choose DAILY, WEEKLY, or MONTHLY.{RESET}")
        return
    job_names = input(f"{GREEN}JOB NAMES (comma-separated, e.g., JOB1,JOB2): {RESET}").strip()
    if not job_names:
        print(f"{GREEN}ERROR: At least one job name required.{RESET}")
        return
    jobs = []
    for job_name in job_names.split(","):
        job_name = job_name.strip().upper()
        if not validate_job_name(job_name):
            print(f"{GREEN}ERROR: Invalid job name {job_name}. Must start with letter, alphanumeric/underscores, max 40 chars.{RESET}")
            return
        workstation = input(f"{GREEN}WORKSTATION FOR {job_name} [AGENT1]: {RESET}").strip().upper() or "AGENT1"
        if not validate_workstation(workstation):
            print(f"{GREEN}ERROR: Invalid workstation for {job_name}. Alphanumeric, max 16 chars.{RESET}")
            return
        dependencies = input(f"{GREEN}DEPENDENCIES FOR {job_name} (comma-separated job names, e.g., JOB1,JOB2) [NONE]: {RESET}").strip()
        job_deps = [dep.strip().upper() for dep in dependencies.split(",") if dep.strip() and validate_job_name(dep.strip())] if dependencies and dependencies != "NONE" else []
        jobs.append({
            "jobDefinitionName": job_name,
            "workstationName": workstation,
            "dependencies": [{"jobDefinitionName": dep} for dep in job_deps]
        })

    job_stream_data = {
        "name": job_stream_name,
        "timeRestrictions": {
            "start": {
                "time": f"{start_time[:2]}:{start_time[2:]}:00"
            }
        },
        "runCycleGroups": [
            {
                "runCycles": [
                    {
                        "rule": {
                            "type": "PERIODIC",
                            "interval": frequency
                        }
                    }
                ]
            }
        ],
        "jobs": jobs
    }

    try:
        client.create_job_stream_definition(job_stream_data)
        print(f"{GREEN}JOB STREAM {job_stream_name} INSTALLED{RESET}")
        send_webhook_notification(f"Job stream definition {job_stream_name} created successfully.", "teams")
        send_webhook_notification(f"Job stream definition {job_stream_name} created successfully.", "email")
    except Exception as e:
        print(f"{GREEN}CRITICAL ERROR: {e}{RESET}")

def prompt_get_job_stream_definition(client, masters):
    """Prompt for retrieving a job stream definition."""
    print(f"\n{GREEN}EXTRACT JOB STREAM DEFINITION{RESET}")
    if not REQUESTS_AVAILABLE:
        print(f"{GREEN}WARNING: Using urllib fallback. Limited functionality.{RESET}")
    engine = input(f"{GREEN}TARGET ENGINE (e.g., BAP051): {RESET}").strip().upper()
    if not validate_engine(engine, masters):
        return
    job_stream_name = input(f"{GREEN}JOB STREAM NAME: {RESET}").strip()
    if not validate_required_input(job_stream_name, "Job stream name"):
        return
    try:
        definition = client.get_job_stream_definition(job_stream_name)
        print(f"{GREEN}JOB STREAM DEFINITION: {json.dumps(definition, indent=2)}{RESET}")
    except Exception as e:
        print(f"{GREEN}CRITICAL ERROR: {e}{RESET}")

def prompt_create_resource(client, masters):
    """Prompt for creating a resource."""
    print(f"\n{GREEN}INSTALL RESOURCE{RESET}")
    if not REQUESTS_AVAILABLE:
        print(f"{GREEN}WARNING: Using urllib fallback. Limited functionality.{RESET}")
    engine = input(f"{GREEN}TARGET ENGINE (e.g., BAP051): {RESET}").strip().upper()
    if not validate_engine(engine, masters):
        return
    resource_name = input(f"{GREEN}RESOURCE NAME: {RESET}").strip()
    if not validate_required_input(resource_name, "Resource name"):
        return
    quantity = input(f"{GREEN}QUANTITY [1]: {RESET}").strip() or "1"
    if not quantity.isdigit() or int(quantity) < 1:
        print(f"{GREEN}ERROR: Quantity must be a positive integer.{RESET}")
        return
    resource_data = {
        "name": resource_name,
        "quantity": int(quantity)
    }
    try:
        client.create_resource(resource_data)
        print(f"{GREEN}RESOURCE {resource_name} INSTALLED{RESET}")
    except Exception as e:
        print(f"{GREEN}CRITICAL ERROR: {e}{RESET}")

def prompt_get_resource(client, masters):
    """Prompt for retrieving a resource."""
    print(f"\n{GREEN}EXTRACT RESOURCE{RESET}")
    if not REQUESTS_AVAILABLE:
        print(f"{GREEN}WARNING: Using urllib fallback. Limited functionality.{RESET}")
    engine = input(f"{GREEN}TARGET ENGINE (e.g., BAP051): {RESET}").strip().upper()
    if not validate_engine(engine, masters):
        return
    resource_name = input(f"{GREEN}RESOURCE NAME: {RESET}").strip()
    if not validate_required_input(resource_name, "Resource name"):
        return
    try:
        resource = client.get_resource(resource_name)
        print(f"{GREEN}RESOURCE: {json.dumps(resource, indent=2)}{RESET}")
    except Exception as e:
        print(f"{GREEN}CRITICAL ERROR: {e}{RESET}")

def prompt_create_prompt(client, masters):
    """Prompt for creating a prompt."""
    print(f"\n{GREEN}INSTALL PROMPT{RESET}")
    if not REQUESTS_AVAILABLE:
        print(f"{GREEN}WARNING: Using urllib fallback. Limited functionality.{RESET}")
    engine = input(f"{GREEN}TARGET ENGINE (e.g., BAP051): {RESET}").strip().upper()
    if not validate_engine(engine, masters):
        return
    prompt_name = input(f"{GREEN}PROMPT NAME: {RESET}").strip()
    if not validate_prompt_name(prompt_name):
        print(f"{GREEN}ERROR: Invalid prompt name. Alphanumeric, max 40 chars.{RESET}")
        return
    message = input(f"{GREEN}PROMPT MESSAGE: {RESET}").strip()
    if not validate_required_input(message, "Prompt message"):
        return
    prompt_data = {
        "name": prompt_name,
        "message": message
    }
    try:
        client.create_prompt(prompt_data)
        print(f"{GREEN}PROMPT {prompt_name} INSTALLED{RESET}")
    except Exception as e:
        print(f"{GREEN}CRITICAL ERROR: {e}{RESET}")

def prompt_get_prompt(client, masters):
    """Prompt for retrieving a prompt."""
    print(f"\n{GREEN}EXTRACT PROMPT{RESET}")
    if not REQUESTS_AVAILABLE:
        print(f"{GREEN}WARNING: Using urllib fallback. Limited functionality.{RESET}")
    engine = input(f"{GREEN}TARGET ENGINE (e.g., BAP051): {RESET}").strip().upper()
    if not validate_engine(engine, masters):
        return
    prompt_name = input(f"{GREEN}PROMPT NAME: {RESET}").strip()
    if not validate_prompt_name(prompt_name):
        print(f"{GREEN}ERROR: Invalid prompt name. Alphanumeric, max 40 chars.{RESET}")
        return
    try:
        prompt = client.get_prompt(prompt_name)
        print(f"{GREEN}PROMPT: {json.dumps(prompt, indent=2)}{RESET}")
    except Exception as e:
        print(f"{GREEN}CRITICAL ERROR: {e}{RESET}")

def prompt_test_connectivity(client, masters):
    """Prompt for testing connectivity to the engine."""
    print(f"\n{GREEN}TEST CONNECTIVITY{RESET}")
    if not REQUESTS_AVAILABLE:
        print(f"{GREEN}WARNING: Using urllib fallback. Limited functionality.{RESET}")
    engine = input(f"{GREEN}TARGET ENGINE (e.g., BAP051): {RESET}").strip().upper()
    if not validate_engine(engine, masters):
        return
    try:
        result = client.test_connectivity()
        if result:
            print(f"{GREEN}CONNECTION TO {engine} SUCCESSFUL{RESET}")
        else:
            print(f"{GREEN}CONNECTION TO {engine} FAILED{RESET}")
    except Exception as e:
        print(f"{GREEN}CRITICAL ERROR: {e}{RESET}")

def prompt_get_engine_status(client, masters):
    """Prompt for retrieving engine status."""
    print(f"\n{GREEN}PROBE ENGINE STATUS{RESET}")
    if not REQUESTS_AVAILABLE:
        print(f"{GREEN}WARNING: Using urllib fallback. Limited functionality.{RESET}")
    engine = input(f"{GREEN}TARGET ENGINE (e.g., BAP051，如果您没有提供引擎名称，将返回): {RESET}").strip().upper()
    if not validate_engine(engine, masters):
        return
    try:
        status = client.get_engine_status()
        print(f"{GREEN}ENGINE {engine} STATUS: {json.dumps(status, indent=2)}{RESET}")
    except Exception as e:
        print(f"{GREEN}CRITICAL ERROR: {e}{RESET}")

def main():
    """Main function to run the TWS API client."""
    print(generate_ascii_art())
    print(f"{GREEN}TWS API CLIENT INITIALIZED{RESET}")

    # Load master engines (simulated)
    masters = ["BAP051", "BAP052", "PROD01"]  # Replace with actual master list from config

    # Prompt for API base URL
    base_url = input(f"{GREEN}API BASE URL (e.g., https://tws.abhii.com:9443/twsd): {RESET}").strip()
    if not base_url:
        print(f"{GREEN}ERROR: API base URL required.{RESET}")
        return

    # Prompt for credentials
    username, password = prompt_credentials()
    if not validate_required_input(username, "Username") or not validate_required_input(password, "Password"):
        return

    # Prompt for proxy settings
    proxies = prompt_proxy_settings()

    # Prompt for SSL verification
    verify_ssl = prompt_ssl_verification()

    # Initialize TWS API client
    try:
        client = TWSApiClient(base_url, username, password, "", proxies=proxies, verify_ssl=verify_ssl)
    except Exception as e:
        print(f"{GREEN}CRITICAL ERROR: Failed to initialize client - {e}{RESET}")
        return

    # Test connectivity
    print(f"\n{GREEN}TESTING CONNECTION...{RESET}")
    if not client.test_connectivity():
        print(f"{GREEN}CRITICAL ERROR: Connection test failed. Check URL, credentials, or network.{RESET}")
        return

    while True:
        print(f"\n{GREEN}=== TWS API CLIENT MENU ==={RESET}")
        print("1. Create Job and Schedule")
        print("2. Submit Ad-Hoc Job")
        print("3. Get Job Status")
        print("4. Hold Job")
        print("5. Release Job")
        print("6. Cancel Job")
        print("7. Rerun Job")
        print("8. Get Job Definition")
        print("9. Create Workstation")
        print("10. Get Workstation")
        print("11. Update Workstation")
        print("12. Delete Workstation")
        print("13. Create Calendar")
        print("14. Get Calendar")
        print("15. Update Calendar")
        print("16. Delete Calendar")
        print("17. Submit Job Stream")
        print("18. Get Job Stream Status")
        print("19. Create Job Stream Definition")
        print("20. Get Job Stream Definition")
        print("21. Create Resource")
        print("22. Get Resource")
        print("23. Create Prompt")
        print("24. Get Prompt")
        print("25. Test Connectivity")
        print("26. Get Engine Status")
        print("27. Exit")
        choice = input(f"{GREEN}SELECT OPTION (1-27): {RESET}").strip()

        if choice == "1":
            chat_input = input(f"{GREEN}ENTER CHAT INPUT (or press Enter for manual): {RESET}").strip()
            prompt_create_job(client, masters, chat_input if chat_input else None)
        elif choice == "2":
            prompt_submit_ad_hoc_job(client, masters)
        elif choice == "3":
            prompt_get_job_status(client, masters)
        elif choice == "4":
            prompt_hold_job(client, masters)
        elif choice == "5":
            prompt_release_job(client, masters)
        elif choice == "6":
            prompt_cancel_job(client, masters)
        elif choice == "7":
            prompt_rerun_job(client, masters)
        elif choice == "8":
            prompt_get_job_definition(client, masters)
        elif choice == "9":
            prompt_create_workstation(client, masters)
        elif choice == "10":
            prompt_get_workstation(client, masters)
        elif choice == "11":
            prompt_update_workstation(client, masters)
        elif choice == "12":
            prompt_delete_workstation(client, masters)
        elif choice == "13":
            prompt_create_calendar(client, masters)
        elif choice == "14":
            prompt_get_calendar(client, masters)
        elif choice == "15":
            prompt_update_calendar(client, masters)
        elif choice == "16":
            prompt_delete_calendar(client, masters)
        elif choice == "17":
            prompt_submit_job_stream(client, masters)
        elif choice == "18":
            prompt_get_job_stream_status(client, masters)
        elif choice == "19":
            prompt_create_job_stream_definition(client, masters)
        elif choice == "20":
            prompt_get_job_stream_definition(client, masters)
        elif choice == "21":
            prompt_create_resource(client, masters)
        elif choice == "22":
            prompt_get_resource(client, masters)
        elif choice == "23":
            prompt_create_prompt(client, masters)
        elif choice == "24":
            prompt_get_prompt(client, masters)
        elif choice == "25":
            prompt_test_connectivity(client, masters)
        elif choice == "26":
            prompt_get_engine_status(client, masters)
        elif choice == "27":
            print(f"{GREEN}SHUTTING DOWN...{RESET}")
            break
        else:
            print(f"{GREEN}ERROR: Invalid option. Choose 1-27.{RESET}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{GREEN}USER INTERRUPT: Shutting down...{RESET}")
    except Exception as e:
        print(f"{GREEN}FATAL ERROR: {e}{RESET}")
        sys.exit(1)