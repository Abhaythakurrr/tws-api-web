import logging
import sys
from getpass import getpass
import os
import json
try:
    import requests
    from requests.auth import HTTPBasicAuth
    from urllib3.util.retry import Retry
    from requests.adapters import HTTPAdapter
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    import urllib.request
    import urllib.error
    import urllib.parse
    import base64

# ANSI color codes for hacker vibe
GREEN = "\033[32m"
RESET = "\033[0m"

# Setup console logging with hacker style
logging.basicConfig(
    level=logging.INFO,
    format=f'{GREEN}%(asctime)s - %(levelname)s - %(message)s{RESET}',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Static ASCII art
STATIC_ASCII_ART = f"""
{GREEN}
   _____ _          _ _       
  / ____| |        (_) |      
 | |    | |__   __ _ _| |__   
 | |    | '_ \ / _` | | '_ \  
 | |____| | | | (_| | | |_) | 
  \_____|_| |_|__,_|_|_.__/  
   A B H I I - TWS API CLIENT
{RESET}
"""

def generate_ascii_art():
    """Return static ASCII art."""
    return STATIC_ASCII_ART

def configure_session():
    """Configure a requests session with retries and timeout if requests is available."""
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

def prompt_proxy_settings():
    """Prompt for proxy settings or use environment variables."""
    use_proxy = input(f"{GREEN}USE PROXY? (y/n) [n]: {RESET}").strip().lower() == 'y'
    if use_proxy:
        proxy_url = input(f"{GREEN}PROXY URL (e.g., http://proxy.company.com:8080): {RESET}").strip()
        if proxy_url:
            return {'http': proxy_url, 'https': proxy_url}
    return os.environ.get('HTTPS_PROXY', {})

def prompt_ssl_verification():
    """Prompt for SSL verification preference."""
    disable_ssl = input(f"{GREEN}DISABLE SSL VERIFICATION? (y/n) [n]: {RESET}").strip().lower() == 'y'
    return not disable_ssl

class TWSApiClient:
    def __init__(self, base_url, username, password, engine, proxies=None, verify_ssl=True):
        """Initialize the TWS API client with base URL, credentials, and engine."""
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
                return json.loads(response.read().decode())
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

def prompt_submit_ad_hoc_job(client, masters):
    """Prompt for submitting an ad hoc job."""
    print(f"\n{GREEN}DEPLOY JOB{RESET}")
    if not REQUESTS_AVAILABLE:
        print(f"{GREEN}WARNING: Using urllib fallback. Limited functionality.{RESET}")
    engine = input(f"{GREEN}TARGET ENGINE (e.g., BAP051): {RESET}").strip().upper()
    if not validate_engine(engine, masters):
        return
    plan_id = input(f"{GREEN}PLAN ID [CURRENT]: {RESET}").strip() or "CURRENT"
    job_name = input(f"{GREEN}JOB NAME [BATCH_JOB]: {RESET}").strip() or "BATCH_JOB"
    task_string = input(f"{GREEN}INJECT JCL [EXEC PGM=MYPROG]: {RESET}").strip() or "EXEC PGM=MYPROG"
    user_login = input(f"{GREEN}OPERATOR [USER1]: {RESET}").strip() or "USER1"

    job_data = {
        "task": {
            "type": "zOSJob",
            "jobDefinition": {
                "name": job_name,
                "taskString": task_string
            },
            "userLogin": user_login
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

def prompt_create_job_definition(client, masters):
    """Prompt for creating a job definition."""
    print(f"\n{GREEN}INSTALL JOB DEFINITION{RESET}")
    if not REQUESTS_AVAILABLE:
        print(f"{GREEN}WARNING: Using urllib fallback. Limited functionality.{RESET}")
    engine = input(f"{GREEN}TARGET ENGINE (e.g., BAP051): {RESET}").strip().upper()
    if not validate_engine(engine, masters):
        return
    job_definition_name = input(f"{GREEN}DEFINITION NAME: {RESET}").strip()
    task_string = input(f"{GREEN}INJECT JCL [EXEC PGM=MYPROG]: {RESET}").strip() or "EXEC PGM=MYPROG"
    if not validate_required_input(job_definition_name, "Definition name"):
        return

    job_definition_data = {
        "name": job_definition_name,
        "taskString": task_string,
        "taskType": "EXEC"
    }

    try:
        client.create_job_definition(job_definition_data)
        print(f"{GREEN}DEFINITION {job_definition_name} INSTALLED{RESET}")
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
    workstation_name = input(f"{GREEN}WORKSTATION NAME: {RESET}").strip()
    workstation_type = input(f"{GREEN}TYPE [AGENT]: {RESET}").strip() or "AGENT"
    if not validate_required_input(workstation_name, "Workstation name"):
        return

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
    workstation_name = input(f"{GREEN}WORKSTATION NAME: {RESET}").strip()
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
    workstation_name = input(f"{GREEN}WORKSTATION NAME: {RESET}").strip()
    workstation_type = input(f"{GREEN}TYPE [AGENT]: {RESET}").strip() or "AGENT"
    if not validate_required_input(workstation_name, "Workstation name"):
        return

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
    workstation_name = input(f"{GREEN}WORKSTATION NAME: {RESET}").strip()
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
    job_stream_name = input(f"{GREEN}STREAM NAME: {RESET}").strip()
    if not validate_required_input(job_stream_name, "Stream name"):
        return

    job_stream_data = {
        "jobStream": {
            "name": job_stream_name,
            "jobs": [
                {
                    "jobDefinitionName": "BATCH_JOB"
                }
            ]
        }
    }

    try:
        job_stream_id = client.submit_job_stream(plan_id, job_stream_data)
        print(f"{GREEN}STREAM DEPLOYED: ID {job_stream_id}{RESET}")
    except Exception as e:
        print(f"{GREEN}CRITICAL ERROR: {e}{RESET}")

def prompt_get_job_stream_status(client, masters):
    """Prompt for retrieving job stream status."""
    print(f"\n{GREEN}PROBE STREAM STATUS{RESET}")
    if not REQUESTS_AVAILABLE:
        print(f"{GREEN}WARNING: Using urllib fallback. Limited functionality.{RESET}")
    engine = input(f"{GREEN}TARGET ENGINE (e.g., BAP051): {RESET}").strip().upper()
    if not validate_engine(engine, masters):
        return
    plan_id = input(f"{GREEN}PLAN ID [CURRENT]: {RESET}").strip() or "CURRENT"
    job_stream_id = input(f"{GREEN}STREAM ID: {RESET}").strip()
    if not validate_required_input(job_stream_id, "Stream ID"):
        return

    try:
        status = client.get_job_stream_status(plan_id, job_stream_id)
        print(f"{GREEN}STREAM {job_stream_id} STATUS: {status}{RESET}")
    except Exception as e:
        print(f"{GREEN}CRITICAL ERROR: {e}{RESET}")

def prompt_create_job_stream_definition(client, masters):
    """Prompt for creating a job stream definition."""
    print(f"\n{GREEN}INSTALL JOB STREAM{RESET}")
    if not REQUESTS_AVAILABLE:
        print(f"{GREEN}WARNING: Using urllib fallback. Limited functionality.{RESET}")
    engine = input(f"{GREEN}TARGET ENGINE (e.g., BAP051): {RESET}").strip().upper()
    if not validate_engine(engine, masters):
        return
    job_stream_name = input(f"{GREEN}STREAM NAME: {RESET}").strip()
    if not validate_required_input(job_stream_name, "Stream name"):
        return

    job_stream_data = {
        "name": job_stream_name,
        "jobs": [
            {
                "jobDefinitionName": "BATCH_JOB"
            }
        ]
    }

    try:
        client.create_job_stream_definition(job_stream_data)
        print(f"{GREEN}STREAM {job_stream_name} INSTALLED{RESET}")
    except Exception as e:
        print(f"{GREEN}CRITICAL ERROR: {e}{RESET}")

def prompt_get_job_stream_definition(client, masters):
    """Prompt for retrieving a job stream definition."""
    print(f"\n{GREEN}EXTRACT JOB STREAM{RESET}")
    if not REQUESTS_AVAILABLE:
        print(f"{GREEN}WARNING: Using urllib fallback. Limited functionality.{RESET}")
    engine = input(f"{GREEN}TARGET ENGINE (e.g., BAP051): {RESET}").strip().upper()
    if not validate_engine(engine, masters):
        return
    job_stream_name = input(f"{GREEN}STREAM NAME: {RESET}").strip()
    if not validate_required_input(job_stream_name, "Stream name"):
        return

    try:
        job_stream = client.get_job_stream_definition(job_stream_name)
        print(f"{GREEN}STREAM: {json.dumps(job_stream, indent=2)}{RESET}")
    except Exception as e:
        print(f"{GREEN}CRITICAL ERROR: {e}{RESET}")

def prompt_get_engine_status(client, masters):
    """Prompt for retrieving engine status."""
    print(f"\n{GREEN}PROBE ENGINE STATUS{RESET}")
    if not REQUESTS_AVAILABLE:
        print(f"{GREEN}WARNING: Using urllib fallback. Limited functionality.{RESET}")
    engine = input(f"{GREEN}TARGET ENGINE (e.g., BAP051): {RESET}").strip().upper()
    if not validate_engine(engine, masters):
        return

    try:
        status = client.get_engine_status()
        print(f"{GREEN}ENGINE {engine} STATUS: {json.dumps(status, indent=2)}{RESET}")
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
    quantity = input(f"{GREEN}QUANTITY [1]: {RESET}").strip() or "1"
    if not validate_required_input(resource_name, "Resource name"):
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
    message = input(f"{GREEN}MESSAGE: {RESET}").strip()
    if not validate_required_input(prompt_name, "Prompt name"):
        return
    if not validate_required_input(message, "Message"):
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
    if not validate_required_input(prompt_name, "Prompt name"):
        return

    try:
        prompt = client.get_prompt(prompt_name)
        print(f"{GREEN}PROMPT: {json.dumps(prompt, indent=2)}{RESET}")
    except Exception as e:
        print(f"{GREEN}CRITICAL ERROR: {e}{RESET}")

def prompt_test_connectivity(client, masters):
    """Prompt for testing connectivity."""
    print(f"\n{GREEN}PING TARGET{RESET}")
    if not REQUESTS_AVAILABLE:
        print(f"{GREEN}WARNING: Using urllib fallback. Limited functionality.{RESET}")
    engine = input(f"{GREEN}TARGET ENGINE (e.g., BAP051): {RESET}").strip().upper()
    if not validate_engine(engine, masters):
        return

    try:
        if client.test_connectivity():
            print(f"{GREEN}PING TO {engine} SUCCESSFUL{RESET}")
        else:
            print(f"{GREEN}PING TO {engine} FAILED{RESET}")
    except Exception as e:
        print(f"{GREEN}CRITICAL ERROR: {e}{RESET}")

def main():
    """Main function to run the TWS API CLI."""
    if not REQUESTS_AVAILABLE:
        print(f"{GREEN}WARNING: 'requests' module not found. Falling back to urllib.request. Install 'requests' for full functionality.{RESET}")
        print(f"{GREEN}See instructions to install 'requests' manually if pip is unavailable.{RESET}")

    # List of TWS masters
    masters = [
        "BAP051", "BAP151", "BAP251",
        "BAT052", "BAT152", "BAT252",
        "BEP051", "BEP151", "BEP251",
        "BET052", "BET152", "BET252",
        "BOP051", "BOP052", "BOP151", "BOP152", "BOP251", "BOP252",
        "BOT054", "BOT154", "BOT254",
        "BTP051", "BTP151", "BTP251",
        "BTT052", "BTT152"
    ]

    # Clear screen and display ASCII art
    print("\033[H\033[J", end="")  # Clear terminal
    print(generate_ascii_art())
    username, password = prompt_credentials()
    proxies = prompt_proxy_settings()
    verify_ssl = prompt_ssl_verification()

    while True:
        print(f"\n{GREEN}HACK THE MAINFRAME{RESET}")
        print(f"{GREEN}1. DEPLOY JOB{RESET}")
        print(f"{GREEN}2. PROBE JOB STATUS{RESET}")
        print(f"{GREEN}3. LOCK JOB{RESET}")
        print(f"{GREEN}4. UNLOCK JOB{RESET}")
        print(f"{GREEN}5. TERMINATE JOB{RESET}")
        print(f"{GREEN}6. REBOOT JOB{RESET}")
        print(f"{GREEN}7. INSTALL JOB DEFINITION{RESET}")
        print(f"{GREEN}8. EXTRACT JOB DEFINITION{RESET}")
        print(f"{GREEN}9. INSTALL WORKSTATION{RESET}")
        print(f"{GREEN}10. EXTRACT WORKSTATION{RESET}")
        print(f"{GREEN}11. UPDATE WORKSTATION{RESET}")
        print(f"{GREEN}12. REMOVE WORKSTATION{RESET}")
        print(f"{GREEN}13. INSTALL CALENDAR{RESET}")
        print(f"{GREEN}14. EXTRACT CALENDAR{RESET}")
        print(f"{GREEN}15. UPDATE CALENDAR{RESET}")
        print(f"{GREEN}16. REMOVE CALENDAR{RESET}")
        print(f"{GREEN}17. DEPLOY JOB STREAM{RESET}")
        print(f"{GREEN}18. PROBE STREAM STATUS{RESET}")
        print(f"{GREEN}19. INSTALL JOB STREAM{RESET}")
        print(f"{GREEN}20. EXTRACT JOB STREAM{RESET}")
        print(f"{GREEN}21. PROBE ENGINE STATUS{RESET}")
        print(f"{GREEN}22. INSTALL RESOURCE{RESET}")
        print(f"{GREEN}23. EXTRACT RESOURCE{RESET}")
        print(f"{GREEN}24. INSTALL PROMPT{RESET}")
        print(f"{GREEN}25. EXTRACT PROMPT{RESET}")
        print(f"{GREEN}26. PING TARGET{RESET}")
        print(f"{GREEN}27. DISCONNECT{RESET}")
        choice = input(f"{GREEN}SELECT OPERATION [1-27]: {RESET}").strip()

        if choice == '27':
            print(f"{GREEN}DISCONNECTING...{RESET}")
            break

        if choice not in {str(i) for i in range(1, 28)}:
            print(f"{GREEN}ERROR: Invalid operation.{RESET}")
            continue

        engine = input(f"{GREEN}TARGET ENGINE (e.g., BAP051): {RESET}").strip().upper()
        if not validate_engine(engine, masters):
            continue

        base_url = f"https://{engine.lower()}a.s2.ms.unilever.com:31116/twsd"
        client = TWSApiClient(base_url, username, password, engine, proxies, verify_ssl)

        try:
            if choice == '1':
                prompt_submit_ad_hoc_job(client, masters)
            elif choice == '2':
                prompt_get_job_status(client, masters)
            elif choice == '3':
                prompt_hold_job(client, masters)
            elif choice == '4':
                prompt_release_job(client, masters)
            elif choice == '5':
                prompt_cancel_job(client, masters)
            elif choice == '6':
                prompt_rerun_job(client, masters)
            elif choice == '7':
                prompt_create_job_definition(client, masters)
            elif choice == '8':
                prompt_get_job_definition(client, masters)
            elif choice == '9':
                prompt_create_workstation(client, masters)
            elif choice == '10':
                prompt_get_workstation(client, masters)
            elif choice == '11':
                prompt_update_workstation(client, masters)
            elif choice == '12':
                prompt_delete_workstation(client, masters)
            elif choice == '13':
                prompt_create_calendar(client, masters)
            elif choice == '14':
                prompt_get_calendar(client, masters)
            elif choice == '15':
                prompt_update_calendar(client, masters)
            elif choice == '16':
                prompt_delete_calendar(client, masters)
            elif choice == '17':
                prompt_submit_job_stream(client, masters)
            elif choice == '18':
                prompt_get_job_stream_status(client, masters)
            elif choice == '19':
                prompt_create_job_stream_definition(client, masters)
            elif choice == '20':
                prompt_get_job_stream_definition(client, masters)
            elif choice == '21':
                prompt_get_engine_status(client, masters)
            elif choice == '22':
                prompt_create_resource(client, masters)
            elif choice == '23':
                prompt_get_resource(client, masters)
            elif choice == '24':
                prompt_create_prompt(client, masters)
            elif choice == '25':
                prompt_get_prompt(client, masters)
            elif choice == '26':
                prompt_test_connectivity(client, masters)
        except Exception as e:
            print(f"{GREEN}CRITICAL ERROR: {e}{RESET}")

if __name__ == "__main__":
    main()