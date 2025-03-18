import re
import requests
import logging
import time


class NessusAPI:
    """Simple wrapper to interact with the Nessus API."""
    def __init__(self, base_url, api_token=None, username=None, password=None, verify=True, logger=None):
        self.base_url = base_url.rstrip('/')
        self.verify = verify
        self.logger = logger or logging.getLogger(__name__)
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.api_token = api_token
        
    def get_logger(self):
        return self.logger
    
    def get_api_token(self):
        return self.api_token
    
    def set_token(self, token):
        self.token = token
    
    def set_api_token(self, api_token):
        self.api_token = api_token
     
    def set_credentials(self, username, password):
        self.username = username
        self.password = password
        
    def set_session_headers(self):
        """Set the session headers for the Nessus server."""
        if not self.token or not self.api_token:
            self.logger.error("No login token or API token set. Please try running the script again")
            return False
        
        self.session.headers.update({
            "X-Cookie": f"token={self.token}",
            "X-Api-Token": self.api_token,
        })
        return True
        
    def set_json_header(self):
        """Enable the application/json Content-Type header."""
        self.session.headers["Content-Type"] = "application/json"

    def remove_json_header(self):
        """Remove the application/json Content-Type header."""
        self.session.headers.pop("Content-Type", None)
        
    def login_nessus(self):
        """Log in to Nessus and return the session token."""
        try:
            self.set_json_header()
            login_url = f"{self.base_url.rstrip('/')}/session"
            payload = {"username": self.username, "password": self.password}
            response = requests.post(login_url, json=payload, verify=self.verify, timeout=10)
            response.raise_for_status()
            data = response.json()
            token = data.get("token")
            if not token:
                return None
            return token
        except Exception as e:
            self.logger.error(f"Error logging in to Nessus: {e}")
            return None
        
    def check_connection(self):
        """Check if the Nessus server is reachable via the /server/status endpoint."""
        base_url = self.base_url
        session = self.session
        verify = self.verify
        logger = self.logger

        try:
            url = f"{base_url.rstrip('/')}/server/status"
            resp = session.get(url, verify=verify, timeout=10)
            resp.raise_for_status()
            data = resp.json()
            logger.debug(f"Nessus server status: {data}")
            return True
        except Exception as e:
            logger.error(f"Unable to connect to Nessus server at {base_url}: {e}")
            return False

    @classmethod
    def check_connection_from_url(cls, url, verify=False):
        session = requests.Session()
        logger = logging.getLogger(__name__)

        try:
            full_url = f"{url.rstrip('/')}/server/status"
            resp = session.get(full_url, verify=verify, timeout=10)
            resp.raise_for_status()
            data = resp.json()
            logger.debug(f"Nessus server status: {data}")
            return True
        except Exception as e:
            logger.error(f"Unable to connect to Nessus server at {url}: {e}")
            return False
        
    def get_api_token_automatically(self):
        """Get the API token from the Nessus server."""
        try:
            nessus_page = requests.get(self.base_url, verify=self.verify, timeout=5)
            nessus_page.raise_for_status()
            nessus_page_text = nessus_page.text
            
            match = re.search(r'nessus6\.js\?v=(\d+)', nessus_page_text)
            if not match:
                self.logger.error("Could not find the 'v' parameter in the HTML.")
                return None
                
            v_param = match.group(1)
            self.logger.debug(f"Extracted v parameter: {v_param}")
            
            nessus_js_url = f"{self.base_url}/nessus6.js?v={v_param}"
            nessus_js_response = requests.get(nessus_js_url, verify=self.verify, timeout=5)
            nessus_js_response.raise_for_status()
            nessus_js_text = nessus_js_response.text
            
            token_match = re.search(r'key:\s*"getApiToken",\s*value:\s*function\(\)\s*{\s*return\s*"([^"]+)"', nessus_js_text)
            
            if not token_match:
                self.logger.error("Could not find the 'getApiToken' function in the JavaScript file.")
                return None
            
            api_token = token_match.group(1)
            self.logger.debug(f"Extracted API token: {api_token}")
            self.api_token = api_token
            return True
            
        except Exception as e:
            self.logger.error(f"Error getting API token: {e}")
            return None
        
    def create_folder(self, folder_name):
        """
        Create a new folder on the Nessus server.
        Returns the new folder's ID or None if creation fails.
        """
        self.set_json_header()
        url = f"{self.base_url.rstrip('/')}/folders"
        payload = {"name": folder_name}
        try:
            response = self.session.post(url, json=payload, verify=self.verify, timeout=10)
            
            self.logger.debug(f"Payload: {payload}")
            self.logger.debug(f"Response status: {response.status_code}")
            self.logger.debug(f"Response headers: {response.headers}")
            self.logger.debug(f"Response content: {response.text}")
                  
            response.raise_for_status()
            data = response.json()
            folder_id = data.get("id")
            if not folder_id:
                self.logger.error(f"Folder creation failed for '{folder_name}'; no ID returned.")
                return None
            self.logger.info(f"Created folder '{folder_name}' with ID {folder_id}")
            return folder_id
        except Exception as e:
            self.logger.error(f"Error creating folder '{folder_name}': {e}")
            return None

    def get_folders(self):
        """
        Retrieve the list of folders from Nessus.
        Returns a dictionary mapping folder names to folder IDs.
        """
        try:
            url = f"{self.base_url.rstrip('/')}/folders"
            resp = self.session.get(url, verify=self.verify, timeout=10)
            resp.raise_for_status()
            data = resp.json()
            folders = data.get("folders", [])
            self.logger.debug(f"Retrieved {len(folders)} folders from Nessus")
            return {folder["name"]: folder["id"] for folder in folders}
        except Exception as e:
            self.logger.error(f"Error retrieving folders: {e}")
            return {}
        
    def upload_file(self, file_path, index=None, total=None):
        self.remove_json_header()
        upload_url = f"{self.base_url.rstrip('/')}/file/upload"
        try:
            with open(file_path, 'rb') as f:
                files_dict = {"Filedata": f}
                response = self.session.post(upload_url, files=files_dict, verify=self.verify, timeout=30)
            
            response.raise_for_status()
            data = response.json()
            uploaded_file = data.get("fileuploaded")
            if not uploaded_file:
                self.logger.error(f"File upload failed for {file_path}; no 'fileuploaded' returned.")
                return False
            self.logger.debug(f"{'[' + f'{index}/{total}' + '] ' if index and total else ''}Uploaded successfully as {uploaded_file}")
            return uploaded_file
        except Exception as e:
            self.logger.error(f"Error uploading file {file_path}: {e}")
            return False

    def import_scan(self, folder_id, file_path, nessus_file_id, index=None, total=None):
        self.set_json_header()
        import_url = f"{self.base_url.rstrip('/')}/scans/import"
        payload = {"folder_id": folder_id, "file": nessus_file_id}
        try:
            response = self.session.post(import_url, json=payload, verify=self.verify, timeout=30)
            response.raise_for_status()
            self.logger.debug(f"{'[' + f'{index}/{total}' + '] ' if index and total else ''}Imported scan from file: {file_path}")
            return True
        except Exception as e:
            self.logger.error(f"Error importing scan for file {file_path}: {e}")
            return False

    def get_scans(self):
        """
        Retrieve the list of scans from Nessus.
        Returns a list of scan dictionaries.
        """
        try:
            url = f"{self.base_url.rstrip('/')}/scans"
            resp = self.session.get(url, verify=self.verify, timeout=20)
            resp.raise_for_status()
            data = resp.json()
            scans = data.get("scans", [])
            self.logger.debug(f"Retrieved {len(scans)} scans from Nessus")
            return scans
        except Exception as e:
            self.logger.error(f"Error retrieving scans: {e}")
            return []

    def export_scan(self, scan_id):
        """
        Export a scan (in CSV format) and return its CSV content as a string.
        The process is asynchronous: first create an export request, poll until ready,
        and then download the file.
        """
        try:
            self.set_json_header()
            payload = {"format": "csv"}
            url = f"{self.base_url.rstrip('/')}/scans/{scan_id}/export"
            self.logger.debug(f"Requesting export for scan ID {scan_id}")
            resp = self.session.post(url, json=payload, verify=self.verify, timeout=10)
            resp.raise_for_status()
            file_id = resp.json().get("file")
            if not file_id:
                self.logger.error(f"No file id returned for scan {scan_id} export")
                return None

            # Poll for export readiness.
            status_url = f"{self.base_url.rstrip('/')}/scans/{scan_id}/export/{file_id}/status"
            while True:
                status_resp = self.session.get(status_url, verify=self.verify, timeout=10)
                status_resp.raise_for_status()
                status = status_resp.json().get("status")
                self.logger.debug(f"Scan {scan_id} export status: {status}")
                if status == "ready":
                    break
                time.sleep(1)

            # Download the export.
            download_url = f"{self.base_url.rstrip('/')}/scans/{scan_id}/export/{file_id}/download"
            self.logger.debug(f"Downloading export for scan ID {scan_id}")
            download_resp = self.session.get(download_url, verify=self.verify, timeout=30)
            download_resp.raise_for_status()
            return download_resp.text
        except Exception as e:
            self.logger.error(f"Error exporting scan {scan_id}: {e}")
            return None

