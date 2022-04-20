#------------------------------------
# Author: Christopher Luera
# Program Description:
#     - Write Script to F5
#     - Generate a QKView
#     - Download QKView
#------------------------------------

"""Import Modules for QKView"""
import os
import json
import http.cookiejar #for python3
import requests

dir_path = "roles/qkview/files/"

url = ('https://api.f5.com/auth/pub/sso/login/ihealth-api')
headers = {'content-type': 'application/json', 'user-agent': 'FSE_QKapi'}
payload = {'user_id': '<user id>', 'user_secret': '<password>'}
session = requests.session()
r_token = session.post(url, headers=headers, data=json.dumps(payload))

print("Auth Token ", r_token.status_code)

for f in os.listdir(dir_path):
    if f.endswitch('.qkview'):
        url1 = ('https://ihealth-api.f5.com/qkview-analyzer/api/qkviews')
        headers1 = {'Accept': 'application/vnd.f5.ihealth.api', 'user-agent': 'FSE_QKapi'}
        payload1 = {'visible_in_gui': 'True'}
        fvar = {'qkview': open(dir_path + f, 'rb')}
        r_Up = session.post(url1, headers=headers1, files=fvar, data=payload1)
        print("Upload Status ",r_Up.status_code)

# These are your iHealth credentials - either fill in the double quotes, or better yet, use environment variables
# during invocation
USER=${USER:-""}
PASS=${PASS:-""}


class LoadBalancer:
	def __init__(self, username: str, password: str, address: str):
		self.username = username
		self.password = password
		self.address = address
		self._lb_base_url = f"https://{address}/ngnt"
		self._lb = requests.session()
		self._lb.headers/update({'Content-Type': 'Application/JSON'})
		self._lb.verify = False
		self._token = {'Token': '000000', 'TimeStamp': 0.0}
		self._get_token()

	def _get_token(self) -> None:
		_auth_url = f"{self._lb_base_url}/shared/authn/login"
		self._lb.auth = (self.username, self.password)
		_payload = {'username': self.username, 'password': self.password, 'LoginProviderName': 'tmos'}
		_ = self._lb.post(_auth_url, json=_payload)
		self._token['token'] = _.json()['token']['token']
		self._token['timestamp'] = time.time()
		self._lb.headers.update({'X-F5-Auth-Token': self._token['token']})
		self._lb.auth = ()
		return

	def _token_validation(self) -> None:
		if (time.time() - self._token('timestamp')) > 1140:
			self._get_token()
		return

	def file_upload(self, file_path: str) -> None:
		self._token_validation()
		self._lb.headers.update({'Content-Type': 'Application/octet-stream'})
		file_name = os.path.basename(file_path)
		_file_upload_url = f"{self._lb_base_url}/shared/file_transfer/uploads/{file_name}"
		chunk_size = 512 * 1024
		start = 0
		# Try - Except Block?

	def file_download(self, file: str, destination: str) -> None:
		self._token_validation()
		self._lb.headers.update({'Content-Type': 'Application/octet-stream'})
		file_name = os.path.basename(file_path)
		_file_url = f"{self._lb_base_url}/cm/autodeploy/software-image-downloads/{file}"
		chunk_size = 512 * 1024
		file_out = f"{destination}/{file}"
		try:
			with open(file_out, 'wb') as of:
				start = 0
				end = chunk_size - 1
				size = 0
				current_bytes = 0
				while True:
					content_range = f"{start}-{end}/{size}"
					_session_headers = {'Content-Range': content_range}
					_ = self._lb.get(_file_url, headers = _session_headers, stream = True)
					if _.status_code == 200:
						if size > 0:
							current_bytes += chunk_size
							for chunk in _.iter_content(chunk_size):
								of.write(chunk)
						if end == size:
							break
					c_range = _.headers['Content_Range']

					if size == 0:
						size = int(c_range.split('/')[-1]) - 1
						if chunk_size > size:
							end = size
						continue
					start += chunk_size
					if (current_bytes + chunk_size) > size:
						end = size
					else:
						end = start + chunk_size - 1
			pass
		finally:
			self._lb.headers.update({'Content-Type': 'Application/Json'})
		return

	def get_hostname(self) -> str:
		self._token_validation()
		_cm_hostname = f"{self._lb_base_url}/tm/cm/device"
		_ = self._lb.get(_cm_hostname).json()['items'][0]['name']
		return _

	def get_host_info(self, host_name='') -> dict:
		self._token_validation()
		_cm_host = f"{self._lb_base_url}/tm/cm/device/{host_name}"
		_ = self._lb.get(_cm_host).json()

	def get_tokens(self) -> list:
		self._token_validation()
		_share_host = f"{self._lb_base_url}/shared/authz/tokens"
		_ = self._lb.get(_share_host).json()['items']
		return _

#======================================================================================================
#= Global Code = derived from web
# This is the path to the cookiefile that curl uses to utilize the inital authentication
COOKIEJAR=/tmp/.cookiefile_${RANDOM}_$$

# set verbose to default on, easy to switch off at runtime
VERBOSE=${VERBOSE:-1}

# Set our data format: json or xml
RESPONSE_FORMAT=${FORMAT:-"xml"}

# location of helper utilities
readonly CURL=/usr/bin/curl

# How many time do we poll the server, and how long do we wait?
readonly POLL_COUNT=100
readonly POLL_WAIT=2
# Shouldn't need to muck with much below here
########################################

CURL_OPTS="-s --user-agent 'showmethemoney' --cookie ${COOKIEJAR} --cookie-jar ${COOKIEJAR} -o /dev/null"
if [[ $DEBUG ]]; then
	CURL_OPTS="--trace-ascii /dev/stderr "${CURL_OPTS}
fi

ACCEPT_HEADER="-H'Accept: application/vnd.f5.ihealth.api+${RESPONSE_FORMAT}'"

function clean {
	if [[ ! $DEBUG ]]; then
		\rm -f ${COOKIEJAR}
	fi
}

function usage {
	echo
	echo "usage: USER=[user] PASS=[pass] <path-to-qkview>"
	echo " - [user] is your iHealth username (email)"
	echo " - [pass] is your iHealth password"
	echo " - OPT: VERBOSE=0 will turn off status messages"
	echo " - OPT: DEBUG=1 will flood you with details"
	echo " - OPT: FORMAT=json will switch responses and processing to be in json"
	echo " - OPT: VISIBLE=1 will show the uploaded qkview in the iHealth GUI"
	echo
	echo "This script will produce a diagnostics summary, and is a companion to"
	echo "an F5 Dev Central article series about the iHealth API"

}

function error {
	msg="$1"
	printf "\nERROR: %s\n" "${msg}"
	usage
	clean
	exit 1
}

function xml_extract {
	xml="$1"
	xpath="$2"
	if [[ ! "${xpath}" ]] || [[ "$xpath" = "" ]]; then
		error "Not enough arguments to xml_extract()"
	fi
	cmd=$(printf "echo '%s' | %s select -t -v '%s' -" "${xml}" ${XMLPROCESSOR} "${xpath}")
	echo $(eval ${cmd})
}

function authenticate {
	user="$1"
	pass="$2"
	# Yup!  Security issues here! we're eval'ing with user input.  Don't put this code into a CGI script...
	CURL_CMD="${CURL} --data-ascii \"{\\\"user_id\\\": \\\"${user}\\\", \\\"user_secret\\\": \\\"${pass}\\\"}\" ${CURL_OPTS} -H'Content-type: application/json' -H'Accept: */*' https://api.f5.com/auth/pub/sso/login/ihealth-api"
	[[ $DEBUG ]] && echo ${CURL_CMD}

	if [[ ! "$user" ]] || [[ ! "$pass" ]]; then
		error "missing username or password"
	fi
	eval "$CURL_CMD"
	rc=$?
	if [[ $rc -ne 0 ]]; then
		error "curl authentication request failed with exit code: ${rc}"
	fi

	if ! \grep -e "ssosession" "${COOKIEJAR}" > /dev/null 2>&1; then
		error "Authentication failed, check username and password"
	fi
	[[ $VERBOSE ]] && echo "Authentication successful" >&2
}

function upload_qkview {
	path="$1"
	form_data="-F 'qkview=@${path}'"
	if [[ $VISIBLE ]]; then
		[[ $DEBUG ]] && echo "Flagging upload for GUI visibility" >&2
		form_data="${form_data} -F visible_in_gui=True"
	fi
	CURL_CMD="${CURL} ${ACCEPT_HEADER} ${CURL_OPTS} ${form_data} -D /dev/stdout https://ihealth-api.f5.com/qkview-analyzer/api/qkviews"
	[[ $DEBUG ]] && echo "${CURL_CMD}" >&2
	out="$(eval "${CURL_CMD}")"
	if [[ $? -ne 0 ]]; then
		error "Couldn't retrieve diagnostics for ${qid}"
	fi
	location=$(echo "${out}" | grep -e '^Location:' | tr -d '\r\n')
	transformed=${location/Location: /}
	echo "${transformed}"
}

function wait_for_state {
	url="$1"
	count=0
	CURL_CMD="${CURL} ${ACCEPT_HEADER} ${CURL_OPTS} -w "%{http_code}" ${url}"
	[[ $DEBUG ]] && echo "${CURL_CMD}" >&2
	_status=202
	time_passed=0
	while [[ "$_status" -eq 202 ]] && [[ $count -lt ${POLL_COUNT} ]]; do
		_status="$(eval "${CURL_CMD}")"
		count=$((count + 1))
		time_passed=$((count * POLL_WAIT))
		[[ $VERBOSE ]] && echo -ne "waiting (${time_passed} seconds and counting)\r" >&2
		sleep ${POLL_WAIT}
	done
	printf "\nFinished in %s seconds\n" "${time_passed}" >&2
	if [[ "$_status" -eq 200 ]]; then
		[[ $VERBOSE ]] && echo "Success - qkview is ready"
	elif [[ ${count} -ge ${POLL_COUNT} ]]; then
		error "Timed out waiting for qkview to process"
	else
		error "Something went wrong with qkview processing, status: ${_status}"
	fi
}

# Check to see if we got a file path
if [[ ! "$1" ]] || [[ "$1" == '' ]] || [[ ! -f "$1" ]]; then
	error "I need a path to a valid qkview file to continue"
else
	QKVIEW_PATH="$1"
	[[ $VERBOSE -gt 0 ]] && echo "Preparing to upload ${QKVIEW_PATH}"
fi

#Check that we know the response format
if [[ "${RESPONSE_FORMAT}" != 'xml' ]] && [[ "${RESPONSE_FORMAT}" != 'json' ]]; then
	error "$(printf "Response format must be either 'xml' or 'json', '%s' is unknown" "${RESPONSE_FORMAT}")"
fi

# Start fresh
clean

# Auth ourselves
[[ $VERBOSE -gt 0 ]] && echo "Authenticating" >&2
authenticate "${USER}" "${PASS}"

qkview_url="$(upload_qkview "${QKVIEW_PATH}")"

[[ $VERBOSE -gt 0 ]] && echo "Got location of new qkview: ${qkview_url}"

wait_for_state "${qkview_url}"

[[ $VERBOSE ]] && echo "${QKVIEW_PATH} uploaded successfully, see ${qkview_url}"
[[ $VERBOSE ]] && [[ $VISIBLE ]] && echo "May also be viewed in the GUI: https://ihealth.f5.com/qkview-analyzer/qv/${qkview_url##*/}"

#-------------------
# Downloading QKView
#-------------------
from f5.bigip import ManagementRoot
mgmt = ManagementRoot('192.168.1.1', 'user', 'pass')
mgmt.tm.util.qkview.exec_cmd('run', utilCmdArgs='-C --exclude all')

def _download(host, creds, fp):
    chunk_size = 512 * 1024

    headers = {'Content-Type': 'application/octet-stream'}
    filename = os.path.basename(fp)
    uri = 'https://%s/mgmt/cm/autodeploy/qkview-downloads/%s' % (host, filename)
    requests.packages.urllib3.disable_warnings()

    with open(fp, 'wb') as f:
        start = 0
        end = chunk_size - 1
        size = 0
        current_bytes = 0

        while True:
            content_range = ("%s-%s/%s" % (start, end, size))
            headers['Content-Range'] = content_range
            resp = requests.get(uri,
                                auth=creds,
                                headers=headers,
                                verify=False,
                                stream=True)
            if resp.status_code == 200:
                if size > 0:
                    current_bytes += chunk_size
                    for chunk in resp.iter_content(chunk_size):
                        f.write(chunk)
                if end == size:
                    break

            crange = resp.headers['Content-Range']

            if size == 0:
                size = (int(crange.split('/')[-1]) - 1)
                if chunk_size > size: #if file smaller than chunk_size, BIGIP will give HTTP4 00
                    end = size
                continue
            start += chunk_size
            if (current_bytes + chunk_size) > size:
                end = size
            else:
                end = (start + chunk_size - 1)

def main():
  _download('LTM1.example.com', ('admin', 'testing'), 'LTM1.example.com.qkview')

if __name__ == '__main__':
  main()


#----------------
# iHealth Upload
#----------------

import time
import getpass
import sys

if len(sys.argv) != 2:
	print("Usage: %s <qkview file>" % sys.argv[0])
	quit(0)

# Uncomment to enable debug output
# pyHealth.enable_debug()

username = raw_input('Enter iHealth Username: ')
password = getpass.getpass('Enter iHealth Password: ')

print("Authenticating to iHealth...")
if not pyHealth.authenticate(username,password):
	print("iHealth Auth Failed")
	quit(0)

print("Uploading qkview to iHealth...")
qkviewid = pyHealth.upload_qkview(sys.argv[1])
if qkviewid <= 0:
	print("File upload failed")
	quit(0)

print("Uploaded iHealth QKView ID is %d\n" % qkviewid)

print("Details:")
print(pyHealth.get_qkview(qkviewid))

print("Setting visible... ")
print(pyHealth.set_visible(qkviewid, 1))

print("Setting shareable... ")
print(pyHealth.set_share(qkviewid, 1))

print("Setting description... ")
print(pyHealth.set_description(qkviewid, "My description"))

print("Setting case number... ")
print(pyHealth.set_case(qkviewid, "C123456"))

print("\nUpdated Details:")
print(pyHealth.get_qkview(qkviewid))

print("\nList of qkviews in this account")
mylist = pyHealth.get_list()
print(mylist)

print("Diagnostics output:")
print(pyHealth.get_diagnostics(qkviewid))

print("\n\nDiagnostics output (inluding misses):")
print(pyHealth.get_diagnostics_all(qkviewid))

print("\nDeleting uploaded qkview")
print(pyHealth.delete_qkview(qkviewid))

print("Deleting all qkviews")
print(pyHealth.delete_all())

#---------------------------
# 
#---------------------------





