import requests, json
from json import *
from xml.etree import ElementTree
import time
import logging

# Uncomment the following to turn on full REST tracing
#try:
#	import http.client as http_client
#except ImportError:
#	import httplib as http_client
#	http_client.HTTPConnection.debuglevel = 1

DEBUG = 0
VERSION = "1.0"
USERAGENT = "pyHealth/%s" % VERSION

def enable_debug():
	global DEBUG
	DEBUG = 1
	logging.basicConfig() 
	logging.getLogger().setLevel(logging.DEBUG)
	requests_log = logging.getLogger("requests.packages.urllib3")
	requests_log.setLevel(logging.DEBUG)
	requests_log.propagate = True
	print("DEBUG: debug ENABLED")

def disable_debug():
	global DEBUG
	DEBUG = 0
	print("DEBUG: debug DISABLED")

# Output: 0=Failure
#         1=Success
def authenticate(user, passwd):
	global s
	s = requests.Session()
	s.headers.update({'User-Agent': "%s %s" % (s.headers['User-Agent'], USERAGENT)})
	payload = {'userid':user, 'passwd':passwd}
	if DEBUG: 
		print("DEBUG: authenticate: payload=")
	 	print(payload)

	r = s.post('https://login.f5.com/resource/loginAction.jsp', data=payload, allow_redirects=False)
	if DEBUG: 
		resp_debug(r)
		print("DEBUG: authenticate: cookies=")
		print(r.cookies)

	if not "ssosession" in r.cookies:
		if DEBUG: print("DEBUG authenticate: auth failed")
		return 0

	if DEBUG:(print "DEBUG: authenticate: auth successful, ssosession=%s" % r.cookies['ssosession'])
	return 1

# Input: STR filename
# Output: -1 File could not be opened
#		   0 iHealth did not return a valid ID
#		  >1 The ID of the qkview file in iHealth
def upload_qkview(filename):
	if DEBUG: print("DEBUG: upload_qkview: filename=%s" % filename)
	try: 
		files = {'qkview': open(filename, 'rb')}
	except:
		return -1
	r = s.post('https://ihealth-api.f5.com/qkview-analyzer/api/qkviews', files=files, allow_redirects=False)
	parts = r.headers['Location'].split('/')
	try:
		qkviewid = int(parts.pop())
	except:
		if DEBUG: print("DEBUG: upload_qkview: ID was not an int")
		return 0
	resp_debug(r)
	if r.status_code != 303:
		if DEBUG: print ("DEBUG: upload_qkview: didn't get a 303 response...")
		return 0
	return qkviewid


# Input: INT qkviewid
# Output: -1   iHealth returned a error
#          1   qkview deleted
def delete_qkview(qkviewid):
	if DEBUG: print ("DEBUG: delete_qkview: qkviewid=%d" % qkviewid)
	r = s.delete("https://ihealth-api.f5.com/qkview-analyzer/api/qkviews/%d" % qkviewid)
	resp_debug(r)
	if r.status_code != 200:
		return (-1)
	return 1
	
def delete_all():
	if DEBUG: print ("DEBUG: delete_all")
	r = s.delete("https://ihealth-api.f5.com/qkview-analyzer/api/qkviews")
	resp_debug(r)
	if r.status_code != 200:
		return (-1)
	return 1
	
def set_visible(qkviewid, visible):
	if DEBUG: print ("DEBUG: set_visible: qkviewid=%d visible=%d" % (qkviewid, visible))	
	if visible:
		payload = {'visible_in_gui':'true'}
	else:
		payload = {'visible_in_gui':'false'}
	r = s.post("https://ihealth-api.f5.com/qkview-analyzer/api/qkviews/%d" % qkviewid, data=payload, allow_redirects=False)
	resp_debug(r)

	if r.status_code == 200:
		return 1
	else:
		return 0

def set_share(qkviewid, share):
	if DEBUG: print ("DEBUG: set_share: qkviewid=%d share=%d" % (qkviewid, share))	
	if share:
		payload = {'share_with_case_owner':'true'}
	else:
		payload = {'share_with_case_owner':'false'}	
	r = s.post("https://ihealth-api.f5.com/qkview-analyzer/api/qkviews/%d" % qkviewid, data=payload, allow_redirects=False)
	resp_debug(r)
	if r.status_code == 200:
		return 1
	else:
		return 0


def set_description(qkviewid, descr):
	if DEBUG: print ("DEBUG: set_description: qkviewid=%d description=%s" % (qkviewid, descr))	
	payload = {'description':descr}	
	r = s.post("https://ihealth-api.f5.com/qkview-analyzer/api/qkviews/%d" % qkviewid, data=payload, allow_redirects=False)
	resp_debug(r)
	if r.status_code == 200:
		return 1
	else:
		return 0

def set_case(qkviewid, case):
	if DEBUG: print ("DEBUG: set_case: qkviewid=%d case=%s" % (qkviewid, case))	
	payload = {'f5_support_case':case}
	r = s.post("https://ihealth-api.f5.com/qkview-analyzer/api/qkviews/%d" % qkviewid, data=payload, allow_redirects=False)
	resp_debug(r)
	if r.status_code == 200:
		return 1
	else:
		return 0


def resp_debug(r):
	if DEBUG:
		print ("DEBUG: resp_debug: Status code: %d" % r.status_code)
		print ("DEBUG: resp_debug: Request Headers: %s" % r.request.headers)
		print ("DEBUG: resp_debug: Response Headers: %s" % r.headers)
		print ("DEBUG: resp_debug: Response Content: %s" % r.content)
