import mysql.connector as mysql
import jwt
import hashlib
import bcrypt
import datetime
import re
import magic
import mimetypes
import os
from fastapi import Request
from fastapi.security import HTTPBearer
from slowapi.util import get_remote_address
from starlette.responses import JSONResponse, Response
from slowapi.errors import RateLimitExceeded
from starlette.exceptions import HTTPException as StarletteHTTPException
from typing import Any, Dict, Optional, Sequence, Type, Union
from typing_extensions import Annotated, Doc
from dotenv import load_dotenv
import traceback # for testing

log_file = 'ape.log'
folders = ['temp', 'images']
# Two letter abbreviation for states, Puerto Rico, and D.C.
TLAbbr = ["AL", "AK", "AZ", "AR", "CA", "CO", "CT", "DE", "DC", "FL", "GA", "HI", "ID", "IL", "IN", "IA", "KS", "KY", "LA", "ME", "MD", "MA", "MI", "MN", "MS", "MO", "MT", "NE", "NV", "NH", "NJ", "NM", "NY", "NC", "ND", "OH", "OK", "OR", "PA", "PR", "RI", "SC", "SD", "TN", "TX", "UT", "VT", "VA", "WA", "WV", "WI", "WY"]

# Iterator
it = 0

load_dotenv()
jwt_key = os.getenv('JWT_KEY')

class CustomException(StarletteHTTPException):
		'''
		Custom version of FastAPI HTTPException intended for internal server errors.
		Can be thought of as an middleman for exceptions.
		'''
		def __init__(
				self,
				status_code: Annotated[
						int,
						Doc(
								"""
								HTTP status code to send to the client.
								"""
						),
				],
				error: Annotated[
					Any,
					Doc(
						'''
						General error as to why exception was raised, used for error logging.
						'''
					)
				],
				detail: Annotated[
						Any,
						Doc(
								"""
								Any data to be sent to the client in the `detail` key of the JSON
								response.
								"""
						),
				] = None,
				headers: Annotated[
						Optional[Dict[str, str]],
						Doc(
								"""
								Any headers to send to the client in the response.
								"""
						),
				] = None,
		) -> None:
				super().__init__(status_code=status_code, detail=detail, headers=headers)
				self.error = error

def tester():
	mysql.Timestamp

def get_new_time():
	time = datetime.datetime.now()
	return time

# Check if user already exists for that type of user
async def check_user(request: Request, e_mail: str):
	new_time = get_new_time()
	try:
		request.state.cursor.execute(
			'''
			SELECT CASE 
					WHEN EXISTS(SELECT 1 FROM Employer WHERE (email = %(email)s AND delete_flag = 0))
						THEN (SELECT delete_flag FROM Employer WHERE (email = %(email)s AND delete_flag = 0))
					WHEN EXISTS(SELECT 1 FROM Seeker WHERE (email = %(email)s AND delete_flag = 0))
						THEN (SELECT delete_flag FROM Seeker WHERE (email = %(email)s AND delete_flag = 0))
					ELSE NULL
				END AS checked,
				CASE 
					WHEN EXISTS(SELECT 1 FROM Employer WHERE (email = %(email)s AND delete_flag = 0))
						THEN (SELECT "employer" AS usertype)
					WHEN EXISTS(SELECT 1 FROM Seeker WHERE (email = %(email)s AND delete_flag = 0))
						THEN (SELECT "seeker" AS usertype)
					ELSE NULL
				END AS usertype,
				CASE 
					WHEN EXISTS(SELECT 1 FROM Employer WHERE (email = %(email)s AND delete_flag = 0))
						THEN (SELECT HEX(employer_id) FROM Employer WHERE (email = %(email)s AND delete_flag = 0))
					WHEN EXISTS(SELECT 1 FROM Seeker WHERE (email = %(email)s AND delete_flag = 0))
						THEN (SELECT HEX(seeker_id) FROM Seeker WHERE (email = %(email)s AND delete_flag = 0))
					ELSE NULL
				END AS user_id;
			''',{
				'email': e_mail
			}
		)
		check = request.state.cursor.fetchone()
		match check['checked']:
			case 0:
				return {'exists': True, 'reason': 'email already registered', 'usertype': check['usertype'], 'userId': check['user_id']}
			case 1 | None:
				return {'exists': False, 'reason': 'user not found'}
			case _:
				raise CustomException(status_code=500, error='MySQL query error', detail='unexpected value returned while looking for user')
	except Exception as err:
		print(err)
		if type(err) == CustomException:
			write_log(f'{set_timestamp(new_time)} | | source: helper.check_user | error: ${err.detail} |	| server\n')
		else:
			write_log(f'{set_timestamp(new_time)} | | source: helper.check_user | error: ${err} | | server\n')
		return err
	
def check_auth(req: Request, user_id: str, company: str):
	new_time = get_new_time()
	try:
		req.state.cursor.execute(
			'''
			SELECT approve_flag, company FROM employer
        WHERE employer_id = UNHEX(%(id)s);
			''',{
				'id': user_id
			}
		)
		[check] = req.state.cursor.fetchall()
		if check['approve_flag'] != 1 and company != check['company']:
			return False
		else:
			return True
	except Exception as err:
		print(err)
		#traceback.print_exc()
		error = str(err)
		write_log(f'{set_timestamp(new_time)} | | source: helper.check_auth | error: {error} | | server\n')
		raise err

# def check_jwt(req: Request):
# 	print('Verify attempt: JWT')
# 	new_time = get_new_time()
# 	write_log(f'{set_timestamp(new_time)} | | source: JWT | info: verify attempt: JWT | | attempt: @@{get_remote_address(req)}\n')
# 	if not 'Authorization' in req.headers:
# 		return CustomException(status_code=400, error='failed JWT verify', detail='invalid authorization, no authorization headers')
	
# 	return True

# Check if log file exists, creates one if it does not
def check_log():
	try:
		with open(log_file, mode='a') as f:
			f.close()
	except:
		with open(log_file, mode='x', encoding='utf-8') as f:
			f.write(set_timestamp(datetime.datetime.now) + ' | info: Log created')
			f.close()

# Log writing function
def write_log(msg: str):

	with open(log_file, mode='a', encoding='utf-8') as f:
		f.write(msg)
		f.close()

# Ensure directories used exist, create if they don't
def check_folders():
	new_time = datetime.datetime.now()
	try:
		for folder in folders:
			check = os.path.exists(folder)
			if not check:
				os.mkdir(folder)
	except Exception as err:
		print(err)
		write_log(f'{set_timestamp(new_time)} | | source: helper.check_folders | error: ${err} | | server\n')
		return err

# For testing, easy to search and remove
def bob(msg):
	global it
	if not msg:
		print(it)
		it += 1
	elif msg == 'reset':
		print('resetting count')
		it = 0
	else:
		print(msg)

def set_timestamp(time_update: datetime.datetime):
	formatted = time_update.strftime('%Y-%m-%d %H:%M:%S')
	return formatted

def check_date(check):
	new_time = datetime.datetime.now()
	try:
		pat = r'^[1-2][0-9][0-9][0-9]-[0-1][0-9]$'
		checked = re.match(pattern=pat, string=check)
		pat = r'^[1-2][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]$'
		checked2 = re.match(pattern=pat, string=check)
		if not checked and not checked2:
			return False
	
		arr = str.split(check, '-')
		if len(arr) == 2:
			arr.append('1')
		try_for_exception = datetime.date(int(arr[0]), int(arr[1]), int(arr[2]))
		return True
	except Exception as err:
		print(err)
		write_log(f'{set_timestamp(new_time)} | | source: helper.valid_json | error: ${err} | | server\n')
		return False

# Regex input validation
# Special, Alphabetical, Numerical
def valid_san(check, leng:int = 255):
	if type(check) == str:
		if len(check) < 3 or len(check) > leng:
			return False
		pat = r'^[A-Za-z 0-9!@#$%^&*)(+=._-]+$'
		checked = re.match(pattern=pat, string=check)
		if checked:
			return True
		else:
			return False
	else:
		return False
	
# Special, Alphabetical
def valid_sa(check, leng):
	if type(check) == str:
		if len(check) < 3 or len(check) > leng:
			return False
		pat = r'^[A-Za-z !@#$%^&*)(+=._-]+$'
		checked = re.match(pattern=pat, string=check)
		if checked:
			return True
		else:
			return False
	else:
		return False

# Alphabetical, Numerical
def valid_an(check, leng):
	if type(check) == str:
		if len(check) < 3 or len(check) > leng:
			return False
		pat = r'^[A-Za-z 0-9]+$'
		checked = re.match(pattern=pat, string=check)
		if checked:
			return True
		else:
			return False
	else:
		return False

# Alphabetical
def valid_a(check, leng):
	if type(check) == str:
		if len(check) < 3 or len(check) > leng:
			return False
		pat = r'^[A-Za-z ]+$'
		checked = re.match(pattern=pat, string=check)
		if checked:
			return True
		else:
			return False
	else:
		return False

# Numerical
def valid_n(check):
		if type(check) != int and type(check) != float:
			return False
		else:
			return True

# USPS state and territory abbreviations
def valid_state(check):
	if type(check) == str:
		if len(check) == 2:
			arr = list(filter(lambda state: state == check, TLAbbr))
			if not arr:
				return False
			return True
		else:
			return False
	else:
		return False

# JSON, API request body is expected to be JSON. FastAPI auto-converts to dictionary
def valid_json(check):
	if type(check) == str:
		return True
	new_time = datetime.datetime.now()
	if check == None:
		return True
	if type(check) != dict and type(check) != list:
		print(type(check))
		return False
	try:
		valid = False
		arr: list
		if type(check) == dict:
			arr = list(check.values())
		elif type(check) == list:
			arr = list(check)
		for entry in arr:
			if type(entry) != str and type(entry) != dict and type(entry) != list and type(entry) != bool and type(entry) != int and type(entry) != float:
				return False
		for entry in arr:
			if type(entry) == dict or type(entry) == list:
				valid2 = valid_json(entry)
				if not valid2:
					return False
		return True
	except Exception as err:
		print(err)
		write_log(f'{set_timestamp(new_time)} | | source: helper.valid_json | error: ${err} | | server\n')
		return False

# Date
def valid_date(check):
	if type(check) != str:
		return False
	new_time = datetime.datetime.now()
	try:
		checked = check_date(check)
		if not checked:
			return False
		arr = str.split(check, '-')
		year = int(arr[0])
		if year > new_time.year or year < 1950:
			return False
		days = 1
		if len(arr) == 3:
			days = int(arr[2])
		check_date = datetime.date(int(arr[0]), int(arr[1]), days)
		max_date = datetime.date.today()
		if max_date > check_date:
			return True
		else:
			return False
	except Exception as err:
		print(err)
		write_log(f'{set_timestamp(new_time)} | | source: helper.valid_date | error: ${err} | | server\n')
		return False

# Non-paradoxical dates
def valid_dates(check, check2):
	if type(check) != str:
		return False
	new_time = datetime.datetime.now()
	try:
		checked = check_date(check)
		checked2 = check_date(check2)
		if not checked or not checked2:
			return False
	
		arr = str.split(check, '-')
		arr2 = str.split(check2, '-')
		if len(arr) == 2:
			arr.append('1')
		if len(arr2) == 2:
			arr2.append('1')
		if int(arr[0]) <= int(arr2[0]):
			if int(arr[1]) <= int(arr2[1]) or int(arr[0]) < int(arr2[0]):
				if int(arr[0]) == int(arr2[0]) and int(arr[1]) == int(arr2[1]) and int(arr[2]) > int(arr2[2]):
					return False
				return True
			else:
				return False
		else:
			return False
	except Exception as err:
		print(err)
		write_log(f'{set_timestamp(new_time)} | | source: helper.valid_dates | error: ${err} | | server\n')
		return False

# Expiration date
def valid_exp_date(check):
	new_time = datetime.datetime.now()
	try:
		if check == None:
			return True
		checked = check_date(check)
		if not checked:
			return False
		arr = str.split(check, '-')
		year = int(arr[0])
		if year < new_time.year or year > 3000:
			return False
		if len(arr) == 2:
			arr.append('1')
		exp_date = datetime.datetime(year, int(arr[1]), int(arr[2]))
		date_offset = datetime.timedelta(days=15.0) # Earliest expiration date permitted is two weeks
		today = datetime.datetime(new_time.year, new_time.month, new_time.day)
		min_exp_date = today + date_offset
		if exp_date >= min_exp_date:
			return True
		else:
			return False
	except Exception as err:
		print(err)
		write_log(f'{set_timestamp(new_time)} | | source: helper.valid_exp_date | error: ${err} | | server\n')
		return False

# Keyword arguments
def valid_kwargs(check: str):
	good: bool = False
	check1: bool = False
	check2: bool = False
	check3: bool = False
	try:
		check.index(';')
	except:
		check1 = True
	try:
		check.index('/')
	except:
		check2 = True
	try:
		check.index('\\')
	except:
		check3 = True
	if check1 == True and check2 == True and check3 == True:
		good = True
	return good

# Convert datetime to unix timestamp
def unix_timestamp(date):
	new_time = datetime.datetime.now()
	try:
		return int(new_time.timestamp())
	except Exception as err:
		print(err)
		write_log(f'{set_timestamp(new_time)} | | source: helper.unix_timestamp | error: ${err} | | server\n')
		return False

# To be used to prevent writing of disallowed filetypes, returns False or file extension. If False is returned, do not write file
def file_filter_image(file):
	new_time = datetime.datetime.now()
	try:
		filetype = magic.from_buffer(file, mime=True)
		if filetype != 'image/gif' and filetype != 'image/jpeg' and filetype != 'image/png':
			return False
		file_ext = mimetypes.guess_extension(filetype)
		return file_ext
	except Exception as err:
		print(err)
		write_log(f'{set_timestamp(new_time)} | | source: helper.file_filter_image | error: ${err} | | server\n')
		return False
	
def file_filter_resume(file):
	new_time = datetime.datetime.now()
	try:
		filetype = magic.from_buffer(file, mime=True)
		if filetype != 'application/pdf' and filetype != 'application/vnd.openxmlformats-officedocument.wordprocessingml.document':
			return False
		file_ext = mimetypes.guess_extension(filetype)
		return file_ext
	except Exception as err:
		print(err)
		write_log(f'{set_timestamp(new_time)} | | source: helper.file_filter_image | error: ${err} | | server\n')
		return False

# Creates unique name for storage of files, SHA-256 has sufficiently low collision probability for this use. Not intended as security measure
def name_file(filepath, file_ext):
	new_time = datetime.datetime.now()
	try:
		hasher = hashlib.sha256()
		with open(filepath, mode='rb') as f:
			chunk = 0
			while chunk != b'':
				chunk = f.read(1024)
				hasher.update(chunk)
			f.close()
		hasher.digest()
		return str(hasher.hexdigest() + file_ext)
	except Exception as err:
		print(err)
		write_log(f'{set_timestamp(new_time)} | | source: helper.name_file | error: ${err} | | server\n')
		return err

def limit_handler(ip, endpoint):
	print(ip, 'hi')
	return 'Too many requests'

def get_path_desc(path: str):
	match path:
		case '/':
			return 'root check'
		case '/register/seeker':
			return 'registration attempt: seeker'
		case '/register/employer':
			return 'registration attempt: employer'
		case '/login/seeker':
			return 'login attempt: seeker'
		case '/login/employer':
			return 'login attempt: employer'
		case '/job/search/get':
			return 'get attempt: jobs'
		case _:
			return 'other attempt'

def get_email(req_body: str):
	try:
		email: str = ''
		if 'email' in req_body:
			if not valid_san(req_body['email']):
				raise Exception()
			email = req_body['email']
		return email
	except:
		return ''
			

async def get_user(req: Request):
	new_time = datetime.datetime.now()
	params: dict
	try:
		params = await req.json()
		if not params['email']:
			return False
		return params['email']
	except Exception as err:
		print(err)
		write_log(f'{set_timestamp(new_time)} | | source: helper.get_user| error: ${err} | | server\n')
		return err



async def login(request: Request, email, passwd, table):
	time_now = unix_timestamp(get_new_time())
	try:
		users = None
		if table == 'seeker':
			request.state.cursor.execute(
				'''
				SELECT first_name, last_name, user_pass, email, hex(seeker_id) AS user_id FROM Seeker
					WHERE (email = %(email)s AND delete_flag = 0);
				''',
				{'email': email}
			)
			users = request.state.cursor.fetchone()
		elif table == 'employer':
			request.state.cursor.execute(
				'''
				SELECT first_name, last_name, user_pass, email, hex(employer_id) AS user_id, company FROM Employer
					WHERE (email = %(email)s AND delete_flag = 0);
				''',
				{'email': email}
			)
			users = request.state.cursor.fetchone()
		else:
			raise CustomException(status_code=500, error='failed login', detail='user logging in')
		if not users:
			raise CustomException(status_code=500, error='failed login', detail='user not found')
		db_password = users['user_pass'].encode()
		#hashed_password = 
		compare = bcrypt.checkpw(passwd, db_password)
		if not compare:
			raise CustomException(status_code=500, error='failed login', detail='incorrect password')
		payload: dict
		if table == 'seeker':
			payload = {
				'user_id': users['user_id'],
				'email': users['email'],
				'company': None,
				'type': table,
				'exp': time_now + (60*60*24*7*2)
			}
		elif table == 'employer':
			payload = {
				'user_id': users['user_id'],
				'email': users['email'],
				'company': users['company'],
				'type': table,
				'exp': time_now + (60*60*24*7*2)
			}
		if not payload:
			raise CustomException(status_code=500, error='failed login', detail='jwt failed')
		encoded_user = jwt.encode(payload=payload, key=jwt_key)
		if not encoded_user:
			raise CustomException(status_code=500, error='failed login', detail='jwt failed')
		if table == 'seeker':
			return {
				'id': users['user_id'],
				'email': users['email'],
				'company': None,
				'firstName': users['first_name'],
				'lastName': users['last_name'],
				'jwt': encoded_user
			}
		elif table == 'employer':
			return {
				'id': users['user_id'],
				'email': users['email'],
				'company': users['company'],
				'firstName': users['first_name'],
				'lastName': users['last_name'],
				'jwt': encoded_user
			}
	except Exception as err:
		print(err)
		if type(err) != CustomException:
			write_log(f'{set_timestamp(get_new_time())} | status: 500 | source: helper.login | error: {err} | | @{get_remote_address(request)}\n')
			return CustomException(status_code=500, error=err, detail='Internal server error')
		write_log(f'{set_timestamp(get_new_time())} | status: {err.status_code} | source: helper.login | error: {err.error} | reason: {err.detail} | @{get_remote_address(request)}\n')
		return err

async def custom_rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded) -> Response:
	"""
	Build a simple JSON response that includes the details of the rate limit
	that was hit. If no limit is hit, the countdown is added to headers.
	"""
	user = await get_user(request)
	if not user:
		write_log(f'{set_timestamp(datetime.datetime.now())} | status: 429 | source: {request.url.components.path} | error: Too Many Requests | | @{get_remote_address(request)}')
	else:
		write_log(f'{set_timestamp(datetime.datetime.now())} | status: 429 | source: {request.url.components.path} | error: Too Many Requests | | {user}@{get_remote_address(request)}')
	response = JSONResponse(
			{"error": f"Rate limit exceeded: {exc.detail}"}, status_code=429
	)
	response = request.app.state.limiter._inject_headers(
			response, request.state.view_rate_limit
	)
	return response