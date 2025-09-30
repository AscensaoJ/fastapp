from typing import Annotated, List
from fastapi import FastAPI, UploadFile, File, HTTPException, Request, Response, Security, Header, Path, Query, Body
from fastapi.responses import JSONResponse
from python.helper import *
from contextlib import asynccontextmanager
import datetime
import mysql.connector as mysql
from dotenv import load_dotenv
import os
import shutil
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer
import traceback # for testing
from fastapi.security import OAuth2PasswordBearer
import json

# Request body is expected to be JSON or file

# Limiter setup
limiter = Limiter(key_func=get_remote_address)

# Database setup
load_dotenv()
db = {
	'host': os.getenv('DB_HOST'),
	'user': os.getenv('DB_USER'),
	'password': os.getenv('DB_PASSWORD'),
	'database': os.getenv('DB_NAME')
}

pool = mysql.pooling.MySQLConnectionPool(
	pool_name='mypool',
	pool_size=10,
	**db
)

# bearer = HTTPBearer()

async def check_jwt(Authorization: Annotated[str | None, Header()] = None):
	print('Verify attempt: JWT')
	new_time = get_new_time()
	write_log(f'{set_timestamp(new_time)} | | source: JWT | info: verify attempt: JWT | | attempt\n')
	try:
		if Authorization == None:
			raise CustomException(status_code=400, error='failed JWT verify', detail='invalid authorization, no authorization headers')
		arr = Authorization.split(' ')
		if arr[0] != 'Bearer' or arr[1] == '':
			raise CustomException(status_code=400, error='failed JWT verify', detail='invalid authorization, invalid authorization scheme')
		try:
			user = jwt.decode(jwt=arr[1], key=jwt_key, algorithms='HS256')
			if not 'user_id' in user or not 'email' in user or not 'type' in user or not 'exp' in user:
				raise CustomException(status_code=400, error='failed JWT verify', detail='invalid authorization, invalid contents')
			email = user['email']
			write_log(f'{set_timestamp(new_time)} | | source: JWT | info: verified: JWT | | {email}\n')
			return user
		except Exception as err:
			msg = str(err)
			raise CustomException(status_code=400, error='failed JWT verify', detail=msg)
	except Exception as err:
		print(err)
		traceback.print_exc()
		if type(err) == CustomException:
			if err.status_code == 500:
				write_log(f'{set_timestamp(new_time)} | status: 500 | source: JWT | error: {err.error} | reason: {err.detail} |\n')
				raise HTTPException(status_code=err.status_code, detail='Internal server error')
			else:
				write_log(f'{set_timestamp(new_time)} | status: {err.status_code} | source: JWT | error: {err.error} | reason: {err.detail} |\n')
				raise HTTPException(status_code=err.status_code, detail=err.detail)
		else:
			write_log(f'{set_timestamp(new_time)} | status: 500 | source: JWT | error: {err} | |\n')
			raise HTTPException(status_code=500, detail='Internal server error')

# Startup and shut down function, yield is separator
@asynccontextmanager
async def lifespan(app: FastAPI):
	check_log()
	check_folders()
	write_log(f'{set_timestamp(datetime.datetime.now())} | info: server started\n')
	yield
	write_log(f'{set_timestamp(datetime.datetime.now())} | info: server closed\n')

# App setup
app = FastAPI(lifespan=lifespan)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, custom_rate_limit_exceeded_handler)
app.add_middleware(
	TrustedHostMiddleware, allowed_hosts=["localhost"]
)

# CORS setup
origins = [
	"http://localhost",
	"https://localhost"
]

app.add_middleware(
	CORSMiddleware,
	allow_origins=origins,
	allow_credentials=True,
	allow_methods=["*"],
	allow_headers=["*"],
)

# # MySQL setup middleware
@app.middleware('http')
async def mysql_db_pooled_handler_middleware(req: Request, call_next):
	new_time = datetime.datetime.now()
	response = None
	try:
		# req_body = await req.json()
		# write_log(f'{set_timestamp(new_time)} | | source: {req.url.components.path} | info: {get_path_desc(req.url.components.path)} | | attempt: {get_email(req_body)}@{get_remote_address(req)}\n')
		db2:mysql.pooling.PooledMySQLConnection = pool.get_connection()
		if db2.is_connected():
			req.state.cursor = db2.cursor(buffered=True, dictionary=True)
			req.state.cursor.execute('SET SESSION sql_mode = "TRADITIONAL"')
			req.state.cursor.execute('SET time_zone = "-8:00"')
			req.state.db = db2
			response = await call_next(req)

	except Exception as err:
		print(err)
		write_log(f'{set_timestamp(new_time)} | | source: helper.mysql_db_pooled_handler_middleware | error: {err} | | server\n')
		return err
	finally:
		if db2.is_connected():
			req.state.cursor.close()
			db2.commit()
			db2.close()
		if not response:
			return JSONResponse(status_code=500, content='Internal server error')
		return response

@app.get("/")

async def root():
	bob('hello')
	return {"message": "Hello World"}

# Register endpoint for job seeker
@app.post('/register/seeker')
@limiter.limit(limit_value='40/minute')
async def register_seeker(params: dict, request: Request, response: Response):
	print('registration attempt: seeker')
	new_time = get_new_time()
	first_name = params['firstName']
	last_name = params['lastName']
	passwd = params['pass']
	email = params['email']
	try:
		# Check if input exists and is safe
		if not first_name and not last_name and not passwd and not email:
			raise CustomException(status_code=400, error='failed seeker add', detail='missing field')
		if not valid_sa(first_name, 255) or not valid_sa(last_name, 255) or not valid_san(passwd, 255) or not valid_san(email, 255):
			raise CustomException(status_code=400, error='failed seeker add', detail='invalid input')
		write_log(f'{set_timestamp(new_time)} | | source: /register/seeker | info: Registration attempt: seeker | | attempt: {email}@{get_remote_address(request)}\n')
		check = None
		try:
			check = await check_user(request, email)
		except Exception as err:
			raise CustomException(status_code=500, error=err, detail='check failed')
		if not check:
			raise CustomException(status_code=500, error=err, detail='check failed')
		if check['exists'] != False:
			raise CustomException(status_code=400, error='failed seeker add', detail=check['reason'])
		# encrypt password, add user to database, respond to caller, and log successful registration
		passwd_bytes = passwd.encode(encoding="utf-8")
		has = bcrypt.hashpw(
			password=passwd_bytes,
			salt=bcrypt.gensalt()
			)
		request.state.cursor.execute(
			"INSERT INTO Seeker (seeker_id, first_name, last_name, user_pass, email)"
			"VALUES (uuid_to_bin(uuid()), %(first_name)s, %(last_name)s, %(pass)s, %(email)s);"
		,{
					'first_name': first_name,
					'last_name': last_name,
					'pass': has,
					'email': email
				})
		
		users = await login(request, email, passwd_bytes, table='seeker')
		if type(users) == CustomException:
			raise CustomException(status_code=users.status_code, error=users.error, detail=users.detail)
		return JSONResponse(status_code=200, content=users)
	except Exception as err:
		print(err)
		if type(err) == CustomException:
			if err.status_code == 500:
				write_log(f'{set_timestamp(new_time)} | status: 500 | source: /register/seeker | error: {err.error} | reason: {err.detail} | @{get_remote_address(request)}\n')
				raise HTTPException(status_code=err.status_code, detail='Internal server error')
			else:
				write_log(f'{set_timestamp(new_time)} | status: {err.status_code} | source: /register/seeker | error: {err.error} | reason: {err.detail} | @{get_remote_address(request)}\n')
				raise HTTPException(status_code=err.status_code, detail=err.detail)
		else:
			write_log(f'{set_timestamp(new_time)} | status: 500 | source: /register/seeker | error: {err} | | @{get_remote_address(request)}\n')
			raise HTTPException(status_code=500, detail='Internal server error')

# Register endpoint for employer
@app.post('/register/employer')
@limiter.limit('40/minute')
async def register_employer(params: dict, request: Request, response: Response):
	print('registration attempt: employer')
	new_time = get_new_time()
	first_name = params['firstName']
	last_name = params['lastName']
	passwd = params['pass']
	email = params['email']
	mobile = params['mobile']
	company = params['company']
	website = params['website']
	industry = params['industry']
	try:
		# Check if input exists and is safe
		if not first_name or not last_name or not passwd or not email or not mobile or not company or not website or not industry:
			raise CustomException(status_code=400, error='failed employer add', detail='missing field')
		if not valid_sa(first_name, 255) or not valid_sa(last_name, 255) or not valid_san(passwd, 255) or not valid_san(email, 255) or not valid_san(mobile, 15) or not valid_san(company, 255) or not valid_san(website, 2047) or not valid_a(industry, 255):
			raise CustomException(status_code=400, error='failed employer add', detail='invalid input')
		write_log(f'{set_timestamp(new_time)} | | source: /register/employer | info: Registration attempt: employer | | attempt: {email}@{get_remote_address(request)}\n')
		check = None
		try:
			check = await check_user(request, email)
		except Exception as err:
			raise CustomException(status_code=500, error=err, detail='check failed')
		if not check:
			raise CustomException(status_code=500, error=err, detail='check failed')
		if check['exists'] != False:
			raise CustomException(status_code=400, error='failed employer add', detail=check['reason'])
		# encrypt password, add user to database, respond to caller, and log successful registration
		passwd_bytes = passwd.encode(encoding="utf-8")
		has = bcrypt.hashpw(
			password=passwd_bytes,
			salt=bcrypt.gensalt()
			)
		request.state.cursor.execute(
			"INSERT INTO Employer (employer_id, first_name, last_name, user_pass, email, mobile, company, website, industry)"
			"VALUES (uuid_to_bin(uuid()), %(first_name)s, %(last_name)s, %(pass)s, %(email)s, %(mobile)s, %(company)s, %(website)s, %(industry)s);"
		,{
					'first_name': first_name,
					'last_name': last_name,
					'pass': has,
					'email': email,
					'mobile': mobile,
					'company': company,
					'website': website,
					'industry': industry
				})
		users = await login(request, email, passwd_bytes, table='employer')
		if type(users) == CustomException:
			raise CustomException(status_code=users.status_code, error=users.error, detail=users.detail)
		return JSONResponse(status_code=200, content=users)
	except Exception as err:
		print(err)
		if type(err) == CustomException:
			if err.status_code == 500:
				write_log(f'{set_timestamp(new_time)} | status: 500 | source: /register/employer | error: {err.error} | reason: {err.detail} | @{get_remote_address(request)}\n')
				raise HTTPException(status_code=err.status_code, detail='Internal server error')
			else:
				write_log(f'{set_timestamp(new_time)} | status: {err.status_code} | source: /register/employer | error: {err.error} | reason: {err.detail} | @{get_remote_address(request)}\n')
				raise HTTPException(status_code=err.status_code, detail=err.detail)
		else:
			write_log(f'{set_timestamp(new_time)} | status: 500 | source: /register/employer | error: {err} | | @{get_remote_address(request)}\n')
			raise HTTPException(status_code=500, detail='Internal server error')

@app.post('/login/seeker')
@limiter.limit(limit_value='40/minute')
async def login_seeker(params: dict, request: Request, response: Response):
	print('login attempt: seeker')
	new_time = get_new_time()
	email = params['email']
	passwd = params['pass']
	try:
		# Check if input exists and is safe
		if not passwd or not email:
			raise CustomException(status_code=400, error='failed seeker login', detail='missing field')
		if not valid_san(passwd, 255) or not valid_san(email, 255):
			raise CustomException(status_code=400, error='failed seeker login', detail='invalid input')
		write_log(f'{set_timestamp(new_time)} | | source: /login/seeker | info: Login attempt: seeker | | attempt: {email}@{get_remote_address(request)}\n')
		check = None
		try:
			check = await check_user(request, email)
		except Exception as err:
			raise CustomException(status_code=500, error=err, detail='check failed')
		if not check:
			raise CustomException(status_code=500, error=err, detail='check failed')
		if check['exists'] == False:
			raise CustomException(status_code=400, error='failed seeker login', detail=check['reason'])
		passwd_bytes = passwd.encode(encoding="utf-8")
		users = await login(request, email, passwd_bytes, table='seeker')
		if type(users) == CustomException:
			raise CustomException(status_code=users.status_code, error=users.error, detail=users.detail)
		return JSONResponse(status_code=200, content=users)
	except Exception as err:
		print(err)
		if type(err) == CustomException:
			if err.status_code == 500:
				write_log(f'{set_timestamp(new_time)} | status: 500 | source: /login/seeker | error: {err.error} | reason: {err.detail} | @{get_remote_address(request)}\n')
				raise HTTPException(status_code=err.status_code, detail='Internal server error')
			else:
				write_log(f'{set_timestamp(new_time)} | status: {err.status_code} | source: /login/seeker | error: {err.error} | reason: {err.detail} | @{get_remote_address(request)}\n')
				raise HTTPException(status_code=err.status_code, detail=err.detail)
		else:
			write_log(f'{set_timestamp(new_time)} | status: 500 | source: /login/seeker | error: {err} | | @{get_remote_address(request)}\n')
			raise HTTPException(status_code=500, detail='Internal server error')

@app.post('/login/employer')
@limiter.limit(limit_value='40/minute')
async def login_employer(params: dict, request: Request, response: Response):
	print('login attempt: employer')
	new_time = get_new_time()
	email = params['email']
	passwd = params['pass']
	try:
		# Check if input exists and is safe
		if not passwd or not email:
			raise CustomException(status_code=400, error='failed employer login', detail='missing field')
		if not valid_san(passwd, 255) or not valid_san(email, 255):
			raise CustomException(status_code=400, error='failed employer login', detail='invalid input')
		write_log(f'{set_timestamp(new_time)} | | source: /login/employer | info: Login attempt: employer | | attempt: {email}@{get_remote_address(request)}\n')
		check = None
		try:
			check = await check_user(request, email)
		except Exception as err:
			raise CustomException(status_code=500, error=err, detail='check failed')
		if not check:
			raise CustomException(status_code=500, error=err, detail='check failed')
		if check['exists'] == False:
			raise CustomException(status_code=400, error='failed employer login', detail=check['reason'])
		passwd_bytes = passwd.encode(encoding="utf-8")
		users = await login(request, email, passwd_bytes, table='employer')
		if type(users) == CustomException:
			raise CustomException(status_code=users.status_code, error=users.error, detail=users.detail)
		return JSONResponse(status_code=200, content=users)
	except Exception as err:
		print(err)
		if type(err) == CustomException:
			if err.status_code == 500:
				write_log(f'{set_timestamp(new_time)} | status: 500 | source: /login/employer | error: {err.error} | reason: {err.detail} | @{get_remote_address(request)}\n')
				raise HTTPException(status_code=err.status_code, detail='Internal server error')
			else:
				write_log(f'{set_timestamp(new_time)} | status: {err.status_code} | source: /login/employer | error: {err.error} | reason: {err.detail} | @{get_remote_address(request)}\n')
				raise HTTPException(status_code=err.status_code, detail=err.detail)
		else:
			write_log(f'{set_timestamp(new_time)} | status: 500 | source: /login/employer | error: {err} | | @{get_remote_address(request)}\n')
			raise HTTPException(status_code=500, detail='Internal server error')

# Search job postings endpoint
@app.get('/job/search/get')
@limiter.limit(limit_value='60/second')
async def job_search_get(request: Request, response: Response, startIndex: int = 1, perPage: int = 10, key: str = None, loc: str = None, rem: str = None, ind: str = None, exp: str = None, emp: str = None, size: str = None, sal: str = None, ben: str = None, cert: str = None):
	print('search attempt: jobs')
	new_time = get_new_time()
	write_log(f'{set_timestamp(new_time)} | | source: /job/search/get | info: get attempt: jobs | | @{get_remote_address(request)}\n')
	keywords = None
	location = None
	remote = True
	industry = None
	experience_level = None
	employment_type = None
	company_size = None
	salary_range = None
	benefits = None
	certifications = None
	try:
		if perPage > 100:
			raise CustomException(status_code=400, error='failed get attempt: jobs', detail='jobs per page too high')
		args = {'start_index': startIndex, 'per_page': perPage}
		search_query = 'SELECT job_id, company, city, state, is_remote, salary_low, salary_high, employment_type FROM Job WHERE (job_id >= %(start_index)s'
		if rem == 'false':
			remote = False
		if remote:
			search_query += ' AND is_remote = 1'
		elif loc != None:
			if not valid_san(loc):
				raise CustomException(status_code=400, error='failed get attempt: jobs', detail='invalid location')
			search_query += ' AND city = %(city)s AND state = %(state)s'
			location = loc.split('-')
			if len(location) != 2:
				raise CustomException(status_code=400, error='failed get attempt: jobs', detail='invalid location')
			args['city'] = location[0]
			args['state'] = location[1]
		if ind != None:
			if not valid_san(ind):
				raise CustomException(status_code=400, error='failed get attempt: jobs', detail='invalid industry')
			search_query += ' AND industry = %(industry)s'
			args['industry'] = industry
		if exp != None:
			if not valid_san(exp):
				raise CustomException(status_code=400, error='failed get attempt: jobs', detail='invalid experience level')
			search_query += ' AND experience_level = %(experience_level)s'
			args['experience_level'] = experience_level
		if emp != None:
			if not valid_san(emp):
				raise CustomException(status_code=400, error='failed get attempt: jobs', detail='invalid employment type')
			search_query += ' AND employment_type = %(employment_type)s'
			args['employment_type'] = employment_type
		if sal != None:
			low = 1
			high = 999999
			dash = False
			try:
				sal.index('-')
				dash = True
			except:
				pass
			if dash == True:
				salary_range = sal.split('-')
				exist = False
				try:
					valid_a(salary_range[0])
					exist = True
				except:
					pass
				if exist == True:
					low = int(salary_range[0])
					args['low'] = int(salary_range[0])
					search_query += ' AND salary_low >= %(low)s'
				high = int(salary_range[1])
				args['high'] = int(salary_range[1])
				search_query += ' AND salary_high <= %(high)s'
			else:
				low = int(sal)
				args['low'] = int(sal)
				search_query += ' AND salary_low >= %(low)s'
			if not valid_n(low) or not valid_n(high):
				raise CustomException(status_code=400, error='failed get attempt: jobs', detail='salary out of range')
		if ben != None:
			if not valid_san(ben):
				raise CustomException(status_code=400, error='failed get attempt: jobs', detail='invalid benefits')
			dash = False
			try:
				ben.index('-')
				dash = True
			except:
				pass
			if dash == True:
				benefits = ben.split('-')
				for i in range(len(benefits)):
					search_query += f' AND locate(%(ben{i})s, JSON_EXTRACT(job.benefits, "$[*]")) > 0'
					args[f'ben{str(i)}'] = benefits[i]
			else:
				search_query += ' AND locate(%(benefits), JSON_EXTRACT(job.benefits, "$[*]")) > 0'
				args['benefits'] = ben
		if cert != None:
			if not valid_san(cert):
				raise CustomException(status_code=400, error='failed get attempt: jobs', detail='invalid certifications')
			dash = False
			try:
				cert.index('-')
				dash = True
			except:
				pass
			if dash == True:
				certifications = cert.split('-')
				for i in range(len(certifications)):
					search_query += f' AND locate(%(cert{i})s, JSON_EXTRACT(job.benefits, "$[*]")) > 0'
					args[f'cert{str(i)}'] = certifications[i]
			else:
				search_query += ' AND locate(%(certifications)s, JSON_EXTRACT(job.benefits, "$[*]")) > 0'
				args['certifications'] = cert
		if key != None:
			query_str = ''
			good = valid_kwargs(key)
			if not good:
				raise CustomException(status_code=400, error='failed get attempt: jobs', detail='malformed query')
			quote = False
			try:
				key.index('"')
				quote = True
			except:
				pass
			if quote == True:
				substr: list = []
				substrquote = key.split('"')
				for i in range(len(substrquote)):
					if not valid_san(substrquote[i], 1023) and substrquote[i] != '':
						raise CustomException(status_code=400, error='failed get attempt: jobs', detail='malformed query')
					if substrquote[i] == '':
						continue
					if i % 2 == 0:
						space = False
						try:
							substrquote[i].index(' ')
							space = True
						except:
							pass
						if space == True:
							temp = substrquote[i].split(' ')
							for j in temp:
								substr.append(j)
						else:
							substr.append(substrquote[i])
					else:
						temp = '+"' + substrquote[i] + '"'
						substr.append(temp)
				print(substr)
				for i in range(len(substr)):
					if len(substr[i]) == 0:
						continue
					if not i + 1 >= len(substr):
						substr[i] += ' '
					query_str += substr[i]
			else:
				if not valid_san(key, 2047):
					raise CustomException(status_code=400, error='failed get attempt: jobs', detail='malformed query')
				query_str = key
			search_query += ' AND MATCH (title, job_description, company, industry, experience_level, employment_type) AGAINST (%(keywords)s IN BOOLEAN MODE)'
			args['keywords'] = query_str
		search_query += ') LIMIT %(per_page)s;'
		request.state.cursor.execute(search_query, args)
		jobs = request.state.cursor.fetchall()
		write_log(f'${set_timestamp(new_time)} | status: 200 | source: /job/search/get | success: search successful | | @${get_remote_address(request)}\n')
		return JSONResponse(status_code=200, content={'success': True, 'jobs': jobs})
	except Exception as err:
		print(err)
		if type(err) == CustomException:
			if err.status_code == 500:
				write_log(f'{set_timestamp(new_time)} | status: 500 | source: /login/employer | error: {err.error} | reason: {err.detail} | @{get_remote_address(request)}\n')
				raise HTTPException(status_code=err.status_code, detail='Internal server error')
			else:
				write_log(f'{set_timestamp(new_time)} | status: {err.status_code} | source: /login/employer | error: {err.error} | reason: {err.detail} | @{get_remote_address(request)}\n')
				raise HTTPException(status_code=err.status_code, detail=err.detail)
		else:
			write_log(f'{set_timestamp(new_time)} | status: 500 | source: /login/employer | error: {err} | | @{get_remote_address(request)}\n')
			raise HTTPException(status_code=500, detail='Internal server error')

# Get job details
@app.get('/job/{job_id}/get')
@limiter.limit(limit_value='100/second')
async def get_job_details(job_id, request: Request, response: Response):
	new_time = get_new_time()
	write_log(f'{set_timestamp(new_time)} | | source: /job/{job_id}/get | info: get attempt: job | | attempt: @${get_remote_address(request)}\n')
	try:
		request.state.cursor.execute(
			'''
			SELECT CASE
				WHEN EXISTS(
					SELECT 1
					FROM Job
					WHERE (job_id = %(job_id)s))
				THEN(
					SELECT delete_flag
					FROM Job
					WHERE job_id = %(job_id)s)
				ELSE NULL
			END AS exist;
			''',{
				'job_id': job_id
			}
		)
		exist = request.state.cursor.fetchone()['exist']
		match exist:
			case 0:
				pass
			case 1 | None:
				raise CustomException(status_code=404, error='failed job get', detail='job not found')
			case _:
				raise CustomException(status_code=500, error='failed job get', detail='search defaulted')
		request.state.cursor.execute(
			'''
			SELECT title, company, city, state, is_remote, industry, website, experience_level, employment_type, company_size, salary_low, salary_high, benefits, certifications, job_description, questions, date_created, expires, date_expires
			FROM Job
			WHERE job_id = %(job_id)s;
			''',{
				'job_id': job_id
			}
		)
		job = request.state.cursor.fetchone()
		dat:datetime.datetime = job['date_created']
		date_iso = dat.isoformat()
		job['date_created'] = date_iso
		if job['expires'] == 1:
			dat:datetime.datetime = job['date_expires']
			date_iso = dat.isoformat()
			job['date_expires'] = date_iso
		write_log(f'{set_timestamp(new_time)} | status: 200 | source: /job/{job_id}/get | success: got job {job_id} | | @{get_remote_address(request)}\n')
		return JSONResponse(status_code=200, content={'success': True, 'job': job})
	except Exception as err:
		print(err)
		if type(err) == CustomException:
			if err.status_code == 500:
				write_log(f'{set_timestamp(new_time)} | status: 500 | source: /login/employer | error: {err.error} | reason: {err.detail} | @{get_remote_address(request)}\n')
				raise HTTPException(status_code=err.status_code, detail='Internal server error')
			else:
				write_log(f'{set_timestamp(new_time)} | status: {err.status_code} | source: /login/employer | error: {err.error} | reason: {err.detail} | @{get_remote_address(request)}\n')
				raise HTTPException(status_code=err.status_code, detail=err.detail)
		else:
			write_log(f'{set_timestamp(new_time)} | status: 500 | source: /login/employer | error: {err} | | @{get_remote_address(request)}\n')
			raise HTTPException(status_code=500, detail='Internal server error')

@app.post('/forgot-password')
@limiter.limit(limit_value='12/hour')
async def forgot_password(params: dict, request: Request, response:Response):
	return JSONResponse(status_code=200, content={'success': True, 'info': 'not yet implemented'})


# Access controlled endpoints

@app.post('/job/add')
@limiter.limit(limit_value='5/minute')
async def add_job(params: dict, request: Request, response: Response, user: Annotated[dict, Security(check_jwt)]):
	new_time = get_new_time()
	new_timestamp = unix_timestamp(new_time)
	try:
		if user['type'] != 'employer':
			raise CustomException(status_code=403, error='failed job add', detail='forbidden')
		print('Add attempt: job')
		email = user['email']
		write_log(f'{set_timestamp(new_time)} | | source: /job/add | info: add attempt: job | | attempt: {email}@{get_remote_address(request)}\n')
		# Input check and validation, must send null for empty or unused values
		if not 'title' in params or not 'city' in params or not 'state' in params or not 'isRemote' in params or not 'experienceLevel' in params or not 'employmentType' in params or not 'companySize' in params or not 'salaryLow' in params or not 'salaryHigh' in params or not 'jobDescription' in params or not 'expDate' in params or not 'questions' in params:
			raise CustomException(status_code=400, error='failed job add', detail='missing field')
		is_remote = params['isRemote']
		title = params['title']
		city = params['city']
		state = params['state']
		experience_level = params['experienceLevel']
		employment_type = params['employmentType']
		company_size = params['companySize']
		salary_low = params['salaryLow']
		salary_high = params['salaryHigh']
		benefits = params['benefits']
		certifications = params['certifications']
		job_description = params['jobDescription']
		exp_date = params['expDate']
		questions = params['questions']
		valid_exp_dates = valid_exp_date(exp_date)
		if not valid_san(title, 255) or not valid_a(city, 255) or not valid_state(state) or not valid_a(experience_level, 255) or not valid_san(employment_type, 255) or not valid_san(company_size, 255) or not valid_n(salary_low) or not valid_n(salary_high) or not valid_json(benefits) or not valid_json(certifications) or not valid_san(job_description, 600) or not valid_json(questions) or not valid_exp_dates == True or not type(is_remote) == bool:
			raise CustomException(status_code=400, error='failed job add', detail='invalid input')
		# Check if user authorized to add job
		check: bool
		try:
			check = check_auth(request, user['user_id'], user['company'])
		except Exception as err:
			errstr = str(err)
			raise CustomException(status_code=500, error=errstr, detail='authorization failed')
		if check == False:
			raise CustomException(status_code=403, error='failed job add', detail='failed approval')
		# Get employer info and add job to database
		try:
			request.state.cursor.execute(
				'SELECT industry, website FROM Employer WHERE employer_id = UNHEX(%(user_id)s);',
				{'user_id': user['user_id']}
			)
			employer = request.state.cursor.fetchone()
			ben_json = None
			if benefits != None:
				ben_json = json.dumps(benefits, separators=(',', ':'))
			cert_json = None
			if certifications != None:
				cert_json = json.dumps(certifications, separators=(',', ':'))
			ques_json = None
			if questions != None:
				ques_json = json.dumps(questions, separators=(',', ':'))
			expire = False
			exp_date_f = None
			new_time_f = new_time.strftime('%Y-%m-%d %H:%M:%S')
			if exp_date != None:
				expire = True
				arr = str.split(exp_date, '-')
				exp = datetime.datetime(int(arr[0]), int(arr[1]), int(arr[2]))
				exp_date_f = exp.strftime('%Y-%m-%d %H:%M:%S')
			request.state.cursor.execute(
				'''
				INSERT INTO Job (title, company, city, state, is_remote, industry, website, experience_level, employment_type, company_size, salary_low, salary_high, benefits, certifications, job_description, questions, employer_id, date_created, expires, date_expires)
        VALUES (%(title)s, %(company)s, %(city)s, %(state)s, %(is_remote)s, %(industry)s, %(website)s, %(experience_level)s, %(employment_type)s, %(company_size)s, %(salary_low)s, %(salary_high)s, %(benefits)s, %(certifications)s, %(job_description)s, %(questions)s, UNHEX(%(employer_id)s), %(date_created)s, %(expires)s, %(date_expires)s);
				'''
			,{
				'title': title,
        'company': user['company'],
        'city': city,
        'state': state,
        'is_remote': is_remote,
        'industry': employer['industry'],
        'website': employer['website'],
        'experience_level': experience_level,
        'employment_type': employment_type,
        'company_size': company_size,
        'salary_low': salary_low,
        'salary_high': salary_high,
        'benefits': ben_json,
        'certifications': cert_json,
        'job_description': job_description,
        'questions': ques_json,
        'employer_id': user['user_id'],
        'date_created': new_time_f,
        'expires': expire,
        'date_expires': exp_date_f
			})
			request.state.db.commit()
			request.state.cursor.execute(
				'''
				SELECT job_id FROM Job 
        WHERE employer_id = UNHEX(%(user_id)s)
        ORDER BY date_created DESC
        LIMIT 1;
				''',{
					'user_id': user['user_id']
				}
			)
			job_id = request.state.cursor.fetchone()['job_id']
			print(job_id)
			email = user['email']
			company = user['company']
			write_log(f'{set_timestamp(new_time)} | status: 201 | source: /job/add | success: {email} @ {company} added job id: {job_id} | | @{get_remote_address(request)}\n')
			return JSONResponse(status_code=201, content={'success': True, 'jobId': job_id})
		except Exception as err:
			errstr = str(err)
			raise CustomException(status_code=500, error='failed job add', detail=errstr)
	except Exception as err:
		print(err)
		if type(err) == CustomException:
			if err.status_code == 500:
				write_log(f'{set_timestamp(new_time)} | status: 500 | source: /login/employer | error: {err.error} | reason: {err.detail} | @{get_remote_address(request)}\n')
				raise HTTPException(status_code=err.status_code, detail='Internal server error')
			else:
				write_log(f'{set_timestamp(new_time)} | status: {err.status_code} | source: /login/employer | error: {err.error} | reason: {err.detail} | @{get_remote_address(request)}\n')
				raise HTTPException(status_code=err.status_code, detail=err.detail)
		else:
			write_log(f'{set_timestamp(new_time)} | status: 500 | source: /login/employer | error: {err} | | @{get_remote_address(request)}\n')
			raise HTTPException(status_code=500, detail='Internal server error')

# Add resume endpoint
@app.post('/resume/add')
@limiter.limit(limit_value='12/minute')
async def add_resume(params: dict, request: Request, response: Response, user: Annotated[dict, Security(check_jwt)]):
	print('Add attempt: resume')
	new_time = get_new_time()
	write_log(f'{set_timestamp(new_time)} | | source: /resume/add | info: add attempt: resume | | attempt: {user["email"]}@{get_remote_address(request)}\n')
	try:
		# Input check and validation, send null for empty or unused fields
		if not 'summary' in params or not 'education' in params or not 'experience' in params or not 'skill' in params or not 'link' in params or not 'publication' in params:
			raise CustomException(status_code=400, error='failed resume add', detail='missing field')
		summary = params['summary']
		education = params['education']
		experience = params['experience']
		skill = params['skill']
		link = params['link']
		publication = params['publication']
		if summary == None:
			raise CustomException(status_code=400, error='failed resume add', detail='missing field')
		if not valid_san(summary, 600):
			raise CustomException(status_code=400, error='failed resume add', detail='invalid input')
		if not valid_json(education):
			raise CustomException(status_code=400, error='failed resume add', detail='invalid input')
		if not valid_json(experience):
			raise CustomException(status_code=400, error='failed resume add', detail='invalid input')
		if not valid_json(skill):
			raise CustomException(status_code=400, error='failed resume add', detail='invalid input')
		if not valid_json(link):
			raise CustomException(status_code=400, error='failed resume add', detail='invalid input')
		if not valid_json(publication):
			raise CustomException(status_code=400, error='failed resume add', detail='invalid input')
		check: dict
		try:
			check = await check_user(request, user['email'])
		except Exception as err:
			errstr = str(err)
			raise CustomException(status_code=500, error=errstr, detail='check failed')
		if check['exists'] == False:
			raise CustomException(status_code=400, error='failed resume add', detail=check['reason'])
		sql_strs = []
		entries = [0,0,0,0,0]
		entries_total = 0
		args = []
		if education != None:
			list_ed = education.values()
			sql_str = "INSERT INTO Education (seeker_id, institution_name, education_level, education_field, date_start, date_end, present) VALUES(UNHEX(%(user_id)s), %(institution_name)s, %(education_level)s, %(education_field)s, %(date_start)s, %(date_end)s, %(present)s);"
			date_end = None
			if len(list_ed) > 2:
				raise CustomException(status_code=400, error='failed resume add', detail='too many education inputs')
			valid: bool
			i = 0
			for entry in list_ed:
				if not 'institutionName' in entry or not 'educationLevel' in entry or not 'educationField' in entry or not 'dateStart' in entry or type(entry['present']) != bool:
					valid = False
					break
				if not valid_san(entry['institutionName'], 255) or not valid_san(entry['educationLevel'], 255) or not valid_san(entry['educationField'], 255) or not valid_date(entry['dateStart']):
					valid = False
					break
				if entry['dateEnd'] != None and not valid_date(entry['dateEnd']):
					valid = False
					break
				if entry['dateEnd'] == None and entry['present'] == False:
					valid = False
					break
				if entry['dateEnd'] != None and entry['present'] == True:
					valid = False
					break
				if entry['dateEnd'] != None and valid_date(entry['dateEnd']):
					if not valid_dates(entry['dateStart'], entry['dateEnd']):
						valid = False
						break
					else:
						date = entry['dateEnd'].split('-')
						date_end = datetime.date(int(date[0]), int(date[1]), 1)
				valid = True		
				date = entry['dateStart'].split('-')
				date_start = datetime.date(int(date[0]), int(date[1]), 1)
				sql_args = {
					'user_id': user['user_id'],
					'institution_name': entry['institutionName'],
					'education_level': entry['educationLevel'],
					'education_field': entry['educationField'],
					'date_start': date_start,
					'date_end': date_end,
					'present': entry['present']
				}
				sql_strs.append(sql_str)
				args.append(sql_args)
				i+=1
			if not valid:
				raise CustomException(status_code=400, error='failed resume add', detail='invalid education input')
			entries[0] = i
			entries_total += i
		if experience != None:
			list_ex = experience.values()
			sql_str = "INSERT INTO Experience (seeker_id, job_title, company_name, remote, address, city, state, date_start, date_end, present, job_description) VALUES(UNHEX(%(user_id)s), %(job_title)s, %(company_name)s, %(remote)s, %(address)s, %(city)s, %(state)s, %(date_start)s, %(date_end)s, %(present)s, %(job_description)s);"
			date_end = None
			if len(list_ex) > 3:
				raise CustomException(status_code=400, error='failed resume add', detail='too many experience inputs')
			valid: bool
			i = 0
			for entry in list_ex:
				if not 'jobTitle' in entry or not 'companyName' in entry or not 'address' in entry or not 'city' in entry or not 'state' in entry or not 'dateStart' in entry or type(entry['remote']) != bool or type(entry['present']) != bool or not 'jobDescription' in entry:
					valid = False
					break
				if not valid_san(entry['jobTitle'], 255) or not valid_san(entry['companyName'], 255) or not valid_san(entry['city'], 255) or not valid_state(entry['state']) or not valid_date(entry['dateStart']):
					valid = False
					break
				if entry['dateEnd'] != None and not valid_date(entry['dateEnd']):
					valid = False
					break
				if entry['dateEnd'] == None and entry['present'] == False:
					valid = False
					break
				if entry['dateEnd'] != None and entry['present'] == True:
					valid = False
					break
				if entry['dateEnd'] != None and valid_date(entry['dateEnd']):
					if not valid_dates(entry['dateStart'], entry['dateEnd']):
						valid = False
						break
					else:
						date = entry['dateEnd'].split('-')
						date_end = datetime.date(int(date[0]), int(date[1]), 1)
				if entry['address'] == None and entry['remote'] == False:
					valid = False
					break
				if entry['address'] != None and entry['remote'] == True:
					valid = False
					break
				if entry['jobDescription'] != None and not valid_san(entry['jobDescription'], 600):
					valid = False
					break
				date = entry['dateStart'].split('-')
				date_start = datetime.date(int(date[0]), int(date[1]), 1)
				sql_args = {
					'user_id': user['user_id'],
					'job_title': entry['jobTitle'],
					'company_name': entry['companyName'],
					'address': entry['address'],
					'city': entry['city'],
					'state': entry['state'],
					'date_start': date_start,
					'date_end': date_end,
					'present': entry['present'],
					'remote': entry['remote'],
					'job_description': entry['jobDescription']
				}
				sql_strs.append(sql_str)
				args.append(sql_args)
				i+=1
			if not valid:
				raise CustomException(status_code=400, error='failed resume add', detail='invalid experience input')
			entries[1] = i
			entries_total += i
		if skill != None:
			list_sk = skill.values()
			sql_str = "INSERT INTO Skill (seeker_id, skill_name, skill_years) VALUES(UNHEX(%(user_id)s), %(skill_name)s, %(skill_years)s);"
			if len(list_sk) > 25:
				raise CustomException(status_code=400, error='failed resume add', detail='too many skill inputs')
			valid: bool
			i = 0
			for entry in list_sk:
				if not 'skillName' in entry or not 'skillYears' in entry:
					valid = False
					break
				if not valid_san(entry['skillName'], 255) or not valid_n(entry['skillYears']):
					valid = False
					break
				if len(entry['skillName']) > 255 or len(entry['skillYears']) > 50 or len(entry['skillYears']) < 1:
					valid = False
					break
				sql_args = {
					'user_id': user['user_id'],
					'skill_name': entry['skillName'],
					'skill_years': entry['skillYears']
				}
				sql_strs.append(sql_str)
				args.append(sql_args)
				i+=1
			if not valid:
				raise CustomException(status_code=400, error='failed resume add', detail='invalid skill input')
			entries[2] = i
			entries_total += i
		if link != None:
			list_lk = link.values()
			sql_str = "INSERT INTO Url (seeker_id, link_name, link_url) VALUES(UNHEX(%(user_id)s), %(link_name)s, %(link_url)s);"
			if len(list_lk) > 5:
				raise CustomException(status_code=400, error='failed resume add', detail='too many experience inputs')
			valid: bool
			i = 0
			for entry in list_lk:
				if not 'linkName' in entry or not 'linkUrl' in entry:
					valid = False
					break
				if not valid_san(entry['linkName'], 255) or not valid_san(entry['linkUrl'], 2047):
					valid = False
					break
				if entry['dateEnd'] != None and not valid_date(entry['dateEnd']):
					valid = False
					break
				sql_args = {
					'link_name': user['linkName'],
					'link_url': entry['linkUrl']
				}
				sql_strs.append(sql_str)
				args.append(sql_args)
				i+=1
			if not valid:
				raise CustomException(status_code=400, error='failed resume add', detail='invalid experience input')
			entries[3] = i
			entries_total += i
		if publication != None:
			list_pb = publication.values()
			sql_str = "INSERT INTO Publication (seeker_id, publication_name, publication_url, publication_date, publication_summary) VALUES(UNHEX(%(user_id)s), %(publication_name)s, %(publication_url)s, %(publication_date)s, %(publication_summary)s);"
			if len(list_ed) > 3:
				raise CustomException(status_code=400, error='failed resume add', detail='too many experience inputs')
			valid: bool
			i = 0
			for entry in list_pb:
				if not 'jobTitle' in entry or not 'pubName' in entry or not 'pubUrl' in entry or not 'pubDate' in entry or not 'pubSummary' in entry:
					valid = False
					break
				if not valid_san(entry['pubName'], 255) or not valid_san(entry['pubUrl'], 2047) or not valid_date(entry['pubDate']) or not valid_san(entry['pubSummary'], 600):
					valid = False
					break
				date = entry['pubDate'].split('-')
				date_pub = datetime.date(int(date[0]), int(date[1]), 1)
				sql_args = {
					'user_id': user['user_id'],
					'publication_name': entry['pubName'],
					'publication_url': entry['pubUrl'],
					'publication_date': date_pub,
					'publication_summary': entry['pubSummary']
				}
				sql_strs.append(sql_str)
				args.append(sql_args)
				i+=1
			if not valid:
				raise CustomException(status_code=400, error='failed resume add', detail='invalid publication input')
			entries[4] = i
			entries_total += i
		if len(sql_strs) != len(args) or len(args) != entries_total:
			raise CustomException(status_code=500, error='failed resume add', detail='stings, args, entries miscount')
		sql_strs.append('UPDATE Seeker SET summary = %(summary)s, education_entries = %(education_entries)s, experience_entries = %(experience_entries)s, skill_entries = %(skill_entries)s, link_entries = %(link_entries)s, publication_entries = %(publication_entries)s WHERE seeker_id = UNHEX(%(user_id)s);')
		args.append({
			'summary': summary,
			'education_entries': entries[0],
			'experience_entries': entries[1],
			'skill_entries': entries[2],
			'link_entries': entries[3],
			'publication_entries': entries[4],
			'user_id': user['user_id']
		})
		entries_total += 1
		tables = ['Education', 'Experience', 'Skill', 'Url', 'Publication']
		for entry in tables:
			request.state.cursor.execute(
				"DELETE "
					f"FROM {entry} "
					"WHERE seeker_id = UNHEX(%(user_id)s);"
			,{
				'user_id': user['user_id']
			})
		request.state.db.commit()
		for i in range(entries_total):
			sql_str = sql_strs[i]
			sql_arg = args[i]
			request.state.cursor.execute(sql_str, sql_arg)
	except Exception as err:
		print(err)
		if type(err) == CustomException:
			if err.status_code == 500:
				write_log(f'{set_timestamp(new_time)} | status: 500 | source: /resume/add | error: {err.error} | reason: {err.detail} | @{get_remote_address(request)}\n')
				raise HTTPException(status_code=err.status_code, detail='Internal server error')
			else:
				write_log(f'{set_timestamp(new_time)} | status: {err.status_code} | source: /resume/add | error: {err.error} | reason: {err.detail} | @{get_remote_address(request)}\n')
				raise HTTPException(status_code=err.status_code, detail=err.detail)
		else:
			write_log(f'{set_timestamp(new_time)} | status: 500 | source: /resume/add | error: {err} | | @{get_remote_address(request)}\n')
			raise HTTPException(status_code=500, detail='Internal server error')

@app.get('/resume')
@limiter.limit('40/minute')
async def get_resume(request: Request, response: Response, user: Annotated[dict, Security(check_jwt)]):
	new_time = get_new_time()
	print('Get attempt: resume')
	try:
		write_log(f'{set_timestamp(new_time)} | | source: /resume | info: get attempt: resume | | {user["email"]}@{get_remote_address(request)}\n')
		check: dict
		try:
			check = await check_user(request, user['email'])
		except Exception as err:
			errstr = str(err)
			raise CustomException(status_code=500, error=errstr, detail='check failed')
		if check['exists'] == False:
			raise CustomException(status_code=400, error='failed get attempt: resume', detail=check['reason'])
		request.state.cursor.execute(
			'''
				SELECT first_name, last_name, email, summary
				FROM Seeker
				WHERE seeker_id = UNHEX(%(user_id)s);
			''',{
				'user_id': user['user_id']
			}
		)
		seeker = request.state.cursor.fetchone()
		request.state.cursor.execute(
			'''
				SELECT institution_name, education_level, education_field, date_start, date_end, present
        FROM Education
				WHERE seeker_id = UNHEX(%(user_id)s);
			''',{
				'user_id': user['user_id']
			}
		)
		education = request.state.cursor.fetchall()
		request.state.cursor.execute(
			'''
				SELECT job_title, company_name, address, city, state, date_start, date_end,  present, remote, job_description
        FROM Experience
				WHERE seeker_id = UNHEX(%(user_id)s);
			''',{
				'user_id': user['user_id']
			}
		)
		experience = request.state.cursor.fetchall()
		request.state.cursor.execute(
			'''
				SELECT skill_name, skill_years
        FROM Skill
				WHERE seeker_id = UNHEX(%(user_id)s);
			''',{
				'user_id': user['user_id']
			}
		)
		skill = request.state.cursor.fetchall()
		request.state.cursor.execute(
			'''
				SELECT link_name, link_url
        FROM Url
				WHERE seeker_id = UNHEX(%(user_id)s);
			''',{
				'user_id': user['user_id']
			}
		)
		link = request.state.cursor.fetchall()
		request.state.cursor.execute(
			'''
				SELECT publication_name, publication_url, publication_date, publication_summary
        FROM Publication
				WHERE seeker_id = UNHEX(%(user_id)s);
			''',{
				'user_id': user['user_id']
			}
		)
		publication = request.state.cursor.fetchall()
		if education == []:
			education = None
		if experience == []:
			experience = None
		if skill == []:
			skill = None
		if link == []:
			link = None
		if publication == []:
			publication = None
		write_log(f'{set_timestamp(new_time)} | status: 200 | source: /resume | success: get attempt: resume | | @{get_remote_address(request)}\n')
		response.status_code = 200
		return {
			'seeker': seeker,
			'education': education,
			'experience': experience,
			'skill': skill,
			'link': link,
			'publication': publication
		}
	except Exception as err:
		print(err)
		traceback.print_exc()
		if type(err) == CustomException:
			if err.status_code == 500:
				write_log(f'{set_timestamp(new_time)} | status: 500 | source: /resume | error: {err.error} | reason: {err.detail} | @{get_remote_address(request)}\n')
				raise HTTPException(status_code=err.status_code, detail='Internal server error')
			else:
				write_log(f'{set_timestamp(new_time)} | status: {err.status_code} | source: /resume | error: {err.error} | reason: {err.detail} | @{get_remote_address(request)}\n')
				raise HTTPException(status_code=err.status_code, detail=err.detail)
		else:
			write_log(f'{set_timestamp(new_time)} | status: 500 | source: /resume | error: {err} | | @{get_remote_address(request)}\n')
			raise HTTPException(status_code=500, detail='Internal server error')

@app.post('/job/apply/{job_id}/submit')
@limiter.limit(limit_value='1/second')# 1/minute
async def apply(job_id: int, params: dict, request: Request, response: Response, user: Annotated[dict, Security(check_jwt)]):
	print('add attempt: application')
	new_time = get_new_time()
	try:
		write_log(f'{set_timestamp(new_time)} | | source: /job/apply/{job_id}/submit | info: add attempt: application | | attempt: {user["email"]}@{get_remote_address(request)}')
		# Get and validate input
		answers = params['answers']
		if not valid_json(answers):
			raise CustomException(status_code=400, error='failed application add', detail='invalid input')
		# Ensure all question are answered
		questions: dict
		request.state.cursor.execute(
			'''
			SELECT questions
			FROM job
			WHERE job_id = %(job_id)s;
			''',{
				'job_id': job_id
			}
		)
		ques_holder = request.state.cursor.fetchone()['questions']
		questions = None
		if ques_holder != None:
			questions = json.loads(ques_holder)
		if questions == None and answers != None:
			raise CustomException(status_code=400, error='failed application add', detail='answers with no questions')
		if questions != None:
			if answers == None or len(answers) < len(questions):
				raise CustomException(status_code=400, error='failed application add', detail='questions with no answers')
			if len(answers) > len(questions):
				raise CustomException(status_code=400, error='failed application add', detail='too many answers')
		# Check if seeker has previously applied to job
		request.state.cursor.execute(
			'''
			SELECT CASE
			WHEN EXISTS (
				SELECT 1 FROM Application
				WHERE (job_id = %(job_id)s AND seeker_id = UNHEX(%(seeker_id)s))
			)
			THEN (
				SELECT job_id FROM Application
				WHERE (job_id = %(job_id)s AND seeker_id = UNHEX(%(seeker_id)s))
			)
			ELSE NULL
			END AS job_id
			FROM Application;
			''',{
				'job_id': job_id,
				'seeker_id': user['user_id']
			}
		)
		check_repeat = request.state.cursor.fetchone()
		if check_repeat['job_id'] != None:
			raise CustomException(status_code=400, error='failed application add', detail='already applied')
		# Check if user exists and is valid to apply
		check: dict
		try:
			check = await check_user(request, user['email'])
		except Exception as err:
			errstr = str(err)
			raise CustomException(status_code=500, error=errstr, detail='check failed')
		if check['exists'] == False:
			raise CustomException(status_code=400, error='failed application add', detail=check['reason'])
		if check['usertype'] != 'seeker':
			raise CustomException(status_code=400, error='failed application add', detail='wrong user type')
		answers_formatted = None
		if answers != None:
			answers_formatted = json.dumps(answers, separators=(',', ':'))
		request.state.cursor.execute(
			'''
			INSERT INTO Application(seeker_id, job_id, answers)
      VALUE(UNHEX(%(seeker_id)s), %(job_id)s, %(answers)s);
			''',{
				'seeker_id': user['user_id'],
				'job_id': job_id,
				'answers': answers_formatted
			}
		)
		write_log(f'{set_timestamp(new_time)} | status: 201 | source: /job/apply | success: application added | | @{get_remote_address(request)}\n')
		return JSONResponse(status_code=201, content={'message': 'application submitted'})
	except Exception as err:
		print(err)
		traceback.print_exc()
		if type(err) == CustomException:
			if err.status_code == 500:
				write_log(f'{set_timestamp(new_time)} | status: 500 | source: /job/apply/{job_id}/submit | error: {err.error} | reason: {err.detail} | @{get_remote_address(request)}\n')
				raise HTTPException(status_code=err.status_code, detail='Internal server error')
			else:
				write_log(f'{set_timestamp(new_time)} | status: {err.status_code} | source: /job/apply/{job_id}/submit | error: {err.error} | reason: {err.detail} | @{get_remote_address(request)}\n')
				raise HTTPException(status_code=err.status_code, detail=err.detail)
		else:
			write_log(f'{set_timestamp(new_time)} | status: 500 | source: /job/apply/{job_id}/submit | error: {err} | | @{get_remote_address(request)}\n')
			raise HTTPException(status_code=500, detail='Internal server error')

@app.get('/job/applied')
@limiter.limit(limit_value='5/second')
async def applied(request: Request, response: Response, user: Annotated[dict, Security(check_jwt)], startIndex: int = 1, perPage: int = 10):
	print('Get attempt: jobs applied')
	new_time = get_new_time()
	try:
		write_log(f'{set_timestamp(new_time)} | | source: /job/applied | info: get attempt: jobs applied | | attempt: @{get_remote_address(request)}\n')
		check: dict
		try:
			check = await check_user(request, user['email'])
		except Exception as err:
			errstr = str(err)
			raise CustomException(status_code=500, error=errstr, detail='check failed')
		if check['exists'] == False:
			raise CustomException(status_code=400, error='failed applied get', detail=check['reason'])
		if check['usertype'] != 'seeker':
			raise CustomException(status_code=400, error='failed applied get', detail='wrong user type')
		request.state.cursor.execute(
			'''
			SELECT title, date_applied, questions, answers, seen, accepted, rejected
			FROM Application INNER JOIN Job
			ON Job.job_id = Application.job_id
			WHERE (app_index >= %(start_index)s AND Application.seeker_id = UNHEX(%(user_id)s) AND Job.delete_flag = 0)
			ORDER BY date_applied DESC
			LIMIT %(per_page)s;
			''',{
				'user_id': user['user_id'],
				'start_index': startIndex,
				'per_page': perPage
			}
		)
		apps = request.state.cursor.fetchall()
		response.status_code = 200
		return apps
	except Exception as err:
		print(type(err))
		if type(err) == CustomException:
			if err.status_code == 500:
				write_log(f'{set_timestamp(new_time)} | status: 500 | source: /job/applied | error: {err.error} | reason: {err.detail} | @{get_remote_address(request)}\n')
				raise HTTPException(status_code=err.status_code, detail='Internal server error')
			else:
				write_log(f'{set_timestamp(new_time)} | status: {err.status_code} | source: /job/applied | error: {err.error} | reason: {err.detail} | @{get_remote_address(request)}\n')
				raise HTTPException(status_code=err.status_code, detail=err.detail)
		else:
			write_log(f'{set_timestamp(new_time)} | status: 500 | source: /job/applied | error: {err} | | @{get_remote_address(request)}\n')
			raise HTTPException(status_code=500, detail='Internal server error')

# Get current applications for user's company
@app.get('/job/applications')
@limiter.limit('5/second')
async def application(request: Request, response: Response, user: Annotated[dict, Security(check_jwt)], endIndex: int = 0, perPage: int = 10):
	print('Get attempt: applications')
	new_time = get_new_time()
	try:
		write_log(f'{set_timestamp(new_time)} | | source: /job/applications | info: get attempt: applications | | attempt: {user["email"]}@{get_remote_address(request)}\n')
		if perPage >100:
			raise CustomException(status_code=400, error='failed applications get', detail='applications per page too high')
		check: dict
		try:
			check = await check_user(request, user['email'])
		except Exception as err:
			errstr = str(err)
			raise CustomException(status_code=500, error=errstr, detail='check failed')
		if check['exists'] == False:
			raise CustomException(status_code=400, error='failed applications get', detail=check['reason'])
		if check['usertype'] != 'employer':
			raise CustomException(status_code=400, error='failed applications get', detail='wrong user type')
		check: bool
		try:
			check = check_auth(request, user['user_id'], user['company'])
		except Exception as err:
			errstr = str(err)
			raise CustomException(status_code=500, error=errstr, detail='authorization failed')
		if check == False:
			raise CustomException(status_code=403, error='failed job add', detail='failed approval')
		if endIndex == 0:
			request.state.cursor.execute(
				'''
				SELECT HEX(Seeker.seeker_id) AS user_id, email, Job.job_id, app_index, title, first_name, last_name, seen, accepted, rejected
				FROM Application INNER JOIN (Seeker, Job)
				ON (Seeker.seeker_id = Application.seeker_id AND Job.job_id = Application.job_id)
				WHERE (Job.company = %(company)s AND Seeker.delete_flag = 0 AND Job.delete_flag = 0)
				ORDER BY date_applied DESC
				LIMIT %(per_page)s;
				''',{
					'company': user['company'],
					'per_page': perPage
				}
			)
		else:
			request.state.cursor.execute(
				'''
				SELECT HEX(Seeker.seeker_id) AS user_id, email, Job.job_id, app_index, title, first_name, last_name, seen, accepted, rejected
				FROM Application INNER JOIN (Seeker, Job)
				ON (Seeker.seeker_id = Application.seeker_id AND Job.job_id = Application.job_id)
				WHERE (Job.company = %(company)s AND Seeker.delete_flag = 0 AND Job.delete_flag = 0 AND app_index < %(end_index)s)
				ORDER BY date_applied DESC
				LIMIT %(per_page)s;
				''',{
					'company': user['company'],
					'end_index': endIndex,
					'per_page': perPage
				}
			)
		appls = request.state.cursor.fetchall()
		response.status_code = 200
		
		return {'success': True, 'apps': appls}
	except Exception as err:
		print(type(err))
		traceback.print_exc()
		if type(err) == CustomException:
			if err.status_code == 500:
				write_log(f'{set_timestamp(new_time)} | status: 500 | source: /login/employer | error: {err.error} | reason: {err.detail} | @{get_remote_address(request)}\n')
				raise HTTPException(status_code=err.status_code, detail='Internal server error')
			else:
				write_log(f'{set_timestamp(new_time)} | status: {err.status_code} | source: /login/employer | error: {err.error} | reason: {err.detail} | @{get_remote_address(request)}\n')
				raise HTTPException(status_code=err.status_code, detail=err.detail)
		else:
			write_log(f'{set_timestamp(new_time)} | status: 500 | source: /login/employer | error: {err} | | @{get_remote_address(request)}\n')
			raise HTTPException(status_code=500, detail='Internal server error')

	# return {'implemented': False}

@app.post('/add') # for testing
@limiter.limit(limit_value='5/minute')
async def add(params: dict, request: Request, response: Response):#, user: Annotated[dict, Security(check_jwt)]):
	new_time = get_new_time()
	try:
		response.status_code = 201
		return {'status_code':200, 'content':'good'}
	except Exception as err:
		print(type(err))
		traceback.print_exc()
		if isinstance(err, Exception):
			bob(1)
		if type(err) == CustomException:
			if err.status_code == 500:
				write_log(f'{set_timestamp(new_time)} | status: 500 | source: /login/employer | error: {err.error} | reason: {err.detail} | @{get_remote_address(request)}\n')
				raise HTTPException(status_code=err.status_code, detail='Internal server error')
			else:
				write_log(f'{set_timestamp(new_time)} | status: {err.status_code} | source: /login/employer | error: {err.error} | reason: {err.detail} | @{get_remote_address(request)}\n')
				raise HTTPException(status_code=err.status_code, detail=err.detail)
		else:
			write_log(f'{set_timestamp(new_time)} | status: 500 | source: /login/employer | error: {err} | | @{get_remote_address(request)}\n')
			raise HTTPException(status_code=500, detail='Internal server error')

# from fastapi.security import OAuth2PasswordBearer
# oauth2_scheme = OAuth2PasswordBearer(tokenUrl="Bearer")


# @app.get("/items/")
# async def read_items(token: Annotated[str, Security(oauth2_scheme)]):
#     return {"token": token}

#@app.post('/add-file')
#async def add_file()
# @app.get('/seeker')
# async def seeker(req: Request):
# 	req.state.cursor.execute('select hex(seeker_id), email, delete_flag from seeker;')
# 	print(req.state.cursor.fetchone())
# 	print('henlo')

@app.post("/upload-image")
@limiter.limit(limit_value='5/minute')
async def upload_image(request: Request, response: Response, file: UploadFile = File(...)):
	copy: str
	try:
		filetype: str
		filepath = 'temp/' + file.filename
		with open(filepath, 'wb') as f:
			it = 0
			while contents := file.file.read(64 * 1024): # Assign and use contents inline
				if it == 0:
					filetype = file_filter_image(contents)
					if not filetype:
						raise HTTPException(status_code=415, detail='Server accepts only .gif, .jpeg, and .png images')
				it += 1
				f.write(contents)
			f.close()
		filename = name_file(filepath=filepath, file_ext=filetype)
		copy = shutil.copyfile(filepath, 'images/' + filename)
		os.remove(filepath)
	except Exception as err:
		print(err)
		print(type(err))
		if type(err) == HTTPException:
			os.remove(filepath)
			raise HTTPException(status_code=err.status_code, detail=err.detail)
		else:
			raise HTTPException(status_code=500, detail='Internal server error')
	finally:
		file.file.close()

	return {"message": f"Successfully uploaded {file.filename}", 'location': copy}