from typing import Annotated, List
from fastapi import FastAPI, UploadFile, File, HTTPException, Request, Response, requests
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
import traceback # for testing

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
		db2:mysql.pooling.PooledMySQLConnection = pool.get_connection()
		if db2.is_connected():
			req.state.cursor = db2.cursor(buffered=True, dictionary=True)
			req.state.cursor.execute('SET SESSION sql_mode = "TRADITIONAL"')
			req.state.cursor.execute('SET time_zone = "-8:00"')
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
		exist = request.state.cursor.fetchall()[0]['exist']
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
		[job] = request.state.cursor.fetchall()
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

@app.post('/resume')
@limiter.limit(limit_value='12/minute')
async def resume(params: dict, request: Request, response: Response):
	pass

@app.post('/add')
@limiter.limit(limit_value='5/minute')
async def add(params: dict, request: Request, response: Response):
	bob(1)
	ben = 'good-okay'
	args = {}
	search_query = ''
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
			bob(i)
			search_query += f' AND locate(%(ben{i})s, JSON_EXTRACT(job.benefits, "$[*]")) > 0'
			bob(i)
			args[f'ben{str(i)}'] = benefits[i]
	else:
		search_query += ' AND locate(:benefits, JSON_EXTRACT(job.benefits, "$[*]")) > 0'
		args['benefits'] = ben
	print(search_query)
	return JSONResponse(status_code=200, content='good')

#@app.post('/add-file')
#async def add_file()
@app.get('/seeker')
async def seeker(req: Request):
	req.state.cursor.execute('select hex(seeker_id), email, delete_flag from seeker;')
	print(req.state.cursor.fetchone())
	print('henlo')

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