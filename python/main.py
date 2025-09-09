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
		db2 = pool.get_connection()
		if db2.is_connected():
			req.state.cursor = db2.cursor(buffered=True)
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
@limiter.limit(limit_value='60/second')
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
		passwd = passwd.encode(encoding="utf-8")
		has = bcrypt.hashpw(
			password=passwd,
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
		
		users = await login(request, email, passwd, table='seeker')
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
			write_log(f'{set_timestamp(new_time)} | status: 500 | source: /register/seeker| error: {err} | | @{get_remote_address(request)}\n')
			raise HTTPException(status_code=500, detail='Internal server error')


@app.post('/add')
@limiter.limit(limit_value='5/minute')
async def add(params: dict, request: Request, response: Response):
	print(params)
	date1 = params["date1"]
	date2 = params["date2"]
	valid = valid_dates(date1, date2)
	valid2 = valid_exp_date(date2)
	print(valid, valid2)
	
	return params

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