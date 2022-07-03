import asyncio
import base64
import contextlib
import datetime as dt
import functools
import json
import logging
import pathlib
import typing as t
import urllib
import urllib.parse
import urllib.request

import aiohttp
import click
import dotenv

# Globals

CHUNK_SIZE = 8192

default_env = {
  'FITBIT_CLIENT_ID': None,
  'FITBIT_CLIENT_SECRET': None,
  'FITBIT_REDIRECT_URI': 'https://localhost:8080',
  'FITBIT_AUTHORIZATION_URI': 'https://www.fitbit.com/oauth2/authorize',
  'FITBIT_TOKEN_URI': 'https://api.fitbit.com/oauth2/token',
}

# Utils

def click_option(*args, envvar=None, default=None, **kwargs):
  ''' Wrap click.option providing default from default_env given envvar
  '''
  assert envvar is not None
  def decorator(func):
    @click.option(*args, envvar=envvar, default=default or default_env.get(envvar), **kwargs)
    @functools.wraps(func)
    def wrapper(**func_kwargs):
      return func(**func_kwargs)
    return wrapper
  return decorator

def async_main(func):
  @functools.wraps(func)
  def wrapper(**kwargs):
    loop = asyncio.new_event_loop()
    loop.run_until_complete(func(**kwargs))
  return wrapper

@contextlib.asynccontextmanager
async def adhoc_ssl_context(
  cn: t.Optional[str] = None,
  protocol: t.Optional[int] = None,
):
  '''
  From https://github.com/pallets/werkzeug/blob/main/src/werkzeug/serving.py
  Produces an adhoc SSL cert and returns an SSL context for https in development.
  '''
  import os
  import ssl
  import tempfile
  from datetime import datetime as dt
  from datetime import timedelta, timezone

  from cryptography import x509
  from cryptography.hazmat.backends import default_backend
  from cryptography.hazmat.primitives import hashes, serialization
  from cryptography.hazmat.primitives.asymmetric import rsa
  from cryptography.x509.oid import NameOID
  backend = default_backend()
  pkey = rsa.generate_private_key(
    public_exponent=65537, key_size=2048, backend=backend
  )
  if cn is None: cn = '*'
  subject = x509.Name([
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Dummy Certificate"),
    x509.NameAttribute(NameOID.COMMON_NAME, cn),
  ])
  backend = default_backend()
  cert = (
      x509.CertificateBuilder()
      .subject_name(subject)
      .issuer_name(subject)
      .public_key(pkey.public_key())
      .serial_number(x509.random_serial_number())
      .not_valid_before(dt.now(timezone.utc))
      .not_valid_after(dt.now(timezone.utc) + timedelta(days=365))
      .add_extension(x509.ExtendedKeyUsage([x509.OID_SERVER_AUTH]), critical=False)
      .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
      .sign(pkey, hashes.SHA256(), backend)
  )
  cert_handle, cert_file = tempfile.mkstemp()
  pkey_handle, pkey_file = tempfile.mkstemp()
  os.write(cert_handle, cert.public_bytes(serialization.Encoding.PEM))
  os.write(
      pkey_handle,
      pkey.private_bytes(
          encoding=serialization.Encoding.PEM,
          format=serialization.PrivateFormat.TraditionalOpenSSL,
          encryption_algorithm=serialization.NoEncryption(),
      ),
  )

  os.close(cert_handle)
  os.close(pkey_handle)

  if protocol is None:
      protocol = ssl.PROTOCOL_TLS_SERVER
  
  ctx = ssl.SSLContext(protocol)
  ctx.load_cert_chain(cert_file, pkey_file)

  try:
    yield ctx
  finally:
    os.remove(pkey_file)
    os.remove(cert_file)

# OAuth2

@contextlib.asynccontextmanager
async def oauth2_redirect_capture_code(redirect_uri=None, **_kwargs):
  assert redirect_uri is not None
  import socket
  future_code = asyncio.Future()
  redirect_uri_parsed = urllib.parse.urlparse(redirect_uri)
  host = socket.gethostbyname(redirect_uri_parsed.hostname)
  port = redirect_uri_parsed.port or 443
  async with adhoc_ssl_context(cn=redirect_uri_parsed.hostname) as ssl_context:
    import aiohttp
    import aiohttp.web
    app = aiohttp.web.Application()
    routes = aiohttp.web.RouteTableDef()
    @routes.get(redirect_uri_parsed.path)
    async def redirected(request: aiohttp.web.Request):
      code = request.query.getone('code')
      if code:
        future_code.set_result(code)
        return aiohttp.web.Response(text='Success!')
      else:
        raise aiohttp.web.HTTPNotFound
    app.add_routes(routes)
    
    runner = aiohttp.web.AppRunner(app)
    await runner.setup()
    logging.info(f"Starting redirect server on https://{host}:{port}...")
    site = aiohttp.web.TCPSite(runner, host, port, ssl_context=ssl_context)
    await site.start()
    try:
      yield future_code
    finally:
      logging.info(f"Cleaning up webserver...")
      await runner.cleanup()

async def oauth2_authorize(
  authorization_uri='https://www.fitbit.com/oauth2/authorize',
  token_uri='https://api.fitbit.com/oauth2/token',
  client_id=None,
  client_secret=None,
  redirect_uri=None,
  **_kwargs,
):
  assert client_id is not None
  assert client_secret is not None
  assert redirect_uri is not None
  logging.info(f"Starting OAuth2 authorization")
  async with oauth2_redirect_capture_code(redirect_uri=redirect_uri) as future_code:
    params = dict(
      response_type='code',
      client_id=client_id,
      redirect_uri=redirect_uri,
      scope='activity heartrate location',
    )
    url = f"{authorization_uri}?{urllib.parse.urlencode(params)}"
    print(f"Login at {url}")
    print("When it's complete you will be directed to the redirect_uri. This page will have an ssl warning which you can safely proceed through anyway this service runs on your local machine and is secure.")
    logging.info(f"Waiting for code...")
    code = await future_code
    logging.info(f"Received code!")
  #
  logging.info(f"Getting token...")
  payload = dict(
    code=code,
    redirect_uri=redirect_uri,
    client_id=client_id,
    grant_type='authorization_code',
  )
  async with aiohttp.ClientSession() as session:
    async with session.post(
      token_uri,
      data=payload,
      headers={
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': f"Basic {base64.b64encode(f'{client_id}:{client_secret}'.encode()).decode()}",
      }) as req:
      assert req.status == 200, await req.text()
      auth = await req.json()
      logging.info(f"OAuth2 authorized")
      return auth

async def oauth2_refresh(
  auth=None,
  token_uri='https://api.fitbit.com/oauth2/token',
  client_id=None,
  client_secret=None,
  **_kwargs,
):
  assert auth is not None
  logging.info(f"Getting token...")
  payload = dict(
    refresh_token=auth['refresh_token'],
    grant_type='refresh_token',
  )
  async with aiohttp.ClientSession() as session:
    async with session.post(
      token_uri,
      data=payload,
      headers={
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': f"Basic {base64.b64encode(f'{client_id}:{client_secret}'.encode()).decode()}",
      }) as req:
      assert req.status == 200, await req.text()
      auth = await req.json()
      logging.info(f"OAuth2 refreshed")
      return auth

async def oauth2_flow(**kwargs):
  envfile = pathlib.Path('.env')
  auth = dotenv.dotenv_values(envfile).get('FITBIT_AUTHORIZATION')
  if auth is None:
    auth = await oauth2_authorize(**kwargs)
    auth['ts'] = dt.datetime.now().timestamp()
    dotenv.set_key(envfile, 'FITBIT_AUTHORIZATION', json.dumps(auth))
  elif type(auth) == str:
    auth = json.loads(auth)
  #
  if dt.datetime.now() > dt.datetime.fromtimestamp(auth['ts'] + auth['expires_in']):
    logging.info('Authorization expired, refreshing...')
    auth = await oauth2_refresh(auth, **kwargs)
    auth['ts'] = dt.datetime.now().timestamp()
    dotenv.set_key(envfile, 'FITBIT_AUTHORIZATION', json.dumps(auth))
  else:
    logging.info('Re-using un-expired authorization')
  #
  return auth

# Fitbit APIs

class TooManyRequests(Exception): pass

async def get_activity_log_list(api_url='https://api.fitbit.com', api_version='1', user_id='-', auth=None, date=None, sort='desc'):
  assert auth is not None
  logging.info(f"Getting activity log list...")
  if date is None: date = dt.datetime.now()
  params = dict(offset=0, limit=100)
  if sort == 'desc': params.update(beforeDate=date.strftime("%Y-%m-%d"), sort='desc')
  elif sort == 'asc': params.update(afterDate=date.strftime("%Y-%m-%d"), sort='asc')
  else: raise Exception('Sort is invalid')
  async with aiohttp.ClientSession() as session:
    async with session.get(
      f"{api_url}/{api_version}/user/{user_id}/activities/list.json",
      params=params,
      headers={ 'Authorization': f"Bearer {auth}" },
    ) as req:
      data = await req.json()
    while data['activities']:
      for activity in data['activities']:
        yield activity
      next = data.get('pagination', {}).get('next', None)
      if not next: break
      async with session.get(
        data['pagination']['next'],
        headers={'Authorization': f"Bearer {auth}"},
      ) as req:
        data = await req.json()

async def fetch_activity_tcx(activity, auth=None, activity_directory=pathlib.Path('.')):
  assert auth is not None
  if not activity.get('tcxLink'):
    logging.debug(f"No tcxLink for {activity}. Skipping")
    return
  outfile = activity_directory / f"{activity['logId']}.tcx"
  if outfile.exists():
    logging.debug(f"{activity} tcx already downloaded. Skipping")
    return
  while True:
    logging.info(f"Fetching activity tcx for {activity}...")
    await asyncio.sleep(0.5)
    async with aiohttp.ClientSession() as session:
      try:
        async with session.get(activity['tcxLink'], headers={'Authorization': f"Bearer {auth}"}) as req:
          if req.status != 200:
            error = (await req.content.read()).decode()
            if error == 'Too Many Requests':
              raise TooManyRequests()
            else:
              raise Exception(error)
          with outfile.open('wb') as fw:
            async for chunk in req.content.iter_chunked(CHUNK_SIZE):
              fw.write(chunk)
          break
      except TooManyRequests:
        logging.warning(f"Reached maximum hourly API requests. Waiting an hour before retry...")
        await asyncio.sleep(3610)

# CLI

@click.group(
  help=
  '''
  Run `init` command and follow instructions to gather the necessary fitbit API credentials.
  '''
)
def cli(): pass

def shared_opts(func):
  @click_option('--client-id', envvar='FITBIT_CLIENT_ID', type=str, required=True)
  @click_option('--client-secret', envvar='FITBIT_CLIENT_SECRET', type=str, required=True)
  @click_option('--redirect-uri', envvar='FITBIT_REDIRECT_URI', type=str)
  @click_option('--authorization-uri', envvar='FITBIT_AUTHORIZATION_URI', type=str)
  @click_option('--token-uri', envvar='FITBIT_TOKEN_URI', type=str)
  @functools.wraps(func)
  def wrapper(**kwargs):
    return func(**kwargs)
  return wrapper

@cli.command()
def init():
  ''' Build .env file for operation
  '''
  import textwrap
  logging.info('Identifying any existing dotenv...')
  current_dotenv = pathlib.Path('.env')
  current_dotenv.touch()
  current_values = {
    k: v
    for k, v in dotenv.dotenv_values(current_dotenv).items()
    if k in default_env
  }
  click.echo(textwrap.dedent('''
    To use this you need to get keys for doing OAuth. These can be obtained by creating an app in
    https://dev.fitbit.com/apps/new. No one checks so you can put random name and urls like "example.com"
    for terms of service and the like. The only important options are:
    - OAuth 2.0 Application Type: Personal
    - Redirect URL: https://localhost:8080
    - Default Access Type: Read Only
    When you've done this, you should use the information the site gives you to fill out the next prompts.
  '''.strip()))
  for key, default_value in default_env.items():
    current_value = current_values.get(key)
    new_value = click.prompt(key, default=current_value or default_value, type=str)
    if new_value and new_value != current_value:
      current_values[key] = new_value
      dotenv.set_key(current_dotenv, key, new_value, quote_mode='never')
  #
  dotenv.load_dotenv(current_dotenv)
  #
  asyncio.new_event_loop().run_until_complete(oauth2_flow(
    authorization_uri=current_values['FITBIT_AUTHORIZATION_URI'],
    token_uri=current_values['FITBIT_TOKEN_URI'],
    client_id=current_values['FITBIT_CLIENT_ID'],
    client_secret=current_values['FITBIT_CLIENT_SECRET'],
    redirect_uri=current_values['FITBIT_REDIRECT_URI'],
  ))

@cli.command(help='Dump all activity high-level metadata')
@shared_opts
@click.option('-f', '--activity-log-file', type=click.Path(file_okay=True, path_type=pathlib.Path), default='activity_log_list.jsonl')
@async_main
async def dump_00_activity_log_list(activity_log_file: pathlib.Path=None, **kwargs):
  authorization = await oauth2_flow(**kwargs)
  activity_log_file.parent.mkdir(parents=True, exist_ok=True)
  # TODO: "diff" this
  with activity_log_file.open('w') as fw:
    async for activity in get_activity_log_list(auth=authorization['access_token']):
      print(json.dumps(activity), file=fw)

@cli.command(help='Fetch tcx files for each activity')
@click.option('-f', '--activity-log-file', type=click.Path(file_okay=True, path_type=pathlib.Path), default='activity_log_list.jsonl')
@click.option('-d', '--activity-directory', type=click.Path(file_okay=True, path_type=pathlib.Path), default='activities')
@shared_opts
@async_main
async def dump_01_activity_tcx(activity_log_file: pathlib.Path=None, activity_directory: pathlib.Path=None, **kwargs):
  authorization = await oauth2_flow(**kwargs)
  activity_directory.mkdir(parents=True, exist_ok=True)
  with activity_log_file.open('r') as fr:
    for activity in map(json.loads, fr):
      await fetch_activity_tcx(activity, auth=authorization['access_token'], activity_directory=activity_directory)


if __name__ == '__main__':
  import logging
  logging.basicConfig(level=logging.INFO)
  dotenv.load_dotenv()
  cli()
