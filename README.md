# Fitbit Dump
This is a python script for dumping fitbit activity logs and associated `.tcx` files for each activity. The script walks you through getting OAuth `client_id` and `client_secret` which are necessary to use the [Fitbit API](https://www.fitbit.com/dev) after which it can authenticate and be used to dump activity logs. The resulting files can be used for later tasks like for example uploading to strava.

## Usage
```bash
# pip install from github
pip install "fitbit-dump@git+https://github.com/u8sand/fitbit-dump"

# create a directory for your dump
mkdir fitbit-data
cd fitbit-data

# initialize fitbit-dump -- follow instructions on the screen to get OAuth credentials for the API
fitbit-dump init

# dump the activity log list, defaults to activity_log_list.jsonl
fitbit-dump dump-00-activity-log-list

# dump tcx files for each activity, defaults to activities directory
fitbit-dump dump-01-activity-tcx
```

If for whatever reason the `fitbit-dump` command is not recognized, this is evidence that you don't have python binaries in your PATH, but could work around it by using `python -m fitbit_dump` instead. It may also be necessary to be more explicit about versions in either `pip` or python (like `pip3.8` | `python3.8`).

## Explanation of Dependencies
- `cryptography` is used to generate ad-hoc ssl keys
- `aiohttp` is used to serve the redirect_uri server and also the web client
- `click` is used to setup the CLI
- `python-dotenv` is used to persist your configuration and authorization keys to a `.env` file
