import os
import boto3
from supabase import create_client, Client
from dotenv import load_dotenv

load_dotenv()

def get_supabase_client() -> Client:
    url: str = os.environ.get("SUPABASE_URL")
    if url and not url.endswith('/'):
        url += '/'
    key: str = os.environ.get("SUPABASE_KEY")
    return create_client(url, key)

def get_storage_client():
    return boto3.client(
        "s3",
        aws_access_key_id=os.environ.get("SUPABASE_STORAGE_ACCESS_KEY"),
        aws_secret_access_key=os.environ.get("SUPABASE_STORAGE_SECRET_KEY"),
        endpoint_url=os.environ.get("SUPABASE_BUCKET_URL"),
        region_name=os.environ.get("SUPABASE_BUCKET_REGION"),
    )