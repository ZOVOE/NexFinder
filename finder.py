import asyncio
import os
import sys
import random
import string
import psutil
import psycopg2 # Installing Directly psycopg2 Giving Error Instead Try pip3 install psycopg2-binary
from pyrogram import Client, filters
import pandas as pd
import re
from threading import Event, Thread, Lock
from pyrogram.types import InlineKeyboardMarkup, InlineKeyboardButton, CallbackQuery
import time 
import signal
import csv
import hashlib
import asyncio
import requests
from datetime import datetime, timedelta

# Telegram Bot API Token
API_ID = 1743158
API_HASH = 'b4cafabbc82cea7bcc280208c650e31b'
#BOT_TOKEN = "7073523342:AAFWmgNC2Hdjy-oaEx7Oeb2ENxIV9z5NAbE"
BOT_TOKEN = "8388226928:AAFW6mP68xGygTkEocvXCIPuQz-seSjHrhA"

# Database connection string To persiatm3@gmail.com account 
conn_string = "postgres://avnadmin:AVNS_tbuc3JMdqN-2FwlkPKo@pg-3c4e9b0a-unzovoex-ebdd.g.aivencloud.com:27111/defaultdb?sslmode=require"

# Owners List [Dr,SPEED,3ZAR]
owners = [5211166230,]  
admin_ids = [5211166230, 28625632]  # Add your admin IDs here
allowed_group_ids = -1001734069938 , -1001593038293,5211166230
user_settings = {}

#Client Connection PersiaTools | Token Owner @ZOVOE
bot = Client("PersiaTools", api_id=API_ID, api_hash=API_HASH, bot_token=BOT_TOKEN)
app = Client("appx", api_id=API_ID, api_hash=API_HASH)

# Active /finder searches (chat_id, owner_user_id) -> stop Event
ACTIVE_SEARCHES: dict[tuple[int, int], Event] = {}
ACTIVE_SEARCHES_LOCK = Lock()


# Files: local BIN databases (supports multiple CSVs)
BIN_CSV_FILES = ("databin.csv", "databin2.csv")

def load_bin_data(csv_files=BIN_CSV_FILES) -> pd.DataFrame:
    """
    Load and merge BIN CSV databases.

    Expected columns:
      number,country,flag,vendor,type,level,bank_name
    """
    expected_cols = ["number", "country", "flag", "vendor", "type", "level", "bank_name"]
    frames: list[pd.DataFrame] = []

    for path in csv_files:
        if not os.path.exists(path):
            continue

        df = pd.read_csv(path, keep_default_na=False)

        # Keep only known columns if present; ignore extra columns safely.
        if not set(expected_cols).issubset(df.columns):
            # Best-effort: normalize column names and retry
            df.columns = [str(c).strip().lower() for c in df.columns]
        if set(expected_cols).issubset(df.columns):
            df = df[expected_cols]
        else:
            # If schema is unexpected, skip this file instead of crashing the bot.
            continue

        # Drop blank rows (databin2.csv sometimes contains an empty line).
        df["number"] = df["number"].astype(str).str.strip()
        df = df[df["number"].ne("")]

        # Normalize number to integer-like for fast lookups.
        df["number"] = pd.to_numeric(df["number"], errors="coerce").astype("Int64")
        df = df.dropna(subset=["number"])

        frames.append(df)

    if not frames:
        return pd.DataFrame(columns=expected_cols)

    combined = pd.concat(frames, ignore_index=True)
    # De-dupe across sources; keep first occurrence.
    combined = combined.drop_duplicates(subset=expected_cols, keep="first")
    return combined

# Load once at startup
bin_data = load_bin_data()


#Functions 
# Execute Query | Directly Access 
def execute_sql(query, params=None):
    conn = psycopg2.connect(conn_string)
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(query, params)
    finally:
        conn.close()
#Fetching SQL
def fetch_sql(query, params=None):
    conn = psycopg2.connect(conn_string)
    try:
        with conn.cursor() as cur:
            cur.execute(query, params)
            return cur.fetchone()
    finally:
        conn.close()

def ensure_db_schema():
    """
    Create required tables/columns if missing.

    This fixes errors like: psycopg2.errors.UndefinedTable: relation "users" does not exist
    """
    conn = psycopg2.connect(conn_string)
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS users (
                        userid BIGINT PRIMARY KEY,
                        first_name TEXT,
                        premium BOOLEAN NOT NULL DEFAULT FALSE,
                        vip BOOLEAN NOT NULL DEFAULT FALSE,
                        admin BOOLEAN NOT NULL DEFAULT FALSE,
                        owner BOOLEAN NOT NULL DEFAULT FALSE,
                        special BOOLEAN NOT NULL DEFAULT FALSE,
                        prefer BOOLEAN NOT NULL DEFAULT FALSE,
                        antispam_fu BOOLEAN NOT NULL DEFAULT FALSE,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                    );
                    """
                )
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS user_settings (
                        user_id BIGINT PRIMARY KEY REFERENCES users(userid) ON DELETE CASCADE,
                        flag_match BOOLEAN NOT NULL DEFAULT FALSE,
                        vendor_match BOOLEAN NOT NULL DEFAULT FALSE,
                        type_match BOOLEAN NOT NULL DEFAULT FALSE,
                        level_match BOOLEAN NOT NULL DEFAULT FALSE
                    );
                    """
                )
    finally:
        conn.close()

# Ensure DB schema exists at startup
try:
    ensure_db_schema()
except Exception as e:
    # Don't crash the whole bot on startup if DB is down;
    # handlers will surface the error when used.
    print(f"[DB] Schema check failed: {e}")
def search_databin(bank_name, filter_criteria=None):
    """
    Search merged local BIN dataset for exact bank_name match.
    """
    if bin_data.empty:
        return []

    df = bin_data[bin_data["bank_name"] == bank_name]

    if filter_criteria:
        for key, value in filter_criteria.items():
            if key not in df.columns:
                continue
            df = df[df[key] == value]

    # Convert to plain dict rows (keep behavior similar to old code).
    out = df.to_dict(orient="records")
    for row in out:
        # Ensure number is serializable/consistent with old csv reader strings.
        if "number" in row and row["number"] is not None:
            row["number"] = int(row["number"])
    return out
def save_matches_to_file(matches, bank_name):
    hash_object = hashlib.md5(bank_name.encode())
    file_name = f"{hash_object.hexdigest()}_BIN.txt"
    with open(file_name, 'w') as f:
        for match in matches:
            f.write(
                f"BIN: {match['number']}\n"
                f"Country: {match['country']} {match['flag']}\n"
                f"Vendor: {match['vendor']}\n"
                f"Type: {match['type']}\n"
                f"Level: {match['level']}\n"
                f"Bank Name: {match['bank_name']}\n\n"
            )
    return file_name
def search_databin_by_bank_name(bank_name):
    """
    Search merged local BIN dataset by bank name regex (case-insensitive).
    """
    if bin_data.empty:
        return []

    pattern = re.compile(bank_name, re.IGNORECASE)
    matches: list[dict] = []

    # Iterate rows for regex matching (pandas .str.contains can choke on bad regex)
    for row in bin_data.to_dict(orient="records"):
        bank = str(row.get("bank_name", ""))
        if pattern.search(bank):
            if "number" in row and row["number"] is not None:
                row["number"] = int(row["number"])
            matches.append(row)

    return matches
def format_message(matches):
    message = ""
    for match in matches:
        message += (
            f"**BIN:** `{match['number']}`\n"
            f"**Country:** {match['country']} {match['flag']}\n"
            f"**Vendor:** {match['vendor']}\n"
            f"**Type:** {match['type']}\n"
            f"**Level:** {match['level']}\n"
            f"**Bank Name:** {match['bank_name']}\n\n"
        )
    return message
def signal_handler(sig, frame):
    print('Signal received, stopping bot...')
    app.stop()
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)  # Handle CTRL+C
signal.signal(signal.SIGTERM, signal_handler)  # Handle termination
def remove_duplicates(lst, key):
    seen = set()
    new_lst = []
    for item in lst:
        k = key(item)
        if k not in seen:
            new_lst.append(item)
            seen.add(k)
    return new_lst
#Fetch Stats

async def fetch_stats():
    # Connect to SQL Aiven Cloud 
    conn = psycopg2.connect(conn_string)
    cur = conn.cursor()

    # Query to get counts for each category
    cur.execute("SELECT COUNT(*) FROM users")
    total_users = cur.fetchone()[0]
    #Finding True - Premium Users 
    cur.execute("SELECT COUNT(*) FROM users WHERE Premium = TRUE")
    premium_users = cur.fetchone()[0]
    #Finding True - VIP Users 
    cur.execute("SELECT COUNT(*) FROM users WHERE VIP = TRUE")
    vip_users = cur.fetchone()[0]
    #Finding True - Special Users - Special Concepts By Dr
    cur.execute("SELECT COUNT(*) FROM users WHERE Special = TRUE")
    special_users = cur.fetchone()[0]
    #Finding True - AdminS  
    cur.execute("SELECT COUNT(*) FROM users WHERE Admin = TRUE")
    admins = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM users WHERE Owner = TRUE")
    owners = cur.fetchone()[0]

    # Closing Postgres Connection 
    cur.close()
    conn.close()

    # Get system stats
    cpu_usage = psutil.cpu_percent()
    ram_usage = psutil.virtual_memory().used // (1024 * 1024)  # Convert to MB
    total_ram = psutil.virtual_memory().total // (1024 * 1024)  # Convert to MB

    # Return stats as a dictionary
    return {
        "total_users": total_users,
        "premium_users": premium_users,
        "vip_users": vip_users,
        "special_users": special_users,
        "admins": admins,
        "owners": owners,
        "cpu_usage": cpu_usage,
        "ram_usage": ram_usage,
        "total_ram": total_ram
    }
def generate_random_string(length=5):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))
    
def is_owner(user_id):
    return user_id in owners
    #BIN LOOKUP 
def bin_lookup(bin_prefix):
    result = bin_data[bin_data['number'] == int(bin_prefix)]
    #bin_data linked To Databin.csv
    if result.empty:
        return None
    return result.iloc[0].to_dict()
def bin_lookup2(bin_number):
    """
    Function to get BIN information from the lookup.binlist.net API.
    """
    url = f'https://lookup.binlist.net/{bin_number}'
    headers = {
        'accept': '*/*',
        'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36',
    }

    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        bin_data = response.json()
        bin_info = {
            'bank_name': bin_data.get('bank', {}).get('name', 'Unknown Bank'),
            'country': bin_data.get('country', {}).get('name', 'Unknown Country'),
            'flag': bin_data.get('country', {}).get('emoji', ''),
            'vendor': bin_data.get('scheme', 'Unknown Vendor'),
            'type': bin_data.get('type', 'Unknown Type'),
            'level': bin_data.get('brand', 'Unknown Level'),
            'prepaid': bin_data.get('prepaid', 'Unknown'),
            'country_code': bin_data.get('country', {}).get('alpha2', 'Unknown'),
            'currency': bin_data.get('country', {}).get('currency', 'Unknown Currency'),
            'latitude': bin_data.get('country', {}).get('latitude', 'Unknown Latitude'),
            'longitude': bin_data.get('country', {}).get('longitude', 'Unknown Longitude'),
        }
        return bin_info
    else:
        return {
            'bank_name': 'N/A',
            'country': 'N/A',
            'flag': '',
            'vendor': 'N/A',
            'type': 'N/A',
            'level': 'N/A',
            'prepaid': 'N/A',
            'country_code': 'N/A',
            'currency': 'N/A',
            'latitude': 'N/A',
            'longitude': 'N/A',
        }
        

def bin_lookup3(bin_number):
    """
    Function to get BIN information from the ChargeBlast API.
    """
    url = f'https://api.chargeblast.io/bin/{bin_number}'
    headers = {
        'accept': 'application/json, text/plain, */*',
        'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36',
    }

    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        bin_data = response.json()
        bin_info = {
            'issuer': bin_data.get('issuer', 'Unknown Issuer'),
            'country': bin_data.get('country', 'Unknown Country'),
            'a2': bin_data.get('a2', 'Unknown A2'),
            'a3': bin_data.get('a3', 'Unknown A3'),
            'brand': bin_data.get('brand', 'Unknown Brand'),
            'type': bin_data.get('type', 'Unknown Type'),
            'latitude': bin_data.get('lat', 'Unknown Latitude'),
            'longitude': bin_data.get('long', 'Unknown Longitude'),
        }
        return bin_info
    else:
        return {
            'issuer': 'N/A',
            'country': 'N/A',
            'a2': 'N/A',
            'a3': 'N/A',
            'brand': 'N/A',
            'type': 'N/A',
            'latitude': 'N/A',
            'longitude': 'N/A',
        }
        
def bin_lookup_pro(bin_number):
    """
    Function to get BIN information from the BTR Proxy API.
    """
    url = 'https://btr-proxy.herokuapp.com/bins'
    headers = {
        'Accept': '*/*',
        'User-Agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36',
        'Content-Type': 'application/json',
        'Origin': 'https://btr-reference-app.herokuapp.com',
        'Referer': 'https://btr-reference-app.herokuapp.com/',
    }
    data = {
        'bin': bin_number
    }

    response = requests.post(url, headers=headers, json=data)
    
    if response.status_code == 200:
        bin_data = response.json()
        bin_info = {
            'customerName': bin_data.get('customerName', 'Unknown Customer'),
            'country': bin_data.get('country', {}).get('name', 'Unknown Country'),
            'countryCode': bin_data.get('country', {}).get('code', 'Unknown Code'),
            'countryAlpha3': bin_data.get('country', {}).get('alpha3', 'Unknown Alpha3'),
            'binNum': bin_data.get('binNum', 'Unknown BIN'),
            'binLength': bin_data.get('binLength', 'Unknown Length'),
            'acceptanceBrand': bin_data.get('acceptanceBrand', 'Unknown Brand'),
            'productCode': bin_data.get('productCode', 'Unknown Code'),
            'productDescription': bin_data.get('productDescription', 'Unknown Description'),
            'fundingSource': bin_data.get('fundingSource', 'Unknown Source'),
            'consumerType': bin_data.get('consumerType', 'Unknown Type'),
            'smartDataEnabled': bin_data.get('smartDataEnabled', False),
            'localUse': bin_data.get('localUse', False),
            'authorizationOnly': bin_data.get('authorizationOnly', False),
            'governmentRange': bin_data.get('governmentRange', False),
            'nonReloadableIndicator': bin_data.get('nonReloadableIndicator', False),
            'anonymousPrepaidIndicator': bin_data.get('anonymousPrepaidIndicator', 'N/A'),
            'cardholderCurrencyIndicator': bin_data.get('cardholderCurrencyIndicator', 'N/A'),
            'programName': bin_data.get('programName', 'Unavailable'),
            'vertical': bin_data.get('vertical', 'Unavailable'),
        }
        return bin_info
    else:
        return {
            'customerName': 'N/A',
            'country': 'N/A',
            'countryCode': 'N/A',
            'countryAlpha3': 'N/A',
            'binNum': 'N/A',
            'binLength': 'N/A',
            'acceptanceBrand': 'N/A',
            'productCode': 'N/A',
            'productDescription': 'N/A',
            'fundingSource': 'N/A',
            'consumerType': 'N/A',
            'smartDataEnabled': 'N/A',
            'localUse': 'N/A',
            'authorizationOnly': 'N/A',
            'governmentRange': 'N/A',
            'nonReloadableIndicator': 'N/A',
            'anonymousPrepaidIndicator': 'N/A',
            'cardholderCurrencyIndicator': 'N/A',
            'programName': 'N/A',
            'vertical': 'N/A',
        }



def get_user_role(user_id):
    user_roles = fetch_sql(
        "SELECT premium, vip, admin, owner FROM users WHERE userid = %s",
        (user_id,),
    )

    if user_roles:
        premium, vip, admin, owner = user_roles
        if owner:
            return "Owner"
        if admin:
            return "Admin"
        if vip:
            return "VIP"
        if premium:
            return "Premium"
    return "Free User"

def get_user_settings(user_id):
    query = """
        SELECT flag_match, vendor_match, type_match, level_match
        FROM user_settings
        WHERE user_id = %s
    """
    settings = fetch_sql(query, (user_id,))
    
    if settings is None:
        settings = (False, False, False, False)
        execute_sql("""
            INSERT INTO user_settings (user_id, flag_match, vendor_match, type_match, level_match)
            VALUES (%s, %s, %s, %s, %s)
        """, (user_id, *settings))

    return settings

def update_user_setting(user_id, setting_name, value):
    query = f"""
        UPDATE user_settings
        SET {setting_name} = %s
        WHERE user_id = %s
    """
    execute_sql(query, (value, user_id))
#Commands 
"""
@bot.on_message(filters.text & ~filters.command("register") & ~filters.command("info"))
async def default_handler(client, message):
    user_id = message.from_user.id
    user_registered = fetch_sql("SELECT userid FROM users WHERE userid = %s", (user_id,))

    if not user_registered:
        await message.reply_text("🚫 You are not registered. Please use the /register command to register.")
"""
@bot.on_message(filters.command("stats"))
async def stats_handler(client, message):
   
    stats = await fetch_stats()

    
    stats_message = (
        f"**📊 Statistics:**\n\n"
        f"👥 **Total Users:** {stats['total_users']}\n"
        f"💎 **Premium Users:** {stats['premium_users']}\n"
        f"🎖 **VIP Users:** {stats['vip_users']}\n"
        f"⭐ **Special Users:** {stats['special_users']}\n"
        f"👮 **Admins:** {stats['admins']}\n"
        f"👑 **Owners:** {stats['owners']}\n\n"
        f"💻 **CPU Usage:** {stats['cpu_usage']}%\n"
        f"🧠 **RAM Available:** {stats['total_ram'] - stats['ram_usage']} MB\n"
        f"📊 **Total RAM:** {stats['total_ram']} MB"
    )

    # Send the stats message
    await message.reply_text(stats_message)


# /admin Command
@bot.on_message(filters.command("admin") & filters.reply)
async def admin_handler(client, message):
    if not is_owner(message.from_user.id):
        return await message.reply_text("🚫 You don't have permission to use this command.")

    target_user_id = message.reply_to_message.from_user.id
    execute_sql("UPDATE users SET Admin = TRUE WHERE USERID = %s", (target_user_id,))
    await message.reply_text(f"👮 User {target_user_id} has been upgraded to Admin.")

# /upgrade Command
@bot.on_message(filters.command("upgrade"))
async def upgrade_handler(client, message):
    if not is_owner(message.from_user.id):
        return await message.reply_text("🚫 You don't have permission to use this command.")

    try:
        cmd, user_or_type, user_type = message.text.split()
        target_user_id = int(user_or_type) if user_or_type.isdigit() else message.reply_to_message.from_user.id
        if user_type.lower() == "premium":
            execute_sql("UPDATE users SET Premium = TRUE WHERE USERID = %s", (target_user_id,))
            await message.reply_text(f"💎 User {target_user_id} has been upgraded to Premium.")
        elif user_type.lower() == "vip":
            execute_sql("UPDATE users SET VIP = TRUE WHERE USERID = %s", (target_user_id,))
            await message.reply_text(f"🎖 User {target_user_id} has been upgraded to VIP.")
    except:
        await message.reply_text("🚫 Usage: /upgrade <USERID | REPLY> <Premium|VIP>")

# /dg Command (downgrade)
@bot.on_message(filters.command("dg"))
async def downgrade_handler(client, message):
    if not is_owner(message.from_user.id):
        return await message.reply_text("🚫 You don't have permission to use this command.")

    try:
        cmd, user_or_type, user_type = message.text.split()
        target_user_id = int(user_or_type) if user_or_type.isdigit() else message.reply_to_message.from_user.id
        if user_type.lower() == "premium":
            execute_sql("UPDATE users SET Premium = FALSE WHERE USERID = %s", (target_user_id,))
            await message.reply_text(f"💎 User {target_user_id} has been downgraded from Premium.")
        elif user_type.lower() == "vip":
            execute_sql("UPDATE users SET VIP = FALSE WHERE USERID = %s", (target_user_id,))
            await message.reply_text(f"🎖 User {target_user_id} has been downgraded from VIP.")
    except:
        await message.reply_text("🚫 Usage: /dg <USERID | REPLY> <Premium|VIP>")

# /specialupg Command
@bot.on_message(filters.command("specialupg"))
async def specialupg_handler(client, message):
    if not (is_owner(message.from_user.id) or message.from_user.id in owners):
        return await message.reply_text("🚫 You don't have permission to use this command.")

    target_user_id = int(message.text.split()[1]) if len(message.text.split()) > 1 else message.reply_to_message.from_user.id
    execute_sql("UPDATE users SET Special = TRUE WHERE USERID = %s", (target_user_id,))
    await message.reply_text(f"⭐ User {target_user_id} has been upgraded to Special.")

# /prefer Command
@bot.on_message(filters.command("prefer"))
async def prefer_handler(client, message):
    if not is_owner(message.from_user.id):
        return await message.reply_text("🚫 You don't have permission to use this command.")

    target_user_id = int(message.text.split()[1]) if len(message.text.split()) > 1 else message.reply_to_message.from_user.id
    execute_sql("UPDATE users SET prefer = TRUE WHERE USERID = %s", (target_user_id,))
    await message.reply_text(f"✅ Prefer mode enabled for user {target_user_id}.")

# /as Command (antispam_fu)
@bot.on_message(filters.command("as"))
async def antispam_fu_handler(client, message):
    if not is_owner(message.from_user.id):
        return await message.reply_text("🚫 You don't have permission to use this command.")

    try:
        cmd, user_or_type, flag = message.text.split()
        target_user_id = int(user_or_type) if user_or_type.isdigit() else message.reply_to_message.from_user.id
        flag_value = flag.lower() == "true"
        execute_sql("UPDATE users SET antispam_fu = %s WHERE USERID = %s", (flag_value, target_user_id))
        await message.reply_text(f"🚨 Anti-spam flag set to {flag_value} for user {target_user_id}.")
    except:
        await message.reply_text("🚫 Usage: /as <USERID | REPLY> <True|False>")

# Additional Management Commands:

# /ownerup Command
@bot.on_message(filters.command("ownerup"))
async def ownerup_handler(client, message):
    if not is_owner(message.from_user.id):
        return await message.reply_text("🚫 You don't have permission to use this command.")

    target_user_id = int(message.text.split()[1]) if len(message.text.split()) > 1 else message.reply_to_message.from_user.id
    execute_sql("UPDATE users SET Owner = TRUE WHERE USERID = %s", (target_user_id,))
    await message.reply_text(f"👑 User {target_user_id} has been promoted to Owner.")

# /adminrm Command (Remove Admin)
@bot.on_message(filters.command("adminrm"))
async def adminrm_handler(client, message):
    if not is_owner(message.from_user.id):
        return await message.reply_text("🚫 You don't have permission to use this command.")

    target_user_id = int(message.text.split()[1]) if len(message.text.split()) > 1 else message.reply_to_message.from_user.id
    execute_sql("UPDATE users SET Admin = FALSE WHERE USERID = %s", (target_user_id,))
    await message.reply_text(f"👮 Admin rights removed from user {target_user_id}.")

# /ownerrm Command (Remove Owner)
@bot.on_message(filters.command("ownerrm"))
async def ownerrm_handler(client, message):
    if not is_owner(message.from_user.id):
        return await message.reply_text("🚫 You don't have permission to use this command.")

    target_user_id = int(message.text.split()[1]) if len(message.text.split()) > 1 else message.reply_to_message.from_user.id
    execute_sql("UPDATE users SET Owner = FALSE WHERE USERID = %s", (target_user_id,))
    await message.reply_text(f"👑 Owner rights removed from user {target_user_id}.")

# /unprefer Command (Disable Prefer mode)
@bot.on_message(filters.command("unprefer"))
async def unprefer_handler(client, message):
    if not is_owner(message.from_user.id):
        return await message.reply_text("🚫 You don't have permission to use this command.")

    target_user_id = int(message.text.split()[1]) if len(message.text.split()) > 1 else message.reply_to_message.from_user.id
    execute_sql("UPDATE users SET prefer = FALSE WHERE USERID = %s", (target_user_id,))
    await message.reply_text(f"❌ Prefer mode disabled for user {target_user_id}.")

# /rmsp Command (Remove Special)
@bot.on_message(filters.command("rmsp"))
async def rmsp_handler(client, message):
    if not (is_owner(message.from_user.id) or message.from_user.id in owners):
        return await message.reply_text("🚫 You don't have permission to use this command.")

    target_user_id = int(message.text.split()[1]) if len(message.text.split()) > 1 else message.reply_to_message.from_user.id
    execute_sql("UPDATE users SET Special = FALSE WHERE USERID = %s", (target_user_id,))
    await message.reply_text(f"❌ Special privileges removed for user {target_user_id}.")


    
# /bin Command
@bot.on_message(filters.command("bin"))
async def bin_handler(client, message):
    # Initialize card number as None
    card = None
    
    # Regex pattern to find the card number in a string
    regex_pattern = r'(\d{15,16})\|(\d{1,2})\|(\d{2,4})\|(\d{3,4})'

    # Check if the command is issued as a reply
    if message.reply_to_message:
        # Extract text from the replied message
        text = message.reply_to_message.text.strip()
        # Find card number using regex
        match = re.search(regex_pattern, text)
        if match:
            card = match.group(1)
    
    # If no card is found in the reply or if it's a direct command with the number
    if not card and len(message.command) > 1:
        # Get the number provided directly after the command
        card_input = message.command[1]
        # Search for the card number in the input using regex
        match = re.search(r'(\d{6,16})', card_input)
        if match:
            card = match.group(0)
    
    # Check if card was successfully found
    if not card or len(card) < 6:
        return await message.reply_text("🚫 BIN Error: Unable to extract a valid card number.")

    # Extract the first 6 digits (BIN)
    bin_number = card[:6]

    # Lookup BIN info
    bin_info = bin_lookup(bin_number)

    # Determine user role
    user_id = message.from_user.id
    user_first_name = message.from_user.first_name
    role = ""
    
    conn = psycopg2.connect(conn_string)
    cur = conn.cursor()
    cur.execute("SELECT Premium, VIP, Admin, Owner FROM users WHERE USERID = %s", (user_id,))
    user_roles = cur.fetchone()
    cur.close()
    conn.close()

    if user_roles:
        if user_roles[3]:  # Owner
            role = "Owner"
        elif user_roles[2]:  # Admin
            role = "Admin"
        elif user_roles[1]:  # VIP
            role = "VIP"
        elif user_roles[0]:  # Premium
            role = "Premium"
        else:
            role = "Free User"

    # Create response message
    response_text = (
        f"**BIN INFO | Local CSV (databin + databin2) ✅**\n\n"
        f"**Bank**: **{bin_info['bank_name']}** - **{bin_info['country']}{bin_info['flag']}**\n"
        f"**Info**: **{bin_info['vendor']}** **{bin_info['type']}** - **{bin_info['level']}**\n"
        f"**User**: <a href='tg://user?id={user_id}'>{user_first_name}</a> {role}\n"
    )
    
    await message.reply_text(response_text)


@bot.on_message(filters.command("register"))
async def register_handler(client, message):
    user_id = message.from_user.id
    user_first_name = message.from_user.first_name

    # Check if the user is already registered
    existing_user = fetch_sql("SELECT userid FROM users WHERE userid = %s", (user_id,))
    if existing_user:
        return await message.reply_text("🚫 You are already registered.")

    # Register the new user in the users table
    execute_sql(
        "INSERT INTO users (userid, first_name) VALUES (%s, %s);",
        (user_id, user_first_name),
    )

    # Initialize user settings in the user_settings table with all False
    execute_sql(
        "INSERT INTO user_settings (user_id, flag_match, vendor_match, type_match, level_match) VALUES (%s, FALSE, FALSE, FALSE, FALSE);",
        (user_id,)
    )

    await message.reply_text("✅ You have been successfully registered!")



    #Not Registered Handle
@bot.on_message(filters.command("info"))
async def info_handler(client, message):
    user_id = message.from_user.id
    users = fetch_sql(
        "SELECT userid, first_name, premium, vip, admin, owner FROM users WHERE userid = %s",
        (user_id,),
    )

    if users:
        _, first_name, premium, vip, admin, owner = users
        role = "User"
        if owner:
            role = "Owner"
        elif admin:
            role = "Admin"
        elif vip:
            role = "VIP"
        elif premium:
            role = "Premium"
        response_text = (
            f"**User Information**\n\n"
            f"**ID**: {user_id}\n"
            f"**First Name**: {first_name}\n"
            f"**Role**: {role}\n"
        )
    else:
        response_text = "🚫 You are not registered."

    await message.reply_text(response_text)




# Database connection (make sure to fill in your own database details)


@bot.on_message(filters.command("finder"))
def find_messages(bot_client, message):
    user_id = message.from_user.id
    role = get_user_role(user_id)

    # Only allow specific roles to use this command
    if role not in ["Owner", "Admin", "VIP", "Premium"]:
        message.reply_text("You are not authorized to use this command.")
        return

    # Process the BIN command
    text = message.text.split(maxsplit=2)
    if len(text) >= 2:
        bin_digit = text[1].strip()
        limit = int(text[2]) if len(text) == 3 and text[2].isdigit() else None

        if len(bin_digit) != 6 or not bin_digit.isdigit():
            message.reply_text("Please provide a valid 6-digit BIN.")
            return

        # Process the request in a new thread to handle multiple users
        Thread(target=process_request, args=(bot_client, message, bin_digit, limit)).start()
    else:
        message.reply_text("Please provide a 6-digit BIN after /finder")

def process_request(bot_client, message, bin_digit, limit):
    regex_pattern = re.compile(rf'({bin_digit})(\d{{9,10}})\|(\d{{1,2}})\|(\d{{2,4}})\|(\d{{3,4}})')
    file_name = f"data_{bin_digit}.txt"
    
    with open(file_name, "w") as f:
        pass

    bin_info = bin_lookup(bin_digit)
    if not bin_info:
        bot_client.send_message(message.chat.id, f"No BIN information found for {bin_digit}.")
        return

    total_found = 0
    start_time = time.time()
    stop_event = Event()

    search_key = (int(message.chat.id), int(message.from_user.id))
    with ACTIVE_SEARCHES_LOCK:
        ACTIVE_SEARCHES[search_key] = stop_event

    def search_messages():
        nonlocal total_found
        for dialog in app.get_dialogs():  # Use the app client for getting dialogs
            if stop_event.is_set() or time.time() - start_time > 300:  # 5 minutes limit
                break

            chat_id = dialog.chat.id
            limit_reached = False

            for msg in app.search_messages(chat_id, query=bin_digit, limit=limit or float('inf')):  # Use app client here
                if msg.text:
                    matches = regex_pattern.findall(msg.text)
                    if matches:
                        with open(file_name, "a") as f:
                            for match in matches:
                                bin_digit_part = match[0]
                                remaining_parts = match[1:]
                                formatted_match = f"{bin_digit_part}{remaining_parts[0]}|{remaining_parts[1]}|{remaining_parts[2]}|{remaining_parts[3]}"
                                f.write(formatted_match + "\n")
                            
                                total_found += 1
                                if limit and total_found >= limit:
                                    limit_reached = True
                                    break
                if limit_reached:
                    break

    status_message = bot_client.send_message(
        message.chat.id,
        f"Searching `{bin_digit}` Cards 🔎\nBin Details: \nLimit: {limit or 'No Limit'}\nTotal CC Found: 0",
        reply_markup=InlineKeyboardMarkup(
            [[InlineKeyboardButton("Stop", callback_data=f"stop_{message.chat.id}_{message.from_user.id}")]]
        )
    )

    def update_status():
        while not stop_event.is_set() and time.time() - start_time <= 300:  # 5 minutes limit
            time.sleep(5)
            elapsed_time = time.time() - start_time
            status_message.edit_text(
                f"""
Searching {bin_digit} Cards 🔎
**Bank**: **{bin_info['bank_name']}** - **{bin_info['country']} {bin_info['flag']}**
**Info**: **{bin_info['vendor']}** **{bin_info['type']}** - **{bin_info['level']}**
**User**: <a href="tg://user?id={message.from_user.id}">{message.from_user.first_name}</a>
Limit: {limit or 'No Limit'}
Total CC Found: {total_found}
Elapsed Time: {int(elapsed_time)}s
""",
                reply_markup=InlineKeyboardMarkup(
                    [[InlineKeyboardButton("Stop", callback_data=f"stop_{message.chat.id}_{message.from_user.id}")]]
                )
            )

            if limit and total_found >= limit:
                break

    try:
        search_thread = Thread(target=search_messages)
        search_thread.start()

        update_thread = Thread(target=update_status)
        update_thread.start()

        search_thread.join()
        update_thread.join()
    finally:
        with ACTIVE_SEARCHES_LOCK:
            ACTIVE_SEARCHES.pop(search_key, None)

    finish_reason = "Time Limit Reached" if time.time() - start_time > 300 else "Stopped by User"

    bot_client.send_message(
        message.chat.id,
        f"""
Searching {bin_digit} Cards 🔎
**Bank**: **{bin_info['bank_name']}** - **{bin_info['country']} {bin_info['flag']}**
**Info**: **{bin_info['vendor']}** **{bin_info['type']}** - **{bin_info['level']}**
**User**: <a href="tg://user?id={message.from_user.id}">{message.from_user.first_name}</a>
Total CC Found: {total_found}
Elapsed Time: {int(time.time() - start_time)}s
FINISHED. Reason: {finish_reason}
"""
    )

    # Send the data file to the user
    if total_found > 0:
        bot_client.send_document(message.chat.id, file_name)
    else:
        bot_client.send_message(message.chat.id, f"No matches found for BIN {bin_digit}.")

def stop_search(client, callback_query):
    parts = callback_query.data.split('_')
    chat_id = int(parts[1])
    target_user_id = int(parts[2])

    if callback_query.from_user.id != target_user_id and callback_query.from_user.id not in admin_ids:
        client.answer_callback_query(
            callback_query.id,
            "You are not authorized to stop this search.",
            show_alert=True,
        )
        return

    with ACTIVE_SEARCHES_LOCK:
        event = ACTIVE_SEARCHES.get((chat_id, target_user_id))

    if not event:
        client.answer_callback_query(callback_query.id, "No active search to stop.", show_alert=True)
        return

    event.set()
    callback_query.message.edit_text("Search stopped.")
    client.answer_callback_query(callback_query.id, "Search stopped.")

@bot.on_callback_query(filters.regex(r"^stop_\d+_\d+$"))
def on_stop_button(bot_client, callback_query):
    stop_search(bot_client, callback_query)







@bot.on_message(filters.command("settings"))
def settings_command(bot_client, message):
    user_id = message.from_user.id
    flag_match, vendor_match, type_match, level_match = get_user_settings(user_id)

    # Create inline buttons for each setting
    keyboard = InlineKeyboardMarkup([
        [
            InlineKeyboardButton(f"Flag Match 🇺🇳: {'True' if flag_match else 'False'}", callback_data=f"toggle_flag_match_{user_id}"),
            InlineKeyboardButton(f"{'True' if flag_match else 'False'}", callback_data=f"toggle_flag_match_status_{user_id}")
        ],
        [
            InlineKeyboardButton(f"Vendor Match ⚔️: {'True' if vendor_match else 'False'}", callback_data=f"toggle_vendor_match_{user_id}"),
            InlineKeyboardButton(f"{'True' if vendor_match else 'False'}", callback_data=f"toggle_vendor_match_status_{user_id}")
        ],
        [
            InlineKeyboardButton(f"Type Match: {'True' if type_match else 'False'}", callback_data=f"toggle_type_match_{user_id}"),
            InlineKeyboardButton(f"{'True' if type_match else 'False'}", callback_data=f"toggle_type_match_status_{user_id}")
        ],
        [
            InlineKeyboardButton(f"Level Match 🎚️: {'True' if level_match else 'False'}", callback_data=f"toggle_level_match_{user_id}"),
            InlineKeyboardButton(f"{'True' if level_match else 'False'}", callback_data=f"toggle_level_match_status_{user_id}")
        ],
        [
            InlineKeyboardButton("Close", callback_data=f"close_settings_{user_id}")
        ]
    ])

    bot_client.send_message(chat_id=message.chat.id, text="Configure your settings:", reply_markup=keyboard)

@bot.on_callback_query(filters.regex(r"^(toggle_|close_)"))
def toggle_or_close_setting(bot_client, query: CallbackQuery):
    user_id = int(query.data.split('_')[-1])
    if query.from_user.id != user_id:
        query.answer("You are not authorized to change these settings.", show_alert=True)
        return

    if query.data.startswith("close_"):
        query.message.delete()
        return

    # Extract setting key from callback data
    action = query.data.split('_')[1]
    if action not in ['flag', 'vendor', 'type', 'level']:
        query.answer("Invalid setting.", show_alert=True)
        return

    setting_key = f"{action}_match"

    # Fetch current settings
    settings = get_user_settings(user_id)
    setting_value_map = {
        'flag_match': settings[0],
        'vendor_match': settings[1],
        'type_match': settings[2],
        'level_match': settings[3]
    }

    # Toggle the selected setting
    new_value = not setting_value_map[setting_key]
    update_user_setting(user_id, setting_key, new_value)

    query.answer(f"{setting_key.replace('_', ' ').capitalize()} set to {'True' if new_value else 'False'}")

    # Update the keyboard
    updated_settings = get_user_settings(user_id)
    updated_keyboard = InlineKeyboardMarkup([
        [
            InlineKeyboardButton(f"Flag Match 🇺🇳: {'True' if updated_settings[0] else 'False'}", callback_data=f"toggle_flag_{user_id}"),
            InlineKeyboardButton(f"{'True' if updated_settings[0] else 'False'}", callback_data=f"toggle_flag_status_{user_id}")
        ],
        [
            InlineKeyboardButton(f"Vendor Match ⚔️: {'True' if updated_settings[1] else 'False'}", callback_data=f"toggle_vendor_{user_id}"),
            InlineKeyboardButton(f"{'True' if updated_settings[1] else 'False'}", callback_data=f"toggle_vendor_status_{user_id}")
        ],
        [
            InlineKeyboardButton(f"Type Match: {'True' if updated_settings[2] else 'False'}", callback_data=f"toggle_type_{user_id}"),
            InlineKeyboardButton(f"{'True' if updated_settings[2] else 'False'}", callback_data=f"toggle_type_status_{user_id}")
        ],
        [
            InlineKeyboardButton(f"Level Match 🎚️: {'True' if updated_settings[3] else 'False'}", callback_data=f"toggle_level_{user_id}"),
            InlineKeyboardButton(f"{'True' if updated_settings[3] else 'False'}", callback_data=f"toggle_level_status_{user_id}")
        ],
        [
            InlineKeyboardButton("Close", callback_data=f"close_settings_{user_id}")
        ]
    ])

    query.message.edit_reply_markup(reply_markup=updated_keyboard)


@bot.on_message(filters.command("sbin"))
async def sbin_command(client, message):
    user_id = message.from_user.id
    user_role = get_user_role(user_id)
    user_registered = fetch_sql("SELECT userid FROM users WHERE userid = %s", (user_id,))

    if not user_registered:
        await message.reply_text("🚫 You are not registered. Please use the /register command to register.")
        return

    if user_role == "Free User":
        await message.reply_text(
            "🚫 **Access Denied:** This command is only available to Premium, VIP, Admin, or Owner users."
        )
        return

    if len(message.command) < 2:
        await message.reply_text("Usage: `/sbin <BIN>`")
        return

    bin_number = message.command[1]
    bin_info = bin_lookup(bin_number)
    if not bin_info:
        await message.reply_text("🚫 BIN not found in local database.")
        return
    bank_name = bin_info['bank_name']

    matches = search_databin(bank_name)

    if len(matches) > 5:
        initial_message = await message.reply_text(
            f"🔍 **BIN Search Results for Bank:** `{bank_name}`\n\n"
            f"Found more than **5** results. Sending the first 5:\n\n"
            f"{format_message(matches[:5])}"
        )
        await asyncio.sleep(7)
        file_name = save_matches_to_file(matches, bank_name)
        await client.send_document(
            chat_id=message.chat.id,
            document=file_name,
            caption=f"📄 **Complete BIN Results for Bank:** `{bank_name}`\n"
                    f"Total Matches Found: **{len(matches)}**",
        )
        await initial_message.edit_text(
            f"🔍 **BIN Search Results for Bank:** `{bank_name}`\n\n"
            f"Found more than **5** results. The complete list of **{len(matches)}** matches has been sent as a file."
        )
    else:
        await message.reply_text(
            f"🔍 **BIN Search Results for Bank:** `{bank_name}`\n\n"
            f"{format_message(matches)}"
        )

@bot.on_message(filters.command("abs"))
async def abs_command(client, message):
    user_id = message.from_user.id
    user_role = get_user_role(user_id)
    
    user_registered = fetch_sql("SELECT userid FROM users WHERE userid = %s", (user_id,))

    if not user_registered:
        await message.reply_text("🚫 You are not registered. Please use the /register command to register.")
        return

    if user_role == "Free User":
        await message.reply_text(
            "🚫 **Access Denied:** This command is only available to Premium, VIP, Admin, or Owner users."
        )
        return

    if len(message.command) < 2:
        await message.reply_text("Usage: `/abs <BIN>`")
        return

    bin_number = message.command[1]
    bin_info = bin_lookup(bin_number)
    if not bin_info:
        await message.reply_text("🚫 BIN not found in local database.")
        return
    settings = get_user_settings(user_id)

    setting_value_map = {
        'flag_match': settings[0],
        'vendor_match': settings[1],
        'type_match': settings[2],
        'level_match': settings[3]
    }

    filter_criteria = {}
    if setting_value_map['flag_match']:
        filter_criteria['country'] = bin_info['country']
    if setting_value_map['vendor_match']:
        filter_criteria['vendor'] = bin_info['vendor']
    if setting_value_map['type_match']:
        filter_criteria['type'] = bin_info['type']
    if setting_value_map['level_match']:
        filter_criteria['level'] = bin_info['level']

    matches = search_databin(bin_info['bank_name'], filter_criteria)

    if len(matches) > 5:
        initial_message = await message.reply_text(
            f"🔍 **Advanced BIN Search Results for Bank:** `{bin_info['bank_name']}`\n\n"
            f"Found more than **5** results. Sending the first 5:\n\n"
            f"{format_message(matches[:5])}"
        )
        await asyncio.sleep(7)
        file_name = save_matches_to_file(matches, bin_info['bank_name'])
        await client.send_document(
            chat_id=message.chat.id,
            document=file_name,
            caption=f"📄 **Complete BIN Results for Bank:** `{bin_info['bank_name']}`\n"
                    f"Total Matches Found: **{len(matches)}**",
        )
        await initial_message.edit_text(
            f"🔍 **Advanced BIN Search Results for Bank:** `{bin_info['bank_name']}`\n\n"
            f"Found more than **5** results. The complete list of **{len(matches)}** matches has been sent as a file."
        )
    else:
        await message.reply_text(
            f"🔍 **Advanced BIN Search Results for Bank:** `{bin_info['bank_name']}`\n\n"
            f"{format_message(matches)}"
        )

@bot.on_message(filters.command("bbs"))
async def bbs_command(client, message):
    user_id = message.from_user.id
    user_role = get_user_role(user_id)
    user_registered = fetch_sql("SELECT userid FROM users WHERE userid = %s", (user_id,))

    if not user_registered:
        await message.reply_text("🚫 You are not registered. Please use the /register command to register.")
        return

    if user_role == "Free User":
        await message.reply_text(
            "🚫 **Access Denied:** This command is only available to Premium, VIP, Admin, or Owner users."
        )
        return

    if len(message.command) < 2:
        await message.reply_text("Usage: `/bbs <bank name>`")
        return

    bank_name_input = " ".join(message.command[1:])
    matches = search_databin_by_bank_name(bank_name_input)

    if len(matches) > 5:
        initial_message = await message.reply_text(
            f"🔍 **Bank Search Results for:** `{bank_name_input}`\n\n"
            f"Found more than **5** results. Sending the first 5:\n\n"
            f"{format_message(matches[:5])}"
        )
        await asyncio.sleep(7)
        file_name = save_matches_to_file(matches, bank_name_input)
        await client.send_document(
            chat_id=message.chat.id,
            document=file_name,
            caption=f"📄 **Complete Bank Search Results for:** `{bank_name_input}`\n"
                    f"Total Matches Found: **{len(matches)}**",
        )
        await initial_message.edit_text(
            f"🔍 **Bank Search Results for:** `{bank_name_input}`\n\n"
            f"Found more than **5** results. The complete list of **{len(matches)}** matches has been sent as a file."
        )
    else:
        await message.reply_text(
            f"🔍 **Bank Search Results for:** `{bank_name_input}`\n\n"
            f"{format_message(matches)}"
        )
@bot.on_message(filters.command("binl"))
async def lookupbin_handler(client, message):
    # Initialize card number as None
    card = None
    
    # Regex pattern to find the card number in a string
    regex_pattern = r'(\d{15,16})\|(\d{1,2})\|(\d{2,4})\|(\d{3,4})'

    # Check if the command is issued as a reply
    if message.reply_to_message:
        # Extract text from the replied message
        text = message.reply_to_message.text.strip()
        # Find card number using regex
        match = re.search(regex_pattern, text)
        if match:
            card = match.group(1)
    
    # If no card is found in the reply or if it's a direct command with the number
    if not card and len(message.command) > 1:
        # Get the number provided directly after the command
        card_input = message.command[1]
        # Search for the card number in the input using regex
        match = re.search(r'(\d{6,16})', card_input)
        if match:
            card = match.group(0)
    
    # Check if card was successfully found
    if not card or len(card) < 6:
        return await message.reply_text("🚫 BIN Error: Unable to extract a valid card number.")

    # Extract the first 6 digits (BIN)
    bin_number = card[:6]

    # Lookup BIN info
    bin_info = bin_lookup2(bin_number)

    # Determine user role
    user_id = message.from_user.id
    user_first_name = message.from_user.first_name
    role = ""
    
    # Database connection
    conn = psycopg2.connect(conn_string)
    cur = conn.cursor()
    cur.execute("SELECT Premium, VIP, Admin, Owner FROM users WHERE USERID = %s", (user_id,))
    user_roles = cur.fetchone()
    cur.close()
    conn.close()

    if user_roles:
        if user_roles[3]:  # Owner
            role = "Owner"
        elif user_roles[2]:  # Admin
            role = "Admin"
        elif user_roles[1]:  # VIP
            role = "VIP"
        elif user_roles[0]:  # Premium
            role = "Premium"
        else:
            role = "Free User"

    # Create response message with additional details
    response_text = (
        f"**BIN Lookup Result | Database2 ✅**\n\n"
        f"**Bank**: **{bin_info['bank_name']}** - **{bin_info['country']} {bin_info['flag']}**\n"
        f"**Scheme (Network)**: **{bin_info['vendor']}**\n"
        f"**Type**: **{bin_info['type']}**\n"
        f"**Brand**: **{bin_info['level']}**\n"
        f"**Prepaid**: **{bin_info['prepaid']}**\n"
        f"**Country Code**: **{bin_info['country_code']}**\n"
        f"**Currency**: **{bin_info['currency']}**\n"
        f"**Country Latitude**: **{bin_info['latitude']}**\n"
        f"**Country Longitude**: **{bin_info['longitude']}**\n\n"
        f"**User**: <a href='tg://user?id={user_id}'>{user_first_name}</a> - **{role}**\n"
    )
    
    await message.reply_text(response_text)

@bot.on_message(filters.command("binw"))
async def binw_handler(client, message):
    # Initialize card number as None
    card = None
    
    # Regex pattern to find the card number in a string
    regex_pattern = r'(\d{15,16})\|(\d{1,2})\|(\d{2,4})\|(\d{3,4})'

    # Check if the command is issued as a reply
    if message.reply_to_message:
        # Extract text from the replied message
        text = message.reply_to_message.text.strip()
        # Find card number using regex
        match = re.search(regex_pattern, text)
        if match:
            card = match.group(1)
    
    # If no card is found in the reply or if it's a direct command with the number
    if not card and len(message.command) > 1:
        # Get the number provided directly after the command
        card_input = message.command[1]
        # Search for the card number in the input using regex
        match = re.search(r'(\d{6,16})', card_input)
        if match:
            card = match.group(0)
    
    # Check if card was successfully found
    if not card or len(card) < 6:
        return await message.reply_text("🚫 BIN Error: Unable to extract a valid card number.")

    # Extract the first 6 digits (BIN)
    bin_number = card[:6]

    # Lookup BIN info using the third API
    bin_info = bin_lookup3(bin_number)

    # Determine user role
    user_id = message.from_user.id
    user_first_name = message.from_user.first_name
    role = ""
    
    # Database connection
    conn = psycopg2.connect(conn_string)
    cur = conn.cursor()
    cur.execute("SELECT Premium, VIP, Admin, Owner FROM users WHERE USERID = %s", (user_id,))
    user_roles = cur.fetchone()
    cur.close()
    conn.close()

    if user_roles:
        if user_roles[3]:  # Owner
            role = "Owner"
        elif user_roles[2]:  # Admin
            role = "Admin"
        elif user_roles[1]:  # VIP
            role = "VIP"
        elif user_roles[0]:  # Premium
            role = "Premium"
        else:
            role = "Free User"

    # Create response message with additional details
    response_text = (
        f"**BIN Lookup Result | ChargeBlast ✅**\n\n"
        f"**Issuer**: **{bin_info['issuer']}**\n"
        f"**Country**: **{bin_info['country']}** ({bin_info['a2']}/{bin_info['a3']})\n"
        f"**Brand**: **{bin_info['brand']}**\n"
        f"**Type**: **{bin_info['type']}**\n"
        f"**Latitude**: **{bin_info['latitude']}**\n"
        f"**Longitude**: **{bin_info['longitude']}**\n\n"
        f"**User**: <a href='tg://user?id={user_id}'>{user_first_name}</a> - **{role}**\n"
    )
    
    await message.reply_text(response_text)
@bot.on_message(filters.command("binpro"))
async def binpro_handler(client, message):
    # Initialize card number as None
    card = None
    
    # Regex pattern to find the card number in a string
    regex_pattern = r'(\d{15,16})\|(\d{1,2})\|(\d{2,4})\|(\d{3,4})'

    # Check if the command is issued as a reply
    if message.reply_to_message:
        # Extract text from the replied message
        text = message.reply_to_message.text.strip()
        # Find card number using regex
        match = re.search(regex_pattern, text)
        if match:
            card = match.group(1)
    
    # If no card is found in the reply or if it's a direct command with the number
    if not card and len(message.command) > 1:
        # Get the number provided directly after the command
        card_input = message.command[1]
        # Search for the card number in the input using regex
        match = re.search(r'(\d{6,16})', card_input)
        if match:
            card = match.group(0)
    
    # Check if card was successfully found
    if not card or len(card) < 6:
        return await message.reply_text("🚫 BIN Error: Unable to extract a valid card number.")

    # Extract the first 6 digits (BIN)
    bin_number = card[:6]

    # Lookup BIN info using the professional BIN API
    bin_info = bin_lookup_pro(bin_number)

    # Determine user role
    user_id = message.from_user.id
    user_first_name = message.from_user.first_name
    role = ""
    
    # Database connection
    conn = psycopg2.connect(conn_string)
    cur = conn.cursor()
    cur.execute("SELECT Premium, VIP, Admin, Owner FROM users WHERE USERID = %s", (user_id,))
    user_roles = cur.fetchone()
    cur.close()
    conn.close()

    if user_roles:
        if user_roles[3]:  # Owner
            role = "Owner"
        elif user_roles[2]:  # Admin
            role = "Admin"
        elif user_roles[1]:  # VIP
            role = "VIP"
        elif user_roles[0]:  # Premium
            role = "Premium"
        else:
            role = "Free User"

    # Create response message with all details
    response_text = (
        f"**Professional BIN Lookup Result | Database ✅**\n\n"
        f"**Customer Name**: **{bin_info['customerName']}**\n"
        f"**Country**: **{bin_info['country']} ({bin_info['countryCode']}/{bin_info['countryAlpha3']})**\n"
        f"**BIN**: **{bin_info['binNum']}** (Length: {bin_info['binLength']})\n"
        f"**Acceptance Brand**: **{bin_info['acceptanceBrand']}**\n"
        f"**Product Code**: **{bin_info['productCode']}**\n"
        f"**Product Description**: **{bin_info['productDescription']}**\n"
        f"**Funding Source**: **{bin_info['fundingSource']}**\n"
        f"**Consumer Type**: **{bin_info['consumerType']}**\n"
        f"**Smart Data Enabled**: **{bin_info['smartDataEnabled']}**\n"
        f"**Local Use**: **{bin_info['localUse']}**\n"
        f"**Authorization Only**: **{bin_info['authorizationOnly']}**\n"
        f"**Government Range**: **{bin_info['governmentRange']}**\n"
        f"**Non-Reloadable**: **{bin_info['nonReloadableIndicator']}**\n"
        f"**Anonymous Prepaid**: **{bin_info['anonymousPrepaidIndicator']}**\n"
        f"**Cardholder Currency Indicator**: **{bin_info['cardholderCurrencyIndicator']}**\n"
        f"**Program Name**: **{bin_info['programName']}**\n"
        f"**Vertical**: **{bin_info['vertical']}**\n\n"
        f"**User**: <a href='tg://user?id={user_id}'>{user_first_name}</a> - **{role}**\n"
    )
    
    await message.reply_text(response_text)
            
            
# /bank command { IDEA BY Kratos }
@bot.on_message(filters.command("bank"))
async def bank_handler(client, message):
    user_id = message.from_user.id
    query = " ".join(message.command[1:]) if len(message.command) > 1 else None
    
    if not query:
        await message.reply_text("❓ *Please provide a bank name to search.*")
        return
    
    results = search_databin_by_bank_name(query)
    
    if not results:
        await message.reply_text(f"🚫 *No results found for* `{query}`")
        return
    
    banks = list({row['bank_name'] for row in results})
    
    # Store user settings with a 30-minute expiration
    user_settings[user_id] = {
        'step': 'bank',
        'banks': banks,
        'time': datetime.now() + timedelta(minutes=30)
    }
    
    if len(banks) == 0:
        await message.reply_text(f"🚫 *No results found for* `{query}`")
    elif len(banks) <= 6:
        inline_buttons = [
            [InlineKeyboardButton(f"🏦 {bank}", callback_data=f"bank_{generate_random_string()}")] for bank in banks
        ]
        await message.reply_text(
            f"🔍 *Select the bank you're interested in:*",
            reply_markup=InlineKeyboardMarkup(inline_buttons)
        )
    elif len(banks) <= 20:
        await message.reply_text(f"🏦 *Bank results:*\n\n" + "\n".join([f"• {bank}" for bank in banks]))
    else:
        filename = "banks_results.txt"
        with open(filename, "w") as f:
            f.write("\n".join(banks))
        await message.reply_document(filename)
        time.sleep(7)


# Callback for selected bank
# Callback for selected bank
@bot.on_callback_query(filters.regex(r"^bank_(.+)"))
async def bank_callback(client, callback_query):
    user_id = callback_query.from_user.id
    
    if user_id not in user_settings or user_settings[user_id]['step'] != 'bank':
        await callback_query.answer("❌ This action is no longer available. Please start again.", show_alert=True)
        return
    
    # Since the callback data is random, we'll retrieve the bank name from user settings
    bank_name = next(bank for bank in user_settings[user_id]['banks'] if f"bank_{callback_query.data.split('_')[1]}" in callback_query.data)
    
    # Update user settings
    user_settings[user_id].update({
        'step': 'country',
        'selected_bank': bank_name
    })
    
    results = search_databin_by_bank_name(bank_name)
    
    # Remove duplicate countries
    countries = remove_duplicates(results, key=lambda x: x['country'])
    
    country_buttons = [
        [InlineKeyboardButton(f"{row['flag']} {row['country']}", callback_data=f"country_{generate_random_string()}_{row['country']}_{bank_name}")]
        for row in countries
    ]
    
    await callback_query.message.edit_text(
        f"🏦 *Bank:* `{bank_name}`\n🌍 *Select a country:*",
        reply_markup=InlineKeyboardMarkup(country_buttons)
    )

@bot.on_callback_query(filters.regex(r"^country_(.+)"))
async def country_callback(client, callback_query):
    user_id = callback_query.from_user.id
    
    if user_id not in user_settings or user_settings[user_id]['step'] != 'country':
        await callback_query.answer("❌ This action is no longer available. Please start again.", show_alert=True)
        return
    
    data = callback_query.data.split("_")
    country = data[2]
    bank_name = data[3]
    
    # Update user settings
    user_settings[user_id].update({
        'step': 'type',
        'selected_country': country
    })
    
    results = search_databin_by_bank_name(bank_name)
    
    # Remove duplicate types
    types = remove_duplicates([row for row in results if row['country'] == country], key=lambda x: x['type'])
    
    type_buttons = [
        [InlineKeyboardButton(f"⚔️ {row['type']}", callback_data=f"type_{user_id}_{generate_random_string()}_{row['type']}_{bank_name}_{country}")]
        for row in types
    ]
    
    await callback_query.message.edit_text(
        f"🏦 *Bank:* `{bank_name}`\n🌍 *Country:* `{country}`\n⚙️ *Select a type:*",
        reply_markup=InlineKeyboardMarkup(type_buttons)
    )


@bot.on_callback_query(filters.regex(r"^type_(.+)"))
async def type_callback(client, callback_query):
    user_id = callback_query.from_user.id
    
    if user_id not in user_settings or user_settings[user_id]['step'] != 'type':
        await callback_query.answer("❌ This action is no longer available. Please start again.", show_alert=True)
        return
    
    data = callback_query.data.split("_")
    type_name = data[3]
    bank_name = data[4]
    country = data[5]
    
    # Update user settings
    user_settings[user_id].update({
        'step': 'vendor',
        'selected_type': type_name
    })
    
    results = search_databin_by_bank_name(bank_name)
    
    # Remove duplicate vendors
    vendors = remove_duplicates([row for row in results if row['country'] == country and row['type'] == type_name], key=lambda x: x['vendor'])
    
    vendor_buttons = [
        [InlineKeyboardButton(f"💳 {vendor}", callback_data=f"vendor_{user_id}_{generate_random_string()}_{vendor}_{bank_name}_{country}_{type_name}")]
        for vendor in vendors
    ]
    
    await callback_query.message.edit_text(
        f"🏦 *Bank:* `{bank_name}`\n🌍 *Country:* `{country}`\n⚙️ *Type:* `{type_name}`\n💳 *Select a vendor:*",
        reply_markup=InlineKeyboardMarkup(vendor_buttons)
    )

# Callback for selected vendor
# Callback for selected vendor
@bot.on_callback_query(filters.regex(r"^vendor_(.+)"))
async def vendor_callback(client, callback_query):
    user_id = callback_query.from_user.id
    
    if user_id not in user_settings or user_settings[user_id]['step'] != 'vendor':
        await callback_query.answer("❌ This action is no longer available. Please start again.", show_alert=True)
        return
    
    data = callback_query.data.split("_")
    vendor = data[3]
    bank_name = data[4]
    country = data[5]
    type_name = data[6]
    
    results = [row for row in search_databin_by_bank_name(bank_name) if row['country'] == country and row['type'] == type_name and row['vendor'] == vendor]
    
    # Generate a unique filename using hashlib
    date_str = datetime.now().strftime("%Y-%m-%d")
    hash_string = f"{bank_name}_{date_str}"
    filename_hash = hashlib.sha256(hash_string.encode()).hexdigest()[:10]
    filename = f"hash_{filename_hash}_{date_str}.txt"
    
    if len(results) > 20:
        with open(filename, "w") as f:
            f.write("\n".join([f"🔢 {row['number']} | 🇺🇳 {row['country']} | ⚙️ {row['type']} | 💳 {row['vendor']}" for row in results]))
        await callback_query.message.reply_document(filename, caption=f"📄 *Complete BIN Results for Bank:* `{bank_name}`\n*Total Matches Found:* `{len(results)}`\n*HASH:* `{filename_hash}`\n*Status:* *FINISHED*")
        await callback_query.message.edit_reply_markup(reply_markup=None)  # Remove inline buttons after completion
    else:
        await callback_query.message.edit_text(
            f"🏦 *Bank:* `{bank_name}`\n🌍 *Country:* `{country}`\n⚙️ *Type:* `{type_name}`\n💳 *Vendor:* `{vendor}`\n🔍 *Results:*\n\n" +
            "\n".join([f"🔢 `{row['number']}` | 🇺🇳 **{row['country']}** | ⚙️ **{row['type']}** | 💳 **{row['vendor']}**" for row in results]),
            disable_web_page_preview=True  # Disable link previews in text
        )


# Clear expired user settings
@bot.on_message(filters.command("cst"))
async def clear_settings_handler(client, message):
    user_id = message.from_user.id
    current_time = datetime.now()
    for user in list(user_settings.keys()):
        if user_settings[user]['time'] < current_time:
            del user_settings[user]
    await message.reply_text("🧹 *Expired settings cleared.*")




if __name__ == "__main__":
    bot.start()
    app.run()








        












