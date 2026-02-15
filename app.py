# -*- coding: utf-8 -*-
# qdzproject no copy
import requests, os, psutil, sys, jwt, pickle, json, binascii, time, urllib3, base64, datetime, re, socket, threading, ssl, pytz, aiohttp
from protobuf_decoder.protobuf_decoder import Parser
from aaa import * ; from bbb import *
from datetime import datetime
from google.protobuf.timestamp_pb2 import Timestamp
from concurrent.futures import ThreadPoolExecutor
from threading import Thread
from Pb2 import DEcwHisPErMsG_pb2 , MajoRLoGinrEs_pb2 , PorTs_pb2 , MajoRLoGinrEq_pb2 , sQ_pb2 , Team_msg_pb2
from aiohttp import web
import signal, sys, random, asyncio, hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  

# Global data
active_clients = []
target_team_code = None
loop_running = False
team_semaphore = asyncio.Semaphore(1) # Chế độ 1 Slot: Acc này ra Acc kia mới vào
background_tasks = set() # Giữ tham chiếu mạnh để tránh lỗi "Task destroyed but pending"
last_activity_time = time.time()
is_restarting = False # Cờ báo hiệu đang trong quá trình login lại



class AccountClient:
    def __init__(self, uid, password):
        self.uid = str(uid).strip()
        self.password = str(password).strip()
        self.key = None
        self.iv = None
        self.token = None
        self.region = None
        self.online_writer = None
        self.whisper_writer = None
        self.bot_uid = None
        self.account_name = "Unknown"
        self.original_index = 0 # Thứ tự trong file để giữ ưu tiên cao
        # Connection management
        self.auth_token = None
        self.chat_ip = None
        self.chat_port = None
        self.online_ip = None
        self.online_port = None
        self.clan_id = None
        self.clan_data = None
        self.ready_event = asyncio.Event()
        self.online_ready = False
        self.chat_ready = False
        self.last_join_time = 0
        self.chat_task = None
        self.online_task = None
        self.running = True # Cờ trạng thái để dừng hẳn acc khi cần

    async def force_abort(self):
        """Ngắt kết nối cực mạnh: transport.abort() + Task.cancel() (Bản FIX lỗi)"""
        try:
            if self.online_writer:
                self.online_writer.transport.abort()
            if self.whisper_writer:
                self.whisper_writer.transport.abort()
        except: pass
        
        self.online_writer = None
        self.whisper_writer = None
        
        # Hủy các task loop và để nó thoát ngầm (Fix lỗi GeneratorExit)
        if self.chat_task and not self.chat_task.done():
            self.chat_task.cancel()
        if self.online_task and not self.online_task.done():
            self.online_task.cancel()
        
        self.chat_ready = False
        self.online_ready = False
        self.ready_event.clear()

    async def restart_tasks_after_delay(self, delay=1):
        """Khởi động lại sau 1 khoảng thời gian chờ"""
        await asyncio.sleep(delay)
        if not self.running: return
        
        self.chat_task = asyncio.create_task(self.chat_loop())
        background_tasks.add(self.chat_task)
        self.chat_task.add_done_callback(background_tasks.discard)
        
        self.online_task = asyncio.create_task(self.online_loop())
        background_tasks.add(self.online_task)
        self.online_task.add_done_callback(background_tasks.discard)

    async def safety_exit_task(self):
        while self.running:
            if target_team_code and self.last_join_time > 0:
                if (time.time() - self.last_join_time) > 0.4:
                    try:
                        # Safety exit if stuck for > 0.3s
                        exit_packet = await ExiT(None, self.key, self.iv)
                        await SEndPacKeT(self.whisper_writer, self.online_writer, 'OnLine', exit_packet)
                        self.last_join_time = 0
                        # print(f"🛡️ Safety Exit Triggered for {self.bot_uid}")
                    except: pass
            await asyncio.sleep(0.1)

    async def chat_loop(self):
        while self.running:
            try:
                reader, writer = await asyncio.open_connection(self.chat_ip, int(self.chat_port))
                self.whisper_writer = writer
                writer.write(bytes.fromhex(self.auth_token))
                await writer.drain()
                
                if self.clan_id:
                    pk = await AuthClan(self.clan_id, self.clan_data, self.key, self.iv)
                    writer.write(pk)
                    await writer.drain()
                
                self.chat_ready = True
                if self.online_ready: self.ready_event.set()
                
                while True:
                    data = await reader.read(9999)
                    if not data: break
            except asyncio.CancelledError:
                break
            except Exception:
                pass
            
            self.whisper_writer = None
            self.chat_ready = False
            await asyncio.sleep(0.5)

    async def online_loop(self):
        while self.running:
            try:
                reader, writer = await asyncio.open_connection(self.online_ip, int(self.online_port))
                self.online_writer = writer
                writer.write(bytes.fromhex(self.auth_token))
                await writer.drain()
                
                self.online_ready = True
                if self.chat_ready: self.ready_event.set()
                
                while True:
                    data = await reader.read(9999)
                    if not data: break
            except asyncio.CancelledError:
                break
            except Exception:
                pass
            
            self.online_writer = None
            self.online_ready = False
            await asyncio.sleep(0.5)

    async def login(self):
        try:
            open_id , access_token = await GeNeRaTeAccEss(self.uid , self.password)
            if not open_id or not access_token: return False
            
            PyL = await EncRypTMajoRLoGin(open_id , access_token)
            MajoRLoGinResPonsE = await MajorLogin(PyL)
            if not MajoRLoGinResPonsE: return False
            
            MajoRLoGinauTh = await DecRypTMajoRLoGin(MajoRLoGinResPonsE)
            self.token = MajoRLoGinauTh.token
            self.key = MajoRLoGinauTh.key
            self.iv = MajoRLoGinauTh.iv
            self.region = MajoRLoGinauTh.region
            self.bot_uid = MajoRLoGinauTh.account_uid
            timestamp = MajoRLoGinauTh.timestamp
            
            LoGinDaTa = await GetLoginData(MajoRLoGinauTh.url , PyL , self.token)
            if not LoGinDaTa: return False
            LoGinDaTaUncRypTinG = await DecRypTLoGinDaTa(LoGinDaTa)
            self.account_name = LoGinDaTaUncRypTinG.AccountName

            self.online_ip, self.online_port = LoGinDaTaUncRypTinG.Online_IP_Port.split(":")
            self.chat_ip, self.chat_port = LoGinDaTaUncRypTinG.AccountIP_Port.split(":")
            self.auth_token = await xAuThSTarTuP(int(self.bot_uid) , self.token , int(timestamp) , self.key , self.iv)
            self.clan_id, self.clan_data = LoGinDaTaUncRypTinG.Clan_ID, LoGinDaTaUncRypTinG.Clan_Compiled_Data
            
            # Khởi chạy các loop kết nối và lưu tham chiếu mạnh
            self.chat_task = asyncio.create_task(self.chat_loop())
            background_tasks.add(self.chat_task)
            self.chat_task.add_done_callback(background_tasks.discard)
            
            self.online_task = asyncio.create_task(self.online_loop())
            background_tasks.add(self.online_task)
            self.online_task.add_done_callback(background_tasks.discard)

            task_ka = asyncio.create_task(self.keep_alive_task())
            background_tasks.add(task_ka)
            task_ka.add_done_callback(background_tasks.discard)

            task_safety = asyncio.create_task(self.safety_exit_task())
            background_tasks.add(task_safety)
            task_safety.add_done_callback(background_tasks.discard)
            
            # Đợi kết nối đầu tiên thành công
            try:
                await asyncio.wait_for(self.ready_event.wait(), timeout=20)
                return True
            except: return False
        except: return False

    async def keep_alive_task(self):
        while True:
            if self.online_writer:
                try:
                    ping_packet = await GeT_Status(int(self.bot_uid), self.key, self.iv)
                    self.online_writer.write(ping_packet)
                    await self.online_writer.drain()
                except: pass
            await asyncio.sleep(45)

async def encrypt_packet(packet_hex, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    packet_bytes = bytes.fromhex(packet_hex)
    padded_packet = pad(packet_bytes, AES.block_size)
    encrypted = cipher.encrypt(padded_packet)
    return encrypted.hex()

async def SEndPacKeT(whisper , online , TypE , PacKeT):
    if TypE == 'ChaT' and whisper : whisper.write(PacKeT) ; await whisper.drain()
    elif TypE == 'OnLine' and online : online.write(PacKeT) ; await online.drain()

async def encrypted_proto(encoded_hex):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(encoded_hex, AES.block_size)
    encrypted_payload = cipher.encrypt(padded_message)
    return encrypted_payload

async def GeNeRaTeAccEss(uid, password):
    url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": (await Ua()),
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close"}
    data = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067"}
    async with aiohttp.ClientSession() as session:
        async with session.post(url, headers=headers, data=data) as response:
            if response.status != 200: return (None, None)
            data = await response.json()
            return data.get("open_id"), data.get("access_token")

async def EncRypTMajoRLoGin(open_id, access_token):
    major_login = MajoRLoGinrEq_pb2.MajorLogin()
    major_login.event_time = str(datetime.now())[:-7]
    major_login.game_name = "free fire"
    major_login.platform_id = 1
    major_login.client_version = "1.120.1"
    major_login.system_software = "Android OS 9 / API-28 (PQ3B.190801.10101846/G9650ZHU2ARC6)"
    major_login.system_hardware = "Handheld"
    major_login.telecom_operator = "Verizon"
    major_login.network_type = "WIFI"
    major_login.screen_width = 1920
    major_login.screen_height = 1080
    major_login.screen_dpi = "280"
    major_login.processor_details = "ARM64 FP ASIMD AES VMH | 2865 | 4"
    major_login.memory = 3003
    major_login.gpu_renderer = "Adreno (TM) 640"
    major_login.gpu_version = "OpenGL ES 3.1 v1.46"
    major_login.unique_device_id = f"Google|{random.randint(1000,9999)}-{random.randint(1000,9999)}-{random.randint(1000,9999)}"
    major_login.client_ip = "223.191.51.89"
    major_login.language = "en"
    major_login.open_id = open_id
    major_login.open_id_type = "4"
    major_login.device_type = "Handheld"
    memory_available = major_login.memory_available
    memory_available.version = 55
    memory_available.hidden_value = 81
    major_login.access_token = access_token
    major_login.platform_sdk_id = 1
    major_login.network_operator_a = "Verizon"
    major_login.network_type_a = "WIFI"
    major_login.client_using_version = "7428b253defc164018c604a1ebbfebdf"
    major_login.external_storage_total = 36235
    major_login.external_storage_available = 31335
    major_login.internal_storage_total = 2519
    major_login.internal_storage_available = 703
    major_login.game_disk_storage_available = 25010
    major_login.game_disk_storage_total = 26628
    major_login.external_sdcard_avail_storage = 32992
    major_login.external_sdcard_total_storage = 36235
    major_login.login_by = 3
    major_login.library_path = "/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/lib/arm64"
    major_login.reg_avatar = 1
    major_login.library_token = "5b892aaabd688e571f688053118a162b|/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/base.apk"
    major_login.channel_type = 3
    major_login.cpu_type = 2
    major_login.cpu_architecture = "64"
    major_login.client_version_code = "2019118695"
    major_login.graphics_api = "OpenGLES2"
    major_login.supported_astc_bitset = 16383
    major_login.login_open_id_type = 4
    major_login.analytics_detail = b"FwQVTgUPX1UaUllDDwcWCRBpWA0FUgsvA1snWlBaO1kFYg=="
    major_login.loading_time = 13564
    major_login.release_channel = "android"
    major_login.extra_info = "KqsHTymw5/5GB23YGniUYN2/q47GATrq7eFeRatf0NkwLKEMQ0PK5BKEk72dPflAxUlEBir6Vtey83XqF593qsl8hwY="
    major_login.android_engine_init_flag = 110009
    major_login.if_push = 1
    major_login.is_vpn = 1
    major_login.origin_platform_type = "4"
    major_login.primary_platform_type = "4"
    string = major_login.SerializeToString()
    return await encrypted_proto(string)

Hr = {
    'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 11; ASUS_Z01QD Build/PI)",
    'Connection': "Keep-Alive",
    'Accept-Encoding': "gzip",
    'Content-Type': "application/x-www-form-urlencoded",
    'Expect': "100-continue",
    'X-Unity-Version': "2018.4.11f1",
    'X-GA': "v1 1",
    'ReleaseVersion': "OB52"}

async def MajorLogin(payload):
    url = "https://loginbp.ggblueshark.com/MajorLogin"
    async with aiohttp.ClientSession() as session:
        async with session.post(url, data=payload, headers=Hr, ssl=False) as response:
            if response.status == 200: return await response.read()
            return None

async def GetLoginData(base_url, payload, token):
    url = f"{base_url}/GetLoginData"
    headers = Hr.copy()
    headers['Authorization'] = f"Bearer {token}"
    async with aiohttp.ClientSession() as session:
        async with session.post(url, data=payload, headers=headers, ssl=False) as response:
            if response.status == 200: return await response.read()
            return None

async def DecRypTMajoRLoGin(MajoRLoGinResPonsE):
    proto = MajoRLoGinrEs_pb2.MajorLoginRes()
    proto.ParseFromString(MajoRLoGinResPonsE)
    return proto

async def DecRypTLoGinDaTa(LoGinDaTa):
    proto = PorTs_pb2.GetLoginData()
    proto.ParseFromString(LoGinDaTa)
    return proto

async def xAuThSTarTuP(TarGeT, token, timestamp, key, iv):
    uid_hex = hex(TarGeT)[2:]
    uid_length = len(uid_hex)
    encrypted_timestamp = await DecodE_HeX(timestamp)
    encrypted_account_token = token.encode().hex()
    encrypted_packet = await EnC_PacKeT(encrypted_account_token, key, iv)
    encrypted_packet_length = hex(len(encrypted_packet) // 2)[2:]
    if uid_length == 9: headers = '0000000'
    elif uid_length == 8: headers = '00000000'
    elif uid_length == 10: headers = '000000'
    elif uid_length == 7: headers = '000000000'
    else: headers = '0000000'
    return f"0115{headers}{uid_hex}{encrypted_timestamp}00000{encrypted_packet_length}{encrypted_packet}"

# Multi-Flow Spam Logic
async def decuple_exit_background(client, exit_packet):
    """Gửi thêm 8 lần exit nữa ở background để đảm bảo 1000% thoát"""
    try:
        # Gửi liên tiếp 8 lần nữa (từ xung 3 đến xung 10) mỗi 0.1s
        for _ in range(8):
            await asyncio.sleep(0.1)
            await SEndPacKeT(client.whisper_writer, client.online_writer, 'OnLine', exit_packet)
    except:
        pass

async def run_one_acc(client):
    global team_semaphore, target_team_code
    try:
        # BỎ KIỂM TRA ĐỂ ĐẠT SỨC MẠNH TUYỆT ĐỐI (NHƯ BẢN LỖI)
        async with team_semaphore:
            join_packet = await GenJoinSquadsPacket(target_team_code, client.key, client.iv)
            await SEndPacKeT(client.whisper_writer, client.online_writer, 'OnLine', join_packet)
            
            # SỨC MẠNH TỐI THƯỢNG: Stay 0.001s (Cực mạnh như bản cũ)
            await asyncio.sleep(0.001)    
            
            # Ép ngắt kết nối thần tốc
            await client.force_abort()
            
        # Hồi sinh cực nhanh ở background (0.5s instead of 1s)
        asyncio.create_task(client.restart_tasks_after_delay(0.5))

    except:
        pass


async def SpamManager():
    """Quản lý và điều phối các luồng spam theo vòng lặp tuần tự"""
    global target_team_code, active_clients
    
    while True:
        if target_team_code and active_clients:
            print(f"🚀 [MANAGER] Starting Turbo Round-Robin (200 Acc Sequence)")
            
            while target_team_code:
                # Xoay vòng qua toàn bộ account đã login
                for client in active_clients:
                    if not target_team_code: break
                    
                    # Chạy ra/vô tuần tự (Sẽ tự đợi slot bên trong run_one_acc)
                    # Chúng ta không dùng SpamWorker nữa mà chạy 1 vòng lặp duy nhất cho đúng 1-by-1
                    await run_one_acc(client)
                    
                    # Tốc độ bắn acc tiếp theo phụ thuộc vào độ trễ mạng và stay-time (0.01s)
        
        await asyncio.sleep(1)



async def handle_index(request):
    """Health Check cho UptimeRobot"""
    return web.json_response({"status": "live", "message": "QDZ Bot is running"})

# API Handlers
async def handle_stop(request):
    global target_team_code, active_clients, is_restarting
    if is_restarting:
        return web.json_response({"status": "false", "message": "đang khởi động lại"})

    target_team_code = None
    print("🛑 Stop command received. Parallel mass exit starting...")
    
    async def fast_exit(c):
        try:
            c.running = False
            exit_packet = await ExiT(None, c.key, c.iv)
            # Gửi song song để thoát nhanh nhất
            await SEndPacKeT(c.whisper_writer, c.online_writer, 'OnLine', exit_packet)
            await c.force_abort()
        except: pass

    # Thoát toàn bộ đồng thời
    await asyncio.gather(*(fast_exit(client) for client in active_clients))
    
    # Kích hoạt login lại ngay lập tức
    asyncio.create_task(perform_full_login())
    
    print("✅ Mass exit finished. Restarting login sequence...")
    return web.json_response({"status": "restarting", "message": "đang khởi động lại"})

async def handle_teamcode(request):
    global target_team_code, last_activity_time, is_restarting
    if is_restarting:
        return web.json_response({"status": "false", "message": "đang khởi động lại"})

    try:
        last_activity_time = time.time() # Cập nhật hoạt động mới nhất
        teamcode = request.match_info.get('teamcode')
        if not teamcode:
            teamcode = request.query.get('teamcode')
        
        if teamcode:
            teamcode = str(teamcode).replace('teamcode=', '').replace('=', '').strip()
            target_team_code = teamcode
            print(f"\n🚀 Received TeamCode: {teamcode}")
            return web.json_response({"status": "ok", "teamcode": teamcode, "active": len(active_clients)})
        return web.json_response({"status": "error", "message": "No teamcode"}, status=400)
    except Exception as e:
        print(f"❌ API Error: {e}")
        return web.json_response({"status": "error", "message": str(e)}, status=500)

async def start_api_server():
    app = web.Application()
    app.router.add_get('/', handle_index) # Cổng cho UptimeRobot
    app.router.add_get('/qdz/stop', handle_stop)
    app.router.add_get('/qdz/teamcode={teamcode}', handle_teamcode)
    app.router.add_get('/qdz', handle_teamcode)
    runner = web.AppRunner(app)
    await runner.setup()
    
    # Render/Cloud yêu cầu bind 0.0.0.0 và lấy PORT từ môi trường
    port = int(os.environ.get("PORT", 8081))
    host = '0.0.0.0'
    try:
        site = web.TCPSite(runner, host, port)
        await site.start()
        print(f"\n🌐 API Server RUNNING on: http://{host}:{port}")
    except Exception as e:
        print(f"❌ Critical: Could not start API on {port}: {e}")

async def load_accounts():
    accounts = []
    files = ['acc1.json']
    for file in files:
        if os.path.exists(file):
            with open(file, 'r', encoding='utf-8') as f:
                try:
                    data = json.load(f)
                    for idx, item in enumerate(data):
                        accounts.append((item['uid'], item['password'], idx))
                except: pass
    return accounts

async def login_worker(uid, pw, index, semaphore):
    async with semaphore:
        client = AccountClient(uid, pw)
        client.original_index = index # Gán thứ tự gốc
        try:
            success = await asyncio.wait_for(client.login(), timeout=60)
            if success:
                return client
        except: pass
        return None

async def perform_full_login():
    global active_clients, is_restarting
    is_restarting = True
    # Log out existing if any
    if active_clients:
        print("🔄 [REFRESH] Logging out existing accounts...")
        for client in active_clients:
            try:
                client.running = False
                await client.force_abort()
            except: pass
    
    active_clients = []
    accounts = await load_accounts()
    print(f"📂 [SYSTEM] Starting Login for {len(accounts)} accounts...")
    
    # Tăng kịch sàn lên 100 parallel workers để treo Render mượt nhất
    semaphore = asyncio.Semaphore(100) 
    for i in range(0, len(accounts), 100):
        batch = accounts[i:i+100]
        tasks = [login_worker(uid, pw, idx, semaphore) for uid, pw, idx in batch]
        results = await asyncio.gather(*tasks)
        active_clients.extend([c for c in results if c is not None])
        print(f"⏳ [LOGIN] Progress: {len(active_clients)}/{len(accounts)}")
    
    # Sắp xếp lại lần cuối để ĐẢM BẢO thứ tự từ trên xuống dưới đúng như file
    active_clients.sort(key=lambda x: x.original_index)
    
    print(f"🚀 [SUCCESS] Total Active: {len(active_clients)} (Đã sắp xếp thứ tự Ưu Tiên)")
    is_restarting = False

async def AutoRefreshManager():
    """Tự động login lại sau 20p nếu không làm gì"""
    global last_activity_time, target_team_code
    while True:
        await asyncio.sleep(60) # Kiểm tra mỗi phút
        idle_time = time.time() - last_activity_time
        
        # Nếu đã quá 20p (1200s) và đang không spam team nào
        if idle_time > 1200 and not target_team_code:
            print(f"⏰ [IDLE] Bot idle for {int(idle_time/60)}m. Refreshing sessions...")
            await perform_full_login()
            last_activity_time = time.time() # Reset timer

async def main():    
    # Start API and Manager FIRST
    asyncio.create_task(start_api_server())
    asyncio.create_task(SpamManager())
    asyncio.create_task(AutoRefreshManager())
    # Initial Login
    await perform_full_login()
    # Keep main alive
    while True:
        await asyncio.sleep(3600)
if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
