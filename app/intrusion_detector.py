from flask import Flask, request, render_template, jsonify, g, Response, stream_with_context # Importado 'g'
import requests
from datetime import datetime
import hashlib
import random
import json
import os
import threading
import socket
import re
from collections import defaultdict, Counter, deque
import time # Para sleep em testes, e para o timer
from io import StringIO # Para ler o conteúdo da URL como um arquivo
import ipaddress
from threading import Condition

app = Flask(__name__)

# --- CONFIGURAÇÃO DE ARQUIVOS E LISTAS ---
DATA_FILE = 'system_kernel_log.json'
IP_BLACKLIST_FILE = 'ip_blacklist.txt'
MALICIOUS_PATHS_FILE = 'malicious_paths.txt'
IP_BLACKLIST_URL = 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset' # Exemplo
MALICIOUS_PATHS_URL = 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt' # Exemplo
# Atenção: LISTS_UPDATE_INTERVAL_SECONDS = 24 * 60 * 60 # 24 horas para produção.
# Para testes rápidos, pode ser menor, exemplo:
LISTS_UPDATE_INTERVAL_SECONDS = 300 # 5 minutos para teste, depois mude para 24 * 60 * 60

# --- BANCOS DE DADOS EM MEMÓRIA ---
access_log = {}
activity_log = {}
blacklisted_ips = set() # Agora populado de arquivo/URL (IPv4Address/IPv6Address)
blacklisted_networks = [] # Agora populado de arquivo/URL (IPv4Network/IPv6Network)
malicious_paths = set() # Agora populado de arquivo/URL
blacklist_lock = threading.Lock() # Um lock para proteger acesso a blacklist de IPs e malicious_paths

# --- CONSTANTES DE CONFIGURAÇÃO (algumas agora são sets dinâmicos) ---
# MALICIOUS_PATHS agora é o set 'malicious_paths' carregado dinamicamente
UNUSUAL_METHODS = ['POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD', 'CONNECT', 'TRACE'] # GET é o mais comum, então outros são "incomuns" para um honeypot simples
HIGH_THREAT_THRESHOLD = 70 # Nível de ameaça para considerar blacklisted
HUMAN_THREAT_THRESHOLD = 40 # Nível de ameaça para considerar humano (baixo)
MIN_HUMAN_HITS = 3 # Mínimo de hits para considerar "humano" e não um pingo único

# NOVO: Lista global de paths que NUNCA devem ser logados por process_hit ou log_detailed_activity
# Isso inclui estáticos, pings, APIs do dashboard, e o sinal humano.
PATHS_TO_EXCLUDE_FROM_ACTIVITY_LOGGING = set([
    '/log',                     # Ping inicial para "ativar" o honeypot
    '/favicon.ico',             # Ícone do navegador
    '/human-activity-signal',   # Sinal explícito de interação humana
    '/telemetry',               # Telemetria do cliente (não deve entrar em activity_log)
    # APIs de dados do dashboard
    '/events/latest',
    '/stream',
    '/map-data',
    '/latest-activity',
    '/summary-data',
    '/data/top-locations',
    '/data/device-profiles',
    '/data/top-targets',
    '/data/human-interaction',
    '/data/malicious-targets',
    '/data/blacklisted-nodes',
    '/data/unusual-methods'
])

# --- LIVE ATTACK FEED (SSE) ---
ATTACK_FEED_MAX_EVENTS = 300
ATTACK_FEED_BOOTSTRAP_EVENTS = 20
ATTACK_FEED_HEARTBEAT_SECONDS = 15
INFO_RATE_LIMIT_CAPACITY = 5
INFO_RATE_LIMIT_WINDOW_SECONDS = 10
INFO_RATE_LIMIT_REFILL_PER_SEC = INFO_RATE_LIMIT_CAPACITY / INFO_RATE_LIMIT_WINDOW_SECONDS
MAX_TELEMETRY_PAYLOAD_BYTES = 20 * 1024
RDNS_CACHE_TTL_SECONDS = 6 * 60 * 60
NET_INTEL_TTL_SECONDS = 6 * 60 * 60

attack_feed = deque(maxlen=ATTACK_FEED_MAX_EVENTS)
attack_feed_cond = Condition()
info_rate_limit = {}
info_rate_limit_lock = threading.Lock()
rdns_cache = {}
rdns_cache_lock = threading.Lock()


# --- Funções para salvar e carregar os dados persistentes (access_log, activity_log) ---
def save_data():
    """Salva os logs de acesso e atividade em um arquivo JSON."""
    try:
        data_to_save = {
            'access_log': {},
            'activity_log': activity_log
        }
        for ip, data in access_log.items():
            copied_data = data.copy()
            copied_data['first_seen'] = copied_data['first_seen'].isoformat()
            copied_data['last_seen'] = copied_data['last_seen'].isoformat()
            # Convertendo Counter para dict para serialização JSON
            if 'user_agents' in copied_data:
                copied_data['user_agents'] = dict(copied_data['user_agents'])
            # Garante que 'is_human_interacted' seja serializável
            if 'is_human_interacted' in copied_data:
                copied_data['is_human_interacted'] = bool(copied_data['is_human_interacted'])
            if 'telemetry_last_updated' in copied_data and isinstance(copied_data['telemetry_last_updated'], datetime):
                copied_data['telemetry_last_updated'] = copied_data['telemetry_last_updated'].isoformat()
            data_to_save['access_log'][ip] = copied_data

        with open(DATA_FILE, 'w') as f:
            json.dump(data_to_save, f, indent=4)
    except Exception as e:
        print(f"Erro ao salvar dados: {e}")

def load_data():
    """Carrega os logs de acesso e atividade do arquivo JSON na inicialização."""
    global access_log, activity_log
    if not os.path.exists(DATA_FILE):
        return

    try:
        with open(DATA_FILE, 'r') as f:
            data = json.load(f)
            
            loaded_access_log = data.get('access_log', {})
            
            for ip, log_data in loaded_access_log.items():
                log_data['first_seen'] = datetime.fromisoformat(log_data['first_seen'])
                log_data['last_seen'] = datetime.fromisoformat(log_data['last_seen'])
                # Convertendo dict de volta para Counter
                if 'user_agents' in log_data and isinstance(log_data['user_agents'], dict):
                    log_data['user_agents'] = Counter(log_data['user_agents'])
                # Garante que 'is_human_interacted' esteja presente e seja booleano
                log_data['is_human_interacted'] = log_data.get('is_human_interacted', False)
                if 'telemetry_last_updated' in log_data and isinstance(log_data['telemetry_last_updated'], str):
                    try:
                        log_data['telemetry_last_updated'] = datetime.fromisoformat(log_data['telemetry_last_updated'])
                    except ValueError:
                        log_data['telemetry_last_updated'] = None
                access_log[ip] = log_data

            activity_log = data.get('activity_log', {})
            print(f">>> Dados carregados com sucesso de {DATA_FILE}")
    except (json.JSONDecodeError, KeyError, Exception) as e:
        print(f"Erro ao carregar ou processar o arquivo de dados {DATA_FILE}: {e}. Começando com logs vazios.")
        access_log = {}
        activity_log = {}


# --- Funções para carregar e atualizar listas externas (blacklist, malicious paths) ---

# Função auxiliar para normalizar paths (remover barras iniciais/finais)
def normalize_path_for_comparison(path):
    return path.strip('/')

def parse_ip_blacklist_lines(lines):
    ips = set()
    networks = []
    network_seen = set()

    for line in lines:
        stripped_line = line.strip()
        if not stripped_line or stripped_line.startswith('#'):
            continue
        try:
            if '/' in stripped_line:
                network = ipaddress.ip_network(stripped_line, strict=False)
                network_key = str(network)
                if network_key not in network_seen:
                    networks.append(network)
                    network_seen.add(network_key)
            else:
                ips.add(ipaddress.ip_address(stripped_line))
        except ValueError:
            continue

    return ips, networks

def is_ip_blacklisted(ip_str):
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    with blacklist_lock:
        if ip_obj in blacklisted_ips:
            return True
        for network in blacklisted_networks:
            if ip_obj in network:
                return True

    return False

def load_list_from_file(file_path, target_set_ref, lock):
    """Carrega uma lista de itens de um arquivo local para um set."""
    print(f">>> Carregando lista de {file_path}...")
    try:
        if not os.path.exists(file_path):
            print(f">>> Arquivo local {file_path} não encontrado. Iniciando com lista vazia.")
            with lock:
                target_set_ref.clear() # Garante que o set está vazio se o arquivo não existe
            return

        items_from_file = set()
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                stripped_line = line.strip()
                if stripped_line and not stripped_line.startswith('#'): # Ignora linhas vazias e comentários
                    items_from_file.add(normalize_path_for_comparison(stripped_line)) # NORMALIZA AQUI
        
        with lock: # Adquire o lock antes de modificar o set global
            target_set_ref.clear()
            target_set_ref.update(items_from_file)
        print(f">>> {len(items_from_file)} itens carregados de {file_path}.")
    except Exception as e:
        print(f"!!! Erro ao carregar lista de {file_path}: {e}. Iniciando com lista vazia.")
        with lock:
            target_set_ref.clear()

def load_ip_blacklist_from_file(file_path):
    """Carrega a blacklist de IPs (IPs únicos e redes CIDR) de um arquivo local."""
    print(f">>> Carregando lista de {file_path}...")
    try:
        if not os.path.exists(file_path):
            print(f">>> Arquivo local {file_path} não encontrado. Iniciando com lista vazia.")
            with blacklist_lock:
                blacklisted_ips.clear()
                blacklisted_networks.clear()
            print(">>> Loaded 0 single IPs and 0 CIDR networks.")
            return

        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            ips, networks = parse_ip_blacklist_lines(f)

        with blacklist_lock:
            blacklisted_ips.clear()
            blacklisted_ips.update(ips)
            blacklisted_networks.clear()
            blacklisted_networks.extend(networks)

        print(">>> Loaded {0} single IPs and {1} CIDR networks.".format(len(ips), len(networks)))
    except Exception as e:
        print(f"!!! Erro ao carregar lista de {file_path}: {e}. Iniciando com lista vazia.")
        with blacklist_lock:
            blacklisted_ips.clear()
            blacklisted_networks.clear()
        print(">>> Loaded 0 single IPs and 0 CIDR networks.")

def update_ip_blacklist_from_url(url, local_file_path):
    """
    Tenta atualizar a blacklist de IPs de uma URL.
    Em caso de sucesso, salva no arquivo local e atualiza a lista.
    Em caso de falha, tenta carregar do arquivo local como fallback.
    """
    print(f">>> Tentando atualizar lista de {url}...")
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()

        content_stream = StringIO(response.text)
        ips, networks = parse_ip_blacklist_lines(content_stream)

        if ips or networks:
            with blacklist_lock:
                blacklisted_ips.clear()
                blacklisted_ips.update(ips)
                blacklisted_networks.clear()
                blacklisted_networks.extend(networks)

            # Salva para o arquivo local para persistência (IPs e redes normalizados)
            entries = [str(ip) for ip in ips] + [str(net) for net in networks]
            with open(local_file_path, 'w', encoding='utf-8') as f:
                for item in sorted(entries):
                    f.write(f"{item}\n")

            print(f">>> Atualizado com sucesso: {len(ips)} IPs e {len(networks)} redes para {local_file_path}.")
            print(">>> Loaded {0} single IPs and {1} CIDR networks.".format(len(ips), len(networks)))
        else:
            print(f">>> Nenhuns itens novos encontrados em {url}. Mantendo lista atual.")

    except requests.exceptions.RequestException as e:
        print(f"!!! Erro ao buscar lista de {url}: {e}")
        print(f">>> Tentando carregar de {local_file_path} como fallback.")
        load_ip_blacklist_from_file(local_file_path)
    except Exception as e:
        print(f"!!! Erro inesperado ao processar {url}: {e}")
        load_ip_blacklist_from_file(local_file_path)

def update_list_from_url(url, local_file_path, target_set_ref, lock):
    """
    Tenta atualizar uma lista de itens de uma URL.
    Em caso de sucesso, salva no arquivo local e atualiza o set.
    Em caso de falha, tenta carregar do arquivo local como fallback.
    """
    print(f">>> Tentando atualizar lista de {url}...")
    try:
        response = requests.get(url, timeout=15) # Aumentar timeout para listas maiores
        response.raise_for_status() # Lança exceção para erros HTTP (4xx ou 5xx)
        
        new_items = set()
        # Usa StringIO para tratar o conteúdo da resposta como um arquivo, para leitura linha a linha
        content_stream = StringIO(response.text)

        for line in content_stream:
            stripped_line = line.strip()
            if stripped_line and not stripped_line.startswith('#'): # Ignora linhas vazias e comentários
                new_items.add(normalize_path_for_comparison(stripped_line)) # NORMALIZA AQUI

        if new_items:
            with lock: # Adquire o lock antes de modificar o set global
                target_set_ref.clear() # Limpa itens existentes
                target_set_ref.update(new_items) # Adiciona novos itens
            
            # Salva para o arquivo local para persistência (salva normalizado também)
            with open(local_file_path, 'w', encoding='utf-8') as f:
                for item in sorted(list(new_items)): # Ordena para consistência no arquivo
                    f.write(f"{item}\n") # Salva o item normalizado (sem barras, como ele será usado)
            print(f">>> Atualizado com sucesso: {len(new_items)} itens para {local_file_path}.")
        else:
            print(f">>> Nenhuns itens novos encontrados em {url}. Mantendo lista atual.")

    except requests.exceptions.RequestException as e:
        print(f"!!! Erro ao buscar lista de {url}: {e}")
        print(f">>> Tentando carregar de {local_file_path} como fallback.")
        load_list_from_file(local_file_path, target_set_ref, lock) # Fallback para arquivo local
    except Exception as e:
        print(f"!!! Erro inesperado ao processar {url}: {e}")
        load_list_from_file(local_file_path, target_set_ref, lock) # Fallback para arquivo local

def periodic_list_update():
    """Função que será chamada periodicamente para atualizar as listas."""
    print(f"\n--- Iniciando atualização periódica das listas ({datetime.now().strftime('%Y-%m-%d %H:%M:%S')}) ---")
    
    # Atualiza IP blacklist
    update_ip_blacklist_from_url(IP_BLACKLIST_URL, IP_BLACKLIST_FILE)
    
    # Atualiza Malicious Paths
    update_list_from_url(MALICIOUS_PATHS_URL, MALICIOUS_PATHS_FILE, malicious_paths, blacklist_lock)

    # Reagenda a si mesma (esta chamada de Timer também deve ser daemon)
    list_update_timer = threading.Timer(LISTS_UPDATE_INTERVAL_SECONDS, periodic_list_update)
    list_update_timer.daemon = True # Garante que as recursões também sejam daemon
    list_update_timer.start()


# --- FUNÇÕES AUXILIARES ---
def _get_event_location(ip):
    if ip in access_log:
        geo_info = access_log[ip].get('geo_info', {})
        location = geo_info.get('location')
        if location and location != 'Localização Indisponível':
            return location
    return 'resolving...'

def _sanitize_ua(ua):
    if not ua or ua == 'N/A':
        return None
    ua = ua.strip()
    if not ua:
        return None
    return ua[:120]

def _allow_info_event(ip):
    now = time.time()
    with info_rate_limit_lock:
        tokens, last_ts = info_rate_limit.get(ip, (INFO_RATE_LIMIT_CAPACITY, now))
        tokens = min(INFO_RATE_LIMIT_CAPACITY, tokens + (now - last_ts) * INFO_RATE_LIMIT_REFILL_PER_SEC)
        if tokens < 1:
            info_rate_limit[ip] = (tokens, now)
            return False
        tokens -= 1
        info_rate_limit[ip] = (tokens, now)
        return True

def emit_attack_event(level, ev_type, ip, message, path=None, method=None, ua=None):
    event = {
        'ts': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'level': level,
        'type': ev_type,
        'ip': ip,
        'location': _get_event_location(ip),
        'message': message
    }
    if path:
        event['path'] = path
    if method:
        event['method'] = method
    sanitized_ua = _sanitize_ua(ua)
    if sanitized_ua:
        event['ua'] = sanitized_ua

    with attack_feed_cond:
        attack_feed.append(event)
        attack_feed_cond.notify_all()

def _truncate_str(value, max_len=200):
    if value is None:
        return None
    try:
        text = str(value)
    except Exception:
        return None
    if not text:
        return None
    return text[:max_len]

def _safe_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None

def _safe_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None

def _safe_bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ['1', 'true', 'yes']
    return None

def _sanitize_telemetry_payload(payload):
    if not isinstance(payload, dict):
        return {}

    sanitized = {}

    int_fields = [
        'viewportWidth', 'viewportHeight', 'screenWidth', 'screenHeight',
        'timezoneOffsetMinutes', 'clickCount', 'scrollPx',
        'visibilityChanges', 'dwellSeconds', 'keyPressCount', 'connectionRtt'
    ]
    float_fields = ['devicePixelRatio', 'connectionDownlink']
    bool_fields = ['touchSupport', 'cookieEnabled']
    str_fields = [
        'language', 'platform', 'doNotTrack', 'referrer', 'path',
        'userAgent', 'clientTs', 'connectionEffectiveType', 'uaPlatform'
    ]

    for key in int_fields:
        val = _safe_int(payload.get(key))
        if val is not None:
            sanitized[key] = val

    for key in float_fields:
        val = _safe_float(payload.get(key))
        if val is not None:
            sanitized[key] = val

    for key in bool_fields:
        val = _safe_bool(payload.get(key))
        if val is not None:
            sanitized[key] = val

    for key in str_fields:
        val = _truncate_str(payload.get(key), 200)
        if val is not None:
            sanitized[key] = val

    return sanitized

def compute_human_confidence(ip):
    data = access_log.get(ip, {})
    telemetry = data.get('telemetry', {}) or {}
    is_human_interacted = data.get('is_human_interacted', False)
    user_agents_counter = data.get('user_agents', Counter()) or Counter()

    score = 10
    pos_signals = []
    neg_signals = []

    def add_signal(points, text):
        nonlocal score
        score += points
        if points >= 0:
            pos_signals.append(f"+ {text}")
        else:
            neg_signals.append(f"- {text}")

    if is_human_interacted:
        add_signal(35, "explicit interaction confirmed")

    if telemetry.get('clickCount', 0) >= 1:
        add_signal(15, "clicks detected")
    if telemetry.get('scrollPx', 0) >= 400:
        add_signal(10, "scroll activity detected")
    if telemetry.get('dwellSeconds', 0) >= 15:
        add_signal(15, "dwell time >= 15s")
    if telemetry.get('visibilityChanges', 0) >= 1:
        add_signal(8, "tab visibility changes")
    if telemetry.get('connectionEffectiveType') or telemetry.get('connectionRtt') is not None:
        add_signal(6, "browser network hints present")
    if telemetry.get('touchSupport') is True:
        add_signal(5, "touch device hints")
    if telemetry.get('language'):
        add_signal(4, "language hint present")
    if telemetry.get('viewportWidth') and telemetry.get('viewportHeight') and telemetry.get('screenWidth') and telemetry.get('screenHeight'):
        add_signal(4, "device viewport/screen provided")

    primary_ua = telemetry.get('userAgent')
    if not primary_ua and user_agents_counter:
        primary_ua = user_agents_counter.most_common(1)[0][0]
    ua_lower = primary_ua.lower() if primary_ua else ''
    if primary_ua and "mozilla/" in ua_lower:
        add_signal(6, "browser user-agent")

    automation_indicators = [
        "python-requests", "curl", "wget", "go-http-client", "zgrab",
        "masscan", "nmap", "httpclient", "libwww", "java/"
    ]
    if ua_lower and any(indicator in ua_lower for indicator in automation_indicators):
        add_signal(-25, "automation user-agent")

    req_per_10s = 0
    unique_paths_30s = set()
    now = datetime.now()
    for entry in activity_log.get(ip, []):
        ts_str = entry.get('timestamp')
        if not ts_str:
            continue
        try:
            ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
        delta = (now - ts).total_seconds()
        if delta < 0:
            continue
        if delta <= 10:
            req_per_10s += 1
        if delta <= 30:
            path = entry.get('path')
            if path:
                unique_paths_30s.add(path)
        if delta > 30:
            break

    if req_per_10s >= 25:
        add_signal(-35, "extreme request burst")
    elif req_per_10s >= 10:
        add_signal(-20, "high request burst")

    if len(unique_paths_30s) >= 20:
        add_signal(-15, "rapid multi-path probing")

    if not telemetry and not is_human_interacted:
        add_signal(-10, "no client telemetry")

    score = max(0, min(100, score))

    signals = pos_signals + neg_signals
    if len(signals) > 10:
        trimmed = signals[:10]
        if neg_signals and not any(sig.startswith('-') for sig in trimmed):
            trimmed[-1] = neg_signals[0]
        signals = trimmed

    if score >= 70:
        human_class = "Likely Human"
    elif score <= 35:
        human_class = "Likely Bot"
    else:
        human_class = "Uncertain"

    return score, signals, human_class

def update_human_confidence(ip):
    if ip not in access_log:
        return
    score, signals, human_class = compute_human_confidence(ip)
    access_log[ip]['human_confidence'] = score
    access_log[ip]['human_signals'] = signals
    access_log[ip]['human_class'] = human_class
    access_log[ip]['human_confidence_updated_at'] = datetime.now().isoformat()

def _ensure_access_log_entry(ip):
    if ip in access_log:
        return
    timestamp = datetime.now()
    threat_level, _ = get_threat_level(ip)
    access_log[ip] = {
        'ip': ip,
        'first_seen': timestamp,
        'last_seen': timestamp,
        'threat_level': threat_level,
        'hits': 1,
        'geo_info': get_geo_info(ip),
        'user_agents': Counter(),
        'is_human_interacted': False
    }

def get_threat_level(ip):
    # Base calculation
    ip_hash = int(hashlib.sha256(ip.encode()).hexdigest(), 16) % (10**8)
    random.seed(ip_hash)
    factors = {'vpn': random.random() < 0.3, 'proxy': random.random() < 0.2, 'tor': random.random() < 0.1, 'bot_score': random.randint(0, 100)}
    threat = 20
    if factors['vpn']: threat += 35
    if factors['proxy']: threat += 20
    if factors['tor']: threat += 40
    if factors['bot_score'] > 80: threat += 25
    
    # Check against dynamic IP Blacklist
    if is_ip_blacklisted(ip):
        threat = 100 # Se o IP está na blacklist, a ameaça é máxima
        print(f"!!! IP {ip} encontrado na blacklist global. Nível de ameaça definido para 100%.")
        emit_attack_event('HIGH', 'BLACKLIST', ip, 'BLACKLIST MATCH')

    threat = min(threat, 100) # Garante que o nível não ultrapasse 100
    return threat, factors

def get_geo_info(ip):
    # Tenta usar a informação de geo_info já existente no access_log
    if ip in access_log and 'geo_info' in access_log[ip]:
        cached_geo = access_log[ip]['geo_info']
        if cached_geo.get('location') != 'Localização Indisponível':
            required_keys = ['asn', 'org', 'hosting', 'proxy', 'mobile']
            if all(key in cached_geo for key in required_keys):
                return cached_geo
    
    # Se não tiver ou for "Indisponível", tenta buscar novamente
    try:
        response = requests.get(f'http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,lat,lon,as,org,hosting,proxy,mobile', timeout=2).json()
        if response.get('status') == 'success':
            geo_info = {
                'location': f"{response.get('city', '?')}, {response.get('regionName', '?')}, {response.get('country', '?')}",
                'isp': response.get('isp', 'Desconhecido'),
                'lat': response.get('lat'),
                'lon': response.get('lon'),
                'asn': response.get('as', 'N/A'),
                'org': response.get('org', 'N/A'),
                'hosting': bool(response.get('hosting', False)),
                'proxy': bool(response.get('proxy', False)),
                'mobile': bool(response.get('mobile', False))
            }
            # Se o IP já está no access_log, atualiza com a info de geo
            if ip in access_log:
                access_log[ip]['geo_info'] = geo_info
            return geo_info
    except requests.RequestException:
        pass # Ignora erros de rede ou timeout
    
    # Retorna info padrão se falhar
    return {
        'location': 'Localização Indisponível',
        'isp': 'N/A',
        'lat': None,
        'lon': None,
        'asn': 'N/A',
        'org': 'N/A',
        'hosting': False,
        'proxy': False,
        'mobile': False
    }

def reverse_dns_lookup(ip):
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(1.5)
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname or 'N/A'
    except (socket.herror, socket.gaierror, TimeoutError, OSError):
        return 'N/A'
    finally:
        socket.setdefaulttimeout(old_timeout)

def get_rdns_cached(ip):
    now = time.time()
    with rdns_cache_lock:
        cached = rdns_cache.get(ip)
        if cached and (now - cached['ts'] < RDNS_CACHE_TTL_SECONDS):
            return cached['value']
    value = reverse_dns_lookup(ip)
    with rdns_cache_lock:
        rdns_cache[ip] = {'value': value, 'ts': now}
    return value

def _net_intel_is_stale(net_intel):
    if not net_intel:
        return True
    updated_at = net_intel.get('updated_at')
    if not updated_at:
        return True
    try:
        updated_dt = datetime.fromisoformat(updated_at)
    except ValueError:
        return True
    return (datetime.now() - updated_dt).total_seconds() > NET_INTEL_TTL_SECONDS

def _normalize_net_text(value):
    if value is None:
        return 'N/A'
    text = re.sub(r'\s+', ' ', str(value)).strip()
    return text if text else 'N/A'

def enrich_network_intel(ip, force=False):
    _ensure_access_log_entry(ip)
    previous = access_log.get(ip, {}).get('net_intel', {})
    if not force and previous and not _net_intel_is_stale(previous):
        return previous

    geo_info = get_geo_info(ip)
    rdns_value = get_rdns_cached(ip)

    net = {
        'rdns': rdns_value,
        'asn': geo_info.get('asn', 'N/A'),
        'org': geo_info.get('org', 'N/A'),
        'hosting': bool(geo_info.get('hosting', False)),
        'proxy': bool(geo_info.get('proxy', False)),
        'mobile': bool(geo_info.get('mobile', False)),
        'isp': geo_info.get('isp', 'N/A'),
        'location': geo_info.get('location', 'Localização Indisponível'),
        'updated_at': datetime.now().isoformat()
    }

    if net['hosting']:
        net['network_type'] = 'DATACENTER'
    elif net['mobile']:
        net['network_type'] = 'MOBILE'
    elif net['proxy']:
        net['network_type'] = 'PROXY/VPN'
    else:
        net['network_type'] = 'RESIDENTIAL/UNKNOWN'

    access_log[ip]['net_intel'] = net

    prev_key = None
    if previous:
        prev_key = (
            _normalize_net_text(previous.get('rdns')),
            _normalize_net_text(previous.get('asn')),
            _normalize_net_text(previous.get('org')),
            previous.get('network_type')
        )
    new_key = (
        _normalize_net_text(net.get('rdns')),
        _normalize_net_text(net.get('asn')),
        _normalize_net_text(net.get('org')),
        net.get('network_type')
    )
    changed = (prev_key != new_key)

    if changed:
        if net['hosting']:
            emit_attack_event('WARN', 'INTEL', ip, f"DATACENTER NODE DETECTED: ASN={net['asn']} | ORG={net['org']}")
        elif net['proxy']:
            emit_attack_event('WARN', 'INTEL', ip, f"PROXY/VPN INDICATOR: ASN={net['asn']} | ORG={net['org']}")
        else:
            emit_attack_event('INFO', 'INTEL', ip, f"INTEL ENRICHED: RDNS={net['rdns']} | ASN={net['asn']} | ORG={net['org']} | TYPE={net['network_type']}")

    save_data()
    return net

def get_approximate_coords(country):
    COUNTRY_COORDS = {
        'Brazil': (-14.2350, -51.9253), 'United States': (37.0902, -95.7129),
        'Russia': (61.5240, 105.3188), 'Japan': (36.2048, 138.2529),
        'Germany': (51.1657, 10.4515), 'China': (35.8617, 104.1954),
        'India': (20.5937, 78.9629), 'Canada': (56.1304, -106.3468),
        'Australia': (-25.2744, 133.7751), 'United Kingdom': (55.3781, -3.4360),
        'France': (46.2276, 2.2137), 'Italy': (41.8719, 12.5674),
        'Spain': (40.4637, -3.7492), 'Mexico': (23.6345, -102.5528),
        'Argentina': (-38.4161, -63.6167), 'South Africa': (-30.5595, 22.9375),
        'Egypt': (26.8206, 30.8025), 'Nigeria': (9.0820, 8.6753),
        'Indonesia': (-0.7893, 113.9213)
    }
    return COUNTRY_COORDS.get(country)

def process_hit(ip):
    # NOVO: Flag para garantir que o logging ocorra apenas uma vez por requisição real.
    if getattr(g, '_hit_processed_for_this_request', False):
        return
    g._hit_processed_for_this_request = True # Marca como processado para esta requisição

    # Filtro existente para paths que não devem acionar um "hit"
    if request.path.startswith('/static/') or request.path in PATHS_TO_EXCLUDE_FROM_ACTIVITY_LOGGING:
        return

    print(f"--- DEBUG: process_hit called for IP: {ip}, Path: {request.path}, Method: {request.method} ---")

    timestamp = datetime.now()
    is_new_ip = False
    if ip not in access_log:
        threat_level, _ = get_threat_level(ip)
        access_log[ip] = {
            'ip': ip,
            'first_seen': timestamp,
            'last_seen': timestamp,
            'threat_level': threat_level,
            'hits': 1,
            'geo_info': get_geo_info(ip),
            'user_agents': Counter(),
            'is_human_interacted': False
        }
        is_new_ip = True
        level = 'HIGH' if threat_level >= HIGH_THREAT_THRESHOLD else 'INFO'
        msg = 'NEW VISITOR (HIGH THREAT)' if level == 'HIGH' else 'NEW VISITOR'
        emit_attack_event(level, 'CONNECTION', ip, msg, path=request.path, method=request.method, ua=request.headers.get('User-Agent', 'N/A'))
        threading.Thread(target=enrich_network_intel, args=(ip,), daemon=True).start()
    else:
        access_log[ip]['last_seen'] = timestamp
        access_log[ip]['hits'] += 1
        if 'geo_info' not in access_log[ip] or access_log[ip]['geo_info']['location'] == 'Localização Indisponível':
            access_log[ip]['geo_info'] = get_geo_info(ip)
        
        if 'is_human_interacted' not in access_log[ip]:
            access_log[ip]['is_human_interacted'] = False
        
    user_agent = request.headers.get('User-Agent', 'N/A')
    if 'user_agents' not in access_log[ip]:
        access_log[ip]['user_agents'] = Counter()
    access_log[ip]['user_agents'][user_agent] += 1

    if is_new_ip or 'human_confidence' not in access_log[ip]:
        update_human_confidence(ip)

    save_data()

def log_detailed_activity(ip, request):
    # NOVO: Flag para garantir que o logging detalhado ocorra apenas uma vez por requisição real.
    if getattr(g, '_detailed_activity_processed_for_this_request', False):
        return
    g._detailed_activity_processed_for_this_request = True # Marca como processado para esta requisição

    # Filtro existente para paths que não devem acionar logging detalhado
    if request.path.startswith('/static/') or request.path in PATHS_TO_EXCLUDE_FROM_ACTIVITY_LOGGING:
        return
    
    print(f"--- DEBUG: log_detailed_activity called for IP: {ip}, Path: {request.path}, Method: {request.method} ---")

    activity_entry = {
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'method': request.method,
        'path': request.path,
        'user_agent': request.headers.get('User-Agent', 'N/A')
    }

    normalized_path = normalize_path_for_comparison(request.path)
    is_malicious = False
    with blacklist_lock:
        is_malicious = normalized_path in malicious_paths

    if is_malicious:
        emit_attack_event('HIGH', 'PROBE', ip, f"MALICIOUS PROBE: {request.path}", path=request.path, method=request.method, ua=request.headers.get('User-Agent', 'N/A'))
    elif request.method in UNUSUAL_METHODS:
        emit_attack_event('WARN', 'METHOD', ip, f"UNUSUAL METHOD: {request.method} {request.path}", path=request.path, method=request.method, ua=request.headers.get('User-Agent', 'N/A'))
    else:
        if _allow_info_event(ip):
            emit_attack_event('INFO', 'CONNECTION', ip, f"{request.method} {request.path}", path=request.path, method=request.method, ua=request.headers.get('User-Agent', 'N/A'))

    if ip not in activity_log:
        activity_log[ip] = []
    activity_log[ip].insert(0, activity_entry)
    save_data()

# --- ROTAS DA APLICAÇÃO ---

# Rota explícita para favicon.ico para garantir que seja servido sem log ou fallback
@app.route('/favicon.ico')
def favicon():
    # Retorna um status 204 (No Content). O navegador entenderá que não há ícone.
    # Isso impede que a requisição de favicon.ico chegue ao 'fallback'.
    return '', 204

# NOVO: Rota para registrar atividade humana explícita (cliques)
@app.route('/human-activity-signal', methods=['POST'])
def human_activity_signal():
    ip = request.remote_addr
    # Esta rota não precisa chamar process_hit ou log_detailed_activity,
    # pois ela já faz o update direto no access_log e está na lista de exclusão.
    if ip in access_log:
        was_human = access_log[ip].get('is_human_interacted', False)
        access_log[ip]['is_human_interacted'] = True
        # Opcional: Ajusta o nível de ameaça para um valor mais baixo se for um humano interagindo
        access_log[ip]['threat_level'] = min(access_log[ip]['threat_level'], HUMAN_THREAT_THRESHOLD - 5)
        # Incrementa hits para este IP, como um sinal de atividade.
        # Esta linha não vai causar o problema de ser logada em "unusual methods"
        # porque process_hit agora tem um filtro no início.
        access_log[ip]['hits'] += 1
        update_human_confidence(ip)
        save_data()
        if not was_human:
            emit_attack_event('INFO', 'HUMAN', ip, 'HUMAN INTERACTION CONFIRMED')
    return "", 204 # Responde sem conteúdo

# NOVO: Rota para receber telemetria do cliente
@app.route('/telemetry', methods=['POST'])
def telemetry():
    if request.content_length and request.content_length > MAX_TELEMETRY_PAYLOAD_BYTES:
        return ("Payload too large", 413)

    payload = request.get_json(silent=True) or {}
    sanitized = _sanitize_telemetry_payload(payload)

    ip = request.remote_addr
    _ensure_access_log_entry(ip)

    received_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    client_ts = sanitized.pop('clientTs', None)

    telemetry_record = {}
    telemetry_record.update(sanitized)
    telemetry_record['received_at'] = received_at
    if client_ts:
        telemetry_record['client_ts'] = client_ts

    access_log[ip]['telemetry'] = telemetry_record
    access_log[ip]['telemetry_last_updated'] = datetime.now()

    ua = telemetry_record.get('userAgent')
    if ua:
        if 'user_agents' not in access_log[ip]:
            access_log[ip]['user_agents'] = Counter()
        access_log[ip]['user_agents'][ua] += 1

    update_human_confidence(ip)
    save_data()
    return "", 204

@app.before_request
def master_log():
    ip = request.remote_addr
    print(f"--- DEBUG: master_log entered for IP: {ip}, Path: {request.path}, Method: {request.method} ---")

    # Inicializa as flags no request.g para cada nova requisição (ou re-dispatch).
    # Como Flask cria um novo objeto 'g' para cada contexto de requisição, isso garante
    # que as flags comecem como False no início de CADA execução de master_log.
    g._hit_processed_for_this_request = False
    g._detailed_activity_processed_for_this_request = False

    # 1. Decidir se é um "HIT" de USUÁRIO (para REQUEST_COUNT)
    is_ajax_root_refresh = (request.path == '/' and request.headers.get('X-Requested-With') == 'XMLHttpRequest')
    if not is_ajax_root_refresh:
        process_hit(ip) # process_hit agora filtra paths indesejados internamente.

    # 2. Decidir se é uma ATIVIDADE DETALHADA (para ACTIVITY_LOG)
    is_root_path = (request.path == '/')
    is_intel_path = request.path.startswith('/intel/')
    if not is_root_path and not is_intel_path:
        log_detailed_activity(ip, request) # log_detailed_activity agora filtra paths indesejados internamente.


@app.route('/')
def dashboard():
    sorted_accesses = sorted(access_log.values(), key=lambda x: x['last_seen'], reverse=True)
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return render_template('access_list_partial.html', accesses=sorted_accesses)
    
    # Prepara os dados de resumo para a dashboard inicial
    summary = get_summary_data()

    # Passa o summary para o template
    return render_template('dashboard.html', accesses=sorted_accesses, summary=summary)

@app.route('/intel/<ip>')
def get_intel(ip):
    if ip not in access_log:
        return jsonify({"error": "IP não encontrado no log"}), 404
    main_info = access_log[ip]
    history = activity_log.get(ip, [])
    net_intel = main_info.get('net_intel', {})
    if not net_intel or _net_intel_is_stale(net_intel):
        threading.Thread(target=enrich_network_intel, args=(ip,), daemon=True).start()
    intel_data = {
        'ip': ip,
        'threat_level': main_info['threat_level'],
        'first_seen': main_info['first_seen'].strftime("%Y-%m-%d %H:%M:%S"),
        'last_seen': main_info['last_seen'].strftime("%Y-%m-%d %H:%M:%S"),
        'total_hits': main_info['hits'],
        'geo_info': main_info.get('geo_info', get_geo_info(ip)),
        'history': history[:20], # Limita a 20 entradas para o modal
        'telemetry': main_info.get('telemetry', {}),
        'human_confidence': main_info.get('human_confidence'),
        'human_class': main_info.get('human_class'),
        'human_signals': main_info.get('human_signals', []),
        'human_confidence_updated_at': main_info.get('human_confidence_updated_at'),
        'net_intel': net_intel
    }
    return jsonify(intel_data)

@app.route('/map-data')
def map_data():
    map_accesses = []
    for access in access_log.values():
        geo_info = access.get('geo_info', {})
        lat, lon = geo_info.get('lat'), geo_info.get('lon')
        if not lat or not lon:
            location_str = geo_info.get('location', '')
            if location_str and ',' in location_str:
                parts = location_str.split(',')
                # Tenta pegar o último elemento como país, removendo espaços
                country_name = parts[-1].strip()
                # Remove "(unknown)" ou similar se houver
                country_name = country_name.split('(')[0].strip() 
                coords = get_approximate_coords(country_name)
                if coords:
                    lat, lon = coords
        if lat and lon:
            map_accesses.append({'ip': access['ip'], 'lat': lat, 'lon': lon, 'threat_level': access['threat_level'], 'location': geo_info.get('location', 'N/A')})
    return jsonify(map_accesses)

@app.route('/latest-activity')
def latest_activity():
    if not access_log:
        return jsonify([])
    sorted_accesses = sorted(access_log.values(), key=lambda x: x['last_seen'], reverse=True)
    recent_activity = []
    for access in sorted_accesses[:4]: # Mostra os 4 mais recentes
        geo_info = access.get('geo_info', {})
        location = geo_info.get('location', 'resolving...')
        recent_activity.append({'ip': access['ip'], 'location': location, 'timestamp': access['last_seen'].strftime('%H:%M:%S')})
    return jsonify(recent_activity)

@app.route('/events/latest')
def latest_events():
    try:
        limit = int(request.args.get('limit', 50))
    except ValueError:
        limit = 50
    limit = max(1, min(limit, ATTACK_FEED_MAX_EVENTS))
    with attack_feed_cond:
        events = list(attack_feed)[-limit:]
    return jsonify(events)

@app.route('/stream')
def stream():
    def generate():
        yield ": connected\n\n"
        with attack_feed_cond:
            snapshot = list(attack_feed)[-ATTACK_FEED_BOOTSTRAP_EVENTS:]
        last_event = snapshot[-1] if snapshot else None
        for ev in snapshot:
            yield f"event: attack\ndata: {json.dumps(ev)}\n\n"

        while True:
            with attack_feed_cond:
                notified = attack_feed_cond.wait(timeout=ATTACK_FEED_HEARTBEAT_SECONDS)
                snapshot = list(attack_feed)
            if not notified:
                yield ": heartbeat\n\n"
                continue
            if not snapshot:
                continue
            if last_event and last_event in snapshot:
                start_idx = snapshot.index(last_event) + 1
                new_events = snapshot[start_idx:]
            else:
                new_events = snapshot[-ATTACK_FEED_BOOTSTRAP_EVENTS:]
            for ev in new_events:
                yield f"event: attack\ndata: {json.dumps(ev)}\n\n"
            last_event = snapshot[-1]

    headers = {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive'
    }
    return Response(stream_with_context(generate()), headers=headers)

# --- NOVAS ROTAS PARA DADOS DETALHADOS ---

@app.route('/summary-data')
def get_summary_data_endpoint():
    """Endpoint para buscar os dados de resumo separadamente via AJAX."""
    return jsonify(get_summary_data())

def get_summary_data():
    """Gera um resumo rápido para exibição na dashboard."""
    num_ips = len(access_log)
    
    # Top Locations
    location_counts = Counter()
    for ip_data in access_log.values():
        location = ip_data.get('geo_info', {}).get('location', 'Unknown')
        if location != 'Localização Indisponível' and location != 'Unknown':
            location_counts[location] += 1
    top_locs_summary = location_counts.most_common(3) # Mostra os 3 principais

    # Device Profiles (contagem de UAs distintos)
    unique_user_agents = set()
    for ip_data in access_log.values():
        if 'user_agents' in ip_data:
            # CORRIGIDO AQUI: Apenas itera sobre as chaves, não tenta desempacotar duas variáveis.
            for ua in ip_data['user_agents'].keys(): 
                if ua != 'N/A' and ua: unique_user_agents.add(ua)
    device_profiles_summary = len(unique_user_agents)

    # Top Targets
    path_counts = Counter()
    for ip_history in activity_log.values():
        for entry in ip_history:
            path_counts[entry['path']] += 1
    top_targets_summary = path_counts.most_common(3) # Mostra os 3 principais

    # Human Interaction (agora baseado na flag is_human_interacted)
    human_ips_count = 0
    for ip_data in access_log.values():
        if ip_data.get('is_human_interacted', False):
            human_ips_count += 1

    # Top Malicious Targets (agora usando o set `malicious_paths` carregado dinamicamente)
    mal_path_counts = Counter() 
    with blacklist_lock: # Adquire o lock antes de ler o set
        for ip_history in activity_log.values():
            for entry in ip_history:
                # Compara o path NORMALIZADO com os paths maliciosos NORMALIZADOS
                if normalize_path_for_comparison(entry['path']) in malicious_paths: # Usa o set dinâmico
                    mal_path_counts[entry['path']] += 1 # Mantém o path original no Counter para exibição
    top_mal_summary = mal_path_counts.most_common(3) # Mostra os 3 principais

    # Top Blacklisted Nodes (agora usando os dados de IPs e redes carregados dinamicamente)
    blacklisted_ips_count = 0
    for ip_data in access_log.values():
        if is_ip_blacklisted(ip_data['ip']) or ip_data['threat_level'] >= HIGH_THREAT_THRESHOLD:
            blacklisted_ips_count += 1
    
    # Unusual Methods
    unusual_method_counts = Counter()
    for ip_history in activity_log.values():
        for entry in ip_history:
            if entry['method'] in UNUSUAL_METHODS:
                unusual_method_counts[entry['method']] += 1
    unusual_methods_summary = unusual_method_counts.most_common(3)

    return {
        'num_ips': num_ips,
        'top_locations': [{"location": loc, "count": count} for loc, count in top_locs_summary],
        'device_profiles_count': device_profiles_summary,
        'top_targets': [{"path": path, "count": count} for path, count in top_targets_summary],
        'human_interactions_count': human_ips_count,
        'top_malicious_targets': [{"path": path, "count": count} for path, count in top_mal_summary],
        'blacklisted_nodes_count': blacklisted_ips_count,
        'unusual_methods': [{"method": m, "count": c} for m, c in unusual_methods_summary]
    }

@app.route('/data/top-locations')
def get_detailed_top_locations():
    location_details = defaultdict(lambda: {'count': 0, 'ips': set()})
    for ip, data in access_log.items():
        location = data.get('geo_info', {}).get('location', 'Unknown')
        if location != 'Localização Indisponível' and location != 'Unknown':
            location_details[location]['count'] += 1
            location_details[location]['ips'].add(ip)
    
    sorted_locations = sorted(location_details.items(), key=lambda item: item[1]['count'], reverse=True)
    
    result = []
    for loc, details in sorted_locations:
        result.append({
            'location': loc,
            'count': details['count'],
            'ips': sorted(list(details['ips'])) # Converte set para list para JSON
        })
    return jsonify(result)

@app.route('/data/device-profiles')
def get_detailed_device_profiles():
    device_profiles = defaultdict(lambda: {'count': 0, 'ips': set()})
    
    for ip, ip_data in access_log.items():
        if 'user_agents' in ip_data:
            for ua, ua_count in ip_data['user_agents'].items(): # Este já estava correto
                if ua != 'N/A' and ua:
                    device_profiles[ua]['count'] += ua_count # Contagem total de vezes que o UA apareceu
                    device_profiles[ua]['ips'].add(ip) # Contagem de IPs distintos que usaram esse UA

    sorted_profiles = sorted(device_profiles.items(), key=lambda item: item[1]['count'], reverse=True)
    
    result = []
    for ua, details in sorted_profiles:
        result.append({
            'user_agent': ua,
            'total_requests': details['count'],
            'unique_ips': sorted(list(details['ips']))
        })
    return jsonify(result)


@app.route('/data/top-targets')
def get_detailed_top_targets():
    target_details = defaultdict(lambda: {'count': 0, 'ips': set()})
    for ip, history in activity_log.items():
        for entry in history:
            path = entry['path']
            target_details[path]['count'] += 1
            target_details[path]['ips'].add(ip)
    
    sorted_targets = sorted(target_details.items(), key=lambda item: item[1]['count'], reverse=True)
    
    result = []
    for path, details in sorted_targets:
        result.append({
            'path': path,
            'count': details['count'],
            'ips': sorted(list(details['ips']))
        })
    return jsonify(result)

@app.route('/data/human-interaction')
def get_detailed_human_interaction():
    human_interactions = []
    for ip, data in access_log.items():
        # Agora, a detecção de humano é primariamente pela flag 'is_human_interacted'
        if data.get('is_human_interacted', False):
            human_interactions.append({
                'ip': ip,
                'location': data.get('geo_info', {}).get('location', 'N/A'),
                'isp': data.get('geo_info', {}).get('isp', 'N/A'),
                'threat_level': data['threat_level'],
                'total_hits': data['hits']
            })
    # Opcional: ordenar por hits ou threat_level para melhor visualização
    human_interactions = sorted(human_interactions, key=lambda x: x['total_hits'], reverse=True)
    return jsonify(human_interactions)

@app.route('/data/malicious-targets')
def get_detailed_malicious_targets():
    malicious_paths_detailed = defaultdict(lambda: {'count': 0, 'ips': set()})
    with blacklist_lock: # Adquire o lock antes de ler o set
        for ip, history in activity_log.items():
            for entry in history:
                # Compara o path NORMALIZADO com os paths maliciosos NORMALIZADOS
                if normalize_path_for_comparison(entry['path']) in malicious_paths: # Usa o set dinâmico
                    malicious_paths_detailed[entry['path']]['count'] += 1
                    malicious_paths_detailed[entry['path']]['ips'].add(ip)
    
    sorted_malicious = sorted(malicious_paths_detailed.items(), key=lambda item: item[1]['count'], reverse=True)
    
    result = []
    for path, details in sorted_malicious:
        result.append({
            'path': path,
            'count': details['count'],
            'ips': sorted(list(details['ips']))
        })
    return jsonify(result)

@app.route('/data/blacklisted-nodes')
def get_detailed_blacklisted_nodes():
    blacklisted_nodes = []
    for ip, data in access_log.items():
        # Considera blacklisted se o IP estiver na lista remota OU se o nível de ameaça local for alto
        if is_ip_blacklisted(data['ip']) or data['threat_level'] >= HIGH_THREAT_THRESHOLD:
            blacklisted_nodes.append({
                'ip': ip,
                'location': data.get('geo_info', {}).get('location', 'N/A'),
                'isp': data.get('geo_info', {}).get('isp', 'N/A'),
                'threat_level': data['threat_level'],
                'total_hits': data['hits']
            })
    # Ordenar por threat_level para mostrar os mais perigosos primeiro
    blacklisted_nodes = sorted(blacklisted_nodes, key=lambda x: x['threat_level'], reverse=True)
    return jsonify(blacklisted_nodes)

@app.route('/data/unusual-methods')
def get_detailed_unusual_methods():
    unusual_methods_data = defaultdict(lambda: {'count': 0, 'requests': []})
    for ip, history in activity_log.items():
        for entry in history:
            if entry['method'] in UNUSUAL_METHODS:
                unusual_methods_data[entry['method']]['count'] += 1
                unusual_methods_data[entry['method']]['requests'].append({
                    'ip': ip,
                    'path': entry['path'],
                    'timestamp': entry['timestamp'],
                    'user_agent': entry['user_agent']
                })
    
    sorted_methods = sorted(unusual_methods_data.items(), key=lambda item: item[1]['count'], reverse=True)
    
    result = []
    for method, details in sorted_methods:
        # Limita o número de requests detalhadas para não sobrecarregar o modal, se houver muitos
        details['requests'] = sorted(details['requests'], key=lambda x: x['timestamp'], reverse=True)[:50] 
        result.append({
            'method': method,
            'count': details['count'],
            'requests': details['requests']
        })
    return jsonify(result)

@app.route('/<path:dummy>')
def fallback(dummy):
    # O logging (process_hit e log_detailed_activity) é EXCLUSIVAMENTE gerido nas próprias funções.
    # Esta rota fallback APENAS retorna a resposta HTTP 404 para paths não encontrados.
    return "Recurso não encontrado.", 404

@app.route('/log')
def log_initial_access():
    return "OK", 200

if __name__ == '__main__':
    load_data() # Carrega os logs de acesso e atividade existentes

    # 1. Carrega as blacklists e malicious paths de arquivos locais na inicialização
    load_ip_blacklist_from_file(IP_BLACKLIST_FILE)
    load_list_from_file(MALICIOUS_PATHS_FILE, malicious_paths, blacklist_lock)

    # 2. Inicia o timer para a atualização periódica das listas em segundo plano
    # IMPORTANTE: use_reloader=False é CRÍTICO quando se usa threading.Timer com Flask.
    # Caso contrário, o reloader do Flask tentará iniciar o aplicativo duas vezes,
    # resultando em dois timers e threads duplicadas.
    print(f">>> Agendando primeira atualização de listas em {LISTS_UPDATE_INTERVAL_SECONDS} segundos...")
    # Cria o objeto Timer
    list_update_timer = threading.Timer(LISTS_UPDATE_INTERVAL_SECONDS, periodic_list_update)
    # Define a thread como daemon (funciona em versões mais antigas do Python, ou a forma mais compatível)
    list_update_timer.daemon = True
    # Inicia a thread
    list_update_timer.start()

    # MUDANÇA CRÍTICA: Definindo debug=False para evitar comportamentos inesperados do servidor de desenvolvimento.
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)
