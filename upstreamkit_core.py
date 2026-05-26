import json
import os
import re
import socket
import ssl
import sys
import tempfile
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler

if sys.platform == "win32":
    import winreg
else:
    winreg = None

try:
    import truststore
except ImportError:
    truststore = None

try:
    import certifi
except ImportError:
    certifi = None

try:
    from PIL import Image, ImageDraw
except ImportError:
    Image = None
    ImageDraw = None


APP_NAME = "UpstreamKit"
DEFAULT_PORT = "8787"
LOG_PREVIEW_LIMIT = 1200
RUN_REGISTRY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"
SAFE_USER_ID_RE = re.compile(r"^[a-zA-Z0-9_-]+$")
UNSAFE_USER_ID_CHAR_RE = re.compile(r"[^a-zA-Z0-9_-]+")


def app_dir():
    if getattr(sys, "frozen", False):
        if sys.platform == "darwin" and ".app/Contents/MacOS" in sys.executable:
            return os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(sys.executable))))
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def configure_ssl_trust():
    if truststore is not None:
        try:
            truststore.inject_into_ssl()
            return "system"
        except Exception:
            pass
    if certifi is not None:
        ssl._create_default_https_context = lambda: ssl.create_default_context(cafile=certifi.where())
        return "certifi"
    return "default"


def quote_command_arg(value):
    return '"' + value.replace('"', r'\"') + '"'


def startup_command():
    if getattr(sys, "frozen", False):
        return f"{quote_command_arg(sys.executable)} --autostart"
    return f"{quote_command_arg(sys.executable)} {quote_command_arg(os.path.abspath(__file__))} --autostart"


def is_startup_enabled():
    if winreg is None:
        return False
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_REGISTRY_PATH, 0, winreg.KEY_READ) as key:
            value, _ = winreg.QueryValueEx(key, APP_NAME)
        return value == startup_command()
    except FileNotFoundError:
        return False
    except OSError:
        return False


def set_startup_enabled(enabled):
    if winreg is None:
        raise RuntimeError("开机自启仅支持 Windows")
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, RUN_REGISTRY_PATH, 0, winreg.KEY_SET_VALUE) as key:
        if enabled:
            winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, startup_command())
        else:
            try:
                winreg.DeleteValue(key, APP_NAME)
            except FileNotFoundError:
                pass


CONFIG_DIR = app_dir()
CONFIG_PATH = os.path.join(CONFIG_DIR, "config.json")
TOKEN_STATS_PATH = os.path.join(CONFIG_DIR, "token_stats.json")
DAILY_TOKEN_STATS_PATH = os.path.join(CONFIG_DIR, "daily_token_stats.json")
PROMPT_LOG_DIR = os.path.join(CONFIG_DIR, "prompt_logs")
SSL_TRUST_SOURCE = configure_ssl_trust()
DEFAULT_UPSTREAM = {
    "name": "默认上游",
    "provider": "openai",
    "base_url": "https://api.openai.com",
    "api_key": "",
    "model": "gpt-4.1",
}
DEFAULT_CONFIG = {
    "upstreams": [dict(DEFAULT_UPSTREAM)],
    "active_upstream": 0,
    "port": DEFAULT_PORT,
    "log_prompt": False,
}
DEFAULT_TOKEN_STATS = {
    "input_tokens": 0,
    "cache_miss_input_tokens": 0,
    "cache_hit_input_tokens": 0,
    "output_tokens": 0,
    "cache_known": False,
}
DEFAULT_DAILY_TOKEN_STATS = {
    "version": 1,
    "daily_stats": {},
    "first_use_date": None,
    "last_use_date": None,
}


def now_text():
    return time.strftime("%H:%M:%S")


def join_url(base_url, path):
    base = (base_url or "").strip().rstrip("/")
    if not base:
        return path
    if base.endswith("/v1") and path.startswith("/v1/"):
        return base + path[3:]
    return base + path


def post_json(url, headers, body, timeout=60):
    payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read()
            return resp.status, data.decode("utf-8", errors="replace")
    except urllib.error.HTTPError as err:
        data = err.read()
        return err.code, data.decode("utf-8", errors="replace")


def unwrap_url_error(exc):
    if isinstance(exc, urllib.error.URLError) and getattr(exc, "reason", None):
        return exc.reason
    return exc


def is_tls_hostname_error(exc):
    reason = unwrap_url_error(exc)
    if isinstance(reason, ssl.CertificateError):
        return True
    text = str(reason).lower()
    return (
        "hostname" in text
        or "certificate is not valid for" in text
        or ("cn" in text and "不匹配" in text)
        or "证书的 cn 名与传递的值不匹配" in text
    )


def describe_connection_error(exc):
    if is_tls_hostname_error(exc):
        return (
            f"{exc}。证书域名校验失败：上游返回的证书和当前 URL 主机名不匹配。"
            "请优先检查代理/VPN/Clash 规则、DNS 解析、公司网关或杀毒软件的 HTTPS 扫描。"
        )
    reason = unwrap_url_error(exc)
    if isinstance(reason, ssl.SSLCertVerificationError):
        return (
            f"{exc}。证书校验失败：请检查系统证书、代理/VPN、DNS、系统时间，"
            "或点击“诊断”查看当前解析 IP 和证书信息。"
        )
    return str(exc)


def cert_field_to_text(items):
    parts = []
    for group in items or []:
        for key, value in group:
            parts.append(f"{key}={value}")
    return ", ".join(parts) or "unknown"


def cert_subject_alt_names(cert):
    names = []
    alt_names = cert.get("subjectAltName", ()) if isinstance(cert, dict) else ()
    for key, value in alt_names:
        if key.lower() == "dns":
            names.append(value)
    return names


def decode_der_certificate(der_cert):
    pem = ssl.DER_cert_to_PEM_cert(der_cert)
    path = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="ascii", delete=False, suffix=".pem") as tmp:
            tmp.write(pem)
            path = tmp.name
        return ssl._ssl._test_decode_cert(path)
    finally:
        if path:
            try:
                os.remove(path)
            except OSError:
                pass


def read_peer_certificate(host, port, timeout):
    context = ssl._create_unverified_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls_sock:
            der_cert = tls_sock.getpeercert(binary_form=True)
    if not der_cert:
        return {}
    return decode_der_certificate(der_cert)


def add_cert_summary(lines, cert):
    if not cert:
        lines.append("证书信息：未能读取")
        return
    lines.append(f"证书 Subject：{cert_field_to_text(cert.get('subject'))}")
    lines.append(f"证书 Issuer：{cert_field_to_text(cert.get('issuer'))}")
    if cert.get("notBefore") or cert.get("notAfter"):
        lines.append(f"证书有效期：{cert.get('notBefore', '?')} -> {cert.get('notAfter', '?')}")
    names = cert_subject_alt_names(cert)
    if names:
        preview = ", ".join(names[:10])
        if len(names) > 10:
            preview += f" ... (+{len(names) - 10})"
        lines.append(f"证书 DNS 名称：{preview}")


def diagnose_tls_endpoint(base_url, timeout=10):
    text = (base_url or "").strip()
    if "://" not in text:
        text = "https://" + text
    parsed = urllib.parse.urlparse(text)
    host = parsed.hostname
    if not host:
        raise ValueError("无法从上游 URL 解析主机名")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    lines = [f"诊断目标：{host}:{port} ({parsed.scheme or 'https'})"]
    proxies = urllib.request.getproxies()
    if proxies:
        proxy_text = ", ".join(f"{key}={value}" for key, value in sorted(proxies.items()))
        lines.append(f"系统代理：{proxy_text}")
    else:
        lines.append("系统代理：未检测到")

    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        ips = sorted({item[4][0] for item in infos})
        lines.append(f"DNS 解析：{', '.join(ips) if ips else '无结果'}")
    except OSError as exc:
        lines.append(f"DNS 解析失败：{exc}")

    if parsed.scheme and parsed.scheme != "https":
        lines.append("TLS 校验：跳过，目标不是 https")
        return lines

    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                cert = tls_sock.getpeercert()
        lines.append("TLS 校验：通过")
        add_cert_summary(lines, cert)
    except Exception as exc:
        lines.append(f"TLS 校验：失败 {type(exc).__name__}: {exc}")
        if is_tls_hostname_error(exc):
            lines.append("判断：证书域名不匹配，通常由代理/VPN/DNS/HTTPS 扫描或上游 CDN 证书异常导致。")
        try:
            cert = read_peer_certificate(host, port, timeout)
            add_cert_summary(lines, cert)
        except Exception as cert_exc:
            lines.append(f"证书信息读取失败：{type(cert_exc).__name__}: {cert_exc}")
    return lines


def strip_reasoning_content(body):
    for message in body.get("messages", []) if isinstance(body, dict) else []:
        if isinstance(message, dict):
            message.pop("reasoning_content", None)
            content = message.get("content")
            if isinstance(content, list):
                message["content"] = [
                    item for item in content
                    if not (isinstance(item, dict) and item.get("type") in ("thinking", "redacted_thinking"))
                ]


def preview_text(text, limit=LOG_PREVIEW_LIMIT):
    text = (text or "").replace("\r", " ").replace("\n", " ")
    if len(text) > limit:
        return text[:limit] + "...[truncated]"
    return text


def request_summary(body):
    if not isinstance(body, dict):
        return "body=non-json"
    messages = body.get("messages") or []
    tools = body.get("tools") or []
    return (
        f"body_keys={list(body.keys())}, "
        f"client_model={body.get('model')}, "
        f"stream={body.get('stream')}, "
        f"messages={len(messages) if isinstance(messages, list) else 'n/a'}, "
        f"tools={len(tools) if isinstance(tools, list) else 'n/a'}, "
        f"max_tokens={body.get('max_tokens')}"
    )


def sanitize_user_id_value(value):
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if SAFE_USER_ID_RE.match(text):
        return text
    sanitized = UNSAFE_USER_ID_CHAR_RE.sub("_", text).strip("_")
    if not sanitized:
        return None
    return sanitized[:128]


def sanitize_user_id_fields(body):
    changes = []
    if not isinstance(body, dict):
        return changes

    metadata = body.get("metadata")
    if isinstance(metadata, dict) and "user_id" in metadata:
        original = metadata.get("user_id")
        sanitized = sanitize_user_id_value(original)
        if sanitized:
            metadata["user_id"] = sanitized
            if sanitized != original:
                changes.append(f"metadata.user_id: {original!r} -> {sanitized!r}")
        else:
            metadata.pop("user_id", None)
            changes.append(f"metadata.user_id: {original!r} -> removed")

    if "user_id" in body:
        original = body.get("user_id")
        sanitized = sanitize_user_id_value(original)
        if sanitized:
            body["user_id"] = sanitized
            if sanitized != original:
                changes.append(f"user_id: {original!r} -> {sanitized!r}")
        else:
            body.pop("user_id", None)
            changes.append(f"user_id: {original!r} -> removed")

    return changes


def rough_token_count(body):
    def walk(value):
        if isinstance(value, str):
            return max(1, len(value) // 4)
        if isinstance(value, list):
            return sum(walk(item) for item in value)
        if isinstance(value, dict):
            return sum(walk(item) for item in value.values())
        return 0

    return max(1, walk(body.get("system", "")) + walk(body.get("messages", [])) + walk(body.get("tools", [])))


def create_tray_image():
    image = Image.new("RGB", (64, 64), "#2563eb")
    draw = ImageDraw.Draw(image)
    draw.rounded_rectangle((8, 8, 56, 56), radius=12, fill="#111827")
    draw.rectangle((18, 20, 46, 26), fill="#ffffff")
    draw.rectangle((18, 32, 46, 38), fill="#ffffff")
    draw.rectangle((18, 44, 36, 50), fill="#ffffff")
    return image


def load_saved_config():
    try:
        if not os.path.exists(CONFIG_PATH):
            save_config_data(DEFAULT_CONFIG)
            return dict(DEFAULT_CONFIG)
        with open(CONFIG_PATH, "r", encoding="utf-8") as file:
            data = json.load(file)
        if isinstance(data, dict):
            # 旧格式配置迁移
            if "upstreams" not in data and "provider" in data:
                migrated = dict(DEFAULT_CONFIG)
                migrated["upstreams"] = [{
                    "name": data.get("name", "迁移的上游"),
                    "provider": data.get("provider", "openai"),
                    "base_url": data.get("base_url", "https://api.openai.com"),
                    "api_key": data.get("api_key", ""),
                    "model": data.get("model", "gpt-4.1"),
                }]
                migrated["port"] = data.get("port", DEFAULT_PORT)
                save_config_data(migrated)
                return migrated
            merged = dict(DEFAULT_CONFIG)
            merged.update(data)
            if not merged.get("upstreams"):
                merged["upstreams"] = [dict(DEFAULT_UPSTREAM)]
            return merged
    except Exception:
        return dict(DEFAULT_CONFIG)
    return dict(DEFAULT_CONFIG)


def save_config_data(data):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(CONFIG_PATH, "w", encoding="utf-8") as file:
        json.dump(data, file, ensure_ascii=False, indent=2)


def normalize_token_stats(data):
    merged = dict(DEFAULT_TOKEN_STATS)
    if isinstance(data, dict):
        for key in DEFAULT_TOKEN_STATS:
            if key in data:
                merged[key] = data[key]
    for key in ("input_tokens", "cache_miss_input_tokens", "cache_hit_input_tokens", "output_tokens"):
        try:
            merged[key] = int(merged.get(key) or 0)
        except (TypeError, ValueError):
            merged[key] = 0
    merged["cache_known"] = bool(merged.get("cache_known"))
    return merged


def load_token_stats():
    try:
        if not os.path.exists(TOKEN_STATS_PATH):
            save_token_stats(DEFAULT_TOKEN_STATS)
            return dict(DEFAULT_TOKEN_STATS)
        with open(TOKEN_STATS_PATH, "r", encoding="utf-8") as file:
            return normalize_token_stats(json.load(file))
    except Exception:
        return dict(DEFAULT_TOKEN_STATS)


def save_token_stats(data):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(TOKEN_STATS_PATH, "w", encoding="utf-8") as file:
        json.dump(normalize_token_stats(data), file, ensure_ascii=False, indent=2)


def normalize_daily_token_stats(data):
    merged = dict(DEFAULT_DAILY_TOKEN_STATS)
    if isinstance(data, dict):
        for key in DEFAULT_DAILY_TOKEN_STATS:
            if key in data:
                merged[key] = data[key]
    return merged


def load_daily_token_stats():
    try:
        if not os.path.exists(DAILY_TOKEN_STATS_PATH):
            save_daily_token_stats(DEFAULT_DAILY_TOKEN_STATS)
            return dict(DEFAULT_DAILY_TOKEN_STATS)
        with open(DAILY_TOKEN_STATS_PATH, "r", encoding="utf-8") as file:
            return normalize_daily_token_stats(json.load(file))
    except Exception:
        return dict(DEFAULT_DAILY_TOKEN_STATS)


def save_daily_token_stats(data):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(DAILY_TOKEN_STATS_PATH, "w", encoding="utf-8") as file:
        json.dump(normalize_daily_token_stats(data), file, ensure_ascii=False, indent=2)


def get_prompt_log_path(request_id):
    """生成日志文件路径"""
    os.makedirs(PROMPT_LOG_DIR, exist_ok=True)
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    filename = f"prompt_{timestamp}_{request_id}.log"
    return os.path.join(PROMPT_LOG_DIR, filename)


def write_prompt_header(file_path, provider, model, request_body):
    """写入请求头部和请求体"""
    header = f"=== provider={provider} model={model} ===\n"
    request_str = json.dumps(request_body, ensure_ascii=False, indent=2)
    with open(file_path, "w", encoding="utf-8") as file:
        file.write(header + "--- Request Body ---\n" + request_str + "\n")


def write_prompt_response(file_path, raw_lines, converted_lines=None):
    """写入响应部分（原始 + 转换后），内存缓冲后一次性写入"""
    with open(file_path, "a", encoding="utf-8") as file:
        # 原始响应
        file.write("--- Response (原始上游 SSE) ---\n")
        for line in raw_lines:
            file.write(line.decode("utf-8", errors="replace") if isinstance(line, bytes) else line)
        # 转换后响应（如果有）
        if converted_lines:
            file.write("\n--- Response (转换后客户端 SSE) ---\n")
            for line in converted_lines:
                file.write(line.decode("utf-8", errors="replace") if isinstance(line, bytes) else line)


def write_prompt_footer(file_path, token_usage):
    """写入日志尾部"""
    input_t = token_usage.get("input_tokens", 0)
    output_t = token_usage.get("output_tokens", 0)
    footer = f"\n=== End tokens: input={input_t} output={output_t} ===\n"
    with open(file_path, "a", encoding="utf-8") as file:
        file.write(footer)


def get_date_key():
    return time.strftime("%Y-%m-%d")


def extract_usage_tokens(payload, provider=None):
    usage = None
    model = None
    if isinstance(payload, dict):
        usage = payload.get("usage")
        if usage is None and isinstance(payload.get("message"), dict):
            usage = payload["message"].get("usage")
            model = payload["message"].get("model")
        if model is None:
            model = payload.get("model")
    if not isinstance(usage, dict):
        return None

    output_tokens = int(usage.get("output_tokens") or usage.get("completion_tokens") or 0)
    cache_hit = int(
        usage.get("cache_read_input_tokens")
        or usage.get("cached_tokens")
        or 0
    )

    prompt_details = usage.get("prompt_tokens_details")
    if isinstance(prompt_details, dict):
        cache_hit = int(prompt_details.get("cached_tokens") or cache_hit)

    cache_creation = int(usage.get("cache_creation_input_tokens") or 0)
    if "input_tokens" in usage:
        cache_miss = int(usage.get("input_tokens") or 0) + cache_creation
        input_tokens = cache_miss + cache_hit
        cache_known = any(key in usage for key in ("cache_creation_input_tokens", "cache_read_input_tokens"))
    elif "prompt_tokens" in usage:
        input_tokens = int(usage.get("prompt_tokens") or 0)
        cache_miss = max(0, input_tokens - cache_hit)
        cache_known = isinstance(prompt_details, dict) and "cached_tokens" in prompt_details
    else:
        input_tokens = 0
        cache_miss = cache_creation
        input_tokens = cache_miss + cache_hit
        cache_known = cache_hit > 0 or cache_creation > 0

    return {
        "input_tokens": input_tokens,
        "cache_miss_input_tokens": cache_miss,
        "cache_hit_input_tokens": cache_hit,
        "output_tokens": output_tokens,
        "cache_known": cache_known,
        "model": model,
    }


def add_token_stats(base, delta):
    out = normalize_token_stats(base)
    if not delta:
        return out
    normalized = normalize_token_stats(delta)
    for key in ("input_tokens", "cache_miss_input_tokens", "cache_hit_input_tokens", "output_tokens"):
        out[key] += normalized[key]
    out["cache_known"] = out["cache_known"] or normalized["cache_known"]
    return out


@dataclass
class RelayConfig:
    provider: str
    base_url: str
    api_key: str
    model: str
    port: int
    log_prompt: bool = False


class RelayState:
    def __init__(self, config, log_func, token_func=None, detailed_token_func=None):
        self.config = config
        self.log = log_func
        self.record_tokens = token_func or (lambda usage: None)
        self.record_detailed_tokens = detailed_token_func or (lambda usage, model: None)
        self.log_prompt_enabled = getattr(config, 'log_prompt', False) if hasattr(config, 'log_prompt') else False
        self.prompt_log_paths = {}  # request_id -> file_path 映射
        self.prompt_log_buffers = {}  # request_id -> {"raw": [], "converted": []} 内存缓冲


def normalize_text_content(content):
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                parts.append(item.get("text", ""))
            elif isinstance(item, dict) and item.get("type") == "thinking":
                parts.append(item.get("thinking", ""))
            elif isinstance(item, str):
                parts.append(item)
        return "\n".join(x for x in parts if x)
    return str(content)


def anthropic_to_openai_request(body, model):
    messages = []
    system = body.get("system")
    if system:
        messages.append({"role": "system", "content": normalize_text_content(system)})

    for msg in body.get("messages", []):
        role = msg.get("role", "user")
        content = msg.get("content", "")

        if isinstance(content, str):
            messages.append({"role": role, "content": content})
            continue

        if not isinstance(content, list):
            messages.append({"role": role, "content": normalize_text_content(content)})
            continue

        text_parts = []
        image_parts = []
        tool_calls = []
        tool_messages = []
        reasoning_content = []

        for item in content:
            if not isinstance(item, dict):
                text_parts.append(str(item))
                continue

            item_type = item.get("type")
            if item_type == "text":
                text_parts.append(item.get("text", ""))
            elif item_type == "thinking":
                reasoning_content.append(item.get("thinking", ""))
            elif item_type == "image":
                source = item.get("source", {})
                if source.get("type") == "base64":
                    media_type = source.get("media_type", "image/png")
                    image_parts.append({
                        "type": "image_url",
                        "image_url": {"url": f"data:{media_type};base64,{source.get('data', '')}"},
                    })
            elif item_type == "tool_use":
                tool_calls.append({
                    "id": item.get("id", ""),
                    "type": "function",
                    "function": {
                        "name": item.get("name", ""),
                        "arguments": json.dumps(item.get("input", {}), ensure_ascii=False),
                    },
                })
            elif item_type == "tool_result":
                tool_messages.append({
                    "role": "tool",
                    "tool_call_id": item.get("tool_use_id", ""),
                    "content": normalize_text_content(item.get("content", "")),
                })

        if tool_messages:
            messages.extend(tool_messages)

        if role == "assistant" and tool_calls:
            assistant = {"role": "assistant", "content": "\n".join(x for x in text_parts if x) or None, "tool_calls": tool_calls}
            if reasoning_content:
                assistant["reasoning_content"] = "\n".join(reasoning_content)
            messages.append(assistant)
        elif image_parts:
            mixed = []
            if text_parts:
                mixed.append({"type": "text", "text": "\n".join(x for x in text_parts if x)})
            mixed.extend(image_parts)
            messages.append({"role": role, "content": mixed})
        elif text_parts or reasoning_content:
            out = {"role": role, "content": "\n".join(x for x in text_parts if x)}
            if role == "assistant" and reasoning_content:
                out["reasoning_content"] = "\n".join(reasoning_content)
            messages.append(out)

    openai_body = {
        "model": model,
        "messages": messages,
        "stream": bool(body.get("stream", False)),
    }

    for src, dst in [
        ("max_tokens", "max_tokens"),
        ("temperature", "temperature"),
        ("top_p", "top_p"),
        ("stop_sequences", "stop"),
    ]:
        if src in body:
            openai_body[dst] = body[src]

    if "reasoning_effort" in body:
        openai_body["reasoning_effort"] = body["reasoning_effort"]

    if body.get("tools"):
        openai_body["tools"] = []
        for tool in body["tools"]:
            openai_body["tools"].append({
                "type": "function",
                "function": {
                    "name": tool.get("name", ""),
                    "description": tool.get("description", ""),
                    "parameters": tool.get("input_schema", {"type": "object", "properties": {}}),
                },
            })

    return openai_body


def openai_to_anthropic_response(openai_body, model):
    choice = (openai_body.get("choices") or [{}])[0]
    message = choice.get("message", {})
    content = []

    if message.get("content"):
        content.append({"type": "text", "text": message["content"]})

    for call in message.get("tool_calls") or []:
        fn = call.get("function", {})
        try:
            args = json.loads(fn.get("arguments") or "{}")
        except json.JSONDecodeError:
            args = {"_raw": fn.get("arguments", "")}
        content.append({
            "type": "tool_use",
            "id": call.get("id", ""),
            "name": fn.get("name", ""),
            "input": args,
        })

    finish_reason = choice.get("finish_reason")
    stop_reason = "tool_use" if finish_reason == "tool_calls" else "end_turn"
    if finish_reason == "length":
        stop_reason = "max_tokens"
    elif finish_reason == "stop":
        stop_reason = "end_turn"

    usage = openai_body.get("usage") or {}
    return {
        "id": openai_body.get("id", "msg_openai"),
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": content or [{"type": "text", "text": ""}],
        "stop_reason": stop_reason,
        "stop_sequence": None,
        "usage": {
            "input_tokens": usage.get("prompt_tokens", 0),
            "output_tokens": usage.get("completion_tokens", 0),
        },
    }


def sse_line(event=None, data=None):
    out = ""
    if event:
        out += f"event: {event}\n"
    if data is not None:
        out += "data: " + json.dumps(data, ensure_ascii=False, separators=(",", ":")) + "\n"
    return (out + "\n").encode("utf-8")


class RelayHandler(BaseHTTPRequestHandler):
    server_version = "ApiRelay/1.0"

    def do_GET(self):
        if self.path in ("/", "/health"):
            self.send_json(200, {"ok": True, "name": APP_NAME})
            return
        self.send_error(404)

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            raw_body = self.rfile.read(length) if length else b"{}"
            body = json.loads(raw_body.decode("utf-8") or "{}")
            self.original_request_body = body  # 存储原始请求体，供日志使用
            cfg = self.server.state.config
            req_id = f"{int(time.time() * 1000) % 1000000:06d}-{threading.get_ident() % 10000:04d}"
            self.request_id = req_id
            self.server.state.log(
                f"[{req_id}] 收到请求 {self.path}，已忽略客户端 key/model，思考参数跟随请求方，"
                f"使用 {cfg.provider} / {cfg.model}；{request_summary(body)}"
            )

            if "/count_tokens" in self.path:
                count = rough_token_count(body)
                self.server.state.log(f"[{req_id}] 本地处理 count_tokens，估算 input_tokens={count}")
                self.send_json(200, {"input_tokens": count})
                return

            if cfg.provider == "openai":
                self.handle_openai_provider(body, cfg)
            else:
                self.handle_anthropic_provider(raw_body, body, cfg)
        except Exception as exc:
            req_id = getattr(self, "request_id", "no-id")
            self.server.state.log(f"[{req_id}] 请求处理失败: {type(exc).__name__}: {exc}")
            self.server.state.log(f"[{req_id}] {traceback.format_exc().splitlines()[-1]}")
            if isinstance(exc, (BrokenPipeError, ConnectionResetError, ConnectionAbortedError)):
                self.server.state.log(f"[{req_id}] 客户端已经断开连接，无法继续写回响应")
                return
            try:
                self.send_json(500, {"error": {"message": str(exc), "type": "relay_error"}})
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                self.server.state.log(f"[{req_id}] 写回 500 时客户端已经断开")

    def log_message(self, fmt, *args):
        return

    def send_json(self, status, data):
        encoded = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def handle_anthropic_provider(self, raw_body, body, cfg):
        body = dict(body)
        body["model"] = cfg.model
        for change in sanitize_user_id_fields(body):
            self.server.state.log(f"[{getattr(self, 'request_id', 'no-id')}] 已修正 user_id：{change}")
        target = join_url(cfg.base_url, self.path if self.path.startswith("/v1/") else "/v1/messages")
        self.server.state.log(
            f"[{getattr(self, 'request_id', 'no-id')}] 转发到 Anthropic 上游 {target}；"
            f"思考参数跟随请求方"
        )
        response = self.forward_json(target, cfg.api_key, body, provider="anthropic", stream=bool(body.get("stream")))
        self.copy_response(response)

    def handle_openai_provider(self, body, cfg):
        if self.path.endswith("/chat/completions"):
            outgoing = dict(body)
            outgoing["model"] = cfg.model
            for change in sanitize_user_id_fields(outgoing):
                self.server.state.log(f"[{getattr(self, 'request_id', 'no-id')}] 已修正 user_id：{change}")
        else:
            outgoing = anthropic_to_openai_request(body, cfg.model)

        target = join_url(cfg.base_url, "/v1/chat/completions")
        self.server.state.log(
            f"[{getattr(self, 'request_id', 'no-id')}] 转发到 OpenAI 上游 {target}；"
            f"思考参数跟随请求方"
        )
        if outgoing.get("stream"):
            response = self.forward_json(target, cfg.api_key, outgoing, provider="openai", stream=True)
            if self.path.endswith("/chat/completions"):
                self.copy_response(response)
            else:
                self.stream_openai_as_anthropic(response, cfg.model)
        else:
            response = self.forward_json(target, cfg.api_key, outgoing, provider="openai", stream=False)
            data = response.read()
            if response.status >= 400:
                self.server.state.log(
                    f"[{getattr(self, 'request_id', 'no-id')}] 上游错误响应体预览："
                    f"{preview_text(data.decode('utf-8', errors='replace'))}"
                )
                self.send_raw(response.status, response.headers.get("Content-Type", "application/json"), data)
                return
            openai_body = json.loads(data.decode("utf-8") or "{}")
            self.record_usage_from_payload(openai_body)
            if self.path.endswith("/chat/completions"):
                self.send_json(response.status, openai_body)
            else:
                self.send_json(200, openai_to_anthropic_response(openai_body, cfg.model))

    def forward_json(self, url, api_key, body, provider, stream):
        payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Accept": "text/event-stream" if stream else "application/json",
            "User-Agent": APP_NAME,
        }
        if provider == "anthropic":
            headers["x-api-key"] = api_key
            headers["anthropic-version"] = self.headers.get("anthropic-version", "2023-06-01")
            if self.headers.get("anthropic-beta"):
                headers["anthropic-beta"] = self.headers.get("anthropic-beta")
        else:
            headers["Authorization"] = f"Bearer {api_key}"

        req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
        req_id = getattr(self, "request_id", "no-id")
        self.server.state.log(
            f"[{req_id}] 上游请求准备完成：provider={provider}, stream={stream}, "
            f"bytes={len(payload)}, {request_summary(body)}"
        )
        try:
            response = urllib.request.urlopen(req, timeout=600)
            self.server.state.log(
                f"[{req_id}] 上游已响应：HTTP {getattr(response, 'status', 'unknown')} "
                f"content-type={response.headers.get('Content-Type', '')}"
            )
            return response
        except urllib.error.HTTPError as err:
            self.server.state.log(
                f"[{req_id}] 上游返回错误：HTTP {err.code} "
                f"content-type={err.headers.get('Content-Type', '')}"
            )
            return err
        except urllib.error.URLError as err:
            self.server.state.log(f"[{req_id}] 上游连接失败：{describe_connection_error(err)}")
            raise

    def send_raw(self, status, content_type, data):
        self.send_response(status)
        self.send_header("Content-Type", content_type or "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def copy_response(self, response):
        req_id = getattr(self, "request_id", "no-id")
        content_type = response.headers.get("Content-Type", "application/json")
        if "text/event-stream" in content_type:
            self.send_response(getattr(response, "status", getattr(response, "code", 200)))
            self.send_header("Content-Type", content_type)
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "close")
            self.end_headers()
            self.server.state.log(f"[{req_id}] 开始向客户端转发流式响应")

            # Prompt 日志：创建文件、写入请求头、初始化缓冲
            if self.server.state.log_prompt_enabled:
                file_path = get_prompt_log_path(req_id)
                self.server.state.prompt_log_paths[req_id] = file_path
                self.server.state.prompt_log_buffers[req_id] = {"raw": [], "converted": None}  # 直接转发无转换
                cfg = self.server.state.config
                write_prompt_header(file_path, cfg.provider, cfg.model, getattr(self, 'original_request_body', {}))
                self.server.state.log(f"[{req_id}] Prompt 日志文件: {file_path}")

            event_name = None
            data_lines = []
            event_counts = {}
            event_samples = 0
            stream_usage = dict(DEFAULT_TOKEN_STATS)
            stream_model = None

            def finish_event():
                nonlocal event_name, data_lines, event_samples, stream_usage, stream_model
                if event_name is None and not data_lines:
                    return
                name = event_name or "message"
                event_counts[name] = event_counts.get(name, 0) + 1
                data_text = "\n".join(data_lines)
                usage_delta = self.usage_from_sse_data(data_text)
                if usage_delta:
                    stream_usage = add_token_stats(stream_usage, usage_delta)
                    if usage_delta.get("model"):
                        stream_model = usage_delta.get("model")
                # 从 message_start 事件提取 model
                if name == "message_start" and not stream_model:
                    try:
                        data = json.loads(data_text)
                        if isinstance(data, dict) and isinstance(data.get("message"), dict):
                            stream_model = data["message"].get("model")
                    except json.JSONDecodeError:
                        pass
                if event_samples < 12:
                    self.log_sse_event(req_id, name, data_text)
                    event_samples += 1
                elif name in ("error", "message_stop"):
                    self.log_sse_event(req_id, name, data_text)
                event_name = None
                data_lines = []

            for line in response:
                # Prompt 日志：累积原始 SSE 行
                if req_id in self.server.state.prompt_log_buffers:
                    self.server.state.prompt_log_buffers[req_id]["raw"].append(line)
                self.wfile.write(line)
                self.wfile.flush()
                stripped = line.decode("utf-8", errors="replace").rstrip("\r\n")
                if stripped == "":
                    finish_event()
                elif stripped.startswith("event:"):
                    event_name = stripped[6:].strip()
                elif stripped.startswith("data:"):
                    data_lines.append(stripped[5:].strip())
            finish_event()
            if stream_usage["input_tokens"] or stream_usage["output_tokens"]:
                self.server.state.record_tokens(stream_usage)
                self.server.state.record_detailed_tokens(stream_usage, stream_model)
                self.server.state.log(
                    f"[{req_id}] token统计：input={stream_usage['input_tokens']}, "
                    f"cache_hit={stream_usage['cache_hit_input_tokens']}, "
                    f"output={stream_usage['output_tokens']}"
                )
            # Prompt 日志：写入响应和尾部，清理缓冲
            if req_id in self.server.state.prompt_log_paths:
                raw_lines = self.server.state.prompt_log_buffers.get(req_id, {}).get("raw", [])
                write_prompt_response(self.server.state.prompt_log_paths[req_id], raw_lines)
                write_prompt_footer(self.server.state.prompt_log_paths[req_id], stream_usage)
                self.server.state.prompt_log_paths.pop(req_id, None)
                self.server.state.prompt_log_buffers.pop(req_id, None)
            self.server.state.log(f"[{req_id}] 流式响应转发结束，events={event_counts}")
            self.close_connection = True
            return

        data = response.read()
        status = getattr(response, "status", getattr(response, "code", 200))
        if status >= 400:
            self.server.state.log(f"[{req_id}] 上游错误响应体预览：{preview_text(data.decode('utf-8', errors='replace'))}")
        else:
            self.server.state.log(f"[{req_id}] 上游成功响应：HTTP {status}, bytes={len(data)}")
            try:
                self.record_usage_from_payload(json.loads(data.decode("utf-8") or "{}"))
            except json.JSONDecodeError:
                pass
        self.send_raw(status, content_type, data)

    def stream_openai_as_anthropic(self, response, model):
        req_id = getattr(self, "request_id", "no-id")
        self.send_response(response.status)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()
        self.server.state.log(f"[{req_id}] 开始将 OpenAI 流式响应转换为 Anthropic SSE")

        # Prompt 日志：创建文件、写入请求头、初始化缓冲
        if self.server.state.log_prompt_enabled:
            file_path = get_prompt_log_path(req_id)
            self.server.state.prompt_log_paths[req_id] = file_path
            self.server.state.prompt_log_buffers[req_id] = {"raw": [], "converted": []}  # OpenAI 转 Anthropic 有转换
            cfg = self.server.state.config
            write_prompt_header(file_path, cfg.provider, model, getattr(self, 'original_request_body', {}))
            self.server.state.log(f"[{req_id}] Prompt 日志文件: {file_path}")

        msg_id = f"msg_{int(time.time() * 1000)}"
        sse_msg_start = sse_line("message_start", {
            "type": "message_start",
            "message": {
                "id": msg_id,
                "type": "message",
                "role": "assistant",
                "model": model,
                "content": [],
                "stop_reason": None,
                "stop_sequence": None,
                "usage": {"input_tokens": 0, "output_tokens": 0},
            },
        })
        self.wfile.write(sse_msg_start)
        # Prompt 日志：累积转换后的 SSE（message_start）
        if req_id in self.server.state.prompt_log_buffers:
            self.server.state.prompt_log_buffers[req_id]["converted"].append(sse_msg_start)

        text_index = None
        next_block_index = 0
        tool_blocks = {}
        stream_usage = dict(DEFAULT_TOKEN_STATS)
        remote_model = None

        for line in response:
            # Prompt 日志：累积原始 OpenAI SSE 行
            if req_id in self.server.state.prompt_log_buffers:
                self.server.state.prompt_log_buffers[req_id]["raw"].append(line)
            if not line.startswith(b"data:"):
                continue
            payload = line[5:].strip()
            if payload == b"[DONE]":
                break
            try:
                chunk = json.loads(payload.decode("utf-8"))
            except json.JSONDecodeError:
                continue
            # 从上游响应提取实际模型名（第一个有model的chunk）
            if remote_model is None:
                remote_model = chunk.get("model")
            usage_delta = extract_usage_tokens(chunk)
            if usage_delta:
                stream_usage = add_token_stats(stream_usage, usage_delta)

            choice = (chunk.get("choices") or [{}])[0]
            delta = choice.get("delta", {})
            text = delta.get("content") or ""
            if text:
                if text_index is None:
                    text_index = next_block_index
                    next_block_index += 1
                    sse_start = sse_line("content_block_start", {
                        "type": "content_block_start",
                        "index": text_index,
                        "content_block": {"type": "text", "text": ""},
                    })
                    self.wfile.write(sse_start)
                    # Prompt 日志：累积转换后的 SSE
                    if req_id in self.server.state.prompt_log_buffers:
                        self.server.state.prompt_log_buffers[req_id]["converted"].append(sse_start)
                sse_delta = sse_line("content_block_delta", {
                    "type": "content_block_delta",
                    "index": text_index,
                    "delta": {"type": "text_delta", "text": text},
                })
                self.wfile.write(sse_delta)
                # Prompt 日志：累积转换后的 SSE
                if req_id in self.server.state.prompt_log_buffers:
                    self.server.state.prompt_log_buffers[req_id]["converted"].append(sse_delta)

            # 实时处理 tool_calls
            for call in delta.get("tool_calls") or []:
                idx = call.get("index", 0)
                fn = call.get("function") or {}
                tool = tool_blocks.setdefault(idx, {
                    "block_index": None,
                    "id": "",
                    "name": "",
                    "pending_arguments": [],
                })
                if call.get("id"):
                    tool["id"] = call["id"]
                if fn.get("name"):
                    tool["name"] = fn["name"]

                if tool["name"] and tool["block_index"] is None:
                    tool["block_index"] = next_block_index
                    next_block_index += 1
                    sse_tool_start = sse_line("content_block_start", {
                        "type": "content_block_start",
                        "index": tool["block_index"],
                        "content_block": {
                            "type": "tool_use",
                            "id": tool["id"] or f"tool_{idx}",
                            "name": tool["name"],
                            "input": {},
                        },
                    })
                    self.wfile.write(sse_tool_start)
                    # Prompt 日志：累积转换后的 SSE
                    if req_id in self.server.state.prompt_log_buffers:
                        self.server.state.prompt_log_buffers[req_id]["converted"].append(sse_tool_start)
                    for pending in tool["pending_arguments"]:
                        sse_pending = sse_line("content_block_delta", {
                            "type": "content_block_delta",
                            "index": tool["block_index"],
                            "delta": {
                                "type": "input_json_delta",
                                "partial_json": pending,
                            },
                        })
                        self.wfile.write(sse_pending)
                        if req_id in self.server.state.prompt_log_buffers:
                            self.server.state.prompt_log_buffers[req_id]["converted"].append(sse_pending)
                    tool["pending_arguments"] = []

                arguments = fn.get("arguments")
                if arguments:
                    if tool["block_index"] is None:
                        tool["pending_arguments"].append(arguments)
                    else:
                        sse_args = sse_line("content_block_delta", {
                            "type": "content_block_delta",
                            "index": tool["block_index"],
                            "delta": {
                                "type": "input_json_delta",
                                "partial_json": arguments,
                            },
                        })
                        self.wfile.write(sse_args)
                        if req_id in self.server.state.prompt_log_buffers:
                            self.server.state.prompt_log_buffers[req_id]["converted"].append(sse_args)

        block_indexes = []
        if text_index is not None:
            block_indexes.append(text_index)
        block_indexes.extend(
            tool["block_index"]
            for tool in tool_blocks.values()
            if tool.get("block_index") is not None
        )
        for block_index in sorted(block_indexes):
            sse_stop = sse_line("content_block_stop", {"type": "content_block_stop", "index": block_index})
            self.wfile.write(sse_stop)
            if req_id in self.server.state.prompt_log_buffers:
                self.server.state.prompt_log_buffers[req_id]["converted"].append(sse_stop)
        tool_count = sum(1 for tool in tool_blocks.values() if tool.get("block_index") is not None)
        stop_reason = "tool_use" if tool_count else "end_turn"
        sse_delta = sse_line("message_delta", {
            "type": "message_delta",
            "delta": {"stop_reason": stop_reason, "stop_sequence": None},
            "usage": {"output_tokens": 0},
        })
        self.wfile.write(sse_delta)
        if req_id in self.server.state.prompt_log_buffers:
            self.server.state.prompt_log_buffers[req_id]["converted"].append(sse_delta)
        sse_msg_stop = sse_line("message_stop", {"type": "message_stop"})
        self.wfile.write(sse_msg_stop)
        if req_id in self.server.state.prompt_log_buffers:
            self.server.state.prompt_log_buffers[req_id]["converted"].append(sse_msg_stop)
        if stream_usage["input_tokens"] or stream_usage["output_tokens"]:
            self.server.state.record_tokens(stream_usage)
            self.server.state.record_detailed_tokens(stream_usage, remote_model)
            self.server.state.log(
                f"[{req_id}] token统计：input={stream_usage['input_tokens']}, "
                f"cache_hit={stream_usage['cache_hit_input_tokens']}, "
                f"output={stream_usage['output_tokens']}"
            )
        # Prompt 日志：写入响应（原始+转换后）、尾部，清理缓冲
        if req_id in self.server.state.prompt_log_paths:
            buffer = self.server.state.prompt_log_buffers.get(req_id, {})
            raw_lines = buffer.get("raw", [])
            converted_lines = buffer.get("converted", [])
            write_prompt_response(self.server.state.prompt_log_paths[req_id], raw_lines, converted_lines)
            write_prompt_footer(self.server.state.prompt_log_paths[req_id], stream_usage)
            self.server.state.prompt_log_paths.pop(req_id, None)
            self.server.state.prompt_log_buffers.pop(req_id, None)
        self.server.state.log(f"[{req_id}] OpenAI 流式转换结束，tool_calls={tool_count}, text_started={text_index is not None}")
        self.close_connection = True

    def record_usage_from_payload(self, payload):
        usage_delta = extract_usage_tokens(payload)
        if not usage_delta:
            return
        self.server.state.record_tokens(usage_delta)
        model = usage_delta.get("model")
        self.server.state.record_detailed_tokens(usage_delta, model)
        self.server.state.log(
            f"[{getattr(self, 'request_id', 'no-id')}] token统计："
            f"input={usage_delta['input_tokens']}, "
            f"cache_hit={usage_delta['cache_hit_input_tokens']}, "
            f"output={usage_delta['output_tokens']}"
        )

    def usage_from_sse_data(self, data_text):
        if not data_text:
            return None
        try:
            payload = json.loads(data_text)
        except json.JSONDecodeError:
            return None
        usage_delta = extract_usage_tokens(payload)
        if usage_delta:
            return usage_delta
        if isinstance(payload, dict) and isinstance(payload.get("usage"), dict):
            return extract_usage_tokens({"usage": payload["usage"]})
        return None

    def log_sse_event(self, req_id, event_name, data_text):
        if not data_text:
            self.server.state.log(f"[{req_id}] SSE event={event_name}")
            return
        try:
            data = json.loads(data_text)
        except json.JSONDecodeError:
            self.server.state.log(f"[{req_id}] SSE event={event_name}, data={preview_text(data_text, 300)}")
            return

        summary = f"[{req_id}] SSE event={event_name}"
        data_type = data.get("type") if isinstance(data, dict) else None
        if data_type:
            summary += f", type={data_type}"
        if isinstance(data, dict) and data_type == "content_block_start":
            block = data.get("content_block") or {}
            summary += f", block_type={block.get('type')}, name={block.get('name')}"
        elif isinstance(data, dict) and data_type == "content_block_delta":
            delta = data.get("delta") or {}
            text = delta.get("text") or delta.get("partial_json") or ""
            summary += f", delta_type={delta.get('type')}, text={preview_text(text, 160)}"
        elif isinstance(data, dict) and data_type == "message_delta":
            delta = data.get("delta") or {}
            summary += f", stop_reason={delta.get('stop_reason')}"
        elif isinstance(data, dict) and data_type == "error":
            summary += f", error={preview_text(json.dumps(data, ensure_ascii=False), 500)}"
        self.server.state.log(summary)
