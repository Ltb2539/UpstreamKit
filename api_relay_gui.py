import argparse
import atexit
import os
import queue
import sys
import tempfile
import threading
from http.server import ThreadingHTTPServer
from tkinter import END, DISABLED, NORMAL, StringVar, BooleanVar, Text, Tk, WORD, ttk

try:
    import pystray
except ImportError:
    pystray = None

from upstreamkit_core import (
    APP_NAME,
    CONFIG_PATH,
    DEFAULT_PORT,
    DEFAULT_TOKEN_STATS,
    DEFAULT_UPSTREAM,
    DAILY_TOKEN_STATS_PATH,
    DEFAULT_DAILY_TOKEN_STATS,
    SSL_TRUST_SOURCE,
    TOKEN_STATS_PATH,
    PROMPT_LOG_DIR,
    RelayConfig,
    RelayHandler,
    RelayState,
    create_tray_image,
    describe_connection_error,
    diagnose_tls_endpoint,
    is_startup_enabled,
    join_url,
    load_saved_config,
    load_token_stats,
    load_daily_token_stats,
    save_daily_token_stats,
    normalize_token_stats,
    post_json,
    save_config_data,
    save_token_stats,
    set_startup_enabled,
    add_token_stats,
    now_text,
    get_date_key,
    get_prompt_log_path,
    write_prompt_header,
    write_prompt_response,
    write_prompt_footer,
    winreg,
)
from upstreamkit_dialogs import UpstreamEditDialog
from token_stats_dialog import TokenStatsDialog


class RelayApp:
    def __init__(self, autostart=False):
        # 单实例保护
        self._lockfile = os.path.join(tempfile.gettempdir(), "UpstreamKit.lock")
        if os.path.exists(self._lockfile):
            try:
                with open(self._lockfile, "r") as f:
                    old_pid = int(f.read().strip())
                os.kill(old_pid, 0)  # 检查进程是否存在
                self.log = lambda _: None  # 占位
                print(f"UpstreamKit 已在运行 (PID {old_pid})，退出。")
                sys.exit(0)
            except (OSError, ValueError):
                os.remove(self._lockfile)  # 僵尸锁，清理
        with open(self._lockfile, "w") as f:
            f.write(str(os.getpid()))
        atexit.register(lambda: os.path.exists(self._lockfile) and os.remove(self._lockfile))
        #单实例保护结束
        self.root = Tk()
        self.root.title(APP_NAME)
        self.root.geometry("860x620")
        self.root.minsize(760, 560)

        self.saved_config = load_saved_config()
        self.upstreams = self.saved_config.get("upstreams", [dict(DEFAULT_UPSTREAM)])
        self.active_upstream = self.saved_config.get("active_upstream", 0)
        if self.active_upstream >= len(self.upstreams):
            self.active_upstream = 0
        active = self.upstreams[self.active_upstream] if self.upstreams else dict(DEFAULT_UPSTREAM)
        self.upstream_var = StringVar(value=active.get("name", "默认上游"))
        self.provider_var = StringVar(value=active.get("provider", "openai"))
        self.url_var = StringVar(value=active.get("base_url", "https://api.openai.com"))
        self.key_var = StringVar(value=active.get("api_key", ""))
        self.model_var = StringVar(value=active.get("model", "gpt-4.1"))
        self.port_var = StringVar(value=str(self.saved_config.get("port", DEFAULT_PORT)))
        self.output_var = StringVar(value="未运行")
        self.session_tokens = dict(DEFAULT_TOKEN_STATS)
        self.total_tokens = load_token_stats()
        self.token_lock = threading.Lock()
        self.daily_stats = load_daily_token_stats()
        self.detailed_token_lock = threading.Lock()
        self.session_models = {}  # 本次会话分模型统计
        self.session_token_var = StringVar()
        self.total_token_var = StringVar()
        self.log_prompt_var = BooleanVar(value=self.saved_config.get("log_prompt", False))

        self.server = None
        self.server_thread = None
        self.tray_icon = None
        self.tray_thread = None
        self.exiting = False
        self.autostart = autostart
        self.close_hint_logged = False
        self.log_queue = queue.Queue()
        self.log_lines = []

        self.build_ui()
        self.update_token_labels()
        self.port_var.trace_add("write", self.schedule_port_save)
        self.start_tray_icon()

    def schedule_port_save(self, *_args):
        if hasattr(self, "port_save_id") and self.port_save_id:
            self.root.after_cancel(self.port_save_id)
        self.port_save_id = self.root.after(500, self.save_config)

    def build_ui(self):
        frame = ttk.Frame(self.root, padding=14)
        frame.pack(fill="both", expand=True)

        # 上游选择器
        ttk.Label(frame, text="上游配置").grid(row=0, column=0, sticky="w", pady=6)
        self.upstream_box = ttk.Combobox(frame, textvariable=self.upstream_var, state="readonly", width=28)
        self.upstream_box.grid(row=0, column=1, columnspan=2, sticky="ew", pady=6)
        self.upstream_box.bind("<<ComboboxSelected>>", self.on_upstream_select)
        self.refresh_upstream_box()

        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=0, column=3, sticky="e", pady=6)
        self.add_button = ttk.Button(btn_frame, text="添加", command=self.add_upstream, width=6)
        self.add_button.pack(side="left", padx=2)
        self.edit_button = ttk.Button(btn_frame, text="编辑", command=self.edit_upstream, width=6)
        self.edit_button.pack(side="left", padx=2)
        self.delete_button = ttk.Button(btn_frame, text="删除", command=self.delete_upstream, width=6)
        self.delete_button.pack(side="left", padx=2)

        # 当前上游信息（只读显示）
        ttk.Label(frame, text="上游 URL").grid(row=1, column=0, sticky="w", pady=6)
        self.url_entry = ttk.Entry(frame, textvariable=self.url_var, state="readonly")
        self.url_entry.grid(row=1, column=1, columnspan=3, sticky="ew", pady=6)

        ttk.Label(frame, text="上游 Key").grid(row=2, column=0, sticky="w", pady=6)
        self.key_entry = ttk.Entry(frame, textvariable=self.key_var, show="*", state="readonly")
        self.key_entry.grid(row=2, column=1, columnspan=3, sticky="ew", pady=6)

        ttk.Label(frame, text="上游类型").grid(row=3, column=0, sticky="w", pady=6)
        self.provider_entry = ttk.Entry(frame, textvariable=self.provider_var, state="readonly", width=18)
        self.provider_entry.grid(row=3, column=1, sticky="w", pady=6)

        ttk.Label(frame, text="上游模型").grid(row=3, column=2, sticky="e", pady=6)
        self.model_entry = ttk.Entry(frame, textvariable=self.model_var, state="readonly", width=28)
        self.model_entry.grid(row=3, column=3, sticky="ew", pady=6)

        ttk.Label(frame, text="本地端口").grid(row=4, column=0, sticky="w", pady=6)
        ttk.Entry(frame, textvariable=self.port_var, width=18).grid(row=4, column=1, sticky="w", pady=6)

        self.run_button = ttk.Button(frame, text="运行", command=self.toggle_server)
        self.run_button.grid(row=4, column=3, sticky="e", pady=6)

        self.log_prompt_check = ttk.Checkbutton(frame, text="记录 Prompt 日志", variable=self.log_prompt_var, command=self.on_log_prompt_change)
        self.log_prompt_check.grid(row=5, column=0, columnspan=2, sticky="w", pady=6)

        self.test_button = ttk.Button(frame, text="测试", command=self.test_upstream)
        self.test_button.grid(row=5, column=3, sticky="e", pady=6)
        self.diagnose_button = ttk.Button(frame, text="诊断", command=self.diagnose_upstream)
        self.diagnose_button.grid(row=5, column=2, sticky="e", pady=6, padx=(0, 8))

        sep = ttk.Separator(frame)
        sep.grid(row=6, column=0, columnspan=4, sticky="ew", pady=12)

        ttk.Label(frame, text="请求中转的 URL").grid(row=7, column=0, sticky="nw", pady=6)
        output = ttk.Entry(frame, textvariable=self.output_var, state="readonly")
        output.grid(row=7, column=1, columnspan=3, sticky="ew", pady=6)

        info = "Claude Code 开发者模式里填上方 URL；Key 可留空或随便填；客户端传来的 model 会被忽略，思考参数会保留。"
        ttk.Label(frame, text=info).grid(row=8, column=1, columnspan=3, sticky="w", pady=3)

        ttk.Label(frame, text="本次开启token：").grid(row=9, column=0, sticky="nw", pady=(10, 2))
        ttk.Label(frame, textvariable=self.session_token_var).grid(row=9, column=1, columnspan=3, sticky="w", pady=(10, 2))

        ttk.Label(frame, text="总计token：").grid(row=10, column=0, sticky="nw", pady=2)
        ttk.Label(frame, textvariable=self.total_token_var).grid(row=10, column=1, columnspan=2, sticky="w", pady=2)
        ttk.Button(frame, text="统计详情", command=self.show_token_stats_dialog).grid(row=10, column=3, sticky="e", pady=2)

        ttk.Label(frame, text="日志").grid(row=11, column=0, sticky="nw", pady=(14, 6))
        log_frame = ttk.Frame(frame)
        log_frame.grid(row=11, column=1, columnspan=3, sticky="nsew", pady=(14, 0))

        self.log_text = Text(log_frame, wrap=WORD, height=15, state=DISABLED)
        scroll = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scroll.set)
        self.log_text.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        frame.columnconfigure(1, weight=1)
        frame.columnconfigure(3, weight=1)
        frame.rowconfigure(11, weight=1)

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def refresh_upstream_box(self):
        names = [u.get("name", f"上游{i+1}") for i, u in enumerate(self.upstreams)]
        self.upstream_box["values"] = names
        if 0 <= self.active_upstream < len(names):
            self.upstream_box.current(self.active_upstream)

    def apply_active_upstream_to_form(self):
        active = self.upstreams[self.active_upstream] if self.upstreams else dict(DEFAULT_UPSTREAM)
        self.upstream_var.set(active.get("name", "默认上游"))
        self.provider_var.set(active.get("provider", "openai"))
        self.url_var.set(active.get("base_url", "https://api.openai.com"))
        self.key_var.set(active.get("api_key", ""))
        self.model_var.set(active.get("model", "gpt-4.1"))

    def update_running_controls(self):
        if self.server:
            self.upstream_box.configure(state=DISABLED)
        else:
            self.upstream_box.configure(state="readonly")

    def on_upstream_select(self, _event=None):
        idx = self.upstream_box.current()
        if idx >= 0 and idx != self.active_upstream:
            self.switch_upstream(idx)

    def switch_upstream(self, idx):
        if self.server:
            self.refresh_upstream_box()
            self.log("运行中不能切换上游，请先停止服务")
            return
        self.active_upstream = idx
        if self.active_upstream >= len(self.upstreams):
            self.active_upstream = 0
        self.apply_active_upstream_to_form()
        active = self.upstreams[self.active_upstream] if self.upstreams else dict(DEFAULT_UPSTREAM)
        self.log(f"已切换到上游：{active.get('name', '默认上游')}")
        self.save_config()

    def add_upstream(self):
        dialog = UpstreamEditDialog(self.root, "添加上游")
        if dialog.result:
            self.upstreams.append(dialog.result)
            if not self.server:
                self.active_upstream = len(self.upstreams) - 1
                self.apply_active_upstream_to_form()
            self.refresh_upstream_box()
            self.log(f"已添加上游：{dialog.result.get('name', '新上游')}")
            if self.server:
                self.log("当前服务仍使用启动时的上游配置，停止后可切换到新上游")
            self.save_config()

    def edit_upstream(self):
        if not self.upstreams:
            return
        dialog = UpstreamEditDialog(self.root, "编辑上游", self.upstreams[self.active_upstream])
        if dialog.result:
            self.upstreams[self.active_upstream] = dialog.result
            self.apply_active_upstream_to_form()
            self.refresh_upstream_box()
            self.log(f"已编辑上游：{dialog.result.get('name', '上游')}")
            if self.server:
                self.log("当前服务仍使用启动时的上游配置，重启服务后新配置生效")
            self.save_config()

    def delete_upstream(self):
        if len(self.upstreams) <= 1:
            self.log("至少需要保留一个上游配置")
            return
        if self.server:
            self.log("运行中不能删除上游，请先停止服务")
            return
        name = self.upstreams[self.active_upstream].get("name", "上游")
        self.upstreams.pop(self.active_upstream)
        self.active_upstream = min(self.active_upstream, len(self.upstreams) - 1)
        self.apply_active_upstream_to_form()
        self.refresh_upstream_box()
        self.log(f"已删除上游：{name}")
        self.save_config()

    def save_config(self):
        data = {
            "upstreams": self.upstreams,
            "active_upstream": self.active_upstream,
            "port": self.port_var.get(),
            "log_prompt": self.log_prompt_var.get(),
        }
        try:
            save_config_data(data)
        except Exception as exc:
            self.log(f"保存配置失败：{exc}")

    def on_log_prompt_change(self):
        """Prompt 日志开关变化时，同时更新运行中的服务状态"""
        self.save_config()
        if self.server:
            self.server.state.log_prompt_enabled = self.log_prompt_var.get()
            status = "已启用" if self.log_prompt_var.get() else "已关闭"
            self.log(f"Prompt 日志记录 {status}")

    def format_token_line(self, stats):
        stats = normalize_token_stats(stats)
        if stats["cache_known"]:
            return (
                f"输入（未命中）{stats['cache_miss_input_tokens']}    "
                f"输入（命中）{stats['cache_hit_input_tokens']}    "
                f"输出{stats['output_tokens']}"
            )
        return f"输入 {stats['input_tokens']}    输出 {stats['output_tokens']}"

    def update_token_labels(self):
        self.session_token_var.set(self.format_token_line(self.session_tokens))
        self.total_token_var.set(self.format_token_line(self.total_tokens))

    def record_token_usage(self, usage_delta):
        if not usage_delta:
            return
        with self.token_lock:
            self.session_tokens = add_token_stats(self.session_tokens, usage_delta)
            self.total_tokens = add_token_stats(self.total_tokens, usage_delta)
            try:
                save_token_stats(self.total_tokens)
            except Exception as exc:
                self.log(f"保存 token 统计失败：{exc}")
        self.root.after(0, self.update_token_labels)

    def record_detailed_token_usage(self, usage_delta, model=None):
        """记录每日和分模型的详细统计"""
        if not usage_delta:
            return
        date_key = get_date_key()
        model_key = model or "unknown"
        # 简化模型名（去掉日期后缀等）
        if model_key and "-" in model_key:
            # 尝试识别 claude-xxx 格式
            parts = model_key.split("-")
            if len(parts) >= 2 and parts[0] in ("claude", "gpt"):
                # 保留前两部分作为简化名
                model_key = f"{parts[0]}-{parts[1]}"
        with self.detailed_token_lock:
            # 更新本次会话的分模型统计
            if model_key not in self.session_models:
                self.session_models[model_key] = {
                    "input_tokens": 0,
                    "cache_miss_input_tokens": 0,
                    "cache_hit_input_tokens": 0,
                    "output_tokens": 0,
                    "request_count": 0,
                }
            model_stats = self.session_models[model_key]
            model_stats["input_tokens"] += usage_delta.get("input_tokens", 0)
            model_stats["cache_miss_input_tokens"] += usage_delta.get("cache_miss_input_tokens", 0)
            model_stats["cache_hit_input_tokens"] += usage_delta.get("cache_hit_input_tokens", 0)
            model_stats["output_tokens"] += usage_delta.get("output_tokens", 0)
            model_stats["request_count"] += 1

            # 更新每日统计
            self.daily_stats = load_daily_token_stats()
            daily_stats = self.daily_stats.get("daily_stats", {})
            day_stats = daily_stats.setdefault(date_key, {
                "input_tokens": 0,
                "cache_miss_input_tokens": 0,
                "cache_hit_input_tokens": 0,
                "output_tokens": 0,
                "request_count": 0,
                "models": {},
            })
            # 累加日统计
            day_stats["input_tokens"] += usage_delta.get("input_tokens", 0)
            day_stats["cache_miss_input_tokens"] += usage_delta.get("cache_miss_input_tokens", 0)
            day_stats["cache_hit_input_tokens"] += usage_delta.get("cache_hit_input_tokens", 0)
            day_stats["output_tokens"] += usage_delta.get("output_tokens", 0)
            day_stats["request_count"] += 1
            # 累加模型统计
            model_day_stats = day_stats["models"].setdefault(model_key, {
                "input_tokens": 0,
                "cache_miss_input_tokens": 0,
                "cache_hit_input_tokens": 0,
                "output_tokens": 0,
                "request_count": 0,
            })
            model_day_stats["input_tokens"] += usage_delta.get("input_tokens", 0)
            model_day_stats["cache_miss_input_tokens"] += usage_delta.get("cache_miss_input_tokens", 0)
            model_day_stats["cache_hit_input_tokens"] += usage_delta.get("cache_hit_input_tokens", 0)
            model_day_stats["output_tokens"] += usage_delta.get("output_tokens", 0)
            model_day_stats["request_count"] += 1
            # 更新日期范围
            if not self.daily_stats.get("first_use_date"):
                self.daily_stats["first_use_date"] = date_key
            self.daily_stats["last_use_date"] = date_key
            try:
                save_daily_token_stats(self.daily_stats)
            except Exception as exc:
                self.log(f"保存每日 token 统计失败：{exc}")

    def toggle_server(self):
        if self.server:
            self.stop_server()
        else:
            self.start_server()

    def read_config_from_form(self):
        port = int(self.port_var.get().strip())
        if not (1 <= port <= 65535):
            raise ValueError("端口必须在 1-65535 之间")
        if not self.url_var.get().strip():
            raise ValueError("请填写上游 URL")
        if not self.key_var.get().strip():
            raise ValueError("请填写上游 Key")
        if not self.model_var.get().strip():
            raise ValueError("请填写上游模型")
        return RelayConfig(
            provider=self.provider_var.get(),
            base_url=self.url_var.get().strip(),
            api_key=self.key_var.get().strip(),
            model=self.model_var.get().strip(),
            port=port,
            log_prompt=self.log_prompt_var.get(),
        )

    def test_upstream(self):
        try:
            config = self.read_config_from_form()
        except Exception as exc:
            self.log(f"测试失败：{exc}")
            return

        self.test_button.configure(state=DISABLED)
        self.log(
            "开始测试上游："
            f"{config.provider} {config.base_url}，模型 {config.model}"
        )
        threading.Thread(target=self.run_upstream_test, args=(config,), daemon=True).start()

    def run_upstream_test(self, config):
        try:
            if config.provider == "openai":
                url = join_url(config.base_url, "/v1/chat/completions")
                headers = {
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {config.api_key}",
                    "User-Agent": APP_NAME,
                }
                body = {
                    "model": config.model,
                    "messages": [{"role": "user", "content": "ping"}],
                    "max_tokens": 8,
                    "stream": False,
                }
            else:
                url = join_url(config.base_url, "/v1/messages")
                headers = {
                    "Content-Type": "application/json",
                    "x-api-key": config.api_key,
                    "anthropic-version": "2023-06-01",
                    "User-Agent": APP_NAME,
                }
                body = {
                    "model": config.model,
                    "messages": [{"role": "user", "content": "ping"}],
                    "max_tokens": 8,
                    "stream": False,
                }
            status, text = post_json(url, headers, body, timeout=60)
            preview = text.replace("\r", " ").replace("\n", " ")[:500]
            if 200 <= status < 300:
                self.log(f"测试成功：HTTP {status}")
            else:
                self.log(f"测试失败：HTTP {status} {preview}")
        except Exception as exc:
            self.log(f"测试失败：{describe_connection_error(exc)}")
        finally:
            self.root.after(0, lambda: self.test_button.configure(state=NORMAL))

    def diagnose_upstream(self):
        try:
            config = self.read_config_from_form()
        except Exception as exc:
            self.log(f"诊断失败：{exc}")
            return

        self.diagnose_button.configure(state=DISABLED)
        self.log(f"开始诊断上游连接：{config.base_url}")
        threading.Thread(target=self.run_upstream_diagnosis, args=(config.base_url,), daemon=True).start()

    def run_upstream_diagnosis(self, base_url):
        try:
            for line in diagnose_tls_endpoint(base_url):
                self.log(line)
        except Exception as exc:
            self.log(f"诊断失败：{describe_connection_error(exc)}")
        finally:
            self.root.after(0, lambda: self.diagnose_button.configure(state=NORMAL))

    def start_server(self):
        if self.server:
            return
        try:
            self.save_config()
            config = self.read_config_from_form()
            state = RelayState(config, self.log, self.record_token_usage, self.record_detailed_token_usage)
            server = ThreadingHTTPServer(("127.0.0.1", config.port), RelayHandler)
            server.state = state
            self.server = server
            self.server_thread = threading.Thread(target=server.serve_forever, daemon=True)
            self.server_thread.start()
            local_url = f"http://127.0.0.1:{config.port}"
            self.output_var.set(local_url)
            self.run_button.configure(text="停止")
            self.update_running_controls()
            self.log(f"已启动：{local_url}")
            self.log(
                f"上游：{config.provider} {config.base_url}，上游模型（实际请求）为 {config.model}，思考参数跟随请求方"
            )
        except Exception as exc:
            self.log(f"启动失败：{exc}")

    def stop_server(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server = None
            self.server_thread = None
        self.output_var.set("未运行")
        self.run_button.configure(text="运行")
        self.update_running_controls()
        self.log("已停止")

    def show_token_stats_dialog(self):
        """打开统计详情弹窗"""
        TokenStatsDialog(self.root, self)

    def on_close(self):
        self.hide_to_tray()

    def start_tray_icon(self):
        if pystray is None:
            self.log("托盘依赖不可用：关闭窗口会隐藏，但没有右键托盘菜单。打包版会包含托盘依赖。")
            return

        def show_action(_icon=None, _item=None):
            self.root.after(0, self.show_window)

        def exit_action(_icon=None, _item=None):
            self.root.after(0, self.exit_app)

        def startup_text(_item=None):
            return "√ 开机自启" if is_startup_enabled() else "x 开机不自启"

        def toggle_startup(_icon=None, _item=None):
            def do_toggle():
                try:
                    enabled = not is_startup_enabled()
                    set_startup_enabled(enabled)
                    self.log("已开启开机自启" if enabled else "已关闭开机自启")
                    if self.tray_icon:
                        self.tray_icon.update_menu()
                except Exception as exc:
                    self.log(f"设置开机自启失败：{exc}")

            self.root.after(0, do_toggle)

        menu = pystray.Menu(
            pystray.MenuItem("显示窗口", show_action, default=True),
            pystray.MenuItem(startup_text, toggle_startup, enabled=winreg is not None),
            pystray.MenuItem("退出", exit_action),
        )
        self.tray_icon = pystray.Icon("UpstreamKit", create_tray_image(), APP_NAME, menu)
        self.tray_thread = threading.Thread(target=self.tray_icon.run, daemon=True)
        self.tray_thread.start()

    def hide_to_tray(self):
        self.root.withdraw()
        if not self.close_hint_logged:
            self.log("窗口已隐藏到系统托盘；右键托盘图标选择“退出”才会真正关闭程序。")
            self.close_hint_logged = True

    def show_window(self):
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()

    def exit_app(self):
        if os.path.exists(self._lockfile):
            try:
                os.remove(self._lockfile)
            except:
                pass
        if self.exiting:
            return
        self.exiting = True
        self.log("正在退出程序")
        self.stop_server()
        if self.tray_icon:
            try:
                self.tray_icon.stop()
            except Exception:
                pass
            self.tray_icon = None
        self.root.destroy()

    def log(self, message):
        self.log_queue.put((now_text(), message))

    def flush_logs(self):
        while True:
            try:
                item = self.log_queue.get_nowait()
            except queue.Empty:
                break
            self.log_lines.append(item)
            self.log_text.configure(state=NORMAL)
            self.log_text.insert(END, f"{item[0]}  {item[1]}\n")
            if len(self.log_lines) > 1000:
                self.log_lines.pop(0)
                self.log_text.delete("1.0", "2.0")
            self.log_text.configure(state=DISABLED)
            self.log_text.see(END)
        self.root.after(100, self.flush_logs)

    def run(self):
        self.log("程序已就绪")
        self.log(f"配置文件：{CONFIG_PATH}")
        self.log(f"token统计文件：{TOKEN_STATS_PATH}")
        self.log(f"证书信任来源：{SSL_TRUST_SOURCE}")
        self.root.after(100, self.flush_logs)
        if self.autostart:
            self.root.after(500, self.start_server)
        self.root.mainloop()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--autostart", action="store_true", help="启动后自动开始中转服务")
    args = parser.parse_args()
    RelayApp(autostart=args.autostart).run()
