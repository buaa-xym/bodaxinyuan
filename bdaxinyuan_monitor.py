# -*- coding: utf-8 -*-
"""
博大新元（北京经开区青年人才住宿平台）房源监控脚本
================================================
每 15 分钟查询一次「申请项目」列表（同小程序：我的申请 -> 继续申请 -> 申请项目下拉框），
项目 isFull=false 显示"未满"（有房），isFull=true 显示"(已满)"。
一旦发现某个项目从"已满"变为"未满"，立即在控制台提示 + 写入日志（可选 webhook 推送）。

【首次使用 —— 一键登录，无需浏览器抓包】
  python bdaxinyuan_monitor.py --login
  按提示输入手机号 -> 收到短信后输入短信验证码 -> 自动保存 token 到 token.json
  （图形验证码脚本自动获取并填写，你不用管）

之后运行监控：
  python bdaxinyuan_monitor.py           # 持续监控，每 15 分钟一轮
  python bdaxinyuan_monitor.py --once    # 只查一次立即退出（测试用）
token 失效时脚本会提示，重新执行 --login 即可。
"""

import sys
import json
import time
import base64
import os
from datetime import datetime, timezone, timedelta

import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# ========================= CONFIG（按需修改） =========================
# 监控的人才类别（对应小程序"人才类别选择"）
# GC0060001=求职青年人才  GC0060002=实习青年人才  GC0060003=就业青年人才  GC0060004=创业青年人才
STUDENT_STATUSES = ["GC0060003"]   # 只监控：就业青年人才

SUBMIT_TYPE = "APPLY"          # APPLY=新申请；续住场景用 RENEWED（一般不用）

# 运行环境说明：
# - 本地运行：--login 保存 token.json，生日/性别自动从账号资料读取
# - GitHub Actions 运行：token 和 Server酱 SendKey 通过环境变量注入（仓库 Secrets），
#   生日/性别写在 config.json 里（随仓库提交）
TOKEN = os.environ.get("BD_TOKEN", "")                 # GitHub Secret: BD_TOKEN
# Server酱 SendKey，支持多个（逗号分隔），每人一个 key，消息会推给每个人
# 也可写在 config.json 的 "sendkeys" 字段里（本地运行时用）
SENDKEY = os.environ.get("SENDKEY", "")
BIRTHDAY = os.environ.get("BD_BIRTHDAY", "")           # 也可用 config.json
GENDER = os.environ.get("BD_GENDER", "")               # 字典编码如 GC0048001，也可用 config.json

INTERVAL_MINUTES = 15          # 轮询间隔（分钟，仅本地常驻模式用）
DAILY_REPORT_TIME = "20:00"   # 每天日报时间（北京时间），之后的第一轮检查时推送"今日已查询 N 次"

BASE = "https://qnrc.bdalife.cn/api"
TENANT_ID = "DII55AMT"
AES_KEY = b"wX$9XdJv3l2hJlhH"  # 来自前端固定 key
ORIGIN = "http://dxs.bdalife.cn:4443"

HERE = os.path.dirname(os.path.abspath(__file__))
STATE_FILE = os.path.join(HERE, "state.json")
LOG_FILE = os.path.join(HERE, "monitor.log")
TOKEN_FILE = os.path.join(HERE, "token.json")
CONFIG_FILE = os.path.join(HERE, "config.json")
# =====================================================================

# 从 config.json 读取覆盖（用于 GitHub Actions 场景）
if os.path.exists(CONFIG_FILE):
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as _f:
            _cfg = json.load(_f)
        BIRTHDAY = BIRTHDAY or _cfg.get("birthday", "")
        GENDER = GENDER or _cfg.get("gender", "")
        SENDKEY = SENDKEY or ",".join(_cfg.get("sendkeys", []))
        DAILY_REPORT_TIME = os.environ.get("DAILY_REPORT_TIME") or _cfg.get("daily_report_time", DAILY_REPORT_TIME)
    except Exception:
        pass
DAILY_REPORT_TIME = os.environ.get("DAILY_REPORT_TIME", DAILY_REPORT_TIME)

CST = timezone(timedelta(hours=8))   # 北京时间（GitHub Actions 机器是 UTC，必须统一时区）


def now_cst() -> datetime:
    return datetime.now(CST)

SESSION = requests.Session()
SESSION.headers.update({
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "origin": ORIGIN,
    "referer": ORIGIN + "/",
})


# ---------------- 加解密 ----------------
def _encrypt(payload: dict):
    """POST 请求体加密：AES-128-CBC(key固定, iv=毫秒时间戳+'000', PKCS7) -> Base64"""
    ts = str(int(time.time() * 1000))
    iv = (ts + "000").encode()
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()
    return ts, base64.b64encode(AES.new(AES_KEY, AES.MODE_CBC, iv).encrypt(pad(raw, 16))).decode()


def _decrypt(text: str, ts: str) -> dict:
    blob = base64.b64decode(text)
    raw = AES.new(AES_KEY, AES.MODE_CBC, (ts + "000").encode()).decrypt(blob)
    return json.loads(raw[: -raw[-1]].decode("utf-8"))


def api_get(path: str, params: dict = None, token: str = "") -> dict:
    """GET：请求体不加密，但需要 en-ch 头；响应加密需解密"""
    ts = str(int(time.time() * 1000))
    headers = {"en-ch": ts}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    r = SESSION.get(BASE + path, params=params, headers=headers, timeout=30)
    r.raise_for_status()
    return _decrypt(r.text, ts)


def api_post(path: str, payload: dict, token: str = "") -> dict:
    """POST：请求体和响应都加密"""
    ts, body = _encrypt(payload)
    headers = {"en-ch": ts, "content-type": "text/plain"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    r = SESSION.post(BASE + path, data=body.encode(), headers=headers, timeout=30)
    r.raise_for_status()
    return _decrypt(r.text, ts)


# ---------------- 登录 ----------------
def cmd_login():
    """一键登录：手机号 + 短信验证码（图形验证码自动处理）"""
    print("=" * 56)
    print(" 博大新元 登录（与小程序账号通用，手机号+短信验证码）")
    print("=" * 56)
    phone = input("手机号: ").strip()
    if not phone.isdigit() or len(phone) != 11:
        print("手机号格式不对"); sys.exit(1)

    # 1. 图形验证码：接口直接返回验证码文本，自动填
    cap = api_get(f"/message/ncr/sms_verification/get_verification_code/{phone}",
                  params={"tenantId": TENANT_ID})
    if cap.get("code") != "200" or not cap.get("data"):
        print(f"获取图形验证码失败: {cap}"); sys.exit(1)
    image_code = str(cap["data"])
    print(f"图形验证码已自动获取: {image_code}")

    # 2. 发送短信验证码
    resp = api_post("/customer/ncr/customer/applet/get_message_code",
                    {"phone": phone, "verificationCode": image_code})
    if resp.get("code") != "200":
        print(f"短信发送失败: {resp.get('msg')}（可重跑一次本命令重试）")
        sys.exit(1)
    print("短信已发送，请查看手机")

    # 3. 输入短信验证码，提交登录
    sms = input("短信验证码: ").strip()
    resp = api_post("/ncr/wchatapp_login",
                    {"phone": phone, "password": "", "code": sms,
                     "verificationCode": image_code, "type": 1,
                     "tenantId": TENANT_ID, "isQRCodeLogin": False,
                     "isMultipleBrand": False})
    if resp.get("code") != "200" or not resp.get("data"):
        print(f"登录失败: {resp.get('msg')}（验证码错误请重跑 --login）")
        sys.exit(1)

    data = resp["data"]
    token = data.get("token") or (data.get("user_info") or {}).get("token")
    if not token:
        print(f"登录成功但未找到 token 字段，原始返回如下，请反馈：\n{json.dumps(data, ensure_ascii=False)[:500]}")
        sys.exit(1)

    with open(TOKEN_FILE, "w", encoding="utf-8") as f:
        json.dump({"token": token, "phone": phone,
                   "login_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                   "raw": data}, f, ensure_ascii=False, indent=1)
    print(f"\n✅ 登录成功，token 已保存到 {TOKEN_FILE}")
    print("现在可以直接运行: python bdaxinyuan_monitor.py")


def load_token() -> str:
    if os.path.exists(TOKEN_FILE):
        try:
            with open(TOKEN_FILE, "r", encoding="utf-8") as f:
                return json.load(f).get("token", "")
        except Exception:
            return ""
    return ""


def load_profile(token: str) -> tuple:
    """从 token.json 读生日/性别；没有则调用账号资料接口自动获取并缓存。
    返回 (birthday, gender)；获取失败返回 ('', '')。"""
    data = {}
    if os.path.exists(TOKEN_FILE):
        try:
            with open(TOKEN_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            data = {}
    if data.get("birthday") and data.get("gender"):
        return data["birthday"], data["gender"]
    last_err = "未知"
    for _ in range(2):   # 失败重试一次，避免偶发网络抖动
        try:
            info = api_post("/customer/customer/applet/get_customer_info",
                            {"tenantId": TENANT_ID}, token=token)
            if info.get("code") == "200" and info.get("data"):
                d = info["data"]
                data["birthday"] = d.get("birthday") or ""
                data["gender"] = d.get("gender") or ""   # 字典编码，如 GC0048001
                with open(TOKEN_FILE, "w", encoding="utf-8") as f:
                    json.dump(data, f, ensure_ascii=False, indent=1)
                return data["birthday"], data["gender"]
            last_err = f"code={info.get('code')} msg={info.get('msg')}"
        except Exception as e:
            last_err = repr(e)
        time.sleep(1)
    log(f"读取账号资料失败（{last_err}）")
    return "", ""


# ---------------- 监控 ----------------
STATUS_NAMES = {
    "GC0060001": "求职青年人才",
    "GC0060002": "实习青年人才",
    "GC0060003": "就业青年人才",
    "GC0060004": "创业青年人才",
}


def load_state() -> dict:
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_state(state: dict):
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=1)


def log(msg: str):
    line = f"[{datetime.now():%Y-%m-%d %H:%M:%S}] {msg}"
    print(line, flush=True)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        pass


def notify(title: str, body: str):
    """检测到有房时的提醒动作：控制台高亮 + 日志 + Server酱微信推送"""
    log("=" * 60)
    log(f"*** {title} ***")
    for line in body.splitlines():
        log("    " + line)
    log("=" * 60)
    keys = [k.strip() for k in SENDKEY.split(",") if k.strip()]
    for key in keys:
        try:
            r = requests.post(f"https://sctapi.ftqq.com/{key}.send",
                              data={"title": title, "desp": body}, timeout=15)
            log(f"Server酱推送({key[:8]}...): HTTP {r.status_code}")
        except Exception as e:  # 推送失败不影响监控
            log(f"Server酱推送失败({key[:8]}...): {e}")


def check_once(token: str) -> bool:
    """执行一轮检查。返回 False 表示 token 失效等需要人工干预。"""
    birthday, gender = BIRTHDAY, GENDER
    if not birthday or not gender:
        b2, g2 = load_profile(token)
        birthday = birthday or b2
        gender = gender or g2
    if not birthday or not gender:
        log("无法获取账号资料（生日/性别），请重新登录: python bdaxinyuan_monitor.py --login")
        return False
    state = load_state()
    snapshot = {}   # 本轮最新状态: {status: {projectName: isFull_bool}}
    problems = []
    # 冷启动判定：state 里还没有任何基线数据（首次运行 / state 被清空），或 token 刚更新过
    _meta0 = state.get("_meta") if isinstance(state.get("_meta"), dict) else {}
    _tok_fp = (token or "")[:16]
    token_changed = bool(_meta0.get("token_fp")) and _meta0.get("token_fp") != _tok_fp
    cold_start = (not any(isinstance(state.get(st), dict) and state.get(st) for st in STUDENT_STATUSES)) or token_changed

    for st in STUDENT_STATUSES:
        label = STATUS_NAMES.get(st, st)
        try:
            resp = api_get(f"/customer/ncr/project_maintenance/list/{st}",
                           params={"tenantId": TENANT_ID, "submitType": SUBMIT_TYPE,
                                   "birthday": birthday, "gender": gender},
                           token=token)
        except requests.HTTPError as e:
            code = e.response.status_code if e.response is not None else "?"
            problems.append(f"{label}: HTTP {code}")
            continue
        except Exception as e:
            problems.append(f"{label}: {e}")
            continue

        if resp.get("code") == "401" or (isinstance(resp.get("data"), str) and "登录" in str(resp.get("msg"))):
            log(f"token 已失效（{label}）。请重新执行: python bdaxinyuan_monitor.py --login")
            notify("⚠️ 房源监控 token 已失效",
                   "监控已停止。请在电脑上执行: python bdaxinyuan_monitor.py --login\n"
                   "然后到 GitHub 仓库 Settings -> Secrets -> BD_TOKEN 更新 token。")
            return False
        if resp.get("code") != "200":
            problems.append(f"{label}: 接口返回 {resp.get('code')} {resp.get('msg')}")
            continue

        projects = resp.get("data") or []
        snapshot[st] = {p.get("projectName", "?"): bool(p.get("isFull")) for p in projects}

        prev = state.get(st, {})
        newly_available = [n for n, f in snapshot[st].items() if not f and prev.get(n) is True]
        available_now = [n for n, f in snapshot[st].items() if not f]
        log(f"{label}: 共 {len(projects)} 个项目，未满 {len(available_now)} 个")
        # 逐个输出项目名字及满/空状态
        for name, is_full in snapshot[st].items():
            log(f"    - {name} [{'已满' if is_full else '未满(有房)'}]")

        if newly_available:
            notify(
                f"🎉 博大新元有房了！[{label}]",
                "以下项目刚刚从\"已满\"变为\"未满\"：\n" + "\n".join(newly_available)
                + f"\n\n快去申请：{ORIGIN}/?v=1792906247546#/pages/my/apply/application-sub",
            )

    # ---- 启动通知：仅冷启动（首次运行/状态被清空）时发一次 ----
    if cold_start and snapshot:
        lines = []
        for st in STUDENT_STATUSES:
            label = STATUS_NAMES.get(st, st)
            cur = snapshot.get(st, {})
            if not cur:
                continue
            avail = [n for n, f in cur.items() if not f]
            lines.append(f"- {label}: " + ("、".join(avail) if avail else "全部已满"))
        notify("🚀 房源监控已启动",
               "已记录当前基线状态：\n" + "\n".join(lines)
               + "\n\n之后仅在放房、每天日报或 token 失效时推送。")
        log("已发送启动通知")

    if problems:
        log("本轮存在异常: " + "; ".join(problems))

    if snapshot:
        state.update(snapshot)

    # ---- 每日查询计数 + 定时日报（北京时间） ----
    meta = state.get("_meta") if isinstance(state.get("_meta"), dict) else {}
    today = now_cst().strftime("%Y-%m-%d")
    if meta.get("date") != today:
        meta = {"date": today, "count": 0, "last_report": ""}
    meta["count"] = meta.get("count", 0) + 1
    meta["token_fp"] = _tok_fp
    state["_meta"] = meta

    if now_cst().strftime("%H:%M") >= DAILY_REPORT_TIME and meta.get("last_report") != today:
        avail_lines = []
        for st in STUDENT_STATUSES:
            label = STATUS_NAMES.get(st, st)
            cur = state.get(st, {})
            avail = [n for n, f in cur.items() if not f]
            avail_lines.append(f"- {label}: " + ("、".join(avail) if avail else "全部已满"))
        notify(
            f"📊 房源日报（今日已查询 {meta['count']} 次）",
            f"日期：{today}  报告时间：{DAILY_REPORT_TIME}\n" + "\n".join(avail_lines)
            + "\n\n有房会随时单独推送，请留意。",
        )
        meta["last_report"] = today
        log(f"已发送每日报告（今日查询 {meta['count']} 次）")

    save_state(state)
    return True


def main():
    if "--login" in sys.argv:
        cmd_login()
        return

    token = TOKEN or load_token()
    if not token:
        print("!!! 尚未登录。请先执行一键登录：python bdaxinyuan_monitor.py --login")
        sys.exit(1)

    if "--once" in sys.argv:
        # 必须把失败向上传递，否则 Actions 会显示成功但实际没跑出数据
        sys.exit(0 if check_once(token) else 1)

    log(f"开始监控博大新元房源，每 {INTERVAL_MINUTES} 分钟检查一次（Ctrl+C 停止）...")
    while True:
        ok = check_once(token)
        if not ok:
            log("已停止：请重新登录后运行（python bdaxinyuan_monitor.py --login）。")
            sys.exit(2)
        for _ in range(INTERVAL_MINUTES * 60):  # 按秒睡眠，便于 Ctrl+C 及时响应
            time.sleep(1)


if __name__ == "__main__":
    main()
